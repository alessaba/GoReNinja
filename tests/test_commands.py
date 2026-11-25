"""Headless tests for the plugin command and settings surface.

The plugin imports Binary Ninja and the parser internals at import time, so this
test replaces both with lightweight stubs before importing the package. Nothing
here needs a Binary Ninja license or UI.
"""
import importlib
import json
import sys
import types
import unittest
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parents[1]
PACKAGE_NAME = PLUGIN_DIR.name
PLUGIN_PARENT = str(PLUGIN_DIR.parent)

# Ordered ("run" | "log" | "error", name_or_message) records.
EVENTS = []
INSTANCES = []
REGISTERED_COMMANDS = []
REGISTERED_SETTINGS = {}
BUILD_INFO = {"value": None}
FAILING_STAGES = set()


class FakeBackgroundTaskThread:
    def __init__(self, name, can_cancel=False):
        self.name = name

    def start(self):
        self.run()

    def join(self):
        pass


class FakeGoTask(FakeBackgroundTaskThread):
    def __init__(self, bv, name=None, target=None, **kwargs):
        self.bv = bv
        self.target = target
        INSTANCES.append((type(self).__name__, target))
        super().__init__(type(self).__name__, True)

    def start(self):
        raise AssertionError("pipeline stages must run in the pipeline thread")

    def join(self):
        raise AssertionError("pipeline stages must not be joined")

    def run(self):
        stage_name = type(self).__name__
        EVENTS.append(("run", stage_name))
        if stage_name in FAILING_STAGES:
            raise RuntimeError(f"{stage_name} exploded")


def fake_task(name):
    return type(name, (FakeGoTask,), {})


def fake_command_task(name):
    # Commands that are not pipeline stages are started directly.
    return type(name, (FakeGoTask,), {"start": lambda self: self.run()})


class FakeSettings:
    values = {}

    def get_bool(self, key):
        return bool(self.values.get(key, False))

    def get_integer(self, key):
        return self.values.get(key, 0)

    def get_string(self, key):
        return self.values.get(key, "")

    def register_group(self, name, title):
        pass

    def register_setting(self, key, payload):
        REGISTERED_SETTINGS[key] = json.loads(payload)


class FakePluginCommand:
    @staticmethod
    def register(name, description, callback):
        REGISTERED_COMMANDS.append(("register", name, callback))

    @staticmethod
    def register_for_address(name, description, callback):
        REGISTERED_COMMANDS.append(("register_for_address", name, callback))


def install_stubs():
    binaryninja = types.ModuleType("binaryninja")
    binaryninja.BinaryView = object
    binaryninja.Settings = FakeSettings
    binaryninja.PluginCommand = FakePluginCommand
    plugin = types.ModuleType("binaryninja.plugin")
    plugin.BackgroundTaskThread = FakeBackgroundTaskThread
    binaryninja.plugin = plugin
    sys.modules["binaryninja"] = binaryninja
    sys.modules["binaryninja.plugin"] = plugin

    def record_log(message):
        EVENTS.append(("log", message))

    def record_error(message):
        EVENTS.append(("error", message))

    def get_go_build_info(bv):
        return BUILD_INFO["value"]

    def stub(suffix, **attributes):
        module = types.ModuleType(f"{PACKAGE_NAME}.parsers.{suffix}")
        for key, value in attributes.items():
            setattr(module, key, value)
        sys.modules[module.__name__] = module

    stub("common", NAME="Golang Loader Helper", log_info=record_log, log_error=record_error)
    stub("functions_renamer",
         FunctionRenamer=fake_task("FunctionRenamer"),
         FunctionCommenter=fake_task("FunctionCommenter"))
    stub("type_parser", TypeParser=fake_task("TypeParser"))
    stub("structure_recovery", StructRecovery=fake_task("StructRecovery"))
    stub("decompiler", DecompilerEnhancer=fake_task("DecompilerEnhancer"))
    stub("file_printer", PrintFiles=fake_task("PrintFiles"))
    stub("goresym_parser",
         GoReSymImporter=fake_command_task("GoReSymImporter"),
         GoResSymExecutor=fake_command_task("GoResSymExecutor"))
    stub("interface_recovery", InterfaceRecovery=fake_task("InterfaceRecovery"))
    stub("buildinfo", get_go_build_info=get_go_build_info)


def load_plugin():
    install_stubs()
    sys.path.insert(0, PLUGIN_PARENT)
    return importlib.import_module(PACKAGE_NAME)


EXPECTED_COMMANDS = [
    ("register", "golang\\Parse Go binary"),
    ("register", "golang\\Recover functions"),
    ("register", "golang\\Recover Go types"),
    ("register_for_address", "golang\\Recover Go type at address"),
    ("register", "golang\\GoReSym\\Import JSON..."),
    ("register", "golang\\GoReSym\\Run and import"),
    ("register", "golang\\Utilities\\Show build info and source files"),
]

EXPECTED_SETTINGS = {
    "golang_binary_parser.components": ("boolean", True),
    "golang_binary_parser.sanitize": ("boolean", False),
    "golang_binary_parser.minimum_name_length": ("number", 2),
    "golang_binary_parser.goresym_path": ("string", "GoReSym"),
    "golang_binary_parser.recover_native_types": ("boolean", False),
    "golang_binary_parser.comment_functions": ("boolean", True),
    "golang_binary_parser.source_lines": ("boolean", True),
    "golang_binary_parser.use_typelinks": ("boolean", True),
    "golang_binary_parser.recover_interfaces": ("boolean", True),
    "golang_binary_parser.recover_prototypes": ("boolean", True),
    "golang_binary_parser.decompiler_annotations": ("boolean", True),
}

STAGE_NAMES = {"FunctionRenamer", "FunctionCommenter", "TypeParser",
               "StructRecovery", "InterfaceRecovery", "DecompilerEnhancer",
               "PrintFiles"}


class PluginCommandsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.bv = object()

    @classmethod
    def tearDownClass(cls):
        for name in list(sys.modules):
            if name == PACKAGE_NAME or name.startswith(PACKAGE_NAME + "."):
                del sys.modules[name]
        sys.modules.pop("binaryninja", None)
        sys.modules.pop("binaryninja.plugin", None)
        sys.path.remove(PLUGIN_PARENT)

    def setUp(self):
        EVENTS.clear()
        INSTANCES.clear()
        FAILING_STAGES.clear()
        BUILD_INFO["value"] = None
        FakeSettings.values = {
            "golang_binary_parser.comment_functions": True,
            "golang_binary_parser.recover_native_types": False,
            "golang_binary_parser.recover_interfaces": True,
        }

    def invoke(self, name, *args):
        callbacks = {registered_name: callback
                     for _, registered_name, callback in REGISTERED_COMMANDS}
        return callbacks[name](self.bv, *args)

    def stage_events(self):
        return [event for event in EVENTS
                if event[0] == "run" and event[1] in STAGE_NAMES]

    def test_exactly_seven_commands(self):
        self.assertEqual([(kind, name) for kind, name, _ in REGISTERED_COMMANDS],
                         EXPECTED_COMMANDS)

    def test_required_settings(self):
        self.assertEqual(set(REGISTERED_SETTINGS), set(EXPECTED_SETTINGS))
        for key, (setting_type, default) in EXPECTED_SETTINGS.items():
            with self.subTest(setting=key):
                self.assertEqual(REGISTERED_SETTINGS[key]["type"], setting_type)
                self.assertEqual(REGISTERED_SETTINGS[key]["default"], default)

    def test_full_parse_runs_layers_in_order(self):
        BUILD_INFO["value"] = types.SimpleNamespace(
            go_version="go1.22.1",
            module_info="path\texample.com/main",
        )
        self.invoke("golang\\Parse Go binary")

        self.assertEqual(self.stage_events(), [
            ("run", "FunctionRenamer"),
            ("run", "FunctionCommenter"),
            ("run", "TypeParser"),
            ("run", "InterfaceRecovery"),
            ("run", "DecompilerEnhancer"),
        ])
        logs = [message for kind, message in EVENTS if kind == "log"]
        self.assertTrue(any("go1.22.1" in message for message in logs))
        self.assertTrue(any("example.com/main" in message for message in logs))
        self.assertLess(EVENTS.index(("log", "Go build info: go1.22.1")),
                        EVENTS.index(("run", "FunctionRenamer")))

    def test_full_parse_respects_settings(self):
        FakeSettings.values.update({
            "golang_binary_parser.comment_functions": False,
            "golang_binary_parser.recover_native_types": True,
            "golang_binary_parser.recover_interfaces": False,
        })
        self.invoke("golang\\Parse Go binary")

        starts = [name for kind, name in EVENTS if kind == "run"]
        self.assertIn("FunctionRenamer", starts)
        self.assertNotIn("FunctionCommenter", starts)
        self.assertIn("StructRecovery", starts)
        self.assertNotIn("TypeParser", starts)
        self.assertNotIn("InterfaceRecovery", starts)
        self.assertEqual(starts[-1], "DecompilerEnhancer")

    def test_recover_functions_comment_setting(self):
        self.invoke("golang\\Recover functions")
        self.assertEqual(self.stage_events(), [
            ("run", "FunctionRenamer"),
            ("run", "FunctionCommenter"),
        ])

        EVENTS.clear()
        FakeSettings.values["golang_binary_parser.comment_functions"] = False
        self.invoke("golang\\Recover functions")
        self.assertEqual(self.stage_events(), [
            ("run", "FunctionRenamer"),
        ])

    def test_recover_types_respects_settings(self):
        self.invoke("golang\\Recover Go types")
        self.assertEqual(self.stage_events(), [
            ("run", "TypeParser"),
            ("run", "InterfaceRecovery"),
            ("run", "DecompilerEnhancer"),
        ])

        EVENTS.clear()
        FakeSettings.values.update({
            "golang_binary_parser.recover_native_types": True,
            "golang_binary_parser.recover_interfaces": False,
        })
        self.invoke("golang\\Recover Go types")
        self.assertEqual(self.stage_events(), [
            ("run", "StructRecovery"),
            ("run", "DecompilerEnhancer"),
        ])

    def test_decompiler_enhancement_runs_last(self):
        FakeSettings.values.update({
            "golang_binary_parser.recover_prototypes": False,
            "golang_binary_parser.decompiler_annotations": False,
        })
        self.invoke("golang\\Parse Go binary")
        self.assertEqual(self.stage_events()[-1], ("run", "DecompilerEnhancer"))

        EVENTS.clear()
        self.invoke("golang\\Recover Go types")
        self.assertEqual(self.stage_events()[-1], ("run", "DecompilerEnhancer"))

    def test_stage_exception_is_logged_and_later_stages_run(self):
        FAILING_STAGES.add("FunctionCommenter")
        self.invoke("golang\\Parse Go binary")

        self.assertEqual(self.stage_events(), [
            ("run", "FunctionRenamer"),
            ("run", "FunctionCommenter"),
            ("run", "TypeParser"),
            ("run", "InterfaceRecovery"),
            ("run", "DecompilerEnhancer"),
        ])
        errors = [message for kind, message in EVENTS if kind == "error"]
        self.assertTrue(any("FunctionCommenter failed" in message
                            and "RuntimeError" in message
                            and "exploded" in message
                            for message in errors))
        self.assertTrue(any("failed in 1 stage" in message
                            and "FunctionCommenter" in message
                            for message in errors))

        messages = [message for kind, message in EVENTS if kind == "log"]
        self.assertIn("Terminated all analysis", messages)

    def test_failed_stage_does_not_abort_recover_functions(self):
        FAILING_STAGES.add("FunctionRenamer")
        self.invoke("golang\\Recover functions")

        self.assertEqual(self.stage_events(), [
            ("run", "FunctionRenamer"),
            ("run", "FunctionCommenter"),
        ])
        errors = [message for kind, message in EVENTS if kind == "error"]
        self.assertTrue(any("FunctionRenamer failed" in message for message in errors))

    def test_recover_type_at_address_passes_target(self):
        FakeSettings.values["golang_binary_parser.recover_native_types"] = True
        self.invoke("golang\\Recover Go type at address", 0x401000)

        self.assertEqual(INSTANCES, [("StructRecovery", 0x401000)])

    def test_show_build_info_then_files(self):
        BUILD_INFO["value"] = types.SimpleNamespace(
            go_version="go1.21.0",
            module_info="mod\texample.com/main\t(devel)",
        )
        self.invoke("golang\\Utilities\\Show build info and source files")

        logs = [message for kind, message in EVENTS if kind == "log"]
        self.assertTrue(any("go1.21.0" in message for message in logs))
        self.assertIn(("run", "PrintFiles"), EVENTS)
        log_index = next(index for index, event in enumerate(EVENTS)
                         if event[0] == "log" and "go1.21.0" in event[1])
        self.assertLess(log_index, EVENTS.index(("run", "PrintFiles")))

    def test_show_build_info_without_build_info(self):
        self.invoke("golang\\Utilities\\Show build info and source files")

        logs = [message for kind, message in EVENTS if kind == "log"]
        self.assertTrue(any("not available" in message for message in logs))
        self.assertIn(("run", "PrintFiles"), EVENTS)

    def test_goresym_commands(self):
        self.invoke("golang\\GoReSym\\Import JSON...")
        self.invoke("golang\\GoReSym\\Run and import")

        self.assertEqual([name for name, _ in INSTANCES],
                         ["GoReSymImporter", "GoResSymExecutor"])


if __name__ == "__main__":
    unittest.main()
