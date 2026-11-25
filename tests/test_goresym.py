import importlib
import json
import os
import sys
import tempfile
import types
import unittest

from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "_goresym_plugin_under_test"
MAGIC_ADDRESS = 0x8000
MAGIC_BYTES = b"\xf1\xff\xff\xff\x00\x00"  # Go 1.20 pclntab magic


def _install_binaryninja_stub():
    """
    Install a minimal binaryninja module so the parser can be imported and
    exercised without a Binary Ninja installation, license or UI.
    """
    module = types.ModuleType("binaryninja")

    class BinaryView:
        pass

    class Section:
        pass

    class Function:
        pass

    class BinaryReader:
        def __init__(self, bv=None):
            self.bv = bv

    class SymbolType:
        FunctionSymbol = "FunctionSymbol"
        DataSymbol = "DataSymbol"

    class Symbol:
        def __init__(self, symbol_type, address, name, raw_name=None):
            self.type = symbol_type
            self.address = address
            self.name = name
            self.raw_name = raw_name

    class Logger:
        def __init__(self, level=0, name=""):
            self.level = level
            self.name = name

        def log_debug(self, *args, **kwargs):
            pass

        def log_info(self, *args, **kwargs):
            pass

        def log_warn(self, *args, **kwargs):
            pass

        def log_error(self, *args, **kwargs):
            pass

    class BackgroundTaskThread:
        def __init__(self, name, pausable=False):
            self.name = name
            self.pausable = pausable

    class FakeSettings:
        def __init__(self):
            self.values = {
                "golang_binary_parser.components": True,
                "golang_binary_parser.sanitize": False,
                "golang_binary_parser.minimum_name_length": 2,
                "golang_binary_parser.goresym_path": "GoReSym",
            }

        def get_bool(self, name):
            return bool(self.values.get(name, False))

        def get_integer(self, name):
            return int(self.values.get(name, 0))

        def get_string(self, name):
            return self.values.get(name, "")

    settings = FakeSettings()

    module.BinaryView = BinaryView
    module.Section = Section
    module.Function = Function
    module.SymbolType = SymbolType
    module.Symbol = Symbol
    module.Logger = Logger
    module.Settings = lambda: settings
    module.redirect_output_to_log = lambda: None
    module.plugin = types.SimpleNamespace(BackgroundTaskThread=BackgroundTaskThread)
    module.binaryview = types.SimpleNamespace(BinaryReader=BinaryReader)
    module.interaction = types.SimpleNamespace(get_open_filename_input=lambda *args, **kwargs: None)

    sys.modules["binaryninja"] = module
    return module, settings


BN_STUB, BN_SETTINGS = _install_binaryninja_stub()


def _load_parser_module():
    # Register synthetic parent packages so the plugin's top-level __init__.py
    # (which registers Binary Ninja commands) is not executed by the tests.
    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = [str(ROOT)]
    sys.modules[PACKAGE_NAME] = package

    parsers_package = types.ModuleType(f"{PACKAGE_NAME}.parsers")
    parsers_package.__path__ = [str(ROOT / "parsers")]
    sys.modules[parsers_package.__name__] = parsers_package

    internal_package = types.ModuleType(f"{PACKAGE_NAME}.internal_types")
    internal_package.__path__ = [str(ROOT / "internal_types")]
    sys.modules[internal_package.__name__] = internal_package

    return importlib.import_module(f"{PACKAGE_NAME}.parsers.goresym_parser")


PARSER = _load_parser_module()


class FakeRawFile:
    def __init__(self, view):
        self.view = view

    def save(self, path):
        with open(path, "wb") as output:
            output.write(b"\x7fELF")
        self.view.saved_binary_paths.append(path)


class FakeFile:
    def __init__(self, view):
        self.raw = FakeRawFile(view)


class FakeArch:
    address_size = 8


class FakeFunction:
    def __init__(self, address):
        self.address = address
        self.comment = ""


class FakeComponent:
    def __init__(self, name):
        self.name = name
        self.functions = []

    def add_function(self, function):
        self.functions.append(function)


class FakeBinaryView:
    def __init__(self, readable_start=0, readable_end=0x100000):
        self.readable_start = readable_start
        self.readable_end = readable_end
        self.functions = {}
        self.created_functions = []
        self.symbols = []
        self.components = {}
        self.writes = []
        self.comments = {}
        self.analysis_updates = 0
        self.saved_binary_paths = []
        self.arch = FakeArch()
        self.file = FakeFile(self)

    def read(self, address, length):
        if address >= self.readable_start and address + length <= self.readable_end:
            return b"\x00" * length
        return None

    def get_function_at(self, address):
        return self.functions.get(address)

    def create_user_function(self, address):
        function = FakeFunction(address)
        self.functions[address] = function
        self.created_functions.append(address)
        return function

    def define_user_symbol(self, symbol):
        self.symbols.append(symbol)

    def get_component_by_path(self, path):
        return self.components.get(path)

    def create_component(self, name, parent=None):
        component = FakeComponent(name)
        self.components[name] = component
        return component

    def write(self, address, data):
        if not self.read(address, len(data)):
            raise ValueError("write to unmapped address")
        self.writes.append((address, data))

    def set_comment_at(self, address, comment):
        self.comments[address] = comment

    def update_analysis_and_wait(self):
        self.analysis_updates += 1


class GoReSymTestBase(unittest.TestCase):
    def setUp(self):
        self.bv = FakeBinaryView()
        self.temp_files = []
        BN_SETTINGS.values.update({
            "golang_binary_parser.components": True,
            "golang_binary_parser.sanitize": False,
            "golang_binary_parser.goresym_path": "GoReSym",
        })

    def tearDown(self):
        for path in self.temp_files:
            Path(path).unlink(missing_ok=True)

    def run_importer(self, data):
        file_descriptor, path = tempfile.mkstemp(prefix="goresym_test_", suffix=".json")
        os.close(file_descriptor)
        with open(path, "w", encoding="utf-8") as output:
            json.dump(data, output)
        self.temp_files.append(path)

        importer = PARSER.GoReSymImporter(self.bv, path)
        importer.run()
        return importer

    def function_symbols(self):
        return [symbol for symbol in self.bv.symbols
                if symbol.type == BN_STUB.SymbolType.FunctionSymbol]

    def data_symbols(self):
        return [symbol for symbol in self.bv.symbols
                if symbol.type == BN_STUB.SymbolType.DataSymbol]


class GoReSymImporterTestCase(GoReSymTestBase):

    def test_user_and_std_functions_are_imported_and_deduplicated(self):
        data = {
            "Version": "1.20.3",
            "TabMeta": {"VA": MAGIC_ADDRESS, "Version": "1.20"},
            "UserFunctions": [
                {"Start": 0x1000, "FullName": "main.main"},
                {"Start": 0x2000, "FullName": "main.helper"},
            ],
            "StdFunctions": [
                {"Start": 0x2000, "FullName": "main.duplicate"},
                {"Start": 0x3000, "FullName": "fmt.Println"},
            ],
        }

        self.run_importer(data)

        symbols = self.function_symbols()
        self.assertEqual(sorted(symbol.address for symbol in symbols), [0x1000, 0x2000, 0x3000])
        names = {symbol.address: symbol.name for symbol in symbols}
        self.assertEqual(names[0x1000], "main.main")
        self.assertEqual(names[0x2000], "main.helper")
        self.assertEqual(names[0x3000], "fmt.Println")

        self.assertEqual(self.bv.created_functions, [0x1000, 0x2000, 0x3000])
        self.assertEqual(self.bv.writes, [(MAGIC_ADDRESS, MAGIC_BYTES)])
        self.assertEqual(self.bv.analysis_updates, 1)

        self.assertEqual([function.address for function in self.bv.components["main"].functions],
                         [0x1000, 0x2000])
        self.assertEqual([function.address for function in self.bv.components["fmt"].functions],
                         [0x3000])

    def test_existing_function_is_reused(self):
        self.bv.functions[0x1000] = FakeFunction(0x1000)

        self.run_importer({
            "Version": "1.20.3",
            "UserFunctions": [{"Start": 0x1000, "FullName": "main.main"}],
        })

        self.assertEqual(self.bv.created_functions, [])
        self.assertEqual([symbol.name for symbol in self.function_symbols()], ["main.main"])

    def test_missing_null_and_malformed_function_arrays_are_tolerated(self):
        self.run_importer({"Version": "1.20.3", "UserFunctions": None})
        self.assertEqual(self.function_symbols(), [])
        self.assertEqual(self.bv.analysis_updates, 1)

        self.run_importer({"Version": "1.20.3", "StdFunctions": None})
        self.assertEqual(self.function_symbols(), [])

        self.run_importer({
            "Version": "1.20.3",
            "UserFunctions": [
                "not an object",
                {"FullName": "main.missing_start"},
                {"Start": 0, "FullName": "main.zero_address"},
                {"Start": 0x1000},
                {"Start": 0x2000, "FullName": "main.valid"},
            ],
        })

        symbols = self.function_symbols()
        self.assertEqual([symbol.address for symbol in symbols], [0x2000])
        self.assertEqual([symbol.name for symbol in symbols], ["main.valid"])

    def test_invalid_magic_addresses_are_not_written(self):
        cases = {
            "missing tabmeta": {},
            "null va": {"TabMeta": {"VA": None, "Version": "1.20"}},
            "zero va": {"TabMeta": {"VA": 0, "Version": "1.20"}},
            "negative va": {"TabMeta": {"VA": -1, "Version": "1.20"}},
            "string va": {"TabMeta": {"VA": "0x8000", "Version": "1.20"}},
            "unmapped va": {"TabMeta": {"VA": 0x200000, "Version": "1.20"}},
            "unsupported version": {"TabMeta": {"VA": MAGIC_ADDRESS, "Version": "unknown"}},
            "malformed tabmeta": {"TabMeta": "not an object"},
        }

        for label, extra in cases.items():
            with self.subTest(label):
                self.bv = FakeBinaryView()
                data = {
                    "Version": "1.20.3",
                    "UserFunctions": [{"Start": 0x1000, "FullName": "main.main"}],
                }
                data.update(extra)

                self.run_importer(data)

                self.assertEqual(self.bv.writes, [])
                self.assertEqual([symbol.name for symbol in self.function_symbols()],
                                 ["main.main"])

    def test_write_failure_does_not_abort_function_import(self):
        class FailingWriteView(FakeBinaryView):
            def write(self, address, data):
                raise RuntimeError("database is read-only")

        self.bv = FailingWriteView()

        with mock.patch.object(PARSER, "log_error") as log_error:
            self.run_importer({
                "Version": "1.20.3",
                "TabMeta": {"VA": MAGIC_ADDRESS, "Version": "1.20"},
                "UserFunctions": [{"Start": 0x1000, "FullName": "main.main"}],
            })

        messages = [call.args[0] for call in log_error.call_args_list if call.args]
        self.assertTrue(any("Unable to restore pclntab magic" in message
                            for message in messages))
        self.assertEqual([symbol.name for symbol in self.function_symbols()],
                         ["main.main"])

    def test_invalid_json_root_is_rejected(self):
        with mock.patch.object(PARSER, "log_error") as log_error:
            self.run_importer([])

        messages = [call.args[0] for call in log_error.call_args_list if call.args]
        self.assertTrue(any("root must be an object" in message for message in messages))
        self.assertEqual(self.function_symbols(), [])
        self.assertEqual(self.bv.analysis_updates, 0)

    def test_top_level_version_is_reported_as_go_release(self):
        with mock.patch.object(PARSER, "log_info") as log_info:
            self.run_importer({
                "Version": "1.20.3",
                "TabMeta": {"VA": MAGIC_ADDRESS, "Version": "1.20"},
                "UserFunctions": [],
            })

        messages = [call.args[0] for call in log_info.call_args_list if call.args]
        self.assertTrue(any("Go release: 1.20.3" in message for message in messages))
        self.assertFalse(any(message == "Go version: 1.20" for message in messages))

    def test_missing_top_level_version_is_reported(self):
        with mock.patch.object(PARSER, "log_info") as log_info, \
                mock.patch.object(PARSER, "log_warn") as log_warn:
            self.run_importer({"UserFunctions": []})

        warnings = [call.args[0] for call in log_warn.call_args_list if call.args]
        self.assertTrue(any("does not contain a top-level Version" in message
                            for message in warnings))

        messages = [call.args[0] for call in log_info.call_args_list if call.args]
        self.assertFalse(any("Go release:" in message for message in messages))

    def test_source_files_from_paths_flag_are_logged(self):
        with mock.patch.object(PARSER, 'log_debug') as log_debug:
            self.run_importer({
                "Version": "1.20.3",
                "Files": ["/src/main.go", "/src/helper.go"],
                "UserFunctions": [],
            })

        messages = [call.args[0] for call in log_debug.call_args_list if call.args]
        self.assertTrue(any("/src/main.go" in message for message in messages))
        self.assertTrue(any("/src/helper.go" in message for message in messages))

    def test_types_and_interfaces_name_data_best_effort(self):
        with mock.patch.object(PARSER, "log_info") as log_info:
            self.run_importer({
                "Version": "1.20.3",
                "UserFunctions": [{"Start": 0x1000, "FullName": "main.main"}],
                "Files": ["/src/main.go", "/src/helper.go"],
                "Types": [
                    {"VA": 0x5000, "Str": "main.MyStruct", "CStr": "main_MyStruct",
                     "Kind": "Struct"},
                    {"VA": 0x5000, "Str": "main.Duplicate", "Kind": "Struct"},
                    {"VA": None, "Str": "main.NoAddress", "Kind": "Struct"},
                    {"VA": 0x5100, "Str": "", "CStr": "", "Kind": "Struct"},
                    {"VA": 0x5200, "CStr": "main.FromCStr", "Kind": "Struct"},
                    "not an object",
                ],
                "Interfaces": [
                    {"VA": 0x6000, "Str": "main.MyInterface", "Kind": "Interface"},
                    {"VA": 0x999999, "Str": "main.Unmapped", "Kind": "Interface"},
                ],
            })

        messages = [call.args[0] for call in log_info.call_args_list if call.args]
        self.assertTrue(any("2 files" in message and "6 types" in message
                            and "2 interfaces" in message
                            for message in messages))
        self.assertFalse(any("package" in message.lower() for message in messages))

        symbols = {symbol.address: symbol.name for symbol in self.data_symbols()}
        self.assertEqual(symbols, {
            0x5000: "main.MyStruct",
            0x5200: "main.FromCStr",
            0x6000: "main.MyInterface",
        })
        self.assertEqual(self.bv.comments[0x5000],
                         "GoReSym type: main.MyStruct (Struct)")
        self.assertEqual(self.bv.comments[0x5200],
                         "GoReSym type: main.FromCStr (Struct)")
        self.assertEqual(self.bv.comments[0x6000],
                         "GoReSym interface: main.MyInterface (Interface)")

        # Malformed or partially unusable metadata must not stop function import.
        self.assertEqual([symbol.name for symbol in self.function_symbols()], ["main.main"])


class GoResSymExecutorTestCase(GoReSymTestBase):
    def test_run_passes_std_types_and_file_path_flags(self):
        importer = PARSER.GoResSymExecutor(self.bv)
        output_path = importer.file
        completed = PARSER.subprocess.CompletedProcess(
            args=["GoReSym", "input"],
            returncode=1,
            stdout=b"",
            stderr=b"",
        )

        with mock.patch.object(PARSER.subprocess, "run", return_value=completed) as run, \
                mock.patch.object(PARSER, "log_error"):
            importer.run()

        self.assertEqual(run.call_args.args[0], [
            "GoReSym", "-d", "-t", "-p", self.bv.saved_binary_paths[0],
        ])
        self.assertFalse(Path(output_path).exists())
        self.assertFalse(Path(self.bv.saved_binary_paths[0]).exists())

    def test_missing_executable_is_reported_and_temp_files_are_cleaned(self):
        importer = PARSER.GoResSymExecutor(self.bv)
        output_path = importer.file

        with mock.patch.object(PARSER.subprocess, "run", side_effect=FileNotFoundError), \
                mock.patch.object(PARSER, "log_error") as log_error:
            importer.run()

        messages = [call.args[0] for call in log_error.call_args_list if call.args]
        self.assertTrue(any("not found" in message for message in messages))
        self.assertFalse(Path(output_path).exists())
        self.assertEqual(len(self.bv.saved_binary_paths), 1)
        self.assertFalse(Path(self.bv.saved_binary_paths[0]).exists())

    def test_non_zero_exit_code_is_reported_and_import_is_skipped(self):
        importer = PARSER.GoResSymExecutor(self.bv)
        output_path = importer.file
        completed = PARSER.subprocess.CompletedProcess(
            args=["GoReSym", "input"],
            returncode=3,
            stdout=b"",
            stderr=b"boom",
        )

        with mock.patch.object(PARSER.subprocess, "run", return_value=completed), \
                mock.patch.object(PARSER, "log_error") as log_error:
            importer.run()

        messages = [call.args[0] for call in log_error.call_args_list if call.args]
        self.assertTrue(any("exit code 3" in message and "boom" in message
                            for message in messages))
        self.assertEqual(self.function_symbols(), [])
        self.assertEqual(self.bv.analysis_updates, 0)
        self.assertFalse(Path(output_path).exists())

    def test_timeout_is_reported_and_temp_files_are_cleaned(self):
        importer = PARSER.GoResSymExecutor(self.bv)
        output_path = importer.file

        with mock.patch.object(
                PARSER.subprocess,
                "run",
                side_effect=PARSER.subprocess.TimeoutExpired(cmd="GoReSym", timeout=600)), \
                mock.patch.object(PARSER, "log_error") as log_error:
            importer.run()

        messages = [call.args[0] for call in log_error.call_args_list if call.args]
        self.assertTrue(any("did not finish" in message for message in messages))
        self.assertFalse(Path(output_path).exists())

    def test_successful_run_imports_goresym_output(self):
        importer = PARSER.GoResSymExecutor(self.bv)
        output_path = importer.file
        payload = json.dumps({
            "Version": "1.20.3",
            "TabMeta": {"VA": MAGIC_ADDRESS, "Version": "1.20"},
            "UserFunctions": [{"Start": 0x1000, "FullName": "main.main"}],
        }).encode("utf-8")
        completed = PARSER.subprocess.CompletedProcess(
            args=["GoReSym", "input"],
            returncode=0,
            stdout=payload,
            stderr=b"",
        )

        with mock.patch.object(PARSER.subprocess, "run", return_value=completed):
            importer.run()

        self.assertEqual([symbol.name for symbol in self.function_symbols()], ["main.main"])
        self.assertEqual(self.bv.writes, [(MAGIC_ADDRESS, MAGIC_BYTES)])
        self.assertFalse(Path(output_path).exists())
        self.assertFalse(Path(self.bv.saved_binary_paths[0]).exists())


if __name__ == "__main__":
    unittest.main()
