import binaryninja as bn
from binaryninja import Settings

from .buildinfo import get_go_build_info
from .common import NAME, log_error, log_info
from .decompiler import DecompilerEnhancer
from .file_printer import PrintFiles
from .functions_renamer import FunctionCommenter, FunctionRenamer
from .interface_recovery import InterfaceRecovery
from .structure_recovery import StructRecovery
from .type_parser import TypeParser


def type_recovery_class():
    if Settings().get_bool('golang_binary_parser.recover_native_types'):
        return StructRecovery
    return TypeParser


def log_build_info(bv: bn.BinaryView):
    try:
        build_info = get_go_build_info(bv)
    except Exception as e:
        log_info(f"Go build info not available: {e}")
        return

    if build_info is None:
        log_info("Go build info not available")
        return

    log_info(f"Go build info: {build_info.go_version}")
    if build_info.module_info:
        log_info(f"Module info:\n{build_info.module_info}")


class _Pipeline(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv, name: str):
        super().__init__(f"{NAME} ({name})", True)
        self.bv = bv
        self.failed_stages = []

    def _run_stage(self, task_class, **kwargs):
        # Building a task can be expensive (it reads the gopclntab), so tasks are
        # created here and not on the UI thread. The stage body runs directly in
        # this pipeline thread: BackgroundTaskThread.start()/join() does not
        # propagate exceptions raised by the child's run(), which would hide a
        # crashed stage and log success.
        try:
            task = task_class(self.bv, **kwargs)
            task.run()
        except Exception as e:
            self.failed_stages.append(task_class.__name__)
            log_error(f"{task_class.__name__} failed: {type(e).__name__}: {e}")

    def _log_summary(self):
        if self.failed_stages:
            log_error(f"Analysis failed in {len(self.failed_stages)} stage(s): "
                      f"{', '.join(self.failed_stages)}")
        log_info("Terminated all analysis")


class ParseGoBinary(_Pipeline):
    def __init__(self, bv):
        super().__init__(bv, "Parse Go binary")

    def run(self):
        log_build_info(self.bv)
        self._run_stage(FunctionRenamer)
        if Settings().get_bool('golang_binary_parser.comment_functions'):
            self._run_stage(FunctionCommenter)
        self._run_stage(type_recovery_class())
        if Settings().get_bool('golang_binary_parser.recover_interfaces'):
            self._run_stage(InterfaceRecovery)
        # Safe without type metadata: it applies the recovered prototypes and
        # the IL annotations according to its own settings.
        self._run_stage(DecompilerEnhancer)
        self._log_summary()


class RecoverFunctions(_Pipeline):
    def __init__(self, bv):
        super().__init__(bv, "Recover functions")

    def run(self):
        self._run_stage(FunctionRenamer)
        if Settings().get_bool('golang_binary_parser.comment_functions'):
            self._run_stage(FunctionCommenter)
        self._log_summary()


class RecoverGoTypes(_Pipeline):
    def __init__(self, bv):
        super().__init__(bv, "Recover Go types")

    def run(self):
        self._run_stage(type_recovery_class())
        if Settings().get_bool('golang_binary_parser.recover_interfaces'):
            self._run_stage(InterfaceRecovery)
        self._run_stage(DecompilerEnhancer)
        self._log_summary()


class RecoverGoTypeAtAddress(_Pipeline):
    def __init__(self, bv, address):
        super().__init__(bv, "Recover Go type at address")
        self.address = address

    def run(self):
        self._run_stage(type_recovery_class(), target=self.address)
        self._log_summary()


class ShowBuildInfoAndSourceFiles(_Pipeline):
    def __init__(self, bv):
        super().__init__(bv, "Show build info and source files")

    def run(self):
        log_build_info(self.bv)
        self._run_stage(PrintFiles)
        self._log_summary()
