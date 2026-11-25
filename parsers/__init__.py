from binaryninja import BinaryView

# TypeParser is bound in the package namespace before run_all imports
# structure_recovery, which does `from . import TypeParser`.
from .type_parser import TypeParser
from .file_printer import PrintFiles
from .goresym_parser import GoReSymImporter, GoResSymExecutor
from .run_all import (
    ParseGoBinary,
    RecoverFunctions,
    RecoverGoTypes,
    RecoverGoTypeAtAddress,
    ShowBuildInfoAndSourceFiles
)


def parse_go_binary(bv: BinaryView):
    helper = ParseGoBinary(bv)
    return helper.start()


def recover_functions(bv: BinaryView):
    helper = RecoverFunctions(bv)
    return helper.start()


def recover_go_types(bv: BinaryView):
    helper = RecoverGoTypes(bv)
    return helper.start()


def recover_go_type_at_address(bv: BinaryView, address):
    helper = RecoverGoTypeAtAddress(bv, address)
    return helper.start()


def goresym_import(bv: BinaryView):
    helper = GoReSymImporter(bv)
    return helper.start()


def goresym_run_and_import(bv: BinaryView):
    helper = GoResSymExecutor(bv)
    return helper.start()


def show_build_info_and_source_files(bv: BinaryView):
    helper = ShowBuildInfoAndSourceFiles(bv)
    return helper.start()
