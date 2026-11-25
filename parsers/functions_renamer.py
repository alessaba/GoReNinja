from binaryninja import Symbol, SymbolType, Settings

from ..internal_types.datatypes import GoVersion

from .common import (
    GoHelper,
    log_error,
    log_info,
    log_debug,
    log_warn,
    santize_gofunc_name,
    make_component_from_gofunc_name,
    add_to_component
)

# Linker-generated pseudo functions (go:buildid, go:textfipsstart, ...) that
# do not correspond to real Go code. Real Go function names cannot contain ':'.
PSEUDO_FUNCTION_PREFIX = 'go:'


def is_pseudo_function(name: str) -> bool:
    return isinstance(name, str) and name.startswith(PSEUDO_FUNCTION_PREFIX)


def source_lines_enabled() -> bool:
    try:
        settings = Settings()
        if settings.contains('golang_binary_parser.source_lines'):
            return settings.get_bool('golang_binary_parser.source_lines')
    except Exception:
        pass
    # The setting is registered by the plugin entry point; default to the
    # documented value when running with an older registration or from tests.
    return True


class FunctionRenamer(GoHelper):

    def get_text_section(self):
        for section_name in ('.text', '__text'):
            section = self.get_section_by_name(section_name)
            if section:
                return section
        return None

    @staticmethod
    def is_code_address(address: int, text_section) -> bool:
        # When the text section cannot be found (unusual file formats) fall
        # back to creating the functions, as the old implementation did.
        if text_section is None:
            return True
        return text_section.start <= address < text_section.end

    def rename_functions(self):
        gopclntab = self.init_gopclntab()
        if gopclntab is None:
            log_error("Unable to recover function names: no valid .gopclntab found")
            return

        try:
            min_function_name_len = Settings().get_integer('golang_binary_parser.minimum_name_length')
        except Exception:
            min_function_name_len = 2
        if not isinstance(min_function_name_len, int):
            min_function_name_len = 2

        log_info("renaming functions based on .gopclntab section")
        log_info(f"gopclntab contains {gopclntab.nfunctab} functions")

        text_section = self.get_text_section()

        renamed = 0
        created = 0
        skipped = 0
        failed = 0

        max_entries = min(gopclntab.nfunctab, gopclntab.maxFuncEntries())
        for fidx in range(max_entries):
            try:
                if gopclntab.version == GoVersion.ver12:
                    function = gopclntab.go12FuncInfo(fidx)
                else:
                    function = gopclntab.funcInfo(fidx)

                if function is None:
                    failed += 1
                    log_debug(f"Unable to read the function entry {fidx}")
                    continue

                function_addr, name = function.entry, function.resolvedName
                log_debug(f"Found function at 0x{function_addr:x} with name {name}")

                if not function_addr or is_pseudo_function(name):
                    skipped += 1
                    log_debug(f"Skipping pseudo function {name} at 0x{function_addr:x}")
                    continue

                if not self.is_code_address(function_addr, text_section):
                    skipped += 1
                    log_debug(f"The function {name} at 0x{function_addr:x} is outside the text section")
                    continue

                func = self.bv.get_function_at(function_addr)
                if not func:
                    func = self.bv.create_user_function(function_addr)
                    if func:
                        created += 1

                # if the function is outside the .text range (which should not happen, but you never know, ignore it)
                if not func:
                    skipped += 1
                    log_debug(f"The function {name} at 0x{function_addr:x} not backed by the file")
                    continue

                if name and len(name) > min_function_name_len:
                    name = santize_gofunc_name(name)
                    sym = Symbol(SymbolType.FunctionSymbol,
                                 function_addr,
                                 name,
                                 name)
                    self.bv.define_user_symbol(sym)
                    component_name = make_component_from_gofunc_name(name)
                    add_to_component(self.bv, component_name, func)
                    renamed += 1
                else:
                    skipped += 1
                    log_warn(f"not using function name {name} for function at {hex(function_addr)} which is '{name}'")
            except Exception as e:
                failed += 1
                log_debug(f"Unable to parse the function entry {fidx}: {type(e).__name__}: {e}")

        log_info(f"Created {created} functions")
        log_info(f"Renamed {renamed} functions")
        log_info(f"Skipped {skipped} functions")
        if failed:
            log_debug(f"Failed to parse {failed} function entries")
        self.bv.update_analysis_and_wait()

    def run(self):
        return self.rename_functions()


class FunctionCommenter(GoHelper):
    OVERRIDE_COMMENT = True
    COMMENT_KEY = "File:"

    def comment_functions(self):
        gopclntab = self.init_gopclntab()
        if gopclntab is None:
            log_error("Unable to comment functions: no valid .gopclntab found")
            return

        with_source_lines = source_lines_enabled()

        log_info("Commenting functions based on .gopclntab section")
        log_info(f"gopclntab contains {gopclntab.nfunctab} functions")

        commented = 0
        skipped = 0
        failed = 0

        max_entries = min(gopclntab.nfunctab, gopclntab.maxFuncEntries())
        for fidx in range(max_entries):
            try:
                if gopclntab.version == GoVersion.ver12:
                    function = gopclntab.go12FuncInfo(fidx)
                else:
                    function = gopclntab.funcInfo(fidx)

                if function is None:
                    failed += 1
                    log_debug(f"Unable to read the function entry {fidx}")
                    continue

                function_addr = function.entry
                func = self.bv.get_function_at(function_addr)
                # Parse only already existing functions
                if not func:
                    skipped += 1
                    continue

                filename = gopclntab.pc2filename(function)
                if not filename:
                    skipped += 1
                    continue

                if not self.OVERRIDE_COMMENT and func.comment:
                    log_debug("Already commented, skipping")
                    skipped += 1
                    continue

                source_file = filename.decode('utf-8', errors='replace')
                comment = f"{self.COMMENT_KEY} {source_file}"

                if with_source_lines:
                    line = gopclntab.pc2line(function)
                    if 0 < line < 0x7fffffff:
                        comment = f"{comment}:{line}"

                func.comment = comment
                commented += 1
            except Exception as e:
                failed += 1
                log_debug(f"Unable to comment the function entry {fidx}: {type(e).__name__}: {e}")

        log_info(f"Commented {commented} functions")
        log_info(f"Skipped {skipped} functions")
        if failed:
            log_debug(f"Failed to parse {failed} function entries")

    def run(self):
        return self.comment_functions()
