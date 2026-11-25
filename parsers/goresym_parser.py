import json
import os
import re
import subprocess

from tempfile import NamedTemporaryFile

import binaryninja as bn

from binaryninja import BinaryView, interaction, Symbol, SymbolType

from ..internal_types.datatypes import GoVersion

from .common import (
    NAME,
    log_error,
    log_info,
    log_debug,
    log_warn,
    santize_gofunc_name,
    make_component_from_gofunc_name,
    add_to_component
)

GO_VERSION_RE = re.compile(r"(\d+)\.(\d+)")


def _is_valid_address(address) -> bool:
    # bool is a subclass of int, but is not a valid address
    return isinstance(address, int) and not isinstance(address, bool) and address > 0


def _is_usable_name(name) -> bool:
    return isinstance(name, str) and bool(name.strip())


def _version_for_magic(pclntab_version) -> GoVersion:
    """
    Parse the pclntab layout version reported by GoReSym (for example "1.20")
    into the GoVersion enum used to restore the pclntab magic.

    Unknown or malformed values must never abort the import, so anything that
    cannot be mapped to a supported version is reported as GoVersion.invalid.
    """
    if not isinstance(pclntab_version, str):
        return GoVersion.invalid

    match = GO_VERSION_RE.search(pclntab_version)
    if not match:
        return GoVersion.invalid

    try:
        return GoVersion.from_string(f"{match.group(1)}.{match.group(2)}")
    except (TypeError, ValueError, IndexError):
        return GoVersion.invalid


class GoReSymImporter(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv: BinaryView, file: str = None):
        super().__init__(NAME, True)
        self.bv = bv
        self.file = file or interaction.get_open_filename_input('GoReSym JSON file')

    def _load_json(self):
        if not self.file:
            log_error("No GoReSym JSON file selected")
            return None

        try:
            with open(self.file, encoding='utf-8') as json_file:
                data = json.load(json_file)
        except (OSError, TypeError, json.JSONDecodeError) as exc:
            log_error(f"Unable to load GoReSym JSON file {self.file}: {exc}")
            return None

        if not isinstance(data, dict):
            log_error(f"GoReSym JSON root must be an object, got {type(data).__name__}")
            return None
        return data

    def _address_is_mapped(self, address: int, size: int = 1) -> bool:
        try:
            return bool(self.bv.read(address, size))
        except Exception:
            return False

    def _restore_pclntab_magic(self, data):
        tab_meta = data.get('TabMeta')
        if not isinstance(tab_meta, dict):
            log_warn("GoReSym JSON does not contain usable TabMeta information; "
                     "skipping pclntab magic restoration")
            return

        magic_address = tab_meta.get('VA')
        pclntab_version = tab_meta.get('Version')
        log_debug(f"GoReSym pclntab version (used for magic restoration): {pclntab_version!r}")

        if not _is_valid_address(magic_address):
            log_warn(f"GoReSym TabMeta.VA is missing or invalid ({magic_address!r}); "
                     "skipping pclntab magic restoration")
            return

        try:
            go_version = _version_for_magic(pclntab_version)
            go_magic = (GoVersion.to_magic(go_version)
                        if go_version != GoVersion.invalid else None)
        except Exception as exc:
            log_warn(f"Unable to determine pclntab magic for version "
                     f"{pclntab_version!r}: {exc}")
            return

        if go_version == GoVersion.invalid:
            log_warn(f"Unsupported GoReSym pclntab version {pclntab_version!r}; "
                     "skipping pclntab magic restoration")
            return

        if not go_magic:
            log_warn(f"No pclntab magic available for Go version {go_version!r}; "
                     "skipping pclntab magic restoration")
            return

        if not self._address_is_mapped(magic_address, len(go_magic)):
            log_warn(f"GoReSym TabMeta.VA 0x{magic_address:X} is not mapped; "
                     "skipping pclntab magic restoration")
            return

        log_debug(f"Setting go magic to {go_magic} at address 0x{magic_address:X}")
        try:
            self.bv.write(magic_address, go_magic)
        except Exception as exc:
            log_error(f"Unable to restore pclntab magic at 0x{magic_address:X}: {exc}")

    def _import_functions(self, data):
        renamed = 0
        created = 0
        skipped_duplicates = 0
        skipped_invalid = 0
        imported_addresses = set()

        for array_name in ('UserFunctions', 'StdFunctions'):
            entries = data.get(array_name)
            if entries is None:
                log_debug(f"GoReSym JSON does not contain {array_name}")
                continue
            if not isinstance(entries, list):
                log_warn(f"GoReSym {array_name} is not a list; skipping it")
                continue

            for entry in entries:
                try:
                    if not isinstance(entry, dict):
                        log_warn(f"Skipping malformed GoReSym {array_name} entry: not an object")
                        skipped_invalid += 1
                        continue

                    function_addr = entry.get('Start')
                    name = entry.get('FullName')

                    if not _is_valid_address(function_addr):
                        log_warn(f"Skipping GoReSym {array_name} entry with invalid Start: "
                                 f"{function_addr!r}")
                        skipped_invalid += 1
                        continue

                    if function_addr in imported_addresses:
                        log_debug(f"Skipping duplicate function at 0x{function_addr:x} "
                                  f"({name!r})")
                        skipped_duplicates += 1
                        continue

                    if not _is_usable_name(name):
                        log_warn(f"Skipping GoReSym {array_name} entry at 0x{function_addr:x} "
                                 f"with invalid FullName: {name!r}")
                        skipped_invalid += 1
                        continue

                    imported_addresses.add(function_addr)
                    log_debug(f"Got function at 0x{function_addr:x} with name {name}")

                    func = self.bv.get_function_at(function_addr)
                    if not func:
                        func = self.bv.create_user_function(function_addr)
                        if func:
                            created += 1

                    # if the function is outside the .text range (which should not happen, but you never know, ignore it)
                    if not func:
                        log_debug(f"The function {name} at 0x{function_addr:x} not backed by the file")
                        continue

                    name = santize_gofunc_name(name)
                    sym = Symbol(SymbolType.FunctionSymbol,
                                 function_addr,
                                 name,
                                 name)
                    self.bv.define_user_symbol(sym)
                    component_name = make_component_from_gofunc_name(name)
                    add_to_component(self.bv, component_name, func)
                    renamed += 1
                except Exception as exc:
                    log_warn(f"Failed to import GoReSym {array_name} entry: {exc}")
                    skipped_invalid += 1

        return renamed, created, skipped_duplicates, skipped_invalid

    def _log_files(self, data):
        files = data.get('Files')
        file_count = 0
        if files is None:
            log_debug("GoReSym JSON does not contain Files")
        elif not isinstance(files, list):
            log_warn("GoReSym Files is not a list; skipping it")
        else:
            file_names = [name.strip() for name in files if _is_usable_name(name)]
            file_count = len(file_names)
            if file_count:
                log_info(f"GoReSym listed {file_count} source files")
                for file_name in file_names[:5]:
                    log_debug(f"GoReSym file: {file_name}")
                if file_count > 5:
                    log_debug(f"GoReSym file list truncated, {file_count - 5} more entries")
            elif files:
                log_debug("GoReSym Files contains no usable paths")

        return file_count

    def _name_type_data(self, entry, entry_kind, named_addresses):
        if not isinstance(entry, dict):
            return False

        address = entry.get('VA')
        if not _is_valid_address(address) or address in named_addresses:
            return False

        name = entry.get('Str')
        if not _is_usable_name(name):
            name = entry.get('CStr')
        if not _is_usable_name(name):
            return False
        name = name.strip()

        if not self._address_is_mapped(address):
            log_debug(f"Skipping GoReSym {entry_kind} {name!r}: "
                      f"address 0x{address:X} is not mapped")
            return False

        kind = entry.get('Kind')
        if _is_usable_name(kind):
            comment = f"GoReSym {entry_kind}: {name} ({kind.strip()})"
        else:
            comment = f"GoReSym {entry_kind}: {name}"

        try:
            symbol = Symbol(SymbolType.DataSymbol, address, name)
            self.bv.define_user_symbol(symbol)
            self.bv.set_comment_at(address, comment)
        except Exception as exc:
            log_warn(f"Unable to name GoReSym {entry_kind} {name!r} at "
                     f"0x{address:X}: {exc}")
            return False

        named_addresses.add(address)
        return True

    def _import_type_entries(self, entries, entry_kind, named_addresses):
        if entries is None:
            log_debug(f"GoReSym JSON does not contain {entry_kind} metadata entries")
            return 0, 0
        if not isinstance(entries, list):
            log_warn(f"GoReSym {entry_kind} metadata is not a list; skipping it")
            return 0, 0

        named = 0
        for entry in entries:
            try:
                if self._name_type_data(entry, entry_kind, named_addresses):
                    named += 1
            except Exception as exc:
                log_debug(f"Skipping malformed GoReSym {entry_kind} metadata entry: {exc}")

        return len(entries), named

    def _import_metadata(self, data):
        named_addresses = set()
        file_count = self._log_files(data)
        type_count, named_types = self._import_type_entries(data.get('Types'),
                                                            'type',
                                                            named_addresses)
        interface_count, named_interfaces = self._import_type_entries(data.get('Interfaces'),
                                                                      'interface',
                                                                      named_addresses)
        log_info(f"GoReSym metadata: {file_count} files, "
                 f"{type_count} types, {interface_count} interfaces; "
                 f"named {named_types + named_interfaces} data locations")

    def run(self):
        data = self._load_json()
        if data is None:
            return

        release_version = data.get('Version')
        if _is_usable_name(release_version):
            log_info(f"GoReSym reported Go release: {release_version.strip()}")
        else:
            log_warn("GoReSym JSON does not contain a top-level Version; "
                     "the Go release is unknown")

        self._restore_pclntab_magic(data)

        log_info("renaming functions based on GoReSym output")

        renamed, created, skipped_duplicates, skipped_invalid = self._import_functions(data)

        try:
            self._import_metadata(data)
        except Exception as exc:
            log_warn(f"Unable to import GoReSym metadata: {exc}")

        log_info(f"Created {created} functions")
        log_info(f"Renamed {renamed - created} functions")
        log_info(f"Total {renamed} functions")
        if skipped_duplicates or skipped_invalid:
            log_info(f"Skipped {skipped_duplicates} duplicate and "
                     f"{skipped_invalid} invalid function entries")
        self.bv.update_analysis_and_wait()


class GoResSymExecutor(GoReSymImporter):
    TIMEOUT_SECONDS = 600

    def __init__(self, bv: BinaryView):
        # Delete=False so the file can be closed before GoReSym runs (required on Windows)
        output_file = NamedTemporaryFile(prefix='goresym_output_', suffix='.json', delete=False)
        output_path = output_file.name
        output_file.close()
        log_debug(f"Saving GoReSym output to file {output_path}")
        super().__init__(bv, output_path)

    def run(self):
        goresym_path = bn.Settings().get_string('golang_binary_parser.goresym_path')
        if not goresym_path:
            log_error("GoReSym path is not configured (golang_binary_parser.goresym_path)")
            self._remove_file(self.file)
            return

        go_file = NamedTemporaryFile(prefix='goresym_input_', suffix='.bin', delete=False)
        go_file_path = go_file.name
        try:
            # Close the file before handing its path to the subprocess (required on Windows)
            go_file.close()

            try:
                self.bv.file.raw.save(go_file_path)
            except Exception as exc:
                log_error(f"Unable to save the binary for GoReSym: {exc}")
                return

            # -d also lists standard-library packages, -t emits Types and
            # Interfaces, and -p emits the source file paths.
            command = [goresym_path, '-d', '-t', '-p', go_file_path]
            log_debug(f"Running GoReSym: {' '.join(command)}")
            try:
                result = subprocess.run(command,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        timeout=self.TIMEOUT_SECONDS,
                                        check=False)
            except FileNotFoundError:
                log_error(f"GoReSym executable not found: {goresym_path}. "
                          "Set golang_binary_parser.goresym_path to its full path.")
                return
            except subprocess.TimeoutExpired:
                log_error(f"GoReSym did not finish within {self.TIMEOUT_SECONDS} seconds")
                return

            stderr = self._decode_output(result.stderr)
            if result.returncode != 0:
                log_error(f"GoReSym failed with exit code {result.returncode}: "
                          f"{stderr or '<no stderr output>'}")
                return

            if not result.stdout:
                log_error("GoReSym produced no JSON output")
                return

            if stderr:
                log_debug(f"GoReSym stderr: {stderr}")

            try:
                with open(self.file, 'wb') as output_file:
                    output_file.write(result.stdout)
            except OSError as exc:
                log_error(f"Unable to write GoReSym output to {self.file}: {exc}")
                return

            super().run()
        except Exception as exc:
            log_error(f"Unable to run GoReSym: {exc}")
        finally:
            self._remove_file(go_file_path)
            self._remove_file(self.file)

    @staticmethod
    def _decode_output(value):
        if not value:
            return ''
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        value = value.strip()
        return value[:2000]

    @staticmethod
    def _remove_file(path):
        if not path:
            return
        try:
            if os.path.exists(path):
                os.unlink(path)
        except OSError as exc:
            log_debug(f"Unable to remove temporary file {path}: {exc}")
