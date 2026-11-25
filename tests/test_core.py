"""Pure Python tests for the pclntab parsing core and GoHelper lifecycle.

The tests install a tiny binaryninja stub and load the real plugin modules
through a synthetic package, so no Binary Ninja installation, license or UI is
required.
"""

import importlib
import struct
import sys
import types
import unittest

from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "_core_plugin_under_test"


def _install_binaryninja_stub():
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

    class SymbolType:
        FunctionSymbol = "FunctionSymbol"

    class Symbol:
        def __init__(self, symbol_type, address, name, raw_name=None):
            self.type = symbol_type
            self.address = address
            self.name = name
            self.raw_name = raw_name

    class FakeSettings:
        values = {}

        def contains(self, key):
            return True

        def get_bool(self, key):
            return bool(self.values.get(key, False))

        def get_integer(self, key):
            return int(self.values.get(key, 2))

        def get_string(self, key):
            return ""

    settings = FakeSettings()

    module.BinaryView = BinaryView
    module.Section = Section
    module.Function = Function
    module.Logger = Logger
    module.Symbol = Symbol
    module.SymbolType = SymbolType
    module.Settings = lambda: settings
    module.redirect_output_to_log = lambda: None
    module.plugin = types.SimpleNamespace(BackgroundTaskThread=BackgroundTaskThread)
    module.binaryview = types.SimpleNamespace(BinaryReader=BinaryReader)

    sys.modules["binaryninja"] = module
    sys.modules["binaryninja.plugin"] = module.plugin
    sys.modules["binaryninja.binaryview"] = module.binaryview

    return settings


def _install_packages():
    for name, subdirectory in (
            (PACKAGE_NAME, ""),
            (PACKAGE_NAME + ".parsers", "parsers"),
            (PACKAGE_NAME + ".internal_types", "internal_types"),
    ):
        module = types.ModuleType(name)
        module.__path__ = [str(ROOT / subdirectory)]
        sys.modules[name] = module


BINARYNINJA_SETTINGS = _install_binaryninja_stub()
_install_packages()

constants = importlib.import_module(PACKAGE_NAME + ".internal_types.datatypes.constants")
pclntab = importlib.import_module(PACKAGE_NAME + ".internal_types.datatypes.pclntab")
common = importlib.import_module(PACKAGE_NAME + ".parsers.common")
file_printer = importlib.import_module(PACKAGE_NAME + ".parsers.file_printer")
functions_renamer = importlib.import_module(PACKAGE_NAME + ".parsers.functions_renamer")

GoMagics = constants.GoMagics
GoVersion = constants.GoVersion
FuncEntry = pclntab.FuncEntry
GoPclnTab = pclntab.GoPclnTab


def p32(value):
    return struct.pack("<I", value)


def p64(value):
    return struct.pack("<Q", value)


def func118(entry_offset=0x10, name_offset=0, pcfile=0, pcln=0, cu_offset=0):
    # entryOff, nameOff, args, deferreturn, pcsp, pcfile, pcln, npcdata,
    # cuOffset, startLine, followed by funcID/flag/pad/nfuncdata.
    return struct.pack("<10I", entry_offset, name_offset, 0, 0, 0,
                       pcfile, pcln, 0, cu_offset, 0) + b"\x00\x00\x00\x00"


def func116(entry_address, name_offset=0):
    # entry uintptr, then nameoff, args, deferreturn, pcsp, pcfile, pcln,
    # npcdata, cuOffset, then funcID/pad/nfuncdata.
    return (p64(entry_address) +
            struct.pack("<8I", name_offset, 0, 0, 0, 0, 0, 0, 0) +
            b"\x00\x00\x00\x00")


def build_go118_table(version=GoVersion.ver120,
                      names=b"main.main\x00",
                      files=b"main.go\x00",
                      cutab=b"",
                      pctab=b"",
                      functions=None,
                      entry_offsets=None,
                      text_start=0x2000,
                      nfile_count=None,
                      nfunc_override=None):
    functions = functions if functions is not None else [func118()]
    nfunc = len(functions)

    header_size = 8 + 8 * 8
    funcname_offset = header_size
    cu_offset = funcname_offset + len(names)
    filetab_offset = cu_offset + len(cutab)
    pctab_offset = filetab_offset + len(files)
    pcln_offset = pctab_offset + len(pctab)

    functab_size = (2 * nfunc + 1) * 4
    entries = entry_offsets or [0x10 + i * 0x10 for i in range(nfunc)]
    func_offsets = []
    function_data = b""
    for function in functions:
        func_offsets.append(functab_size + len(function_data))
        function_data += function

    functab = b"".join(p32(entries[i]) + p32(func_offsets[i])
                       for i in range(nfunc))
    functab += p32(entries[-1] + 0x10 if entries else 0)

    header = (GoVersion.to_magic(version) + bytes([1, 8]) +
              p64(nfunc if nfunc_override is None else nfunc_override) +
              p64(files.count(b'\x00') if nfile_count is None else nfile_count) +
              p64(text_start) +
              p64(funcname_offset) +
              p64(cu_offset) +
              p64(filetab_offset) +
              p64(pctab_offset) +
              p64(pcln_offset))

    return (header + names + cutab + files + pctab + functab + function_data)


def build_go116_table(names=b"main.main\x00", files=b"main.go\x00", text_start=0x2000):
    header_size = 8 + 7 * 8
    funcname_offset = header_size
    cu_offset = funcname_offset + len(names)
    filetab_offset = cu_offset
    pctab_offset = filetab_offset + len(files)
    pcln_offset = pctab_offset

    entry_address = text_start + 0x10
    functab_size = 3 * 8
    function = func116(entry_address)
    functab = (p64(entry_address) +
               p64(functab_size) +
               p64(entry_address + 0x10))

    header = (GoMagics.go116magic + bytes([1, 8]) +
              p64(1) +                    # nfunctab
              p64(files.count(b'\x00')) +  # nfiletab
              p64(funcname_offset) +
              p64(cu_offset) +
              p64(filetab_offset) +
              p64(pctab_offset) +
              p64(pcln_offset))

    return header + names + files + functab + function


def build_go12_table(names=b"main.main\x00", filename=b"main.go\x00"):
    ptr_size = 8
    entry_address = 0x401000
    functab_size = (2 * 1 + 1) * ptr_size
    fileoff_position = 8 + ptr_size + functab_size

    function_offset = 48
    filetab_offset = 92
    filename_offset = 100
    name_offset = filename_offset + len(filename)

    function = (p64(entry_address) +
                struct.pack("<8I", name_offset, 0, 0, 0, 0, 0, 0, 0) +
                b"\x00\x00\x00\x00")

    raw = bytearray()
    raw += GoMagics.go12magic + bytes([1, 8])
    raw += p64(1)  # nfunctab
    raw += p64(entry_address) + p64(function_offset) + p64(entry_address + 0x10)
    assert len(raw) == fileoff_position
    raw += p32(filetab_offset)
    raw += b"\x00" * (function_offset - len(raw))
    raw += function
    assert len(raw) == filetab_offset
    raw += p32(1) + p32(filename_offset)
    raw += filename
    assert len(raw) == name_offset
    raw += names
    return bytes(raw)


class FakeSection:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def __contains__(self, address):
        return self.start <= address < self.end


class FakeBinaryView:
    def __init__(self, data=b"", base=0x1000, arch_size=8):
        self._data = bytes(data)
        self.start = base
        self.end = base + len(self._data)
        self.sections = {}
        self.allocated_ranges = []
        self.arch = types.SimpleNamespace(address_size=arch_size)
        self.functions = {}
        self.symbols = []

    def add_section(self, name, start, end):
        self.sections[name] = FakeSection(start, end)

    def get_function_at(self, address):
        return self.functions.get(address)

    def create_user_function(self, address):
        function = types.SimpleNamespace(address=address, comment=None)
        self.functions[address] = function
        return function

    def define_user_symbol(self, symbol):
        self.symbols.append(symbol)

    def update_analysis_and_wait(self):
        pass

    def read(self, address, length):
        offset = address - self.start
        if offset < 0 or length <= 0:
            return b""
        return self._data[offset:offset + length]

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = self.start if key.start is None else key.start
            stop = self.end if key.stop is None else key.stop
            return self.read(start, stop - start)
        return self.read(key, 1)

    def find_next_data(self, start, data):
        start = max(start, self.start)
        index = self._data.find(data, start - self.start)
        if index < 0:
            return None
        return self.start + index


class RecordingBinaryView(FakeBinaryView):
    """FakeBinaryView that records the length of every slice it is asked for."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sliced_lengths = []

    def __getitem__(self, key):
        if isinstance(key, slice):
            self.sliced_lengths.append(key.stop - key.start)
        return super().__getitem__(key)


def make_view(raw, base=0x1000, text_start=0x2000, text_size=0x1000,
              with_pclntab_section=True, arch_size=8):
    view = FakeBinaryView(raw, base=base, arch_size=arch_size)
    if with_pclntab_section:
        view.add_section('.gopclntab', base, base + len(raw))
    view.add_section('.text', text_start, text_start + text_size)
    view.allocated_ranges = [FakeSection(base, base + max(len(raw), 1) + 0x1000)]
    return view


def parse_table(view):
    return common.GoHelper(view).init_gopclntab()


class GoVersionTest(unittest.TestCase):
    def test_from_string_known_layouts(self):
        self.assertEqual(GoVersion.from_string("1.2"), GoVersion.ver12)
        self.assertEqual(GoVersion.from_string("1.16"), GoVersion.ver116)
        self.assertEqual(GoVersion.from_string("1.18"), GoVersion.ver118)
        self.assertEqual(GoVersion.from_string("1.20"), GoVersion.ver120)

    def test_from_string_version_ranges_and_prefixes(self):
        self.assertEqual(GoVersion.from_string("go1.4"), GoVersion.ver12)
        self.assertEqual(GoVersion.from_string("1.17"), GoVersion.ver116)
        self.assertEqual(GoVersion.from_string("1.19.7"), GoVersion.ver118)
        self.assertEqual(GoVersion.from_string("go1.21.3"), GoVersion.ver120)
        self.assertEqual(GoVersion.from_string("devel go1.26-abcdef"), GoVersion.ver120)

    def test_from_string_malformed(self):
        for value in ("", "go", "1", "2.20", "not-a-version", None, 120):
            with self.subTest(value=value):
                self.assertEqual(GoVersion.from_string(value), GoVersion.invalid)

    def test_from_magic_short_or_unknown(self):
        self.assertEqual(GoVersion.from_magic(b""), GoVersion.invalid)
        self.assertEqual(GoVersion.from_magic(GoMagics.go120magic[:4]), GoVersion.invalid)
        self.assertEqual(GoVersion.from_magic(b"\x00" * 6), GoVersion.invalid)
        self.assertEqual(GoVersion.from_magic(GoMagics.go120magic), GoVersion.ver120)


class VarintTest(unittest.TestCase):
    def setUp(self):
        self.table = GoPclnTab(0, 0, b"")
        self.table.quantum = 1

    def test_read_varint(self):
        self.assertEqual(GoPclnTab.read_varint(b"\x00"), (0, 1))
        self.assertEqual(GoPclnTab.read_varint(b"\xac\x02"), (300, 2))
        self.assertEqual(GoPclnTab.read_varint(b"\x01", 1), (0, 0))

    def test_read_varint_is_bounded(self):
        value, read = GoPclnTab.read_varint(b"\x80\x80\x80\x80\x80\x80")
        self.assertEqual(read, 5)
        self.assertEqual(value, 0)

    def test_step_positive_delta(self):
        offset, pc, value, ok = self.table.step(b"\x0a\x02", 0, 0x100, -1, True)
        self.assertTrue(ok)
        self.assertEqual((offset, pc, value), (2, 0x102, 4))

    def test_step_negative_delta(self):
        offset, pc, value, ok = self.table.step(b"\x01\x02", 0, 0x100, -1, True)
        self.assertTrue(ok)
        self.assertEqual((offset, pc, value), (2, 0x102, -2))

    def test_step_larger_negative_delta(self):
        # Zig-zag encoding of -64 is 127 (0x7f).
        offset, pc, value, ok = self.table.step(b"\x7f\x03", 0, 0, -1, True)
        self.assertTrue(ok)
        self.assertEqual((pc, value), (3, -65))

    def test_step_stop_marker(self):
        offset, pc, value, ok = self.table.step(b"\x00", 0, 0x100, 7, False)
        self.assertFalse(ok)
        self.assertEqual((pc, value), (0x100, 7))

    def test_pcvalue_decodes_line(self):
        self.table.pctab = b"\x16\x01"  # val delta +11, pc delta 1
        self.assertEqual(self.table.pcvalue(0, 0x100, 0x100), 10)

    def test_pcvalue_out_of_bounds(self):
        self.assertEqual(self.table.pcvalue(0, 0x100, 0x100), -1)
        self.assertEqual(self.table.pcvalue(-1, 0x100, 0x100), -1)
        self.assertEqual(self.table.pcvalue(10, 0x100, 0x100), -1)


class FuncEntryFieldsTest(unittest.TestCase):
    def test_go118_field_layout(self):
        raw = struct.pack("<10I", 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9) + b"\x00" * 4
        function = FuncEntry(raw, 8, textStart=0x2000, version=GoVersion.ver120)
        self.assertEqual(function.entry, 0x2010)
        self.assertEqual(function.nameOffset, 1)
        self.assertEqual(function.args, 2)
        self.assertEqual(function.deferreturn, 3)
        self.assertEqual(function.pcsp, 4)
        self.assertEqual(function.pcfile, 5)
        self.assertEqual(function.pcln, 6)
        self.assertEqual(function.npcdata, 7)
        self.assertEqual(function.cuOffset, 8)
        self.assertEqual(function.startLine, 9)

    def test_go12_field_layout(self):
        raw = (p64(0x401000) +
               struct.pack("<8I", 100, 1, 2, 3, 4, 5, 6, 7) +
               b"\x00" * 4)
        function = FuncEntry(raw, 8, version=GoVersion.ver12)
        self.assertEqual(function.entry, 0x401000)
        self.assertEqual(function.nameOffset, 100)
        self.assertEqual(function.args, 1)
        self.assertEqual(function.frame, 2)
        self.assertEqual(function.deferreturn, 0)
        self.assertEqual(function.pcsp, 3)
        self.assertEqual(function.pcfile, 4)
        self.assertEqual(function.pcln, 5)
        self.assertEqual(function.npcdata, 6)
        self.assertEqual(function.nfuncdata, 7)
        self.assertEqual(function.cuOffset, 0)


class MalformedTableTest(unittest.TestCase):
    def test_empty_table_is_safe(self):
        table = GoPclnTab(0, 0, b"")
        self.assertEqual(table.version, GoVersion.invalid)
        self.assertIsNone(table.funcInfo(0))
        self.assertEqual(table.funcName(0), "")
        self.assertEqual(table.fileName(0), b"")
        self.assertEqual(table.pc2filename(None), b"")
        self.assertEqual(table.pc2line(None), -1)
        self.assertIn("GoPclnTab", repr(table))

    def test_short_func_entry_is_safe(self):
        function = FuncEntry(b"\x01\x02", 8, version=GoVersion.ver118)
        self.assertEqual(function.entry, 0)
        self.assertEqual(function.nameOffset, 0)
        self.assertEqual(function.field(2), 0)
        self.assertIn("FuncEntry", repr(function))

    def test_name_offsets_are_validated(self):
        table = GoPclnTab(0, 0, b"")
        table.funcnametab = b"unterminated"
        self.assertEqual(table.funcName(-1), "")
        self.assertEqual(table.funcName(100), "")
        # A missing NUL terminates at the end of the table instead of throwing.
        self.assertEqual(table.funcName(0), "unterminated")

    def test_file_offsets_are_validated(self):
        table = GoPclnTab(0, 0, b"")
        table.nfiletab = 1
        table.filetab = b"no-terminator"
        self.assertEqual(table.fileName(0), b"")
        self.assertEqual(table.fileName(1), b"")
        self.assertEqual(table.fileName(-1), b"")

        table.filetab = b"main.go\x00"
        self.assertEqual(table.fileName(0), b"main.go")

    def test_file_names_are_parsed_once(self):
        table = GoPclnTab(0, 0, b"")
        table.nfiletab = 3
        table.filetab = b"a.go\x00b.go\x00c.go\x00"

        with mock.patch.object(table, '_parse_file_names',
                               wraps=table._parse_file_names) as parse:
            for _ in range(3):
                self.assertEqual(table.fileName(0), b"a.go")
                self.assertEqual(table.fileName(1), b"b.go")
                self.assertEqual(table.fileName(2), b"c.go")
            self.assertEqual(parse.call_count, 1)

        self.assertEqual(table.fileNames(), [b"a.go", b"b.go", b"c.go"])

    def test_go12_file_names_use_offset_layout(self):
        table = GoPclnTab(0, 0, b"")
        table.version = GoVersion.ver12
        table.nfiletab = 2
        names = b"main.go\x00helper.go\x00"
        table.funcdata = b"\xff" * 8 + names
        table.filetab = (p32(2) + p32(8) + p32(8 + len(b"main.go\x00")) +
                         p32(0xffff))  # fourth slot is out of range

        self.assertEqual(table.fileName(0), b"main.go")
        self.assertEqual(table.fileName(1), b"helper.go")
        self.assertEqual(table.fileName(2), b"")
        self.assertEqual(table.fileName(-1), b"")

        table.nfiletab = 3
        self.assertEqual(table.fileName(2), b"")

    def test_file_names_cache_is_invalidated_when_table_changes(self):
        table = GoPclnTab(0, 0, b"")
        table.nfiletab = 1
        table.filetab = b"a.go\x00"
        self.assertEqual(table.fileName(0), b"a.go")

        table.filetab = b"b.go\x00"
        self.assertEqual(table.fileName(0), b"b.go")

    def test_file_name_list_is_bounded_by_available_bytes(self):
        table = GoPclnTab(0, 0, b"")
        table.nfiletab = 2 ** 20
        table.filetab = b"only.go\x00"

        names = table.fileNames()
        self.assertEqual(names[0], b"only.go")
        self.assertLessEqual(len(names), len(table.filetab))
        self.assertEqual(table.fileName(0), b"only.go")
        self.assertEqual(table.fileName(1), b"")

    def test_func_at_rejects_bad_offsets_and_truncation(self):
        table = GoPclnTab(0, 0, b"")
        table.version = GoVersion.ver120
        table.ptrsize = 8
        table.nfunctab = 1
        table.functab = p32(0x10) + p32(0) + p32(0x20)
        table.funcdata = table.functab
        self.assertIsNone(table.funcAt(0))
        self.assertIsNone(table.funcInfo(0))
        self.assertIsNone(table.funcAt(-1))

        table.funcdata = table.functab + b"\x00" * 4
        self.assertIsNone(table.funcAt(0))

    def test_pc2filename_rejects_out_of_range_cu_offset(self):
        table = GoPclnTab(0, 0, b"")
        table.version = GoVersion.ver120
        table.quantum = 1
        table.pctab = b"\x02\x01"
        table.cutab = b""
        table.filetab = b"main.go\x00"
        function = FuncEntry(b"\x10\x00\x00\x00" + b"\x00" * 40, 8,
                             textStart=0x2000, version=GoVersion.ver120)
        function.pcfile = 0
        function.cuOffset = 0x1000
        self.assertEqual(table.pc2filename(function), b"")


class PclnTabLayoutTest(unittest.TestCase):
    def test_go120_table(self):
        pctab = b"\x02\x01" + b"\x16\x01"
        raw = build_go118_table(version=GoVersion.ver120,
                                cutab=p32(0),
                                pctab=pctab,
                                functions=[func118(pcfile=0, pcln=2)])
        table = parse_table(make_view(raw))

        self.assertIsNotNone(table)
        self.assertEqual(table.version, GoVersion.ver120)
        self.assertEqual(table.nfunctab, 1)
        self.assertEqual(table.textStart, 0x2000)
        self.assertEqual(table.funcInfo(0).resolvedName, "main.main")
        self.assertEqual(table.funcInfo(0).entry, 0x2010)
        self.assertEqual(table.fileName(0), b"main.go")

        function = table.funcInfo(0)
        self.assertEqual(table.pc2filename(function), b"main.go")
        self.assertEqual(table.pc2line(function), 10)

    def test_go118_table(self):
        raw = build_go118_table(version=GoVersion.ver118)
        table = parse_table(make_view(raw))
        self.assertIsNotNone(table)
        self.assertEqual(table.version, GoVersion.ver118)
        self.assertEqual(table.funcInfo(0).resolvedName, "main.main")

    def test_go116_table(self):
        raw = build_go116_table()
        table = parse_table(make_view(raw))
        self.assertIsNotNone(table)
        self.assertEqual(table.version, GoVersion.ver116)
        self.assertEqual(table.nfunctab, 1)
        self.assertEqual(table.funcInfo(0).resolvedName, "main.main")
        self.assertEqual(table.funcInfo(0).entry, 0x2010)

    def test_go12_table(self):
        raw = build_go12_table()
        view = make_view(raw)
        del view.sections['.text']
        table = parse_table(view)
        self.assertIsNotNone(table)
        self.assertEqual(table.version, GoVersion.ver12)
        self.assertEqual(table.go12FuncInfo(0).resolvedName, "main.main")
        self.assertEqual(table.go12FuncInfo(0).entry, 0x401000)
        self.assertEqual(table.fileName(0), b"main.go")


class FunctionRecoveryTest(unittest.TestCase):
    def setUp(self):
        BINARYNINJA_SETTINGS.values.clear()
        BINARYNINJA_SETTINGS.values['golang_binary_parser.source_lines'] = True

    def tearDown(self):
        BINARYNINJA_SETTINGS.values.clear()

    @staticmethod
    def make_view():
        names = b"go:buildid\x00main.main\x00main.outside\x00"
        pctab = b"\x02\x01" + b"\x16\x01"  # pcfile -> 0, pcln -> line 10
        functions = [
            func118(entry_offset=0x0, name_offset=0),
            func118(entry_offset=0x10, name_offset=11, pcfile=0, pcln=2),
            func118(entry_offset=0x1000, name_offset=21),
        ]
        raw = build_go118_table(names=names,
                                cutab=p32(0),
                                pctab=pctab,
                                functions=functions,
                                entry_offsets=[0x0, 0x10, 0x1000])
        return make_view(raw, text_size=0x100)

    def test_renamer_skips_pseudo_and_outside_functions(self):
        view = self.make_view()
        functions_renamer.FunctionRenamer(view).rename_functions()

        self.assertEqual(list(view.functions), [0x2010])
        self.assertEqual(len(view.symbols), 1)
        self.assertEqual(view.symbols[0].name, "main.main")
        self.assertEqual(view.symbols[0].address, 0x2010)

    def test_commenter_uses_source_line(self):
        view = self.make_view()
        functions_renamer.FunctionRenamer(view).rename_functions()
        functions_renamer.FunctionCommenter(view).comment_functions()

        self.assertEqual(view.functions[0x2010].comment, "File: main.go:10")

    def test_commenter_falls_back_to_file_name(self):
        BINARYNINJA_SETTINGS.values['golang_binary_parser.source_lines'] = False
        view = self.make_view()
        functions_renamer.FunctionRenamer(view).rename_functions()
        functions_renamer.FunctionCommenter(view).comment_functions()

        self.assertEqual(view.functions[0x2010].comment, "File: main.go")


class GoHelperLifecycleTest(unittest.TestCase):
    def test_valid_table_is_cached(self):
        helper = common.GoHelper(make_view(build_go118_table()))
        # Construction is lazy: the table is parsed on first use.
        self.assertIsNone(helper.gopclntab)
        table = helper.init_gopclntab()
        self.assertIsNotNone(table)
        self.assertIs(helper.init_gopclntab(), table)
        self.assertEqual(helper.quick_go_version(), GoVersion.ver120)
        self.assertEqual(helper.ptr_size, 8)

    def test_missing_table_stays_none(self):
        helper = common.GoHelper(FakeBinaryView(b""))
        self.assertIsNone(helper.init_gopclntab())
        self.assertIsNone(helper.gopclntab)
        self.assertEqual(helper.quick_go_version(), GoVersion.invalid)
        self.assertEqual(helper.ptr_size, 8)

    def test_invalid_header_does_not_leave_partial_table(self):
        raw = bytearray(build_go118_table())
        raw[7] = 3  # invalid ptrsize
        helper = common.GoHelper(make_view(bytes(raw)))
        self.assertIsNone(helper.init_gopclntab())
        self.assertIsNone(helper.gopclntab)
        self.assertEqual(helper.quick_go_version(), GoVersion.invalid)
        self.assertEqual(helper.ptr_size, helper.bv.arch.address_size)

    def test_missing_text_section_does_not_leave_partial_table(self):
        view = make_view(build_go118_table())
        del view.sections['.text']
        helper = common.GoHelper(view)
        self.assertIsNone(helper.init_gopclntab())
        self.assertIsNone(helper.gopclntab)
        self.assertEqual(helper.quick_go_version(), GoVersion.invalid)

    def test_absurd_function_count_is_clamped(self):
        raw = build_go118_table(nfunc_override=2 ** 40)
        helper = common.GoHelper(make_view(raw))
        table = helper.init_gopclntab()
        self.assertIsNotNone(table)
        self.assertGreater(table.nfunctab, 0)
        self.assertLess(table.nfunctab, 10)
        self.assertLessEqual(table.functabsize, len(table.funcdata))

    def test_failed_initialization_is_cached(self):
        helper = common.GoHelper(FakeBinaryView(b""))
        with mock.patch.object(helper, '_parse_gopclntab',
                               side_effect=RuntimeError("boom")) as parse, \
                mock.patch.object(common, 'log_error') as log_error:
            self.assertIsNone(helper.init_gopclntab())
            self.assertIsNone(helper.init_gopclntab())
            self.assertEqual(helper.quick_go_version(), GoVersion.invalid)
        self.assertEqual(parse.call_count, 1)
        messages = [call.args[0] for call in log_error.call_args_list if call.args]
        self.assertTrue(any("Unable to initialize .gopclntab" in message
                            for message in messages))

    def test_magic_fallback_skips_false_positive(self):
        table_raw = build_go118_table()
        prefix = GoMagics.go118magic + b"\x00\x00" + b"\x00" * 8
        combined = prefix + table_raw
        view = make_view(combined, with_pclntab_section=False)
        table = common.GoHelper(view).init_gopclntab()
        self.assertIsNotNone(table)
        self.assertEqual(table.start, view.start + len(prefix))
        self.assertEqual(table.funcInfo(0).resolvedName, "main.main")

    def test_magic_scan_stops_at_failed_candidate_budget(self):
        false_positive = GoMagics.go118magic + b"\x00\x00" + b"\x00" * 8
        raw = false_positive * (common.MAX_MAGIC_CANDIDATES + 16)
        view = make_view(raw, with_pclntab_section=False)
        helper = common.GoHelper(view)

        with mock.patch.object(helper, 'is_valid_gopclntab_header',
                               wraps=helper.is_valid_gopclntab_header) as validate, \
                mock.patch.object(common, 'log_warn') as log_warn:
            self.assertIsNone(helper.init_gopclntab())

        self.assertEqual(validate.call_count, common.MAX_MAGIC_CANDIDATES)
        warnings = [call.args[0] for call in log_warn.call_args_list if call.args]
        self.assertTrue(any("invalid candidates" in message for message in warnings))

    def test_magic_fallback_read_is_capped(self):
        raw = build_go118_table()
        view = RecordingBinaryView(raw)
        view.add_section('.text', 0x2000, 0x3000)
        view.allocated_ranges = [FakeSection(view.start, view.start + len(raw) + 0x1000)]

        with mock.patch.object(common, 'MAX_PCLNTAB_SIZE', len(raw)), \
                mock.patch.object(common, 'log_warn') as log_warn:
            table = common.GoHelper(view).init_gopclntab()

        self.assertIsNotNone(table)
        self.assertEqual(view.sliced_lengths, [len(raw)])
        warnings = [call.args[0] for call in log_warn.call_args_list if call.args]
        self.assertTrue(any("Capping the .gopclntab read" in message
                            for message in warnings))

    def test_offsets_beyond_available_bytes_fail_cleanly(self):
        raw = bytearray(build_go118_table())
        # Go 1.18+ header word 3 is the funcname table offset.
        struct.pack_into("<Q", raw, 8 + 3 * 8, 0x100000)
        helper = common.GoHelper(make_view(bytes(raw)))

        with mock.patch.object(common, 'log_error') as log_error:
            self.assertIsNone(helper.init_gopclntab())
        messages = [call.args[0] for call in log_error.call_args_list if call.args]
        self.assertTrue(any("Invalid gopclntab offsets" in message
                            for message in messages))

    def test_unknown_magic_stays_none(self):
        view = FakeBinaryView(b"\x00" * 64)
        view.add_section('.gopclntab', view.start, view.end)
        view.add_section('.text', 0x2000, 0x3000)
        helper = common.GoHelper(view)
        self.assertIsNone(helper.init_gopclntab())
        self.assertIsNone(helper.gopclntab)


class PrintFilesTest(unittest.TestCase):
    @staticmethod
    def make_printer(files):
        return file_printer.PrintFiles(make_view(build_go118_table(files=files)))

    def test_logs_cached_file_list_and_truncates(self):
        files = b"".join(f"file{index}.go\x00".encode() for index in range(5))
        printer = self.make_printer(files)

        with mock.patch.object(file_printer, 'log_info') as log_info, \
                mock.patch.object(file_printer, 'log_warn') as log_warn, \
                mock.patch.object(file_printer.PrintFiles, 'MAX_LOGGED_FILES', 2):
            printer.print_files()

        messages = [call.args[0] for call in log_info.call_args_list if call.args]
        self.assertEqual(messages, ["file0.go", "file1.go"])
        warnings = [call.args[0] for call in log_warn.call_args_list if call.args]
        self.assertTrue(any("first 2 of 5 source files" in message
                            for message in warnings))

    def test_file_table_is_parsed_once_across_print_runs(self):
        printer = self.make_printer(b"a.go\x00b.go\x00")
        gopclntab = printer.init_gopclntab()

        with mock.patch.object(gopclntab, '_parse_file_names',
                               wraps=gopclntab._parse_file_names) as parse, \
                mock.patch.object(file_printer, 'log_info'):
            printer.print_files()
            printer.print_files()

        self.assertEqual(parse.call_count, 1)

    def test_warns_when_no_source_files(self):
        printer = self.make_printer(b"")

        with mock.patch.object(file_printer, 'log_warn') as log_warn:
            printer.print_files()

        warnings = [call.args[0] for call in log_warn.call_args_list if call.args]
        self.assertTrue(any("does not contain any source file name" in message
                            for message in warnings))


if __name__ == "__main__":
    unittest.main()
