"""Headless unit tests for the Go type/interface recovery layer.

The plugin imports Binary Ninja at import time. These tests install a small
Binary Ninja stub and a package shim so the parser modules can be imported and
driven with synthetic binary views. No license or UI is required.
"""
import importlib
import struct
import sys
import types
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Minimal Binary Ninja stub
# ---------------------------------------------------------------------------

class FakeBinaryNinjaType:
    def __init__(self, kind, **attributes):
        self.kind = kind
        for name, value in attributes.items():
            setattr(self, name, value)

    def __repr__(self):
        return f"FakeType({self.kind})"


class FakeStructureBuilder(FakeBinaryNinjaType):
    def __init__(self, width=0):
        super().__init__('struct', width=width, fields=[])

    @classmethod
    def create(cls, width=0):
        return cls(width)

    def append(self, type_, name=''):
        self.fields.append((name, type_))
        return self

    def mutable_copy(self):
        copy = FakeStructureBuilder(self.width)
        copy.fields = list(self.fields)
        return copy


class FakeIntegerType:
    @staticmethod
    def create(width=1, sign=True):
        return FakeBinaryNinjaType('integer', width=width, sign=sign)


class FakePointerType:
    @staticmethod
    def create(arch, target):
        return FakeBinaryNinjaType('pointer', target=target, width=arch.address_size)

    @staticmethod
    def create_with_width(width, target):
        return FakeBinaryNinjaType('pointer', target=target, width=width)


class FakeArrayType:
    @staticmethod
    def create(target, count):
        return FakeBinaryNinjaType('array', target=target, count=count)


class FakeFloatType:
    @staticmethod
    def create(width):
        return FakeBinaryNinjaType('float', width=width)


class FakeBoolType:
    @staticmethod
    def create():
        return FakeBinaryNinjaType('bool')


class FakeCharType:
    @staticmethod
    def create():
        return FakeBinaryNinjaType('char')


class FakeVoidType:
    @staticmethod
    def create():
        return FakeBinaryNinjaType('void')


class FakeTypeBuilder:
    pass


class StrictTypeFactory:
    """Type factory that raises when a builder uses an undefined named type,
    like Binary Ninja's Type.named_type_from_registered_type."""

    @staticmethod
    def named_type_from_registered_type(bv, name):
        existing = bv.get_type_by_name(name) if hasattr(bv, 'get_type_by_name') else None
        if existing is None:
            raise ValueError(f"Tried to use the undefined type {name}")
        return existing

    @staticmethod
    def void():
        return FakeTypeFactory.void()

    @staticmethod
    def array(type_, count):
        return FakeTypeFactory.array(type_, count)

    @staticmethod
    def enumeration(members=None, width=1):
        return FakeTypeFactory.enumeration(members=members, width=width)


class FakeTypeFactory:
    @staticmethod
    def void():
        return FakeBinaryNinjaType('void')

    @staticmethod
    def array(type_, count):
        return FakeBinaryNinjaType('array', target=type_, count=count)

    @staticmethod
    def function(ret=None, params=None, variable_arguments=False):
        return FakeBinaryNinjaType('function', ret=ret, params=list(params or []),
                                   variable_arguments=variable_arguments)

    @staticmethod
    def enumeration(members=None, width=1):
        return FakeBinaryNinjaType('enum', members=list(members or []), width=width)

    @staticmethod
    def named_type_from_registered_type(bv, name):
        existing = bv.get_type_by_name(name) if hasattr(bv, 'get_type_by_name') else None
        return existing or FakeBinaryNinjaType('named', name=name)


class FakeSettings:
    overrides = {}
    defaults = {
        'golang_binary_parser.sanitize': False,
        'golang_binary_parser.components': False,
        'golang_binary_parser.use_typelinks': True,
        'golang_binary_parser.minimum_name_length': 2,
        'golang_binary_parser.goresym_path': '',
    }

    def contains(self, key):
        return key in self.overrides or key in self.defaults

    def get_bool(self, key, default=None):
        if key in self.overrides:
            return self.overrides[key]
        if default is not None:
            return default
        return self.defaults.get(key, False)

    def get_integer(self, key, default=None):
        return self.defaults.get(key, 0 if default is None else default)

    def get_string(self, key, default=None):
        return self.defaults.get(key, '' if default is None else default)

    def register_group(self, name, title):
        pass

    def register_setting(self, key, payload):
        pass


class FakeLogger:
    def __init__(self, *args, **kwargs):
        pass

    def log_debug(self, *args, **kwargs):
        pass

    def log_info(self, *args, **kwargs):
        pass

    def log_warn(self, *args, **kwargs):
        pass

    def log_error(self, *args, **kwargs):
        pass


class FakeBackgroundTaskThread:
    def __init__(self, name='', can_cancel=False):
        self.name = name

    def start(self):
        self.run()

    def join(self):
        pass


class FakeBinaryReader:
    def __init__(self, bv):
        self.bv = bv
        self.offset = 0

    def seek(self, offset):
        self.offset = offset

    def read(self, size):
        data = self.bv.read(self.offset, size)
        self.offset += len(data)
        return data

    def read32(self):
        data = self.bv.read(self.offset, 4)
        self.offset += 4
        return struct.unpack('<I', data)[0]

    def read64(self):
        data = self.bv.read(self.offset, 8)
        self.offset += 8
        return struct.unpack('<Q', data)[0]


class FakeMLILOperation:
    MLIL_CALL = 0x10
    MLIL_TAILCALL = 0x11
    MLIL_CALL_UNTYPED = 0x12
    MLIL_CONST = 0x20
    MLIL_CONST_PTR = 0x21
    MLIL_CONST_DATA = 0x22


class FakeHLILOperation:
    HLIL_CALL = 0x30
    HLIL_TAILCALL = 0x31
    HLIL_CONST = 0x40
    HLIL_CONST_PTR = 0x41
    HLIL_CONST_DATA = 0x42


class FakeSymbolType:
    DataSymbol = 1
    FunctionSymbol = 2


class FakeSymbol:
    def __init__(self, symbol_type, address, name, short_name=None):
        self.type = symbol_type
        self.address = address
        self.name = name
        self.short_name = short_name or name


class FakeDataVar:
    """Hashable stand-in for bn.DataVariable for the cache decorated methods."""
    def __init__(self, address):
        self.address = address

    def __hash__(self):
        return hash(self.address)

    def __eq__(self, other):
        return isinstance(other, FakeDataVar) and other.address == self.address


class FakeValue:
    def __init__(self, value):
        self.value = value


def _fake_value(value):
    if isinstance(value, dict):
        return {key: _fake_value(inner) for key, inner in value.items()}
    return FakeValue(value)


class FakeTypedDataVar(FakeDataVar):
    """Data variable exposing the BN struct field lookup (``var['size'].value``)."""
    def __init__(self, address, **fields):
        super().__init__(address)
        self.fields = {name: _fake_value(value) for name, value in fields.items()}

    def __getitem__(self, key):
        return self.fields[key]


class FakeBinaryViewMarker:
    pass


def install_stubs():
    """Install (or refresh) the Binary Ninja stub modules."""
    global FakeSettings, FakeSymbol, FakeSymbolType

    binaryninja = sys.modules.get('binaryninja')
    if binaryninja is not None and getattr(binaryninja, '_goplugin_test_stub', False):
        # The plugin modules are already imported against the canonical stub
        # (this happens when the tests are imported under two module names,
        # e.g. `test_types` and `tests.test_types`). Reuse its classes so
        # settings/symbol helpers act on the same objects.
        FakeSettings = binaryninja.Settings
        FakeSymbol = binaryninja.Symbol
        FakeSymbolType = binaryninja.SymbolType
        return

    binaryninja = types.ModuleType('binaryninja')
    binaryninja._goplugin_test_stub = True
    binaryninja.BinaryView = FakeBinaryViewMarker
    binaryninja.Section = FakeBinaryViewMarker
    binaryninja.DataVariable = FakeBinaryViewMarker
    binaryninja.Function = FakeBinaryViewMarker
    binaryninja.Logger = FakeLogger
    binaryninja.Settings = FakeSettings
    binaryninja.Symbol = FakeSymbol
    binaryninja.SymbolType = FakeSymbolType
    binaryninja.MediumLevelILOperation = FakeMLILOperation
    binaryninja.HighLevelILOperation = FakeHLILOperation
    binaryninja.redirect_output_to_log = lambda: None

    plugin = types.ModuleType('binaryninja.plugin')
    plugin.BackgroundTaskThread = FakeBackgroundTaskThread

    binaryview = types.ModuleType('binaryninja.binaryview')
    binaryview.BinaryReader = FakeBinaryReader

    type_factory = FakeTypeFactory()
    bn_types = types.ModuleType('binaryninja.types')
    bn_types.Type = type_factory
    bn_types.StructureBuilder = FakeStructureBuilder
    bn_types.IntegerType = FakeIntegerType
    bn_types.TypeBuilder = FakeTypeBuilder
    bn_types.PointerType = FakePointerType
    bn_types.ArrayType = FakeArrayType
    bn_types.BoolType = FakeBoolType
    bn_types.FloatType = FakeFloatType
    bn_types.CharType = FakeCharType
    bn_types.VoidType = FakeVoidType

    binaryninja.Type = type_factory
    binaryninja.plugin = plugin
    binaryninja.binaryview = binaryview
    binaryninja.types = bn_types

    sys.modules['binaryninja'] = binaryninja
    sys.modules['binaryninja.plugin'] = plugin
    sys.modules['binaryninja.binaryview'] = binaryview
    sys.modules['binaryninja.types'] = bn_types


def load_plugin():
    """Import the parser modules under a synthetic package that skips the
    plugin's top-level command registration (which needs a full BN API)."""
    install_stubs()
    if 'goplugin.parsers.interface_recovery' in sys.modules:
        return sys.modules['goplugin']

    package = types.ModuleType('goplugin')
    package.__path__ = [str(PLUGIN_ROOT)]
    sys.modules['goplugin'] = package

    parsers = types.ModuleType('goplugin.parsers')
    parsers.__path__ = [str(PLUGIN_ROOT / 'parsers')]
    sys.modules['goplugin.parsers'] = parsers
    package.parsers = parsers

    internal_types = types.ModuleType('goplugin.internal_types')
    internal_types.__path__ = [str(PLUGIN_ROOT / 'internal_types')]
    sys.modules['goplugin.internal_types'] = internal_types
    package.internal_types = internal_types

    type_parser = importlib.import_module('goplugin.parsers.type_parser')
    parsers.TypeParser = type_parser.TypeParser
    importlib.import_module('goplugin.parsers.structure_recovery')
    importlib.import_module('goplugin.parsers.interface_recovery')

    return package


# ---------------------------------------------------------------------------
# Synthetic binary view helpers
# ---------------------------------------------------------------------------

class FakeRegion:
    def __init__(self, start, size):
        self.start = start
        self.data = bytearray(size)

    @property
    def end(self):
        return self.start + len(self.data)


class FakeSection:
    def __init__(self, name, start, end, parent=None, flags=0):
        self.name = name
        self.start = start
        self.end = end
        self.length = end - start
        self.parent = parent
        self.flags = flags


class FakeSegment:
    def __init__(self, name):
        self.name = name


class FakeBinaryView:
    def __init__(self, address_size=8, sections=None, endianness='little'):
        self.arch = types.SimpleNamespace(address_size=address_size)
        self.sections = sections if sections is not None else []
        self.endianness = endianness
        self._regions = []
        self._symbols = []
        self._types = {}
        self._data_vars = {}
        self._comments = {}
        self._refs = []
        self._functions = []

    # memory
    def add_region(self, start, size):
        region = FakeRegion(start, size)
        self._regions.append(region)
        return region

    def _region_for(self, address, length=1):
        for region in self._regions:
            if region.start <= address and address + length <= region.end:
                return region
        return None

    def read(self, address, length):
        region = self._region_for(address, length)
        if region is None:
            return b''
        offset = address - region.start
        return bytes(region.data[offset:offset + length])

    def write(self, address, data):
        region = self._region_for(address, len(data))
        if region is None:
            raise ValueError(f"No mapped region at 0x{address:x} for {len(data)} bytes")
        offset = address - region.start
        region.data[offset:offset + len(data)] = data
        return len(data)

    def __getitem__(self, key):
        if isinstance(key, slice):
            return self.read(key.start, key.stop - key.start)
        return self.read(key, 1)

    # symbols
    def get_symbols_by_name(self, name):
        return [symbol for symbol in self._symbols if symbol.name == name]

    def get_symbol_at(self, address):
        for symbol in self._symbols:
            if symbol.address == address:
                return symbol
        return None

    def define_user_symbol(self, symbol):
        self._symbols.append(symbol)

    # comments / refs
    def get_comment_at(self, address):
        return self._comments.get(address)

    def set_comment_at(self, address, comment):
        self._comments[address] = comment

    def add_user_data_ref(self, from_address, to_address):
        self._refs.append((from_address, to_address))

    # types / data variables
    def get_type_by_name(self, name):
        return self._types.get(name)

    def define_user_type(self, name, type_):
        self._types[name] = type_

    def get_data_var_at(self, address):
        return self._data_vars.get(address)

    def define_user_data_var(self, address, type_):
        data_var = types.SimpleNamespace(address=address, type=type_, name=None)
        self._data_vars[address] = data_var
        return data_var

    # functions
    def get_functions_by_name(self, name):
        return [function for function in self._functions if function.name == name]

    def get_function_at(self, address):
        return None


# ---------------------------------------------------------------------------
# Go descriptor builders
# ---------------------------------------------------------------------------

def encode_varint(value):
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            return bytes(result)


def write_name(bv, address, name, version=None):
    from goplugin.internal_types.datatypes import GoVersion
    version = version or GoVersion.ver120
    encoded = name.encode()
    if version > GoVersion.ver116:
        data = bytes([0]) + encode_varint(len(encoded)) + encoded
    else:
        data = bytes([0]) + len(encoded).to_bytes(2, 'big') + encoded
    bv.write(address, data)


def _type_header_size(ptr_size):
    return 48 if ptr_size == 8 else 32


def write_type_header(bv, address, kind, ptr_size=8, size=8, ptrdata=0, tflag=0,
                      hash_=0, equal=0, gcdata=0, name_off=0, type_off=0, version=None):
    # Go 1.12-1.15 use the same _type prefix as Go 1.16+: size, ptrdata, hash,
    # tflag, align, fieldalign, kind, equal, gcdata, nameOff, typeOff.
    header = bytearray(_type_header_size(ptr_size))
    pack_ptr = '<Q' if ptr_size == 8 else '<I'
    struct.pack_into(pack_ptr, header, 0, size)
    struct.pack_into(pack_ptr, header, ptr_size, ptrdata)
    struct.pack_into('<I', header, 2 * ptr_size, hash_)
    header[2 * ptr_size + 4] = tflag
    header[2 * ptr_size + 5] = 8
    header[2 * ptr_size + 6] = 8
    header[2 * ptr_size + 7] = kind & 0x1f
    equal_offset = 2 * ptr_size + 8
    struct.pack_into(pack_ptr, header, equal_offset, equal)
    struct.pack_into(pack_ptr, header, equal_offset + ptr_size, gcdata)
    struct.pack_into('<i', header, equal_offset + 2 * ptr_size, name_off)
    struct.pack_into('<i', header, equal_offset + 2 * ptr_size + 4, type_off)
    bv.write(address, header)
    return header


def write_pointer(bv, address, value, ptr_size=8):
    bv.write(address, value.to_bytes(ptr_size, 'little'))


def write_interface_info(bv, address, methods_data, methods_len, ptr_size=8, **header_kwargs):
    write_type_header(bv, address, 0x14, ptr_size=ptr_size, **header_kwargs)  # INTERFACE
    header_size = _type_header_size(ptr_size)
    write_pointer(bv, address + header_size, 0, ptr_size)  # pkgPath
    write_pointer(bv, address + header_size + ptr_size, methods_data, ptr_size)
    write_pointer(bv, address + header_size + 2 * ptr_size, methods_len, ptr_size)
    write_pointer(bv, address + header_size + 3 * ptr_size, methods_len, ptr_size)


def write_imethod(bv, address, name_off, type_off=0):
    bv.write(address, struct.pack('<ii', name_off, type_off))


def write_moduledata_v127(bv, address, header, types, typedesclen, etypes,
                          itaboffset=0, itabsize=0, ptr_size=8):
    pack_ptr = '<Q' if ptr_size == 8 else '<I'
    slots = {
        0: header,
        37: types,
        38: typedesclen,
        39: etypes,
        40: itaboffset,
        41: itabsize,
    }
    for index, value in slots.items():
        bv.write(address + index * ptr_size, struct.pack(pack_ptr, value))


def make_type_parser(type_parser_module, bv, **attributes):
    parser = type_parser_module.TypeParser.__new__(type_parser_module.TypeParser)
    parser.bv = bv
    parser.target = None
    parser.rodata_section = None
    parser.types_base = None
    parser.types_section = None
    parser.moduledata = None
    parser.gopclntab = None
    for name, value in attributes.items():
        setattr(parser, name, value)
    return parser


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TypeNameTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.datatypes = importlib.import_module('goplugin.internal_types.datatypes')

    def make_bv(self):
        bv = FakeBinaryView()
        bv.add_region(0x100000, 0x1000)
        return bv

    def test_two_byte_length_go116(self):
        bv = self.make_bv()
        name = 'N' * 300
        write_name(bv, 0x100100, name, self.datatypes.GoVersion.ver116)
        type_name = self.datatypes.TypeName.from_bv(
            bv, 0x100100, 0x100000, self.datatypes.GoVersion.ver116)
        self.assertEqual(type_name.size, 300)
        self.assertEqual(type_name.name, name)

    def test_varint_length_go120(self):
        bv = self.make_bv()
        name = 'M' * 300
        write_name(bv, 0x100100, name, self.datatypes.GoVersion.ver120)
        type_name = self.datatypes.TypeName.from_bv(
            bv, 0x100100, 0x100000, self.datatypes.GoVersion.ver120)
        self.assertEqual(type_name.name, name)

    def test_invalid_utf8_is_replaced(self):
        bv = self.make_bv()
        bv.write(0x100100, bytes([0, 2, 0xff, 0xfe]))
        type_name = self.datatypes.TypeName.from_bv(
            bv, 0x100100, 0x100000, self.datatypes.GoVersion.ver120)
        self.assertIn('\ufffd', type_name.name)

    def test_absurd_length_is_bounded(self):
        bv = self.make_bv()
        requested_lengths = []
        original_read = bv.read

        def guarded_read(address, length):
            requested_lengths.append(length)
            return original_read(address, length)

        bv.read = guarded_read
        # bitfield + uvarint 0xffffffff, which must not become a giant read.
        bv.write(0x100100, bytes([0, 0xff, 0xff, 0xff, 0xff, 0x7f]))
        type_name = self.datatypes.TypeName.from_bv(
            bv, 0x100100, 0x100000, self.datatypes.GoVersion.ver120)
        self.assertEqual(type_name.name, "")
        self.assertLessEqual(max(requested_lengths), self.datatypes.TypeName.MAX_NAME_LENGTH)

    def test_unmapped_name_returns_empty(self):
        bv = self.make_bv()
        type_name = self.datatypes.TypeName.from_bv(
            bv, 0xDEAD0000, 0x100000, self.datatypes.GoVersion.ver120)
        self.assertEqual(type_name.name, "")

    def test_go12_encoded_name(self):
        # Go 1.12-1.15 names are encoded: bitfield, big endian uint16 length,
        # then the name bytes (same encoding as Go 1.16).
        bv = self.make_bv()
        write_name(bv, 0x100100, 'hello', self.datatypes.GoVersion.ver12)
        type_name = self.datatypes.TypeName.from_bv(
            bv, 0x100100, 0x100000, self.datatypes.GoVersion.ver12)
        self.assertEqual(type_name.name, 'hello')
        self.assertEqual(type_name.size, 5)

    def test_go12_nameoff_is_relative_to_types_base(self):
        bv = self.make_bv()
        write_type_header(bv, 0x100100, 0x02, name_off=0x40,
                          version=self.datatypes.GoVersion.ver12)
        gotype = self.datatypes.GolangType.from_bv(
            bv, 0x100100, 0x100000, self.datatypes.GoVersion.ver12)
        self.assertEqual(gotype.resolved_name_addr, 0x100040)
        # ptrdata is the second word, exactly like Go 1.16+.
        self.assertEqual(gotype.address_off('ptrdata'), 0x100108)
        self.assertEqual(gotype.address_off('nameOff'), 0x100128)

    def test_go12_layout_matches_the_common_prefix(self):
        self.assertEqual(self.datatypes.GolangType.fields_layout(8, self.datatypes.GoVersion.ver12),
                         self.datatypes.GolangType.fields_layout(8, self.datatypes.GoVersion.ver120))
        bv = self.make_bv()
        self.assertEqual(self.datatypes.GolangType.size_from_bv(
            bv, version=self.datatypes.GoVersion.ver12), 48)


class GolangTypeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.datatypes = importlib.import_module('goplugin.internal_types.datatypes')

    def test_gcdata_zero_is_valid(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x100)
        write_type_header(bv, 0x1000, 0x02, gcdata=0)  # INT
        gotype = self.datatypes.GolangType.from_bv(bv, 0x1000, 0x1000, self.datatypes.GoVersion.ver120)
        self.assertTrue(gotype.is_valid())

    def test_gcdata_unmapped_is_invalid(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x100)
        write_type_header(bv, 0x1000, 0x02, gcdata=0xDEAD0000)
        gotype = self.datatypes.GolangType.from_bv(bv, 0x1000, 0x1000, self.datatypes.GoVersion.ver120)
        self.assertFalse(gotype.is_valid())

    def test_gcdata_outside_types_section_is_valid(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x100)
        bv.add_region(0x2000, 0x100)
        write_type_header(bv, 0x1000, 0x02, gcdata=0x2000)
        gotype = self.datatypes.GolangType.from_bv(bv, 0x1000, 0x1000, self.datatypes.GoVersion.ver120)
        types_section = FakeSection('__rodata', 0x1000, 0x1100)
        self.assertTrue(gotype.is_valid(types_section))

    def test_layout_is_per_instance(self):
        bv64 = FakeBinaryView(address_size=8)
        bv64.add_region(0x1000, 0x100)
        bv32 = FakeBinaryView(address_size=4)
        bv32.add_region(0x1000, 0x100)
        write_type_header(bv64, 0x1000, 0x02, ptr_size=8)
        write_type_header(bv32, 0x1000, 0x02, ptr_size=4)

        gotype64 = self.datatypes.GolangType.from_bv(
            bv64, 0x1000, 0x1000, self.datatypes.GoVersion.ver120)
        self.assertEqual(gotype64.address_off('nameOff'), 0x1028)
        gotype32 = self.datatypes.GolangType.from_bv(
            bv32, 0x1000, 0x1000, self.datatypes.GoVersion.ver120)
        self.assertEqual(gotype32.address_off('nameOff'), 0x1018)
        # The 32 bit view must not have corrupted the 64 bit layout.
        self.assertEqual(gotype64.address_off('nameOff'), 0x1028)
        self.assertEqual(self.datatypes.GolangType.size_from_bv(bv64), 48)
        self.assertEqual(self.datatypes.GolangType.size_from_bv(bv32), 32)

    def test_descriptor_sizes(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x1000)
        datatypes = self.datatypes
        version = datatypes.GoVersion.ver120

        write_type_header(bv, 0x1000, 0x16)  # PTR
        self.assertEqual(datatypes.GolangType.descriptor_size_from_bv(bv, 0x1000, version), 56)

        write_type_header(bv, 0x1100, 0x13)  # FUNC
        bv.write(0x1100 + 48, struct.pack('<HH', 1, 2))
        # 48 header + 8 (aligned counts) + 3 pointers
        self.assertEqual(datatypes.GolangType.descriptor_size_from_bv(bv, 0x1100, version), 80)

        write_interface_info(bv, 0x1200, 0x1300, 2, name_off=0)
        # 48 header + 32 (pkgPath + slice) + 2 imethods
        self.assertEqual(datatypes.GolangType.descriptor_size_from_bv(bv, 0x1200, version), 96)

        write_type_header(bv, 0x1400, 0x19)  # STRUCT
        write_pointer(bv, 0x1400 + 64, 2)  # fields len
        # 48 header + 32 (pkgPath + slice) + 2 * 24 byte fields
        self.assertEqual(datatypes.GolangType.descriptor_size_from_bv(bv, 0x1400, version), 128)

        write_type_header(bv, 0x1500, 0x15)  # MAP (Go 1.27 layout)
        self.assertEqual(datatypes.GolangType.descriptor_size_from_bv(bv, 0x1500, version), 136)

        write_type_header(bv, 0x1600, 0x18)  # STRING
        self.assertEqual(datatypes.GolangType.descriptor_size_from_bv(bv, 0x1600, version), 48)

    def test_descriptor_size_with_uncommon_methods(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x100)
        datatypes = self.datatypes
        version = datatypes.GoVersion.ver120
        write_type_header(bv, 0x1000, 0x16, tflag=0x1)  # PTR + uncommon
        bv.write(0x1000 + 56 + 4, struct.pack('<H', 2))  # mcount
        # 56 base + 16 uncommon + 2 * 16 byte methods
        self.assertEqual(datatypes.GolangType.descriptor_size_from_bv(bv, 0x1000, version), 104)

    def test_slice_type_size_is_one_pointer(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x100)
        self.assertEqual(self.datatypes.SliceTType.size_from_bv(bv), 56)


class MapTypeLayoutTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.datatypes = importlib.import_module('goplugin.internal_types.datatypes')
        cls.binaryninja_types = importlib.import_module('goplugin.internal_types.binaryninja_types')
        cls.type_parser = importlib.import_module('goplugin.parsers.type_parser')
        cls.version = cls.datatypes.GoVersion.ver120
        cls.ptr_size = 8
        cls.header_size = 48

    def make_bv(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x200)
        return bv

    def test_old_layout_fields(self):
        bv = self.make_bv()
        write_type_header(bv, 0x1000, 0x15, size=8)  # MAP
        offset = self.header_size
        for value in (0x1100, 0x1200, 0x1300, 0x1400):
            write_pointer(bv, 0x1000 + offset, value)
            offset += self.ptr_size
        bv.write(0x1000 + offset, bytes([7, 9]))
        struct.pack_into('<H', bv._region_for(0x1000).data, offset + 2, 0x1234)
        struct.pack_into('<I', bv._region_for(0x1000).data, offset + 4, 0x55)

        map_type = self.datatypes.MapType.from_bv(bv, 0x1000, 0x1000, self.version)
        self.assertFalse(map_type.go127)
        self.assertEqual(map_type.key, 0x1100)
        self.assertEqual(map_type.elem, 0x1200)
        self.assertEqual(map_type.bucket, 0x1300)
        self.assertEqual(map_type.hasher, 0x1400)
        self.assertEqual(map_type.keysize, 7)
        self.assertEqual(map_type.valuesize, 9)
        self.assertEqual(map_type.bucketsize, 0x1234)
        self.assertEqual(map_type.flags, 0x55)
        self.assertEqual(self.datatypes.MapType.size_from_bv(bv, version=self.version), 88)

    def test_go127_layout_fields(self):
        bv = self.make_bv()
        write_type_header(bv, 0x1000, 0x15, size=8)  # MAP
        values = (0x1100, 0x1200, 0x1300, 0x1400, 16, 0x20, 0x40, 0x60, 0x80, 0xa0)
        for index, value in enumerate(values):
            write_pointer(bv, 0x1000 + self.header_size + index * self.ptr_size, value)
        struct.pack_into('<I', bv._region_for(0x1000).data, self.header_size + 80, 0x55)

        map_type = self.datatypes.MapType.from_bv(
            bv, 0x1000, 0x1000, self.version, go127=True)
        self.assertTrue(map_type.go127)
        self.assertEqual(map_type.key, 0x1100)
        self.assertEqual(map_type.elem, 0x1200)
        self.assertEqual(map_type.group, 0x1300)
        self.assertEqual(map_type.hasher, 0x1400)
        self.assertEqual(map_type.group_size, 16)
        self.assertEqual(map_type.keys_off, 0x20)
        self.assertEqual(map_type.key_stride, 0x40)
        self.assertEqual(map_type.elems_off, 0x60)
        self.assertEqual(map_type.elem_stride, 0x80)
        self.assertEqual(map_type.elem_off, 0xa0)
        self.assertEqual(map_type.flags, 0x55)
        # 48 header + 10 pointers + uint32 flags, padded to pointer alignment.
        self.assertEqual(self.datatypes.MapType.size_from_bv(
            bv, version=self.version, go127=True), 136)
        # Keep descriptor_size_from_bv consistent with the size helper.
        self.assertEqual(
            self.datatypes.GolangType.descriptor_size_from_bv(bv, 0x1000, self.version), 136)

    def test_go127_uncommon_follows_ptr_aligned_flags(self):
        bv = self.make_bv()
        write_type_header(bv, 0x1000, 0x15, tflag=0x1)  # MAP + uncommon
        pointer = bv._region_for(0x1000)
        uncommon_offset = self.header_size + 10 * self.ptr_size + 4  # 132
        uncommon_offset = (uncommon_offset + self.ptr_size - 1) // self.ptr_size * self.ptr_size
        struct.pack_into('<H', pointer.data, uncommon_offset + 4, 1)  # mcount
        struct.pack_into('<I', pointer.data, uncommon_offset + 8, 0x20)  # moff

        map_type = self.datatypes.MapType.from_bv(
            bv, 0x1000, 0x1000, self.version, go127=True)
        self.assertTrue(map_type.has_uncommon)
        self.assertIsNotNone(map_type.uncommon_type)
        self.assertEqual(map_type.uncommon_type.mcount, 1)
        self.assertEqual(map_type.uncommon_type.resolved_m_offset, 0x1000 + uncommon_offset + 0x20)

    def test_builder_selects_layout_from_gtype(self):
        bv = FakeBinaryView()
        old_gtype = types.SimpleNamespace(version=self.version, has_uncommon=False, go127=False)
        old_fields = dict(self.binaryninja_types.MapTypeTBuilder().build_type_from_gtype(bv, old_gtype)[0].fields)
        self.assertIn('bucket', old_fields)
        self.assertIn('keysize', old_fields)
        self.assertNotIn('group', old_fields)

        go127_gtype = types.SimpleNamespace(version=self.version, has_uncommon=False, go127=True)
        new_fields = dict(self.binaryninja_types.MapTypeTBuilder().build_type_from_gtype(bv, go127_gtype)[0].fields)
        self.assertIn('group', new_fields)
        self.assertIn('group_size', new_fields)
        self.assertIn('elem_off', new_fields)
        self.assertNotIn('bucket', new_fields)
        self.assertEqual(new_fields['group'].kind, 'pointer')
        self.assertEqual(new_fields['group_size'].kind, 'integer')
        self.assertEqual(new_fields['group_size'].width, 8)

    def test_create_types_follows_go127_group(self):
        section = FakeSection('__go_type', 0x1000, 0x1800)
        bv = FakeBinaryView(sections=[section])
        bv.add_region(0x1000, 0x800)
        write_type_header(bv, 0x1000, 0x15, name_off=0x500)  # MAP
        values = (0x1100, 0x1200, 0x1300, 0x1400, 16, 0x20, 0x40, 0x60, 0x80, 0xa0)
        for index, value in enumerate(values):
            write_pointer(bv, 0x1000 + self.header_size + index * self.ptr_size, value)
        write_type_header(bv, 0x1300, 0x19, name_off=0x510)  # STRUCT group descriptor
        write_name(bv, 0x1500, 'map[int]string')
        write_name(bv, 0x1510, 'group')
        parser = make_type_parser(self.type_parser, bv, target=0x1000,
                                  types_base=0x1000, types_section=section,
                                  quick_go_version=lambda: self.version,
                                  use_go127_map_layout=lambda: True)
        parser.create_types()
        self.assertIn(0x1300, bv._data_vars)


class TypesBaseDiscoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.type_parser = importlib.import_module('goplugin.parsers.type_parser')
        cls.datatypes = importlib.import_module('goplugin.internal_types.datatypes')

    def test_runtime_types_symbol_wins(self):
        text_rodata = FakeSection('__rodata', 0x1000, 0x2000, parent=FakeSegment('__TEXT'))
        data_rodata = FakeSection('__rodata', 0x5000, 0x6000, parent=FakeSegment('__DATA_CONST'))
        bv = FakeBinaryView(sections=[text_rodata, data_rodata])
        bv.add_region(0x1000, 0x1000)
        parser = make_type_parser(self.type_parser, bv)
        bv._symbols.append(FakeSymbol(FakeSymbolType.DataSymbol, 0x1800, 'runtime.types'))
        self.assertEqual(parser.find_types_base(), 0x1800)
        self.assertIs(parser.types_section, text_rodata)

    def test_duplicate_rodata_prefers_non_executable(self):
        text_rodata = FakeSection('__rodata', 0x1000, 0x2000, parent=FakeSegment('__TEXT'))
        data_rodata = FakeSection('__rodata', 0x5000, 0x6000, parent=FakeSegment('__DATA_CONST'))
        bv = FakeBinaryView(sections=[text_rodata, data_rodata])
        bv.add_region(0x1000, 0x1000)
        bv.add_region(0x5000, 0x1000)
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x5000)
        self.assertIs(parser.types_section, data_rodata)

    def test_duplicate_rodata_suffix_uses_segment_api(self):
        text_rodata = FakeSection('__rodata', 0x1000, 0x2000)
        data_rodata = FakeSection('__rodata#4', 0x5000, 0x6000)
        bv = FakeBinaryView(sections=[text_rodata, data_rodata])
        bv.add_region(0x1000, 0x1000)
        bv.add_region(0x5000, 0x1000)
        bv.get_segment_at = lambda address: types.SimpleNamespace(executable=address < 0x3000)
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x5000)
        self.assertIs(parser.types_section, data_rodata)

    def test_go_type_section(self):
        section = FakeSection('__go_type', 0x4000, 0x5000, parent=FakeSegment('__DATA_CONST'))
        bv = FakeBinaryView(sections=[section])
        bv.add_region(0x4000, 0x1000)
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x4000)
        self.assertIs(parser.types_section, section)

    def test_legacy_rodata_fallback(self):
        section = FakeSection('.rodata', 0x3000, 0x4000, parent=FakeSegment('.text'))
        bv = FakeBinaryView(sections=[section])
        bv.add_region(0x3000, 0x1000)
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x3000)

    def test_sections_as_binary_ninja_dict(self):
        # Binary Ninja exposes bv.sections as a name -> Section mapping.
        section = FakeSection('.rodata', 0x3000, 0x4000, parent=FakeSegment('.text'))
        bv = FakeBinaryView(sections={'.rodata': section})
        bv.add_region(0x3000, 0x1000)
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x3000)
        self.assertIs(parser.types_section, section)

    def test_typelink_aware_candidate(self):
        wrong = FakeSection('__rodata', 0x10000, 0x11000, parent=FakeSegment('__DATA_CONST'))
        right = FakeSection('__rodata', 0x20000, 0x22000, parent=FakeSegment('__DATA_CONST'))
        typelink = FakeSection('__typelink', 0x40000, 0x40008)
        bv = FakeBinaryView(sections=[wrong, right, typelink])
        bv.add_region(0x20000, 0x2000)
        bv.add_region(0x40000, 0x8)
        write_type_header(bv, 0x20000 + 0x100, 0x02)
        write_type_header(bv, 0x20000 + 0x200, 0x18)
        bv.write(0x40000, struct.pack('<ii', 0x100, 0x200))
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x20000)

    def test_relro_data_section_is_a_type_candidate(self):
        relro = FakeSection('.data.rel.ro', 0x6000, 0x7000, parent=FakeSegment('__DATA_CONST'))
        bv = FakeBinaryView(sections=[relro])
        bv.add_region(0x6000, 0x1000)
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x6000)
        self.assertIs(parser.types_section, relro)

    def test_relro_is_preferred_over_executable_rodata(self):
        text_rodata = FakeSection('.rodata', 0x1000, 0x2000, parent=FakeSegment('.text'))
        relro = FakeSection('.data.rel.ro', 0x6000, 0x7000, parent=FakeSegment('__DATA_CONST'))
        bv = FakeBinaryView(sections=[text_rodata, relro])
        bv.add_region(0x1000, 0x1000)
        bv.add_region(0x6000, 0x1000)
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x6000)

    def test_relro_typelink_section_is_recognized(self):
        wrong = FakeSection('.rodata', 0x10000, 0x11000, parent=FakeSegment('__DATA_CONST'))
        right = FakeSection('.data.rel.ro', 0x20000, 0x22000, parent=FakeSegment('__DATA_CONST'))
        typelink = FakeSection('.data.rel.ro.typelink', 0x40000, 0x40008)
        bv = FakeBinaryView(sections=[wrong, right, typelink])
        bv.add_region(0x20000, 0x2000)
        bv.add_region(0x40000, 0x8)
        write_type_header(bv, 0x20000 + 0x100, 0x02)
        write_type_header(bv, 0x20000 + 0x200, 0x18)
        bv.write(0x40000, struct.pack('<ii', 0x100, 0x200))
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x20000)
        self.assertEqual(parser.types_section, right)

    def test_relro_go_type_section_is_recognized(self):
        section = FakeSection('.data.rel.ro.go.type', 0x6000, 0x7000,
                              parent=FakeSegment('__DATA_CONST'))
        bv = FakeBinaryView(sections=[section])
        bv.add_region(0x6000, 0x1000)
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser.find_types_base(), 0x6000)
        self.assertIs(parser.types_section, section)
        self.assertTrue(parser.use_go127_map_layout())

    def test_go127_map_layout_requires_go_metadata(self):
        section = FakeSection('.rodata', 0x6000, 0x7000)
        bv = FakeBinaryView(sections=[section])
        bv.add_region(0x6000, 0x1000)
        parser = make_type_parser(self.type_parser, bv)
        self.assertFalse(parser.use_go127_map_layout())

    def test_go12_kind_byte_offset_follows_ptrdata(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x100)
        parser = make_type_parser(self.type_parser, bv)
        self.assertEqual(parser._kind_byte_offset(self.datatypes.GoVersion.ver12), 2 * 8 + 7)
        self.assertEqual(parser._kind_byte_offset(self.datatypes.GoVersion.ver120), 2 * 8 + 7)
        # ptrdata occupies the second word in the Go 1.12 layout too.
        write_type_header(bv, 0x1000, 0x19, version=self.datatypes.GoVersion.ver12)
        self.assertIs(parser._type_kind_at(0x1000, self.datatypes.GoVersion.ver12),
                      self.datatypes.GolangTypeKind.STRUCT)

    def test_missing_types_base_is_cached(self):
        bv = FakeBinaryView()
        parser = make_type_parser(self.type_parser, bv)
        self.assertIsNone(parser.find_types_base())

        def fail():
            raise AssertionError("the sections were scanned again")

        parser.all_sections = fail
        self.assertIsNone(parser.find_types_base())

    def test_create_types_skips_non_go_input(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x100)
        parser = make_type_parser(self.type_parser, bv)
        parser.quick_go_version = lambda: self.datatypes.GoVersion.invalid
        self.assertEqual(parser.create_types(), set())
        # No Go base type was defined for a non-Go input.
        self.assertEqual(bv._types, {})


class TypelinkCollectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.type_parser = importlib.import_module('goplugin.parsers.type_parser')
        cls.datatypes = importlib.import_module('goplugin.internal_types.datatypes')

    def setUp(self):
        FakeSettings.overrides = {}

    def tearDown(self):
        FakeSettings.overrides = {}

    def test_collects_valid_offsets_and_skips_malformed(self):
        bv = FakeBinaryView()
        bv.add_region(0x100000, 0x1000)
        bv.add_region(0x200000, 0x10)
        write_type_header(bv, 0x100000 + 0x100, 0x02)
        write_type_header(bv, 0x100000 + 0x200, 0x18)
        typelink = FakeSection('__typelink', 0x200000, 0x200010)
        bv.sections = [typelink]
        bv.write(0x200000, struct.pack('<iiii', 0x100, 0x9000, 0, 0x200))
        parser = make_type_parser(self.type_parser, bv,
                                  types_base=0x100000,
                                  types_section=FakeSection('__rodata', 0x100000, 0x101000))
        result = parser.collect_types_from_typelinks(
            0x100000, self.datatypes.GoVersion.ver120)
        self.assertEqual(result, {(0x100100, 0), (0x100200, 0)})

    def test_use_typelinks_setting_disables_enumeration(self):
        bv = FakeBinaryView()
        bv.add_region(0x100000, 0x1000)
        bv.add_region(0x200000, 0x4)
        write_type_header(bv, 0x100000 + 0x100, 0x02)
        bv.sections = [FakeSection('__typelink', 0x200000, 0x200004)]
        bv.write(0x200000, struct.pack('<i', 0x100))
        parser = make_type_parser(self.type_parser, bv, types_base=0x100000)
        FakeSettings.overrides['golang_binary_parser.use_typelinks'] = False
        self.assertEqual(parser.collect_types_from_typelinks(
            0x100000, self.datatypes.GoVersion.ver120), set())

    def test_use_typelinks_without_settings_contains(self):
        bv = FakeBinaryView()
        parser = make_type_parser(self.type_parser, bv)
        binaryninja = sys.modules['binaryninja']
        original = binaryninja.Settings

        class LegacySettings:
            def get_bool(self, key):
                return False

        binaryninja.Settings = LegacySettings
        try:
            self.assertFalse(parser.use_typelinks())
        finally:
            binaryninja.Settings = original

    def test_typelink_offsets_are_bounded(self):
        bv = FakeBinaryView()
        bv.add_region(0x200000, 0x100)
        bv.write(0x200000, struct.pack('<10i', *range(10)))
        parser = make_type_parser(self.type_parser, bv)
        parser.MAX_TYPELINK_ENTRIES = 3
        section = FakeSection('__typelink', 0x200000, 0x200000 + 40)

        requested_lengths = []
        original_read = bv.read

        def guarded_read(address, length):
            requested_lengths.append(length)
            return original_read(address, length)

        bv.read = guarded_read
        self.assertEqual(parser.read_typelink_offsets(section), [0, 1, 2])
        self.assertLessEqual(max(requested_lengths), 3 * 4)

    def test_typelink_offsets_normal_table_is_not_truncated(self):
        entries = 1956  # the size of the real zybo typelink table
        bv = FakeBinaryView()
        bv.add_region(0x200000, entries * 4)
        bv.write(0x200000, struct.pack(f'<{entries}i', *[index % 100 for index in range(entries)]))
        parser = make_type_parser(self.type_parser, bv)
        section = FakeSection('__typelink', 0x200000, 0x200000 + entries * 4)
        self.assertEqual(len(parser.read_typelink_offsets(section)), entries)


class DescriptorWalkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.type_parser = importlib.import_module('goplugin.parsers.type_parser')
        cls.datatypes = importlib.import_module('goplugin.internal_types.datatypes')
        cls.version = cls.datatypes.GoVersion.ver120

    def build_fixture(self, add_moduledata=True, with_invalid=False, module_name='__go_module'):
        types_base = 0x200000
        types_end = 0x201000
        bv = FakeBinaryView()
        bv.add_region(types_base, types_end - types_base)
        bv.add_region(0x400000, 0x100)  # pclntab header
        bv.add_region(0x300000, 0x1000)  # module metadata
        bv.write(0x400000, b'\xf1\xff\xff\xff\x00\x00\x04\x08')

        addresses = []
        address = types_base + 8
        # PTR (56)
        write_type_header(bv, address, 0x16)
        addresses.append(address)
        address += 56
        # FUNC with one input and one output (56 + 16)
        write_type_header(bv, address, 0x13)
        bv.write(address + 48, struct.pack('<HH', 1, 1))
        addresses.append(address)
        address += 72
        # INTERFACE with two methods (80 + 16)
        write_interface_info(bv, address, address + 0x800, 2, name_off=0)
        addresses.append(address)
        address += 96
        # STRUCT with one field (80 + 24)
        write_type_header(bv, address, 0x19)
        write_pointer(bv, address + 64, 1)
        addresses.append(address)
        address += 104
        # MAP (136)
        write_type_header(bv, address, 0x15)
        addresses.append(address)
        address += 136
        # STRING (48)
        write_type_header(bv, address, 0x18)
        addresses.append(address)
        address += 48
        typedesclen = address - types_base

        invalid_address = None
        if with_invalid:
            invalid_address = address
            write_type_header(bv, address, 0x00)
            address += 48

        section = FakeSection('__go_type', types_base, types_end,
                              parent=FakeSegment('__DATA_CONST'))
        module_section = FakeSection(module_name, 0x300000, 0x300238,
                                     parent=FakeSegment('__DATA'))
        bv.sections = [section, module_section]
        if add_moduledata:
            write_moduledata_v127(bv, 0x300080, 0x400000, types_base, typedesclen,
                                  types_end, 0, 0)
        parser = make_type_parser(self.type_parser, bv,
                                  gopclntab=types.SimpleNamespace(start=0x400000))
        return parser, bv, addresses, types_base, typedesclen, invalid_address

    def test_walk_with_moduledata(self):
        parser, bv, addresses, base, typedesclen, _ = self.build_fixture()
        moduledata = parser.find_moduledata()
        self.assertIsNotNone(moduledata)
        self.assertEqual(moduledata['typedesclen'], typedesclen)
        result = parser.collect_types_from_descriptor_walk(
            version=self.version)
        self.assertEqual(result, {(address, 0) for address in addresses})

    def test_walk_with_dotted_elf_module_section(self):
        # ELF names the moduledata carrier .go.module, Mach-O __go_module.
        parser, bv, addresses, base, typedesclen, _ = self.build_fixture(module_name='.go.module')
        moduledata = parser.find_moduledata()
        self.assertIsNotNone(moduledata)
        self.assertEqual(moduledata['address'], 0x300080)

    def test_walk_with_relro_go_module_section(self):
        parser, bv, addresses, base, typedesclen, _ = self.build_fixture(
            module_name='.data.rel.ro.go.module')
        moduledata = parser.find_moduledata()
        self.assertIsNotNone(moduledata)
        self.assertEqual(moduledata['address'], 0x300080)

    def test_walk_stops_at_invalid_descriptor(self):
        parser, bv, addresses, base, typedesclen, invalid = self.build_fixture(with_invalid=True)
        result = parser.collect_types_from_descriptor_walk(version=self.version)
        self.assertEqual(result, {(address, 0) for address in addresses})
        self.assertNotIn((invalid, 0), result)

    def test_walk_without_moduledata_uses_section_bounds(self):
        parser, bv, addresses, base, typedesclen, _ = self.build_fixture(add_moduledata=False)
        self.assertIsNone(parser.find_moduledata())
        result = parser.collect_types_from_descriptor_walk(version=self.version)
        self.assertTrue({(address, 0) for address in addresses}.issubset(result))

    def test_walk_with_moduledata_without_go_type_section(self):
        # PE keeps everything in .rdata; a validated moduledata still bounds
        # the Go 1.27 descriptor region.
        types_base = 0x200000
        types_end = 0x202000
        bv = FakeBinaryView()
        bv.add_region(types_base, types_end - types_base)
        bv.add_region(0x300000, 0x400)
        bv.add_region(0x400000, 0x100)
        bv.write(0x400000, b'\xf1\xff\xff\xff\x00\x00\x04\x08')
        write_type_header(bv, types_base + 8, 0x16)
        write_type_header(bv, types_base + 64, 0x18)
        bv.sections = [FakeSection('.rdata', types_base, types_end)]
        bv._symbols.append(FakeSymbol(FakeSymbolType.DataSymbol, types_base, 'runtime.types'))
        bv._symbols.append(FakeSymbol(FakeSymbolType.DataSymbol, 0x300000, 'runtime.firstmoduledata'))
        write_moduledata_v127(bv, 0x300000, 0x400000, types_base, 0x78, types_end)
        parser = make_type_parser(self.type_parser, bv,
                                  gopclntab=types.SimpleNamespace(start=0x400000))
        self.assertEqual(parser.find_types_base(), types_base)
        result = parser.collect_types_from_descriptor_walk(version=self.version)
        self.assertEqual(result, {(types_base + 8, 0), (types_base + 64, 0)})

    def test_old_moduledata_layout_is_rejected(self):
        types_base = 0x200000
        types_end = 0x201000
        bv = FakeBinaryView()
        bv.add_region(types_base, types_end - types_base)
        bv.add_region(0x400000, 0x100)
        bv.write(0x400000, b'\xf1\xff\xff\xff\x00\x00\x04\x08')
        write_type_header(bv, types_base + 8, 0x16)
        section = FakeSection('__go_type', types_base, types_end)
        bv.sections = [section]
        bv._symbols.append(FakeSymbol(FakeSymbolType.DataSymbol, 0x500000, 'runtime.firstmoduledata'))
        bv.add_region(0x500000, 0x400)
        # Old (<=Go 1.26) layout read with the Go 1.27 offsets: slot 38 holds
        # etypes (a large address), which must fail the region validation.
        write_moduledata_v127(bv, 0x500000, 0x400000, types_base, types_end,
                              types_end, 0, 0)
        parser = make_type_parser(self.type_parser, bv,
                                  gopclntab=types.SimpleNamespace(start=0x400000))
        self.assertIsNone(parser.find_moduledata())


class CollectXrefsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.type_parser = importlib.import_module('goplugin.parsers.type_parser')
        cls.ops = FakeMLILOperation

    def setUp(self):
        FakeSettings.overrides = {}

    def tearDown(self):
        FakeSettings.overrides = {}

    def make_expression(self, operation, constant=None):
        attributes = {'operation': operation}
        if constant is not None:
            attributes['constant'] = constant
        return types.SimpleNamespace(**attributes)

    def make_il(self, operation, params):
        return types.SimpleNamespace(operation=operation, params=params)

    def test_mlil_constants_tailcalls_and_hlil_fallback(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x1000)
        types_section = FakeSection('__rodata', 0x1000, 0x2000)
        bv.sections = [types_section]

        non_constant = self.make_expression(0x99)
        call_site = types.SimpleNamespace(
            address=0x500,
            mlil=self.make_il(self.ops.MLIL_CALL, [
                self.make_expression(self.ops.MLIL_CONST, 0x1100),
                non_constant,
                self.make_expression(self.ops.MLIL_CONST, 0x9000),
            ]),
            hlil=None,
        )
        tail_call_site = types.SimpleNamespace(
            address=0x600,
            mlil=self.make_il(self.ops.MLIL_TAILCALL, [
                self.make_expression(self.ops.MLIL_CONST_PTR, 0x1200),
            ]),
            hlil=None,
        )
        non_call_site = types.SimpleNamespace(
            address=0x700,
            mlil=self.make_il(self.ops.MLIL_CONST, []),
            hlil=None,
        )
        hlil_site = types.SimpleNamespace(
            address=0x800,
            mlil=None,
            hlil=self.make_il(FakeHLILOperation.HLIL_CALL, [
                self.make_expression(FakeHLILOperation.HLIL_CONST, 0x1300),
            ]),
        )
        function = types.SimpleNamespace(
            name='runtime.newobject',
            parameter_vars=[object()],
            caller_sites=[call_site, tail_call_site, non_call_site, hlil_site],
        )
        bv._functions = [function]

        parser = make_type_parser(self.type_parser, bv,
                                  types_base=0x1000,
                                  types_section=types_section)
        result = parser.collect_xrefs()
        self.assertEqual(result, {(0x1100, 0), (0x1200, 0), (0x1300, 0)})

    def test_iter_type_call_sites_exposes_name_address_and_il(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x1000)
        types_section = FakeSection('__rodata', 0x1000, 0x2000)
        bv.sections = [types_section]

        mlil_site = types.SimpleNamespace(
            address=0x500,
            mlil=self.make_il(self.ops.MLIL_CALL, [
                self.make_expression(self.ops.MLIL_CONST_PTR, 0x1100),
            ]),
            hlil=None,
        )
        hlil_site = types.SimpleNamespace(
            address=0x600,
            mlil=None,
            hlil=self.make_il(FakeHLILOperation.HLIL_CALL, [
                self.make_expression(FakeHLILOperation.HLIL_CONST_PTR, 0x1200),
            ]),
        )
        function = types.SimpleNamespace(
            name='runtime.newobject',
            parameter_vars=[object()],
            caller_sites=[mlil_site, hlil_site],
        )
        bv._functions = [function]

        parser = make_type_parser(self.type_parser, bv,
                                  types_base=0x1000,
                                  types_section=types_section)
        records = list(parser.iter_type_call_sites())
        self.assertEqual(
            [(record['function_name'], record['caller_site'].address,
              record['type_address']) for record in records],
            [('runtime.newobject', 0x500, 0x1100),
             ('runtime.newobject', 0x600, 0x1200)])
        self.assertIs(records[0]['il_instruction'], mlil_site.mlil)
        self.assertIs(records[1]['il_instruction'], hlil_site.hlil)
        self.assertEqual(parser.collect_xrefs(), {(0x1100, 0), (0x1200, 0)})

    def test_iter_type_call_sites_exposes_sanitized_name(self):
        FakeSettings.overrides['golang_binary_parser.sanitize'] = True
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x1000)
        types_section = FakeSection('__rodata', 0x1000, 0x2000)
        bv.sections = [types_section]

        caller_site = types.SimpleNamespace(
            address=0x700,
            mlil=self.make_il(self.ops.MLIL_CALL, [
                self.make_expression(self.ops.MLIL_CONST, 0x1300),
            ]),
            hlil=None,
        )
        bv._functions = [types.SimpleNamespace(
            name='runtime_newobject',
            parameter_vars=[object()],
            caller_sites=[caller_site],
        )]

        parser = make_type_parser(self.type_parser, bv,
                                  types_base=0x1000,
                                  types_section=types_section)
        records = list(parser.iter_type_call_sites())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['function_name'], 'runtime_newobject')
        self.assertEqual(records[0]['caller_site'].address, 0x700)
        self.assertEqual(parser.collect_xrefs(), {(0x1300, 0)})


class FailGracefullyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.structure_recovery = importlib.import_module('goplugin.parsers.structure_recovery')

    def test_integer_target(self):
        @self.structure_recovery.fail_gracefully
        def boom(helper, target):
            raise ValueError("original failure")

        result = boom(None, 0x401000)
        self.assertEqual(result.kind, 'void')

    def test_none_target(self):
        @self.structure_recovery.fail_gracefully
        def boom(helper, target):
            raise ValueError("original failure")

        result = boom(None, None)
        self.assertEqual(result.kind, 'void')

    def test_target_with_broken_address(self):
        class BrokenTarget:
            @property
            def address(self):
                raise RuntimeError("no address")

        @self.structure_recovery.fail_gracefully
        def boom(helper, target):
            raise ValueError("original failure")

        result = boom(None, BrokenTarget())
        self.assertEqual(result.kind, 'void')

    def test_define_struct_with_none_datavar(self):
        instance = self.structure_recovery.StructRecovery.__new__(
            self.structure_recovery.StructRecovery)
        result = instance.define_struct(None)
        self.assertEqual(result.kind, 'void')


class StructureRecoveryDefinitionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.structure_recovery = importlib.import_module('goplugin.parsers.structure_recovery')
        cls.datatypes = importlib.import_module('goplugin.internal_types.datatypes')
        cls.version = cls.datatypes.GoVersion.ver120

    def make_struct_recovery(self, bv, types_base=0x1000):
        parser = self.structure_recovery.StructRecovery.__new__(
            self.structure_recovery.StructRecovery)
        parser.bv = bv
        parser.target = None
        parser.rodata_section = None
        parser.types_base = types_base
        parser.types_section = None
        parser.moduledata = None
        parser.gopclntab = None
        parser.rodata_addr = types_base
        parser.go_version = self.version
        return parser

    def test_define_func_multiple_returns_uses_result_struct(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x200)
        write_type_header(bv, 0x1000, 0x13)  # FUNC
        bv.write(0x1000 + 48, struct.pack('<HH', 0, 2))  # no inputs, two outputs
        write_pointer(bv, 0x1000 + 56, 0x1100)
        write_pointer(bv, 0x1000 + 64, 0x1200)

        parser = self.make_struct_recovery(bv)
        parser.native_type_mapping = lambda address: FakeBinaryNinjaType(
            'integer' if address == 0x1100 else 'char')

        data_var = FakeDataVar(0x1000)
        result = parser.define_func(data_var)

        self.assertEqual(result.kind, 'pointer')
        self.assertEqual(result.target.kind, 'function')
        result_struct = bv.get_type_by_name('golang_func_result_1000_t')
        self.assertIsNotNone(result_struct)
        self.assertEqual([name for name, _ in result_struct.fields], ['ret0', 'ret1'])
        self.assertIs(result.target.ret, result_struct)

    def test_define_func_single_return(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x200)
        write_type_header(bv, 0x1000, 0x13)
        bv.write(0x1000 + 48, struct.pack('<HH', 0, 1))
        write_pointer(bv, 0x1000 + 56, 0x1100)

        parser = self.make_struct_recovery(bv)
        single = FakeBinaryNinjaType('integer')
        parser.native_type_mapping = lambda address: single

        result = parser.define_func(FakeDataVar(0x1000))
        self.assertIs(result.target.ret, single)

    def test_define_struct_rejects_huge_size(self):
        parser = self.make_struct_recovery(FakeBinaryView())
        data_var = FakeTypedDataVar(0x1000, size=1 << 40, fields={'Len': 1})
        self.assertEqual(parser.define_struct(data_var).kind, 'void')

    def test_define_struct_rejects_huge_field_count(self):
        parser = self.make_struct_recovery(FakeBinaryView())
        data_var = FakeTypedDataVar(0x1000, size=16, fields={'Len': 1 << 40})
        self.assertEqual(parser.define_struct(data_var).kind, 'void')

    def test_define_interface_rejects_huge_size(self):
        parser = self.make_struct_recovery(FakeBinaryView())
        data_var = FakeTypedDataVar(0x1000, size=1 << 40)
        self.assertEqual(parser.define_interface(data_var).kind, 'void')

    def test_define_array_rejects_huge_length(self):
        parser = self.make_struct_recovery(FakeBinaryView())
        data_var = FakeTypedDataVar(0x1000, elem=0, len=1 << 40)
        self.assertEqual(parser.define_array(data_var).kind, 'void')


class BinaryNinjaTypesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.binaryninja_types = importlib.import_module('goplugin.internal_types.binaryninja_types')
        cls.datatypes = importlib.import_module('goplugin.internal_types.datatypes')
        cls.version = cls.datatypes.GoVersion.ver120

    def make_bv(self, address_size=8):
        return FakeBinaryView(address_size=address_size)

    def field_names(self, builder):
        return [name for name, _ in builder.fields]

    def find_builder(self, name):
        for builder in self.binaryninja_types.GOLAND_TYPES:
            if builder.name == name:
                return builder
        self.fail(f"Missing type builder {name}")

    def test_struct_builder_returns_extended_copy(self):
        builder = self.binaryninja_types.GolangStructTypeBuilder().build_type(self.make_bv(), self.version)
        names = self.field_names(builder)
        self.assertIn('pkgPath', names)
        self.assertIn('fields', names)

    def test_builders_build_in_registration_order_with_defined_dependencies(self):
        # create_types builds GOLAND_TYPES in registration order; in real
        # Binary Ninja a builder referencing a not-yet-defined type fails with
        # ValueError. Reuse one view as the registered type registry.
        bv = self.make_bv()
        original_type = self.binaryninja_types.Type
        self.binaryninja_types.Type = StrictTypeFactory
        try:
            for builder in self.binaryninja_types.GOLAND_TYPES:
                with self.subTest(builder=builder.name):
                    built = builder().build_type(bv, self.version)
                    self.assertIsNotNone(built)
                    bv.define_user_type(builder.name, built)
        finally:
            self.binaryninja_types.Type = original_type

    def test_interface_builder_returns_extended_copy(self):
        builder = self.binaryninja_types.InterfaceTypeTBuilder().build_type(self.make_bv(), self.version)
        fields = dict(builder.fields)
        self.assertIn('pkgPath', fields)
        self.assertIn('methods', fields)
        self.assertEqual(fields['pkgPath'].width, 8)

    def test_slice_data_is_a_void_pointer(self):
        builder = self.binaryninja_types.SliceTBuilder().build_type(self.make_bv(), self.version)
        fields = dict(builder.fields)
        data = fields['Data']
        self.assertEqual(data.kind, 'pointer')
        self.assertEqual(data.target.kind, 'void')

    def test_uintptr_is_an_integer(self):
        builder_class = self.find_builder('golang_uintptr_t')
        built = builder_class().build_type(self.make_bv(), self.version)
        self.assertEqual(built.kind, 'integer')
        self.assertFalse(built.sign)
        self.assertFalse(any(builder.name == 'golang_uintprt_t'
                             for builder in self.binaryninja_types.GOLAND_TYPES))

    def test_uint_and_byte_are_unsigned(self):
        for name in ('golang_uint_t', 'golang_byte_t'):
            with self.subTest(name=name):
                built = self.find_builder(name)().build_type(self.make_bv(), self.version)
                self.assertEqual(built.kind, 'integer')
                self.assertFalse(built.sign)

    def test_complex_types_are_two_floats(self):
        for name, width in (('golang_complex64_t', 4), ('golang_complex128_t', 8)):
            with self.subTest(name=name):
                built = self.find_builder(name)().build_type(self.make_bv(), self.version)
                fields = dict(built.fields)
                self.assertEqual(fields['real'].kind, 'float')
                self.assertEqual(fields['real'].width, width)
                self.assertEqual(fields['imag'].width, width)

    def test_func_builder_uses_out_count_in_the_name(self):
        gtype = types.SimpleNamespace(version=self.version, has_uncommon=False,
                                      in_count=1, out_count=2)
        built, name = self.binaryninja_types.FuncTypeTBuilder().build_type_from_gtype(
            self.make_bv(), gtype)
        self.assertTrue(name.endswith('i[1]o[2]_t'), name)
        fields = dict(built.fields)
        self.assertEqual(fields['in_params'].count, 1)
        self.assertEqual(fields['out_params'].count, 2)

    def test_ptr_builder_name_has_suffix(self):
        gtype = types.SimpleNamespace(version=self.version, has_uncommon=False)
        _, name = self.binaryninja_types.PtrTypeTBuilder().build_type_from_gtype(
            self.make_bv(), gtype)
        self.assertEqual(name, 'golang_ptr_type_t')

    def test_go12_type_builder_matches_the_common_prefix(self):
        builder_class = self.binaryninja_types.GolangTypeBuilder
        go12_names = self.field_names(
            builder_class().build_type(self.make_bv(), self.datatypes.GoVersion.ver12))
        common_names = self.field_names(builder_class().build_type(self.make_bv(), self.version))
        self.assertEqual(go12_names, common_names)
        self.assertEqual(go12_names.count('ptrdata'), 1)
        self.assertNotIn('ptr_type_ptr', go12_names)


if __name__ == '__main__':
    unittest.main()
