"""Headless tests for Go interface (itab) recovery."""
import importlib
import struct
import types
import unittest

from tests.test_types import (
    FakeBinaryView,
    FakeSection,
    FakeSegment,
    FakeSettings,
    FakeSymbol,
    FakeSymbolType,
    load_plugin,
    write_imethod,
    write_interface_info,
    write_moduledata_v127,
    write_name,
    write_pointer,
    write_type_header,
)


def write_itab(bv, address, interface_address, concrete_address, functions, ptr_size=8):
    size = 4 * ptr_size + max(len(functions) - 1, 0) * ptr_size
    data = bytearray(size)
    data[0:ptr_size] = interface_address.to_bytes(ptr_size, 'little')
    data[ptr_size:2 * ptr_size] = concrete_address.to_bytes(ptr_size, 'little')
    for index, function_address in enumerate(functions):
        offset = 3 * ptr_size + index * ptr_size
        data[offset:offset + ptr_size] = function_address.to_bytes(ptr_size, 'little')
    bv.write(address, bytes(data))


def write_func_type(bv, address, in_count=0, out_count=0, variadic=False):
    """Write a Go FUNC descriptor; parameter descriptors are not needed here."""
    write_type_header(bv, address, 0x13)  # FUNC
    bv.write(address + 48, struct.pack('<HH', in_count,
                                       out_count | (0x8000 if variadic else 0)))
    offset = address + 56  # the counts are padded to pointer alignment
    for _ in range(in_count + out_count):
        write_pointer(bv, offset, 0)
        offset += 8


class FakeFunction:
    def __init__(self, address, has_user_type=False):
        self.address = address
        self.has_user_type = has_user_type
        self.user_type = None
        self.set_user_type_calls = 0

    def set_user_type(self, type_):
        self.set_user_type_calls += 1
        self.user_type = type_


def install_functions(bv, functions):
    bv._functions = list(functions)
    bv.get_function_at = lambda address: next(
        (function for function in bv._functions if function.address == address), None)


class InterfaceRecoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.interface_recovery = importlib.import_module('goplugin.parsers.interface_recovery')
        cls.datatypes = importlib.import_module('goplugin.internal_types.datatypes')
        cls.version = cls.datatypes.GoVersion.ver120

    def setUp(self):
        FakeSettings.overrides = {}

    def tearDown(self):
        FakeSettings.overrides = {}

    def make_parser(self, bv, **attributes):
        parser = self.interface_recovery.InterfaceRecovery.__new__(
            self.interface_recovery.InterfaceRecovery)
        parser.bv = bv
        parser.target = None
        parser.rodata_section = None
        parser.types_base = None
        parser.types_section = None
        parser.moduledata = None
        parser.gopclntab = None
        parser.itabs = []
        for name, value in attributes.items():
            setattr(parser, name, value)
        return parser

    def build_legacy_fixture(self, itablink_name='__itablink', itablink_entries=1):
        types_base = 0x100000
        bv = FakeBinaryView()
        bv.add_region(types_base, 0x2000)
        bv.add_region(0x200000, 0x100)
        bv.add_region(0x210000, 0x10)
        bv.add_region(0x300000, 0x100)

        write_name(bv, 0x100800, 'main.Iface', self.version)
        write_name(bv, 0x100820, 'DoThing', self.version)
        write_name(bv, 0x100840, 'Other', self.version)
        write_name(bv, 0x100860, 'main.Impl', self.version)

        write_interface_info(bv, 0x100100, 0x100300, 2, name_off=0x800)
        write_imethod(bv, 0x100300, 0x820, 0)
        write_imethod(bv, 0x100308, 0x840, 0)
        write_type_header(bv, 0x100180, 0x19, name_off=0x860)  # STRUCT

        write_itab(bv, 0x200000, 0x100100, 0x100180, [0x300000, 0x300010])

        for index in range(itablink_entries):
            write_pointer(bv, 0x210000 + index * 8, 0x200000)
        types_section = FakeSection('__rodata', types_base, types_base + 0x2000)
        itablink = FakeSection(itablink_name, 0x210000, 0x210000 + itablink_entries * 8)
        bv.sections = [types_section, itablink]

        parser = self.make_parser(
            bv,
            types_base=types_base,
            types_section=types_section,
            rodata_section=types_section,
        )
        return parser, bv

    def test_itablink_recovery(self):
        parser, bv = self.build_legacy_fixture()
        itabs = parser.collect_itabs(self.version)
        self.assertEqual(len(itabs), 1)
        itab = itabs[0]
        self.assertEqual(itab['itab_address'], 0x200000)
        self.assertEqual(itab['link_address'], 0x210000)
        self.assertEqual(itab['interface_name'], 'main.Iface')
        self.assertEqual(itab['concrete_name'], 'main.Impl')
        self.assertEqual(itab['size'], 40)
        self.assertEqual([(method['name'], method['address']) for method in itab['methods']],
                         [('DoThing', 0x300000), ('Other', 0x300010)])

    def test_annotations_and_symbols(self):
        parser, bv = self.build_legacy_fixture()
        itabs = parser.recover()
        self.assertEqual(len(itabs), 1)

        self.assertIn('main.Impl implements main.Iface', bv.get_comment_at(0x200000))
        self.assertIn('main.Impl implements main.Iface', bv.get_comment_at(0x300000))
        self.assertIn('DoThing', bv.get_comment_at(0x300000))
        self.assertIn('Other', bv.get_comment_at(0x300010))
        self.assertIn((0x200000, 0x100100), bv._refs)
        self.assertIn((0x210000, 0x200000), bv._refs)

        symbol = bv.get_symbol_at(0x200000)
        self.assertIsNotNone(symbol)
        self.assertEqual(symbol.type, FakeSymbolType.DataSymbol)
        self.assertIn('itab_', symbol.name)

    def test_existing_symbol_is_not_clobbered(self):
        parser, bv = self.build_legacy_fixture()
        existing = FakeSymbol(FakeSymbolType.DataSymbol, 0x200000, 'user_symbol')
        bv._symbols.append(existing)
        parser.recover()
        self.assertIs(bv.get_symbol_at(0x200000), existing)
        self.assertEqual(bv.get_symbol_at(0x200000).name, 'user_symbol')

    def test_missing_itab_metadata_returns_empty(self):
        types_base = 0x100000
        bv = FakeBinaryView()
        bv.add_region(types_base, 0x2000)
        types_section = FakeSection('__rodata', types_base, types_base + 0x2000)
        bv.sections = [types_section]
        parser = self.make_parser(bv, types_base=types_base, types_section=types_section)
        self.assertEqual(parser.collect_itabs(self.version), [])
        self.assertEqual(parser.recover(), [])

    def test_relro_itablink_recovery(self):
        parser, bv = self.build_legacy_fixture(itablink_name='.data.rel.ro.itablink')
        itabs = parser.collect_itabs(self.version)
        self.assertEqual(len(itabs), 1)
        self.assertEqual(itabs[0]['itab_address'], 0x200000)
        self.assertEqual(itabs[0]['interface_name'], 'main.Iface')

    def test_duplicate_itablink_entries_are_parsed_once(self):
        parser, bv = self.build_legacy_fixture(itablink_entries=2)
        itabs = parser.collect_itabs(self.version)
        self.assertEqual(len(itabs), 1)
        self.assertEqual(itabs[0]['itab_address'], 0x200000)
        self.assertEqual(itabs[0]['link_address'], 0x210000)

    # ------------------------------------------------------------------
    # method prototypes
    # ------------------------------------------------------------------

    def build_prototype_fixture(self, type_off=0x400, in_count=1, out_count=0,
                                variadic=False):
        parser, bv = self.build_legacy_fixture()
        # The first imethod points at the FUNC descriptor, the second keeps
        # typeOff 0 and must be skipped as an invalid descriptor.
        write_imethod(bv, 0x100300, 0x820, type_off)
        if type_off >= 0:
            write_func_type(bv, parser.types_base + type_off,
                            in_count, out_count, variadic)
        return parser, bv

    def apply_prototype(self, in_count=1, out_count=0, variadic=False, **function_kwargs):
        parser, bv = self.build_prototype_fixture(in_count=in_count, out_count=out_count,
                                                  variadic=variadic)
        function = FakeFunction(0x300000, **function_kwargs)
        install_functions(bv, [function])
        parser.itabs = parser.collect_itabs(self.version)
        applied = parser.apply_method_prototypes(self.version)
        return applied, function, parser, bv

    def test_method_prototype_receiver_and_params(self):
        applied, function, _, _ = self.apply_prototype(in_count=2, out_count=0)

        self.assertEqual(applied, 1)
        prototype = function.user_type
        self.assertIsNotNone(prototype)
        self.assertEqual(prototype.kind, 'function')
        # One receiver plus one void* per declared Go input.
        self.assertEqual(len(prototype.params), 3)
        for parameter in prototype.params:
            self.assertEqual(parameter.kind, 'pointer')
            self.assertEqual(parameter.target.kind, 'void')
        self.assertEqual(prototype.ret.kind, 'void')
        self.assertFalse(prototype.variable_arguments)
        self.assertEqual(function.set_user_type_calls, 1)

    def test_method_prototype_single_return_is_a_void_pointer(self):
        applied, function, _, _ = self.apply_prototype(in_count=1, out_count=1)

        self.assertEqual(applied, 1)
        prototype = function.user_type
        self.assertEqual(len(prototype.params), 2)
        self.assertEqual(prototype.ret.kind, 'pointer')
        self.assertEqual(prototype.ret.target.kind, 'void')

    def test_method_prototype_multiple_returns_use_a_struct(self):
        applied, function, _, _ = self.apply_prototype(in_count=0, out_count=2,
                                                       variadic=True)

        self.assertEqual(applied, 1)
        prototype = function.user_type
        self.assertEqual(len(prototype.params), 1)
        self.assertTrue(prototype.variable_arguments)
        result_struct = prototype.ret
        self.assertEqual(result_struct.kind, 'struct')
        self.assertEqual([name for name, _ in result_struct.fields], ['ret0', 'ret1'])
        for _, field_type in result_struct.fields:
            self.assertEqual(field_type.kind, 'pointer')
            self.assertEqual(field_type.target.kind, 'void')

    def test_method_prototype_does_not_overwrite_a_user_type(self):
        applied, function, _, _ = self.apply_prototype(has_user_type=True)

        self.assertEqual(applied, 0)
        self.assertIsNone(function.user_type)
        self.assertEqual(function.set_user_type_calls, 0)

    def test_method_prototype_without_a_function_is_not_created(self):
        parser, bv = self.build_prototype_fixture()
        install_functions(bv, [])

        self.assertEqual(parser.apply_method_prototypes(self.version), 0)
        self.assertEqual(bv._functions, [])

    def test_method_prototype_invalid_type_off_is_skipped(self):
        parser, bv = self.build_prototype_fixture()
        function = FakeFunction(0x300000)
        install_functions(bv, [function])

        # 0xffffffff (parsed as -1) marks the absence of a function type.
        write_imethod(bv, 0x100300, 0x820, -1)
        parser.itabs = parser.collect_itabs(self.version)
        self.assertEqual(parser.itabs[0]['methods'][0]['type_off'], -1)
        self.assertEqual(parser.apply_method_prototypes(self.version), 0)

        # A typeOff pointing at a non-FUNC descriptor is not applied either.
        write_imethod(bv, 0x100300, 0x820, 0x600)
        write_type_header(bv, 0x100600, 0x19)  # STRUCT
        parser.itabs = parser.collect_itabs(self.version)
        self.assertEqual(parser.apply_method_prototypes(self.version), 0)

        self.assertIsNone(function.user_type)
        self.assertEqual(function.set_user_type_calls, 0)

    def test_recover_applies_method_prototypes(self):
        parser, bv = self.build_prototype_fixture()
        function = FakeFunction(0x300000)
        install_functions(bv, [function])

        parser.recover()

        self.assertIsNotNone(function.user_type)
        self.assertEqual(function.user_type.kind, 'function')
        self.assertEqual(len(function.user_type.params), 2)

    def test_recover_prototypes_setting_disables_application(self):
        FakeSettings.overrides['golang_binary_parser.recover_prototypes'] = False
        parser, bv = self.build_prototype_fixture()
        function = FakeFunction(0x300000)
        install_functions(bv, [function])

        parser.recover()

        self.assertIsNone(function.user_type)
        self.assertEqual(function.set_user_type_calls, 0)

    def test_global_method_budget_is_enforced(self):
        parser, bv = self.build_go127_fixture()
        parser.MAX_TOTAL_METHODS = 2
        itabs = parser.collect_itabs(self.version)
        self.assertEqual(len(itabs), 2)
        self.assertEqual(sum(len(itab['methods']) for itab in itabs), 2)
        self.assertEqual([method['name'] for method in itabs[0]['methods']], ['Run', 'Stop'])
        self.assertEqual(itabs[1]['methods'], [])
        # The declared method count still sizes the second itab correctly.
        self.assertEqual(itabs[1]['size'], 32)

    def build_go127_fixture(self, go_type_section=True):
        types_base = 0x100000
        types_end = 0x102000
        bv = FakeBinaryView()
        bv.add_region(types_base, types_end - types_base)
        bv.add_region(0x300000, 0x100)   # functions
        bv.add_region(0x400000, 0x300)   # __go_module/moduledata
        bv.add_region(0x500000, 0x100)   # pclntab header
        bv.write(0x500000, b'\xf1\xff\xff\xff\x00\x00\x04\x08')

        # First implementation: two methods.
        write_name(bv, 0x100800, 'main.Runner', self.version)
        write_name(bv, 0x100820, 'Run', self.version)
        write_name(bv, 0x100840, 'Stop', self.version)
        write_name(bv, 0x100860, 'main.Worker', self.version)
        write_interface_info(bv, 0x100100, 0x100300, 2, name_off=0x800)
        write_imethod(bv, 0x100300, 0x820, 0)
        write_imethod(bv, 0x100308, 0x840, 0)
        write_type_header(bv, 0x100180, 0x19, name_off=0x860)

        # Second implementation: one method.
        write_name(bv, 0x100880, 'main.Closer', self.version)
        write_name(bv, 0x1008a0, 'Close', self.version)
        write_name(bv, 0x1008c0, 'main.File', self.version)
        write_interface_info(bv, 0x100200, 0x100320, 1, name_off=0x880)
        write_imethod(bv, 0x100320, 0x8a0, 0)
        write_type_header(bv, 0x1001c0, 0x19, name_off=0x8c0)

        write_itab(bv, 0x101000, 0x100100, 0x100180, [0x300000, 0x300010])
        write_itab(bv, 0x101028, 0x100200, 0x1001c0, [0x300020])

        module_section = FakeSection('__go_module', 0x400000, 0x400300,
                                     parent=FakeSegment('__DATA'))
        if go_type_section:
            sections = [FakeSection('__go_type', types_base, types_end,
                                    parent=FakeSegment('__DATA_CONST')), module_section]
        else:
            # PE-style binary: no Go specific sections, only the symbols.
            sections = [FakeSection('.rdata', types_base, types_end), module_section]
            write_type_header(bv, types_base + 8, 0x16)  # plausible first descriptor
            bv._symbols.append(FakeSymbol(FakeSymbolType.DataSymbol, types_base, 'runtime.types'))
            bv._symbols.append(FakeSymbol(FakeSymbolType.DataSymbol, 0x400080,
                                          'runtime.firstmoduledata'))
        bv.sections = sections
        write_moduledata_v127(bv, 0x400080, 0x500000, types_base, 0x800,
                              types_end, itaboffset=0x1000, itabsize=72)

        parser = self.make_parser(bv, gopclntab=types.SimpleNamespace(start=0x500000))
        return parser, bv

    def test_go127_itab_range_recovery(self):
        parser, bv = self.build_go127_fixture()
        self.assertIsNotNone(parser.find_moduledata())
        itabs = parser.collect_itabs(self.version)
        self.assertEqual(len(itabs), 2)
        self.assertEqual(itabs[0]['interface_name'], 'main.Runner')
        self.assertEqual(itabs[0]['concrete_name'], 'main.Worker')
        self.assertEqual(itabs[0]['size'], 40)
        self.assertEqual([method['address'] for method in itabs[0]['methods']],
                         [0x300000, 0x300010])
        self.assertEqual(itabs[1]['itab_address'], 0x101028)
        self.assertEqual(itabs[1]['interface_name'], 'main.Closer')
        self.assertEqual(itabs[1]['concrete_name'], 'main.File')
        self.assertEqual(itabs[1]['size'], 32)
        self.assertEqual([method['name'] for method in itabs[1]['methods']], ['Close'])

    def test_go127_recover_annotates_range(self):
        parser, bv = self.build_go127_fixture()
        itabs = parser.run()
        self.assertEqual(len(itabs), 2)
        self.assertIn('main.Worker implements main.Runner', bv.get_comment_at(0x101000))
        self.assertIn('main.File implements main.Closer', bv.get_comment_at(0x101028))

    def test_go127_range_without_go_type_section(self):
        # PE-style layout: the moduledata is found through its symbol and the
        # types base through runtime.types, with no Go specific section names.
        parser, bv = self.build_go127_fixture(go_type_section=False)
        self.assertEqual(parser.find_types_base(), 0x100000)
        self.assertEqual(parser.types_section.name, '.rdata')
        moduledata = parser.find_moduledata()
        self.assertIsNotNone(moduledata)
        itabs = parser.collect_itabs(self.version)
        self.assertEqual(len(itabs), 2)
        self.assertEqual(itabs[0]['concrete_name'], 'main.Worker')
        self.assertEqual(itabs[1]['concrete_name'], 'main.File')


if __name__ == '__main__':
    unittest.main()
