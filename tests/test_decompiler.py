"""Headless tests for the decompiler enhancement.

The tests reuse the Binary Ninja stub installed by ``tests.test_types`` and drive
the enhancer with synthetic binary views and function objects. No license or UI
is required.
"""
import importlib
import types
import unittest

from tests.test_types import (
    FakeBinaryView,
    FakeHLILOperation,
    FakeMLILOperation,
    FakeSection,
    FakeSettings,
    load_plugin,
    write_name,
    write_pointer,
    write_type_header,
)


class FakeFunction:
    """Minimal Binary Ninja Function stand-in for prototype application."""

    def __init__(self, name, address=0x0, caller_sites=None,
                 parameter_vars=None, has_user_type=False):
        self.name = name
        self.address = address
        self.caller_sites = list(caller_sites or [])
        self.parameter_vars = list(parameter_vars or [])
        self._has_user_type = has_user_type
        self.user_types = []

    @property
    def has_user_type(self):
        return self._has_user_type

    def set_user_type(self, prototype):
        self.user_types.append(prototype)
        self._has_user_type = True


def make_call_site(address, constants=(), operation=None, use_hlil=False):
    params = [
        types.SimpleNamespace(operation=FakeMLILOperation.MLIL_CONST_PTR, constant=value)
        for value in constants
    ]
    if use_hlil:
        hlil_params = [
            types.SimpleNamespace(operation=FakeHLILOperation.HLIL_CONST_PTR, constant=value)
            for value in constants
        ]
        return types.SimpleNamespace(
            address=address,
            mlil=None,
            hlil=types.SimpleNamespace(
                operation=FakeHLILOperation.HLIL_CALL,
                params=hlil_params,
            ),
        )
    operation = FakeMLILOperation.MLIL_CALL if operation is None else operation
    return types.SimpleNamespace(
        address=address,
        mlil=types.SimpleNamespace(operation=operation, params=params),
        hlil=None,
    )


def make_enhancer(decompiler_module, bv, **attributes):
    enhancer = decompiler_module.DecompilerEnhancer.__new__(
        decompiler_module.DecompilerEnhancer)
    enhancer.bv = bv
    enhancer.target = None
    enhancer.rodata_section = None
    enhancer.types_base = None
    enhancer.types_section = None
    enhancer.moduledata = None
    enhancer.gopclntab = None
    for name, value in attributes.items():
        setattr(enhancer, name, value)
    return enhancer


class SettingsIsolation(unittest.TestCase):
    def setUp(self):
        FakeSettings.overrides = {}

    def tearDown(self):
        FakeSettings.overrides = {}


class RuntimeSignatureTest(SettingsIsolation):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.decompiler = importlib.import_module('goplugin.parsers.decompiler')

    def test_applies_prototypes_and_never_overwrites_user_types(self):
        bv = FakeBinaryView()
        newobject = FakeFunction('runtime.newobject')
        mallocgc = FakeFunction('runtime.mallocgc')
        makemap = FakeFunction('runtime.makemap')
        slicecopy = FakeFunction('runtime.slicecopy')
        user_typed = FakeFunction('runtime.mapassign', has_user_type=True)
        bv._functions = [newobject, mallocgc, makemap, slicecopy, user_typed]

        enhancer = make_enhancer(self.decompiler, bv)
        self.assertEqual(enhancer.apply_runtime_signatures(), 4)

        self.assertEqual(newobject.user_types,
                         ['void* newobject(golang_type_t* typ)'])
        self.assertEqual(len(mallocgc.user_types), 1)
        self.assertIn('uint64_t size', mallocgc.user_types[0])
        self.assertIn('golang_type_t* typ', mallocgc.user_types[0])
        self.assertIn('bool needzero', mallocgc.user_types[0])
        self.assertEqual(makemap.user_types,
                         ['void* makemap(golang_type_t* t, int64_t hint, void* h)'])
        self.assertIn('int64_t slicecopy(', slicecopy.user_types[0])
        self.assertEqual(user_typed.user_types, [])

        # A second run must not replace the prototype it just applied.
        enhancer.apply_runtime_signatures()
        self.assertEqual(len(newobject.user_types), 1)
        self.assertEqual(len(user_typed.user_types), 0)

    def test_pointer_size_selects_the_primitive_integer_types(self):
        bv64 = FakeBinaryView(address_size=8)
        mallocgc64 = FakeFunction('runtime.mallocgc')
        makeslice64 = FakeFunction('runtime.makeslice')
        slicecopy64 = FakeFunction('runtime.slicecopy')
        bv64._functions = [mallocgc64, makeslice64, slicecopy64]
        make_enhancer(self.decompiler, bv64).apply_runtime_signatures()
        self.assertIn('uint64_t size', mallocgc64.user_types[0])
        self.assertIn('int64_t len', makeslice64.user_types[0])
        self.assertIn('int64_t cap', makeslice64.user_types[0])
        self.assertEqual(
            slicecopy64.user_types,
            ['int64_t slicecopy(void* to, int64_t to_len, void* from, int64_t from_len, uint64_t width)'])

        bv32 = FakeBinaryView(address_size=4)
        mallocgc32 = FakeFunction('runtime.mallocgc')
        makeslice32 = FakeFunction('runtime.makeslice')
        slicecopy32 = FakeFunction('runtime.slicecopy')
        bv32._functions = [mallocgc32, makeslice32, slicecopy32]
        make_enhancer(self.decompiler, bv32).apply_runtime_signatures()
        self.assertIn('uint32_t size', mallocgc32.user_types[0])
        self.assertIn('int32_t len', makeslice32.user_types[0])
        self.assertIn('int32_t cap', makeslice32.user_types[0])
        self.assertEqual(
            slicecopy32.user_types,
            ['int32_t slicecopy(void* to, int32_t to_len, void* from, int32_t from_len, uint32_t width)'])
        self.assertNotIn('int64_t', makeslice32.user_types[0])
        self.assertNotIn('uint64_t', mallocgc32.user_types[0])

    def test_container_and_panic_prototypes(self):
        bv = FakeBinaryView()
        slicecopy = FakeFunction('runtime.slicecopy')
        convT = FakeFunction('runtime.convT')
        convTstring = FakeFunction('runtime.convTstring')
        convTslice = FakeFunction('runtime.convTslice')
        gopanic = FakeFunction('runtime.gopanic')
        panicindex = FakeFunction('runtime.panicindex')
        panicslice = FakeFunction('runtime.panicslice')
        bv._functions = [slicecopy, convT, convTstring, convTslice,
                         gopanic, panicindex, panicslice]

        enhancer = make_enhancer(self.decompiler, bv)
        self.assertEqual(enhancer.apply_runtime_signatures(), 5)

        self.assertEqual(
            slicecopy.user_types,
            ['int64_t slicecopy(void* to, int64_t to_len, void* from, int64_t from_len, uint64_t width)'])
        self.assertEqual(convT.user_types,
                         ['void* convT(golang_type_t* t, void* val)'])
        self.assertEqual(convTstring.user_types,
                         ['void* convTstring(golang_string_t val)'])
        self.assertEqual(convTslice.user_types,
                         ['void* convTslice(golang_slice_t val)'])
        self.assertEqual(gopanic.user_types,
                         ['void gopanic(void* type, void* data)'])
        # The index/slice panic helpers have non-trivial signatures: leave them
        # untyped instead of applying a wrong no-argument prototype.
        self.assertEqual(panicindex.user_types, [])
        self.assertEqual(panicslice.user_types, [])

    def test_multi_return_functions_are_not_typed(self):
        # growslice returns a slice and an int: a single C return type would be
        # wrong, so it must be left alone even when the function is present.
        bv = FakeBinaryView()
        growslice = FakeFunction('runtime.growslice')
        bv._functions = [growslice]

        enhancer = make_enhancer(self.decompiler, bv)
        self.assertEqual(enhancer.apply_runtime_signatures(), 0)
        self.assertEqual(growslice.user_types, [])

    def test_recover_prototypes_setting_disables_application(self):
        FakeSettings.overrides['golang_binary_parser.recover_prototypes'] = False
        bv = FakeBinaryView()
        newobject = FakeFunction('runtime.newobject')
        bv._functions = [newobject]

        enhancer = make_enhancer(self.decompiler, bv)
        self.assertEqual(enhancer.apply_runtime_signatures(), 0)
        self.assertEqual(newobject.user_types, [])

    def test_sanitized_function_names_are_matched(self):
        FakeSettings.overrides['golang_binary_parser.sanitize'] = True
        bv = FakeBinaryView()
        newobject = FakeFunction('runtime_newobject')
        bv._functions = [newobject]

        enhancer = make_enhancer(self.decompiler, bv)
        self.assertEqual(enhancer.apply_runtime_signatures(), 1)
        self.assertEqual(newobject.user_types,
                         ['void* newobject(golang_type_t* typ)'])


class TypedCallSiteAnnotationTest(SettingsIsolation):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.decompiler = importlib.import_module('goplugin.parsers.decompiler')

    def build_typed_fixture(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x1000)
        types_section = FakeSection('__rodata', 0x1000, 0x2000)
        bv.sections = [types_section]

        # main.Person struct descriptor.
        write_type_header(bv, 0x1100, 0x19, name_off=0x800)
        write_name(bv, 0x1800, 'main.Person')

        # []main.Person slice descriptor.
        write_type_header(bv, 0x1200, 0x17)
        write_pointer(bv, 0x1200 + 48, 0x1100)

        # chan int descriptor and the int element descriptor.
        write_type_header(bv, 0x1300, 0x12)
        write_pointer(bv, 0x1300 + 48, 0x1400)
        write_pointer(bv, 0x1300 + 56, 3)  # send/receive
        write_type_header(bv, 0x1400, 0x02, name_off=0x820)
        write_name(bv, 0x1820, 'int')

        # map[string]int descriptor.
        write_type_header(bv, 0x1500, 0x15)
        write_pointer(bv, 0x1500 + 48, 0x1600)
        write_pointer(bv, 0x1500 + 56, 0x1700)
        write_type_header(bv, 0x1600, 0x18, name_off=0x840)
        write_name(bv, 0x1840, 'string')
        write_type_header(bv, 0x1700, 0x02, name_off=0x860)
        write_name(bv, 0x1860, 'int')

        # map descriptor without key/elem names.
        write_type_header(bv, 0x1900, 0x15)

        def add_typed_function(name, address, type_address):
            caller_site = make_call_site(address, [type_address])
            bv._functions.append(FakeFunction(
                name, caller_sites=[caller_site], parameter_vars=[object()]))

        add_typed_function('runtime.newobject', 0x5000, 0x1100)
        add_typed_function('runtime.makeslice', 0x5001, 0x1200)
        add_typed_function('runtime.makechan', 0x5002, 0x1300)
        add_typed_function('runtime.makemap', 0x5003, 0x1500)
        add_typed_function('runtime.makemap', 0x5004, 0x1900)

        bv._comments[0x5000] = 'existing annotation'
        enhancer = make_enhancer(self.decompiler, bv,
                                 types_base=0x1000,
                                 types_section=types_section)
        return enhancer, bv

    def test_typed_allocations_comments_and_data_refs(self):
        enhancer, bv = self.build_typed_fixture()

        self.assertEqual(enhancer.annotate_typed_call_sites(), 5)
        self.assertEqual(bv.get_comment_at(0x5000),
                         'existing annotation\nGo: new main.Person')
        self.assertEqual(bv.get_comment_at(0x5001), 'Go: make([]main.Person)')
        self.assertEqual(bv.get_comment_at(0x5002), 'Go: make(chan int)')
        self.assertEqual(bv.get_comment_at(0x5003), 'Go: make(map[string]int)')
        self.assertEqual(bv.get_comment_at(0x5004), 'Go: make(map)')

        self.assertIn((0x5000, 0x1100), bv._refs)
        self.assertIn((0x5001, 0x1200), bv._refs)
        self.assertIn((0x5002, 0x1300), bv._refs)
        self.assertIn((0x5003, 0x1500), bv._refs)
        self.assertIn((0x5004, 0x1900), bv._refs)

        # Existing comments stay intact and the annotation is not duplicated.
        self.assertEqual(enhancer.annotate_typed_call_sites(), 0)
        self.assertEqual(bv.get_comment_at(0x5000).count('Go: new'), 1)
        self.assertEqual(bv.get_comment_at(0x5001), 'Go: make([]main.Person)')

    def test_hlil_fallback_is_annotated(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x1000)
        types_section = FakeSection('__rodata', 0x1000, 0x2000)
        bv.sections = [types_section]
        write_type_header(bv, 0x1100, 0x19, name_off=0x800)
        write_name(bv, 0x1800, 'main.Person')

        caller_site = make_call_site(0x5100, [0x1100], use_hlil=True)
        bv._functions = [FakeFunction(
            'runtime.newobject', caller_sites=[caller_site],
            parameter_vars=[object()])]

        enhancer = make_enhancer(self.decompiler, bv,
                                 types_base=0x1000,
                                 types_section=types_section)
        self.assertEqual(enhancer.annotate_typed_call_sites(), 1)
        self.assertEqual(bv.get_comment_at(0x5100), 'Go: new main.Person')

    def test_decompiler_annotations_setting_disables_comments(self):
        FakeSettings.overrides['golang_binary_parser.decompiler_annotations'] = False
        enhancer, bv = self.build_typed_fixture()

        self.assertEqual(enhancer.annotate_typed_call_sites(), 0)
        self.assertEqual(bv._comments, {0x5000: 'existing annotation'})


class RuntimeIdiomAnnotationTest(SettingsIsolation):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.decompiler = importlib.import_module('goplugin.parsers.decompiler')

    def build_idiom_fixture(self):
        bv = FakeBinaryView()
        cases = (
            ('runtime.gopanic', 0x6000, 'Go: panic'),
            ('runtime.deferreturn', 0x6001, 'Go: defer'),
            ('runtime.memmove', 0x6002, 'Go: memmove'),
            ('runtime.memclrNoHeapPointers', 0x6003, 'Go: memclr'),
            ('runtime.goexit', 0x6004, 'Go: goexit'),
        )
        for name, address, _ in cases:
            bv._functions.append(FakeFunction(
                name, caller_sites=[types.SimpleNamespace(address=address)]))
        bv._comments[0x6000] = 'existing annotation'
        return make_enhancer(self.decompiler, bv), bv, cases

    def test_runtime_idioms_are_commented_once(self):
        enhancer, bv, cases = self.build_idiom_fixture()

        self.assertEqual(enhancer.annotate_runtime_idioms(), len(cases))
        for _, address, comment in cases:
            self.assertIn(comment, bv.get_comment_at(address))
        self.assertEqual(bv.get_comment_at(0x6000),
                         'existing annotation\nGo: panic')

        self.assertEqual(enhancer.annotate_runtime_idioms(), 0)
        self.assertEqual(bv.get_comment_at(0x6000).count('Go: panic'), 1)

    def test_sanitized_idiom_names_are_matched(self):
        FakeSettings.overrides['golang_binary_parser.sanitize'] = True
        bv = FakeBinaryView()
        bv._functions = [FakeFunction(
            'runtime_gopanic', caller_sites=[types.SimpleNamespace(address=0x6100)])]

        enhancer = make_enhancer(self.decompiler, bv)
        self.assertEqual(enhancer.annotate_runtime_idioms(), 1)
        self.assertEqual(bv.get_comment_at(0x6100), 'Go: panic')

    def test_annotations_setting_disables_idiom_comments(self):
        FakeSettings.overrides['golang_binary_parser.decompiler_annotations'] = False
        enhancer, bv, _ = self.build_idiom_fixture()

        self.assertEqual(enhancer.annotate_runtime_idioms(), 0)
        self.assertEqual(bv._comments, {0x6000: 'existing annotation'})


class MissingAnalysisTest(SettingsIsolation):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.decompiler = importlib.import_module('goplugin.parsers.decompiler')

    def test_run_without_type_metadata_or_il_is_safe(self):
        bv = FakeBinaryView()
        enhancer = make_enhancer(self.decompiler, bv)
        self.assertIsNone(enhancer.run())
        self.assertEqual(bv._comments, {})
        self.assertEqual(bv._refs, [])

    def test_typed_function_without_il_is_ignored(self):
        bv = FakeBinaryView()
        bv.add_region(0x1000, 0x100)
        types_section = FakeSection('__rodata', 0x1000, 0x1100)
        bv.sections = [types_section]
        caller_site = types.SimpleNamespace(address=0x5200, mlil=None, hlil=None)
        bv._functions = [FakeFunction(
            'runtime.newobject', caller_sites=[caller_site],
            parameter_vars=[object()])]

        enhancer = make_enhancer(self.decompiler, bv,
                                 types_base=0x1000,
                                 types_section=types_section)
        self.assertEqual(enhancer.annotate_typed_call_sites(), 0)
        self.assertEqual(bv._comments, {})


if __name__ == '__main__':
    unittest.main()
