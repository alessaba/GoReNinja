from typing import Optional

import binaryninja as bn

from ..internal_types.datatypes import (
    ChanType,
    GolangType,
    GolangTypeKind,
    MapType,
    SliceTType,
    TypeName,
)

from .common import log_debug, log_info, sanitize_gotype_name, santize_gofunc_name
from .type_parser import TypeParser


class DecompilerEnhancer(TypeParser):
    """
    Apply the recovered Go information to the decompiler view.

    The enhancer only applies persistent user prototypes and IL-aware comments:
    it never rewrites the Go register ABI parameters or the call sites. Both
    parts are optional and independent (``recover_prototypes`` and
    ``decompiler_annotations``), and every operation tolerates missing type
    metadata and unavailable IL.
    """

    PROTOTYPE_SETTING = 'golang_binary_parser.recover_prototypes'
    ANNOTATION_SETTING = 'golang_binary_parser.decompiler_annotations'

    NEW_FUNCTIONS = ('new', 'newobject')
    SLICE_FUNCTIONS = ('makeslice',)
    CHAN_FUNCTIONS = ('makechan',)
    MAP_FUNCTIONS = ('makemap',)

    # Decompiler comments for the runtime helpers. The names are the bare
    # function names (without the package), so the sanitized variants produced
    # by FunctionRenamer match as well.
    RUNTIME_IDIOMS = {
        'gopanic': 'Go: panic',
        'panicindex': 'Go: panic',
        'panicdivide': 'Go: panic',
        'panicslice': 'Go: panic',
        'panicshift': 'Go: panic',
        'panicoverflow': 'Go: panic',
        'panicmem': 'Go: panic',
        'deferreturn': 'Go: defer',
        'deferproc': 'Go: defer',
        'deferprocStack': 'Go: defer',
        'memmove': 'Go: memmove',
        'typedmemmove': 'Go: memmove',
        'duffcopy': 'Go: memmove',
        'memclrNoHeapPointers': 'Go: memclr',
        'typedmemclr': 'Go: memclr',
        'duffzero': 'Go: memclr',
        'memeq': 'Go: memequal',
        'goexit': 'Go: goexit',
    }

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    @staticmethod
    def _setting_enabled(key: str, default: bool = True) -> bool:
        """
        Read a plugin setting defensively.

        The settings are registered by the plugin entry point; when they are
        not available (tests, older registration, an embedded run) the
        documented default is returned instead of raising.
        """
        try:
            settings = bn.Settings()
        except Exception:
            return default
        contains = getattr(settings, 'contains', None)
        if callable(contains):
            try:
                if not contains(key):
                    return default
            except Exception:
                return default
        try:
            value = settings.get_bool(key)
        except Exception:
            return default
        return default if value is None else bool(value)

    # ------------------------------------------------------------------
    # Prototypes
    # ------------------------------------------------------------------

    def _pointer_size(self) -> int:
        address_size = getattr(getattr(self.bv, 'arch', None), 'address_size', 0)
        return 4 if address_size == 4 else 8

    def _runtime_prototypes(self) -> dict:
        """
        Conservative C prototypes for the runtime helpers.

        Go int/uintptr arguments use pointer sized C integers and the runtime
        type descriptor arguments use ``golang_type_t*``; everything else is a
        ``void*``. Functions with multiple Go return values (for example
        ``runtime.growslice``) are intentionally absent: a single C return type
        would misrepresent them.
        """
        if self._pointer_size() == 4:
            go_int, go_uintptr = 'int32_t', 'uint32_t'
        else:
            go_int, go_uintptr = 'int64_t', 'uint64_t'
        go_type = 'golang_type_t'

        return {
            'runtime.newobject': f'void* newobject({go_type}* typ)',
            'runtime.mallocgc': f'void* mallocgc({go_uintptr} size, {go_type}* typ, bool needzero)',
            'runtime.makeslice': f'void* makeslice({go_type}* et, {go_int} len, {go_int} cap)',
            'runtime.makechan': f'void* makechan({go_type}* t, {go_int} size)',
            'runtime.makemap': f'void* makemap({go_type}* t, {go_int} hint, void* h)',
            'runtime.mapassign': f'void* mapassign({go_type}* t, void* h, void* key)',
            'runtime.mapaccess1': f'void* mapaccess1({go_type}* t, void* h, void* key)',
            'runtime.mapiterinit': f'void mapiterinit({go_type}* t, void* h, void* it)',
            'runtime.mapiternext': 'void mapiternext(void* it)',
            'runtime.mapdelete': f'void mapdelete({go_type}* t, void* h, void* key)',
            'runtime.memmove': f'void memmove(void* dst, void* src, {go_uintptr} n)',
            'runtime.memclrNoHeapPointers': f'void memclrNoHeapPointers(void* ptr, {go_uintptr} n)',
            'runtime.memeq': f'bool memeq(void* a, void* b, {go_uintptr} n)',
            'runtime.convT': f'void* convT({go_type}* t, void* val)',
            'runtime.convTstring': 'void* convTstring(golang_string_t val)',
            'runtime.convTslice': 'void* convTslice(golang_slice_t val)',
            'runtime.getitab': f'void* getitab({go_type}* inter, {go_type}* typ, bool canfail)',
            'runtime.newproc': 'void newproc(int32_t siz, void* fn)',
            'runtime.closechan': 'void closechan(void* c)',
            'runtime.slicecopy': (f'{go_int} slicecopy(void* to, {go_int} to_len, '
                                  f'void* from, {go_int} from_len, {go_uintptr} width)'),
            'runtime.goexit': 'void goexit(void)',
            'runtime.deferreturn': f'void deferreturn({go_uintptr} arg0)',
            'runtime.gopanic': 'void gopanic(void* type, void* data)',
            'runtime.panicdivide': 'void panicdivide(void)',
        }

    def _functions_by_name(self, name: str) -> list:
        getter = getattr(self.bv, 'get_functions_by_name', None)
        if not callable(getter):
            return []
        try:
            functions = list(getter(name) or [])
        except Exception as e:
            log_debug(f"Unable to look up the function {name}: {e}")
            return []
        if functions:
            return functions

        # FunctionRenamer may have sanitized the name.
        try:
            sanitized_name = santize_gofunc_name(name)
        except Exception:
            return []
        if sanitized_name == name:
            return []
        try:
            return list(getter(sanitized_name) or [])
        except Exception as e:
            log_debug(f"Unable to look up the sanitized function {sanitized_name}: {e}")
            return []

    def apply_runtime_signatures(self) -> int:
        if not self._setting_enabled(self.PROTOTYPE_SETTING):
            log_debug("Runtime prototype recovery is disabled")
            return 0

        applied = 0
        skipped = 0
        for name, prototype in self._runtime_prototypes().items():
            for function in self._functions_by_name(name):
                if getattr(function, 'has_user_type', False):
                    # Never overwrite a type the user set explicitly.
                    skipped += 1
                    continue
                setter = getattr(function, 'set_user_type', None)
                if setter is None:
                    skipped += 1
                    continue
                try:
                    setter(prototype)
                    applied += 1
                except Exception as e:
                    skipped += 1
                    log_debug(f"Unable to apply the prototype to {getattr(function, 'name', name)}: {e}")

        log_info(f"Applied {applied} Go runtime prototypes ({skipped} skipped)")
        return applied

    # ------------------------------------------------------------------
    # Typed call site annotations
    # ------------------------------------------------------------------

    @staticmethod
    def _runtime_base_name(name: str) -> str:
        if not isinstance(name, str):
            return ''
        base_name = name.rsplit('.', 1)[-1]
        if base_name.startswith('runtime_'):
            base_name = base_name[len('runtime_'):]
        return base_name

    def _resolve_type_name(self, address: Optional[int]) -> Optional[str]:
        if not address:
            return None
        types_base = self.types_base or self.find_types_base()
        if not types_base:
            return None
        try:
            version = self.version_for_types()
            gotype = GolangType.from_bv(self.bv, address, types_base, version)
            if gotype.kind is GolangTypeKind.INVALID:
                return None
            type_name = TypeName.from_bv(self.bv, gotype.resolved_name_addr, types_base, version)
        except Exception as e:
            log_debug(f"Unable to resolve the type name at 0x{address:x}: {e}")
            return None
        if not type_name.name:
            return None
        return sanitize_gotype_name(type_name.name) or None

    def _element_type_name(self, type_address: int, type_parser_class) -> Optional[str]:
        if not (self.types_base or self.find_types_base()):
            return None
        try:
            gotype = type_parser_class.from_bv(
                self.bv, type_address, self.types_base, self.version_for_types())
        except Exception as e:
            log_debug(f"Unable to parse the container type at 0x{type_address:x}: {e}")
            return None
        return self._resolve_type_name(gotype.element_ptr)

    def _map_type_names(self, type_address: int) -> tuple:
        if not (self.types_base or self.find_types_base()):
            return None, None
        try:
            map_type = MapType.from_bv(
                self.bv, type_address, self.types_base, self.version_for_types(),
                go127=self.use_go127_map_layout())
        except Exception as e:
            log_debug(f"Unable to parse the map type at 0x{type_address:x}: {e}")
            return None, None
        return self._resolve_type_name(map_type.key), self._resolve_type_name(map_type.elem)

    def _typed_call_comment(self, function_name: str, type_address: Optional[int]) -> Optional[str]:
        if not type_address:
            return None
        base_name = self._runtime_base_name(function_name)

        if base_name in self.NEW_FUNCTIONS:
            type_name = self._resolve_type_name(type_address)
            return f"Go: new {type_name}" if type_name else "Go: new object"
        if base_name in self.SLICE_FUNCTIONS:
            element_name = self._element_type_name(type_address, SliceTType)
            return f"Go: make([]{element_name})" if element_name else "Go: make([])"
        if base_name in self.CHAN_FUNCTIONS:
            element_name = self._element_type_name(type_address, ChanType)
            return f"Go: make(chan {element_name})" if element_name else "Go: make(chan)"
        if base_name in self.MAP_FUNCTIONS:
            key_name, element_name = self._map_type_names(type_address)
            if key_name and element_name:
                return f"Go: make(map[{key_name}]{element_name})"
            return "Go: make(map)"
        return None

    def _call_site_address(self, call_site: dict) -> Optional[int]:
        address = getattr(call_site.get('caller_site'), 'address', None)
        if isinstance(address, int):
            return address
        address = getattr(call_site.get('il_instruction'), 'address', None)
        return address if isinstance(address, int) else None

    def annotate_typed_call_sites(self) -> int:
        if not self._setting_enabled(self.ANNOTATION_SETTING):
            log_debug("Decompiler annotations are disabled")
            return 0

        annotated = 0
        for call_site in self.iter_type_call_sites():
            address = self._call_site_address(call_site)
            if address is None:
                continue
            type_address = call_site.get('type_address')
            comment = self._typed_call_comment(call_site.get('function_name'), type_address)
            if comment and self._add_comment(address, comment):
                annotated += 1
            if type_address:
                self._add_ref(address, type_address)

        log_info(f"Annotated {annotated} typed Go call sites")
        return annotated

    # ------------------------------------------------------------------
    # Runtime idiom annotations
    # ------------------------------------------------------------------

    def annotate_runtime_idioms(self) -> int:
        if not self._setting_enabled(self.ANNOTATION_SETTING):
            log_debug("Decompiler annotations are disabled")
            return 0

        annotated = 0
        for function_name, comment in self.RUNTIME_IDIOMS.items():
            for function in self._functions_by_name(f'runtime.{function_name}'):
                try:
                    caller_sites = getattr(function, 'caller_sites', None) or []
                except Exception:
                    continue
                for caller_site in caller_sites:
                    address = getattr(caller_site, 'address', None)
                    if isinstance(address, int) and self._add_comment(address, comment):
                        annotated += 1

        log_info(f"Annotated {annotated} Go runtime idioms")
        return annotated

    # ------------------------------------------------------------------
    # Comments / references
    # ------------------------------------------------------------------

    def _add_comment(self, address: int, comment: str) -> bool:
        setter = getattr(self.bv, 'set_comment_at', None)
        if not isinstance(address, int) or setter is None:
            return False
        try:
            getter = getattr(self.bv, 'get_comment_at', None)
            existing = getter(address) if getter is not None else None
            if existing:
                if comment in existing:
                    # The annotation (or a richer variant of it) is already there.
                    return False
                comment = f"{existing}\n{comment}"
            setter(address, comment)
            return True
        except Exception as e:
            log_debug(f"Unable to comment 0x{address:x}: {e}")
            return False

    def _add_ref(self, from_address: int, to_address: int) -> None:
        adder = getattr(self.bv, 'add_user_data_ref', None)
        if not isinstance(from_address, int) or not isinstance(to_address, int) or adder is None:
            return
        try:
            adder(from_address, to_address)
        except Exception as e:
            log_debug(f"Unable to add a data ref 0x{from_address:x} -> 0x{to_address:x}: {e}")

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self):
        self.apply_runtime_signatures()
        self.annotate_typed_call_sites()
        self.annotate_runtime_idioms()
