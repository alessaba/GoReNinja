import re

from typing import Optional

from ..internal_types.binaryninja_types import *
from ..internal_types.datatypes import GolangType, GolangTypeKind, GoVersion, TypeName

from .type_parser import TypeParser
from .common import log_debug, log_info, log_warn, sanitize_gotype_name

_SYMBOL_UNSAFE = re.compile(r'[^0-9A-Za-z_.$]')


class InterfaceRecovery(TypeParser):
    """
    Recover Go itabs (the interface implementation tables).

    Sources, in order:
      * __itablink/.itablink: pointer sized addresses of itab records.
      * Go 1.27: the contiguous itab range inside the types region described by
        moduledata.itaboffset/itabsize (there is no itablink table anymore).

    The itab layout is: inter *InterfaceType, type *Type, hash uint32,
    padding, then the function table. fun[0] is at 3*ptrSize on 64 bit (and on
    32 bit, where no padding is needed); the base record is 4*ptrSize.
    """

    ITABLINK_SECTIONS = ('__itablink', '.itablink', '.data.rel.ro.itablink')

    MAX_ITABS = 1 << 16
    MAX_INTERFACE_METHODS = 1 << 12
    # Global work budget for parsed imethod entries. Per-interface caps alone
    # still allow MAX_ITABS * MAX_INTERFACE_METHODS reads on hostile input.
    MAX_TOTAL_METHODS = 1 << 18
    # A malformed funcType descriptor must not turn into a prototype with a
    # huge parameter or result list.
    MAX_PROTOTYPE_PARAMS = 1 << 8

    def __init__(self, bv: bn.BinaryView, name: str = None, target: int = None):
        super().__init__(bv, name, target)
        self.itabs = []
        self._method_budget = self.MAX_TOTAL_METHODS

    def _reset_limits(self):
        self._method_budget = self.MAX_TOTAL_METHODS

    # ------------------------------------------------------------------
    # itab helpers
    # ------------------------------------------------------------------

    @staticmethod
    def itab_fun_offset(ptr_size: int) -> int:
        return 3 * ptr_size

    @staticmethod
    def itab_base_size(ptr_size: int) -> int:
        return 4 * ptr_size

    def find_itablink_section(self) -> Optional[bn.Section]:
        return self.find_section(self.ITABLINK_SECTIONS)

    def _name_address(self, name_off: int, types_base: int, version: GoVersion) -> int:
        # nameOff is relative to the types base for Go 1.12-1.15 (encoded
        # names) and for Go 1.16+, mirroring GolangType.resolved_name_addr.
        return types_base + name_off

    def _type_name_at(self, type_address: int, types_base: int, version: GoVersion) -> Optional[str]:
        try:
            gotype = GolangType.from_bv(self.bv, type_address, types_base, version)
            if gotype.kind is GolangTypeKind.INVALID:
                return None
            type_name = TypeName.from_bv(self.bv, gotype.resolved_name_addr, types_base, version)
            name = sanitize_gotype_name(type_name.name)
            return name or None
        except Exception as e:
            log_debug(f"Unable to resolve the type name at 0x{type_address:x}: {e}")
            return None

    def _interface_methods(self, interface_address: int, types_base: int, version: GoVersion):
        """
        Return ``(methods, declared_len)`` for the interface imethods, where
        ``methods`` is capped by the global method budget, or None when the
        interface descriptor cannot be parsed safely.
        """
        try:
            gotype = GolangType.from_bv(self.bv, interface_address, types_base, version)
            if gotype.kind is not GolangTypeKind.INTERFACE:
                return None

            ptr_size = self.bv.arch.address_size
            header_size = GolangType.size_from_bv(self.bv, version=version)
            # interfaceType: rtype, pkgPath name, methods []imethod
            methods_data = self._read_pointer(interface_address + header_size + ptr_size)
            methods_len = self._read_uint(interface_address + header_size + 2 * ptr_size, ptr_size)
            if methods_len > self.MAX_INTERFACE_METHODS:
                log_debug(f"Interface at 0x{interface_address:x} has an implausible method count {methods_len}")
                return None
            if methods_len and not self._is_mapped(methods_data):
                return None

            budget = max(getattr(self, '_method_budget', self.MAX_TOTAL_METHODS), 0)
            parse_count = min(methods_len, budget)
            if parse_count < methods_len:
                log_debug(f"Interface at 0x{interface_address:x}: method budget reached, "
                          f"parsing {parse_count}/{methods_len} imethods")
            # Charge the budget for the entries attempted, even if a read below
            # fails: otherwise malformed descriptors could keep resetting it.
            self._method_budget = budget - parse_count

            methods = []
            for index in range(parse_count):
                entry = methods_data + index * 8  # imethod: nameOff int32, typeOff int32
                raw = self.bv.read(entry, 4)
                if len(raw) != 4:
                    break
                name_off = int.from_bytes(raw, self._byteorder(), signed=True)
                type_off = int.from_bytes(self.bv.read(entry + 4, 4), self._byteorder(), signed=True)
                name = TypeName.from_bv(self.bv,
                                        self._name_address(name_off, types_base, version),
                                        types_base,
                                        version
                                        ).name
                methods.append({
                    'name': sanitize_gotype_name(name) if name else None,
                    'type_off': type_off,
                })
            return methods, methods_len
        except Exception as e:
            log_debug(f"Unable to parse the interface type at 0x{interface_address:x}: {e}")
            return None

    def _parse_itab(self, itab_address: int, types_base: int, version: GoVersion,
                    link_address: int = None) -> Optional[dict]:
        ptr_size = self.bv.arch.address_size
        if not self._is_mapped(itab_address):
            return None
        try:
            interface_address = self._read_pointer(itab_address)
            concrete_address = self._read_pointer(itab_address + ptr_size)
        except Exception:
            return None
        if not self._is_mapped(interface_address) or not self._is_mapped(concrete_address):
            return None

        interface_name = self._type_name_at(interface_address, types_base, version)
        concrete_name = self._type_name_at(concrete_address, types_base, version)
        if interface_name is None and concrete_name is None:
            return None

        methods_result = self._interface_methods(interface_address, types_base, version)
        fun_offset = self.itab_fun_offset(ptr_size)
        base_size = self.itab_base_size(ptr_size)
        if methods_result is None:
            # Without the interface method count the record can only be sized
            # as the base itab; that is enough for pointer based itablinks but
            # not for walking a contiguous range.
            if link_address is None:
                return None
            methods = []
            declared_len = 0
            itab_size = base_size
        else:
            methods, declared_len = methods_result
            try:
                fun0 = self._read_pointer(itab_address + fun_offset)
            except Exception:
                fun0 = 0
            if fun0 == 0:
                itab_size = base_size
            else:
                itab_size = base_size + max(declared_len - 1, 0) * ptr_size

        recovered_methods = []
        for index, method in enumerate(methods):
            slot_address = itab_address + fun_offset + index * ptr_size
            try:
                function_address = self._read_pointer(slot_address)
            except Exception:
                continue
            if not self._is_mapped(function_address):
                continue
            recovered_methods.append({
                'name': method['name'],
                'address': function_address,
                'slot_address': slot_address,
                'type_off': method['type_off'],
            })

        return {
            'itab_address': itab_address,
            'link_address': link_address,
            'interface_address': interface_address,
            'interface_name': interface_name,
            'concrete_address': concrete_address,
            'concrete_name': concrete_name,
            'size': itab_size,
            'methods': recovered_methods,
        }

    # ------------------------------------------------------------------
    # collection
    # ------------------------------------------------------------------

    def _collect_from_itablink(self, section, types_base: int, version: GoVersion) -> list:
        results = []
        seen_itabs = set()
        ptr_size = self.bv.arch.address_size
        length = self._section_end(section) - section.start
        if length <= 0:
            return results
        count = min(length // ptr_size, self.MAX_ITABS)
        for index in range(count):
            link_address = section.start + index * ptr_size
            try:
                itab_address = self._read_pointer(link_address)
            except Exception:
                continue
            if not itab_address or itab_address in seen_itabs:
                # A duplicated itablink entry must not be parsed twice.
                continue
            seen_itabs.add(itab_address)
            itab = self._parse_itab(itab_address, types_base, version, link_address)
            if itab is not None:
                results.append(itab)
            else:
                log_debug(f"Unable to parse the itab at 0x{itab_address:x} (link 0x{link_address:x})")
        log_info(f"Recovered {len(results)} itabs from {section.name}")
        return results

    def _collect_from_moduledata(self, moduledata: dict, types_base: int, version: GoVersion) -> list:
        results = []
        ptr_size = self.bv.arch.address_size
        start = moduledata['types'] + moduledata['itaboffset']
        end = start + moduledata['itabsize']
        address = start
        for _ in range(self.MAX_ITABS):
            if address >= end:
                break
            itab = self._parse_itab(address, types_base, version)
            if itab is None:
                log_debug(f"Unable to parse the Go 1.27 itab at 0x{address:x}, stopping")
                break
            results.append(itab)
            if itab['size'] <= 0:
                break
            address += itab['size']
        log_info(f"Recovered {len(results)} itabs from the Go 1.27 itab range")
        return results

    @staticmethod
    def _dedupe_itabs(itabs: list) -> list:
        unique = []
        seen = set()
        for itab in itabs:
            address = itab['itab_address']
            if address in seen:
                continue
            seen.add(address)
            unique.append(itab)
        return unique

    def collect_itabs(self, version: GoVersion = None) -> list:
        self._reset_limits()
        version = self.version_for_types(version)
        types_base = self.find_types_base()
        if types_base is None:
            log_warn("Unable to locate the Go types region, skipping itab recovery")
            return []

        itablink_section = self.find_itablink_section()
        if itablink_section is not None:
            return self._dedupe_itabs(self._collect_from_itablink(itablink_section, types_base, version))

        moduledata = self.find_moduledata()
        if moduledata and moduledata.get('itabsize'):
            return self._dedupe_itabs(self._collect_from_moduledata(moduledata, types_base, version))

        # Absent itab metadata: return an empty result instead of scanning the
        # whole binary (that is expensive and error prone).
        log_info("No __itablink/.itablink section or Go 1.27 itab range found, skipping itab recovery")
        return []

    # ------------------------------------------------------------------
    # annotations
    # ------------------------------------------------------------------

    def _add_comment(self, address: int, comment: str):
        setter = getattr(self.bv, 'set_comment_at', None)
        if setter is None:
            return
        try:
            getter = getattr(self.bv, 'get_comment_at', None)
            existing = getter(address) if getter is not None else None
            if existing:
                if comment in existing:
                    return
                comment = f"{existing}\n{comment}"
            setter(address, comment)
        except Exception as e:
            log_debug(f"Unable to comment 0x{address:x}: {e}")

    def _add_ref(self, from_address: int, to_address: int):
        adder = getattr(self.bv, 'add_user_data_ref', None)
        if adder is None:
            return
        try:
            adder(from_address, to_address)
        except Exception as e:
            log_debug(f"Unable to add a data ref 0x{from_address:x} -> 0x{to_address:x}: {e}")

    def _itab_symbol_name(self, itab: dict) -> str:
        concrete = itab.get('concrete_name') or 'concrete'
        interface = itab.get('interface_name') or 'interface'
        return _SYMBOL_UNSAFE.sub('_', f"itab_{concrete}_{interface}")

    def _define_itab_symbol(self, itab: dict):
        address = itab['itab_address']
        try:
            getter = getattr(self.bv, 'get_symbol_at', None)
            if getter is not None and getter(address):
                # Never clobber an existing symbol.
                return
        except Exception:
            return
        symbol_class = getattr(bn, 'Symbol', None)
        symbol_type = getattr(bn, 'SymbolType', None)
        define = getattr(self.bv, 'define_user_symbol', None)
        if symbol_class is None or symbol_type is None or define is None:
            return
        try:
            define(symbol_class(symbol_type.DataSymbol, address, self._itab_symbol_name(itab)))
        except Exception as e:
            log_debug(f"Unable to define the itab symbol at 0x{address:x}: {e}")

    def annotate_itab(self, itab: dict):
        interface_name = itab.get('interface_name') or 'interface'
        concrete_name = itab.get('concrete_name') or 'concrete'
        comment = f"{concrete_name} implements {interface_name}"
        itab_address = itab['itab_address']

        self._add_comment(itab_address, comment)
        self._add_ref(itab_address, itab['interface_address'])
        self._add_ref(itab_address, itab['concrete_address'])
        if itab.get('link_address'):
            self._add_ref(itab['link_address'], itab_address)
        self._define_itab_symbol(itab)

        for method in itab.get('methods', []):
            if not method.get('address'):
                continue
            method_name = method.get('name') or 'method'
            self._add_comment(method['address'], f"{comment}: {method_name}")
            self._add_ref(method['slot_address'], method['address'])

    # ------------------------------------------------------------------
    # method prototypes
    # ------------------------------------------------------------------

    def use_recover_prototypes(self) -> bool:
        """Read golang_binary_parser.recover_prototypes defensively (default true)."""
        key = 'golang_binary_parser.recover_prototypes'
        try:
            settings = bn.Settings()
        except Exception:
            return True
        contains = getattr(settings, 'contains', None)
        if callable(contains):
            try:
                if not contains(key):
                    return True
            except Exception:
                return True
        try:
            value = settings.get_bool(key)
        except Exception:
            return True
        return True if value is None else bool(value)

    def _method_func_type(self, type_off: int, types_base: int,
                          version: GoVersion) -> Optional[FuncType]:
        """
        Resolve the FuncType a method's typeOff points at, or None when the
        descriptor is absent, malformed or implausibly large.
        """
        if type_off is None or type_off < 0 or type_off == 0xffffffff:
            return None
        type_address = types_base + type_off
        if not self._is_mapped(type_address):
            return None
        descriptor = GolangType.from_bv(self.bv, type_address, types_base, version)
        if descriptor.kind is not GolangTypeKind.FUNC or not descriptor.is_valid():
            log_debug(f"Method typeOff 0x{type_off:x} does not point to a valid function type")
            return None
        counts_address = type_address + GolangType.size_from_bv(self.bv, version=version)
        counts = self.bv.read(counts_address, 4)
        if len(counts) != 4:
            return None
        in_count = int.from_bytes(counts[:2], self._byteorder())
        out_count = int.from_bytes(counts[2:], self._byteorder()) & 0x7fff
        if in_count > self.MAX_PROTOTYPE_PARAMS or out_count > self.MAX_PROTOTYPE_PARAMS:
            log_debug(f"Function type at 0x{type_address:x} has an implausible arity "
                      f"({in_count} in, {out_count} out)")
            return None
        return FuncType.from_bv(self.bv, type_address, types_base, version)

    def build_method_prototype(self, func_type: FuncType):
        """
        Conservative native prototype for a method implementation: a void*
        receiver followed by one void* per declared Go input. Binary Ninja has
        a single return value, so multiple Go results become a struct of void*
        fields. The exact Go parameter types are deliberately left unresolved.
        """
        def void_pointer():
            return PointerType.create(self.bv.arch, VoidType.create())

        params = [void_pointer()]  # receiver of the concrete implementation
        params.extend(void_pointer() for _ in range(len(func_type.in_params)))

        if not func_type.out_params:
            ret = Type.void()
        elif len(func_type.out_params) == 1:
            ret = void_pointer()
        else:
            results = StructureBuilder.create()
            for index in range(len(func_type.out_params)):
                results.append(void_pointer(), f"ret{index}")
            ret = results

        return Type.function(ret=ret, params=params, variable_arguments=func_type.variadic)

    def apply_method_prototype(self, method: dict, types_base: int,
                               version: GoVersion) -> bool:
        address = method.get('address')
        if not address:
            return False
        function = self.bv.get_function_at(address)
        if function is None:
            log_debug(f"No function at 0x{address:x} for the itab method "
                      f"{method.get('name') or ''}, skipping the prototype")
            return False
        if function.has_user_type:
            # Never replace a prototype the user already provided.
            return False
        func_type = self._method_func_type(method.get('type_off'), types_base, version)
        if func_type is None:
            return False
        function.set_user_type(self.build_method_prototype(func_type))
        return True

    def apply_method_prototypes(self, version: GoVersion = None) -> int:
        if not self.itabs:
            return 0
        version = self.version_for_types(version)
        types_base = self.find_types_base()
        if types_base is None:
            log_warn("Unable to locate the Go types region, skipping method prototypes")
            return 0

        applied = 0
        total = 0
        for itab in self.itabs:
            for method in itab.get('methods', []):
                if not method.get('address'):
                    continue
                total += 1
                try:
                    if self.apply_method_prototype(method, types_base, version):
                        applied += 1
                except Exception as e:
                    log_debug(f"Unable to apply the prototype for the method at "
                              f"0x{method['address']:x}: {type(e).__name__}: {e}")
        log_info(f"Applied prototypes to {applied} of {total} itab methods")
        return applied

    def recover(self) -> list:
        log_info("Recovering Go interface tables (itabs)")
        self.itabs = self.collect_itabs()
        for itab in self.itabs:
            self.annotate_itab(itab)
        if self.use_recover_prototypes():
            self.apply_method_prototypes()
        log_info(f"Recovered {len(self.itabs)} itabs")
        return self.itabs

    def run(self):
        return self.recover()
