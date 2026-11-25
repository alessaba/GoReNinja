from typing import Optional, Union

from ..internal_types.binaryninja_types import *
from ..internal_types.datatypes import *

from .common import GoHelper, log_info, log_debug, log_error, log_warn, sanitize_gotype_name, santize_gofunc_name


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


class TypeParser(GoHelper):
    TYPED = [
        'runtime.new',
        'runtime.newobject',
        'runtime.makechan',
        'runtime.makemap',
        'runtime.mapiterinit',
        'runtime.makeslice'
    ]

    TYPE_SUFFIX = "_type"

    # Go PIE/c-shared/plugin binaries keep the type metadata in the
    # non-executable relro copy of .data; prefer it over a possibly executable
    # .rodata (the linker also emits .data.rel.ro in non-PIE builds).
    RODATA_SECTIIONS = ('.data.rel.ro', '.rodata', '__rodata', '.rdata')
    # Keep the correctly spelled alias for new code.
    RODATA_SECTIONS = RODATA_SECTIIONS

    TYPES_SYMBOLS = ('runtime.types', '_runtime.types')
    TYPELINK_SECTIONS = ('__typelink', '.typelink', '.data.rel.ro.typelink')
    GO_TYPE_SECTIONS = ('__go_type', '.go.type', '.data.rel.ro.go.type')
    GO_MODULE_SECTIONS = ('__go_module', '.go.module', '.data.rel.ro.go.module')

    # Go 1.27 moduledata: types, typedesclen, etypes, itaboffset, itabsize are
    # stored in consecutive pointer sized slots. Older moduledata layouts keep
    # the old `typelinks`/`itablinks` slices instead and must not be parsed with
    # these offsets.
    MODULEDATA_TYPES_SLOT = 37
    MODULEDATA_TYPEDESC_LEN_SLOT = 38
    MODULEDATA_ETYPES_SLOT = 39
    MODULEDATA_ITAB_OFFSET_SLOT = 40
    MODULEDATA_ITAB_SIZE_SLOT = 41
    MODULEDATA_MIN_SLOTS = 42

    MAX_TYPE_DESCRIPTORS = 1 << 20
    # A hostile typelink section must not turn into an unbounded list plus one
    # descriptor read per entry. Real tables stay well below this bound.
    MAX_TYPELINK_ENTRIES = 1 << 18

    def __init__(self, bv: bn.BinaryView, name: str = None, target: int = None):
        super().__init__(bv, name)
        self.target: int = target
        self.rodata_section: Union[bn.Section, None] = None
        self.types_base: Optional[int] = None
        self.types_section: Union[bn.Section, None] = None
        self.moduledata: Optional[dict] = None

    # ------------------------------------------------------------------
    # Generic section / memory helpers
    # ------------------------------------------------------------------

    def _byteorder(self) -> str:
        endianness = getattr(self.bv, 'endianness', None)
        if endianness is not None and 'Big' in str(endianness):
            return 'big'
        return 'little'

    def _read_uint(self, address: int, size: int) -> int:
        data = self.bv.read(address, size)
        if len(data) != size:
            raise ValueError(f"Unable to read {size} bytes at 0x{address:x}")
        return int.from_bytes(data, self._byteorder())

    def _read_pointer(self, address: int) -> int:
        return self._read_uint(address, self.bv.arch.address_size)

    def _is_mapped(self, address: Optional[int]) -> bool:
        if not address:
            return False
        try:
            return bool(self.bv.read(address, 1))
        except Exception:
            return False

    def all_sections(self) -> list:
        sections = getattr(self.bv, 'sections', None)
        if sections is None:
            return []
        values = getattr(sections, 'values', None)
        if callable(values):
            try:
                return list(values())
            except Exception:
                return []
        try:
            return list(sections)
        except TypeError:
            return []

    @staticmethod
    def _section_end(section) -> int:
        end = getattr(section, 'end', None)
        if end is not None:
            return end
        return getattr(section, 'start', 0) + getattr(section, 'length', 0)

    @classmethod
    def _section_contains(cls, section, address: int) -> bool:
        return getattr(section, 'start', 0) <= address < cls._section_end(section)

    def find_section(self, names) -> Optional[bn.Section]:
        for section in self.all_sections():
            if getattr(section, 'name', None) in names:
                return section
        return None

    def section_containing(self, address: int) -> Optional[bn.Section]:
        matches = [section for section in self.all_sections()
                   if self._section_contains(section, address)]
        if not matches:
            return None
        # Prefer the most specific section when segments are also present.
        return min(matches, key=lambda section: self._section_end(section) - section.start)

    def _section_is_executable(self, section) -> bool:
        parent = getattr(section, 'parent', None)
        if parent is not None and getattr(parent, 'name', '') in ('__TEXT', '.text', 'TEXT'):
            return True
        flags = getattr(section, 'flags', 0) or 0
        # Mach-O S_ATTR_PURE_INSTRUCTIONS/S_ATTR_SOME_INSTRUCTIONS and ELF SHF_EXECINSTR.
        if flags & 0x80000000 or flags & 0x400 or flags & 0x4:
            return True
        # Binary Ninja Section objects do not consistently expose parent/flags,
        # so use the segment containing the section when available.
        try:
            segment = self.bv.get_segment_at(section.start)
            if segment is not None:
                return bool(segment.executable)
        except Exception:
            pass
        return False

    def get_symbol_address(self, *names: str) -> Optional[int]:
        getter = getattr(self.bv, 'get_symbols_by_name', None)
        if getter is None:
            return None
        for name in names:
            try:
                symbols = getter(name) or []
            except Exception:
                continue
            for symbol in symbols:
                address = getattr(symbol, 'address', None)
                if address and self._is_mapped(address):
                    return address
        return None

    @staticmethod
    def _section_base_name(section) -> str:
        # Binary Ninja disambiguates duplicate section names with a #N suffix
        # (for example __rodata and __rodata#4 on Mach-O).
        return getattr(section, 'name', '').split('#', 1)[0]

    def _rodata_sections(self) -> list:
        return [section for section in self.all_sections()
                if self._section_base_name(section) in self.RODATA_SECTIIONS]

    def _rodata_sort_key(self, section):
        try:
            name_rank = self.RODATA_SECTIIONS.index(self._section_base_name(section))
        except ValueError:
            name_rank = len(self.RODATA_SECTIIONS)
        return (self._section_is_executable(section), name_rank, getattr(section, 'start', 0))

    def preferred_rodata_section(self) -> Optional[bn.Section]:
        candidates = self._rodata_sections()
        if not candidates:
            return None
        candidates.sort(key=self._rodata_sort_key)
        return candidates[0]

    def types_base_candidates(self) -> list:
        candidates = []
        seen = set()

        def add(section):
            key = (getattr(section, 'name', ''), getattr(section, 'start', 0))
            if key not in seen:
                seen.add(key)
                candidates.append(section)

        rodata = self._rodata_sections()
        rodata.sort(key=self._rodata_sort_key)
        for section in rodata:
            add(section)
        # PE keeps the Go metadata in generic sections; only used as a last resort.
        for name in ('.data.rel.ro', '__const', '__data', '.data'):
            for section in self.all_sections():
                if getattr(section, 'name', None) == name:
                    add(section)
        return candidates

    # ------------------------------------------------------------------
    # Types base discovery
    # ------------------------------------------------------------------

    def find_types_base(self) -> Optional[int]:
        """
        Resolve the base used by nameOff/typeOff.

        Order: runtime.types/_runtime.types symbol, the Go 1.27 __go_type
        section, a validated Go 1.27 moduledata, typelinks-aware candidate
        scoring and finally the legacy .rodata/__rodata/.rdata fallback.
        """
        if getattr(self, 'types_base', None):
            return self.types_base
        # The parser instance is bound to a single view: cache the failed scan
        # so repeated lookups (create_types, collect_xrefs, StructureRecovery)
        # do not rescan the same sections.
        if getattr(self, '_types_base_missing', False):
            return None

        go_type_section = self.find_section(self.GO_TYPE_SECTIONS)

        for symbol_name in self.TYPES_SYMBOLS:
            address = self.get_symbol_address(symbol_name)
            if address is not None:
                self.types_base = address
                self.types_section = self.section_containing(address) or go_type_section
                log_debug(f"Found types base from symbol {symbol_name} at 0x{address:x}")
                return address

        if go_type_section is not None:
            # The linker places runtime.types at the start of the type region.
            self.types_base = go_type_section.start
            self.types_section = go_type_section
            log_debug(f"Found Go 1.27 type section {go_type_section.name} at 0x{go_type_section.start:x}")
            return self.types_base

        moduledata = self.find_moduledata()
        if moduledata and moduledata.get('types'):
            self.types_base = moduledata['types']
            self.types_section = self.section_containing(self.types_base)
            log_debug(f"Found types base from moduledata at 0x{self.types_base:x}")
            return self.types_base

        candidates = self.types_base_candidates()
        scored = self._typelink_aware_base(candidates)
        if scored is not None:
            self.types_base = scored.start
            self.types_section = scored
            log_debug(f"Found types base via typelinks at 0x{scored.start:x} ({scored.name})")
            return self.types_base

        if candidates:
            section = candidates[0]
            self.types_base = section.start
            self.types_section = section
            log_debug(f"Falling back to section {section.name} at 0x{section.start:x} for the types base")
            return self.types_base

        log_error("Unable to locate the Go types region")
        self._types_base_missing = True
        return None

    def _typelink_aware_base(self, candidates) -> Optional[bn.Section]:
        typelink_section = self.find_section(self.TYPELINK_SECTIONS)
        if typelink_section is None or not candidates:
            return None
        offsets = self.read_typelink_offsets(typelink_section)
        if not offsets:
            return None
        version = self.version_for_types()
        best_section = None
        best_score = 0
        for section in candidates:
            score = 0
            for offset in offsets:
                if offset > 0 and self._is_plausible_type(section.start + offset, version):
                    score += 1
            if score > best_score:
                best_section = section
                best_score = score
        if best_section is not None:
            log_debug(f"typelinks best candidate {best_section.name} scored {best_score}/{len(offsets)}")
        return best_section

    def addr_in_types(self, address: Optional[int]) -> bool:
        if not self._is_mapped(address):
            return False
        section = getattr(self, 'types_section', None)
        if section is None:
            section = getattr(self, 'rodata_section', None) or self.preferred_rodata_section()
        if section is None:
            return True
        return self._section_contains(section, address)

    # ------------------------------------------------------------------
    # Go 1.27 moduledata
    # ------------------------------------------------------------------

    def _pclntab_start(self) -> Optional[int]:
        gopclntab = getattr(self, 'gopclntab', None)
        return getattr(gopclntab, 'start', None)

    def _looks_like_pclntab(self, address: int) -> bool:
        try:
            magic = self.bv.read(address, 6)
        except Exception:
            return False
        return magic in GoMagics.all()

    def find_moduledata(self) -> Optional[dict]:
        """
        Parse the Go 1.27 moduledata layout only.

        Older moduledata layouts store `typelinks`/`itablinks` where Go 1.27
        stores `typedesclen`/`itaboffset`/`itabsize`; the region validation in
        _parse_moduledata_v127 rejects them so the new offsets never leak into
        older binaries.
        """
        cached = getattr(self, 'moduledata', None)
        if cached:
            return cached
        if getattr(self, '_moduledata_missing', False):
            return None

        # The moduledata scan compares the pcHeader pointer, so make sure the
        # (lazily parsed) pclntab is available before scanning.
        if not getattr(self, 'gopclntab', None):
            init_gopclntab = getattr(self, 'init_gopclntab', None)
            if init_gopclntab is not None:
                try:
                    init_gopclntab()
                except Exception:
                    pass

        go_type_section = self.find_section(self.GO_TYPE_SECTIONS)
        candidates = []
        for name in ('runtime.firstmoduledata', '_runtime.firstmoduledata'):
            address = self.get_symbol_address(name)
            if address is not None:
                candidates.append(address)
                break

        module_section = self.find_section(self.GO_MODULE_SECTIONS)
        if module_section is not None:
            for candidate in self._scan_module_section(module_section):
                if candidate not in candidates:
                    candidates.append(candidate)

        for candidate in candidates:
            parsed = self._parse_moduledata_v127(candidate, go_type_section)
            if parsed is not None:
                self.moduledata = parsed
                log_debug(f"Found Go 1.27 moduledata at 0x{candidate:x}")
                return parsed
        self._moduledata_missing = True
        return None

    def _scan_module_section(self, section) -> list:
        length = self._section_end(section) - section.start
        if length <= 0:
            return []
        try:
            raw = self.bv.read(section.start, length)
        except Exception:
            return []
        ptr_size = self.bv.arch.address_size
        order = self._byteorder()
        expected_header = self._pclntab_start()
        candidates = []
        last_offset = max(0, len(raw) - self.MODULEDATA_MIN_SLOTS * ptr_size)
        if expected_header is None:
            # No known pclntab start: only probe the first few slots; the
            # moduledata parser validates the pcHeader magic anyway.
            probe_end = min(last_offset, 4 * ptr_size)
            return [section.start + offset for offset in range(0, probe_end, ptr_size)]
        for offset in range(0, last_offset, ptr_size):
            value = int.from_bytes(raw[offset:offset + ptr_size], order)
            if value == expected_header:
                candidates.append(section.start + offset)
        return candidates

    def _parse_moduledata_v127(self, address: int, go_type_section) -> Optional[dict]:
        ptr_size = self.bv.arch.address_size
        try:
            header = self._read_pointer(address)
            if not self._is_mapped(header) or not self._looks_like_pclntab(header):
                return None
            types = self._read_pointer(address + self.MODULEDATA_TYPES_SLOT * ptr_size)
            typedesclen = self._read_pointer(address + self.MODULEDATA_TYPEDESC_LEN_SLOT * ptr_size)
            etypes = self._read_pointer(address + self.MODULEDATA_ETYPES_SLOT * ptr_size)
            itaboffset = self._read_pointer(address + self.MODULEDATA_ITAB_OFFSET_SLOT * ptr_size)
            itabsize = self._read_pointer(address + self.MODULEDATA_ITAB_SIZE_SLOT * ptr_size)
        except Exception:
            return None

        if not types or not etypes or etypes <= types:
            return None
        region = etypes - types
        if typedesclen == 0 or typedesclen > region:
            return None
        if itaboffset + itabsize > region:
            return None
        if itabsize and itaboffset < typedesclen:
            return None
        if not self._is_mapped(types):
            return None
        if go_type_section is not None:
            if types != go_type_section.start or etypes != self._section_end(go_type_section):
                return None
        elif not self._is_plausible_type(types + ptr_size, self.version_for_types()):
            return None

        return {
            'address': address,
            'types': types,
            'typedesclen': typedesclen,
            'etypes': etypes,
            'itaboffset': itaboffset,
            'itabsize': itabsize,
        }

    # ------------------------------------------------------------------
    # Version helpers
    # ------------------------------------------------------------------

    def version_for_types(self, version: GoVersion = None) -> GoVersion:
        if version is not None:
            return version
        try:
            version = self.quick_go_version()
        except Exception:
            return GoVersion.latest()
        if version == GoVersion.invalid:
            return GoVersion.latest()
        return version

    def _kind_byte_offset(self, version: GoVersion) -> int:
        # Go 1.12+ keeps the same _type prefix: two pointer sized words
        # (size, ptrdata), a uint32 hash and three bytes (tflag, align,
        # fieldalign) before the kind byte.
        return 2 * self.bv.arch.address_size + 7

    def _type_kind_at(self, address: int, version: GoVersion) -> Optional[GolangTypeKind]:
        try:
            data = self.bv.read(address + self._kind_byte_offset(version), 1)
        except Exception:
            return None
        if not data:
            return None
        return GolangTypeKind(data[0] & 0x1f)

    def _is_plausible_type(self, address: int, version: GoVersion) -> bool:
        kind = self._type_kind_at(address, version)
        return kind is not None and kind is not GolangTypeKind.INVALID

    def use_typelinks(self) -> bool:
        """Read golang_binary_parser.use_typelinks defensively (default true)."""
        key = 'golang_binary_parser.use_typelinks'
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

    def use_go127_map_layout(self) -> bool:
        """
        True when the binary carries the Go 1.27 serialized mapType layout.

        The presence of the __go_type/.go.type section is authoritative. PE
        binaries have no Go specific sections, so a validated Go 1.27
        moduledata is used as the fallback. A pclntab magic alone is not
        enough: Go 1.20-1.26 share it but keep the old map layout.
        """
        cached = getattr(self, '_go127_map_layout', None)
        if cached is not None:
            return cached

        result = self.find_section(self.GO_TYPE_SECTIONS) is not None
        if not result:
            moduledata = self.find_moduledata()
            result = bool(moduledata and moduledata.get('typedesclen'))
        self._go127_map_layout = result
        return result

    # ------------------------------------------------------------------
    # Typelinks
    # ------------------------------------------------------------------

    def read_typelink_offsets(self, section=None) -> list:
        section = section or self.find_section(self.TYPELINK_SECTIONS)
        if section is None:
            return []
        length = self._section_end(section) - section.start
        if length <= 0:
            return []
        entries = length // 4
        max_entries = self.MAX_TYPELINK_ENTRIES
        read_length = min(length, max_entries * 4)
        if entries > max_entries:
            log_warn(f"Typelink section {getattr(section, 'name', '')} has {entries} entries, "
                     f"only the first {max_entries} are considered")
        try:
            raw = self.bv.read(section.start, read_length)
        except Exception:
            return []
        if len(raw) < read_length:
            log_warn(f"Typelink section {getattr(section, 'name', '')} is truncated: "
                     f"read {len(raw)} of {read_length} bytes")
        order = self._byteorder()
        offsets = []
        for index in range(len(raw) // 4):
            value = int.from_bytes(raw[index * 4:index * 4 + 4], order, signed=True)
            offsets.append(value)
        return offsets

    def collect_types_from_typelinks(self, base: int = None, version: GoVersion = None) -> set:
        if not self.use_typelinks():
            return set()
        section = self.find_section(self.TYPELINK_SECTIONS)
        if section is None:
            return set()
        base = base if base is not None else self.find_types_base()
        if not base:
            return set()
        version = self.version_for_types(version)
        offsets = self.read_typelink_offsets(section)
        data_vars = set()
        skipped = 0
        for index, offset in enumerate(offsets):
            try:
                if offset <= 0:
                    skipped += 1
                    continue
                address = base + offset
                if not self._is_mapped(address):
                    skipped += 1
                    continue
                section_for_types = getattr(self, 'types_section', None)
                if section_for_types is not None and not self._section_contains(section_for_types, address):
                    skipped += 1
                    continue
                if not self._is_plausible_type(address, version):
                    skipped += 1
                    continue
                data_vars.add((address, 0))
            except Exception as e:
                skipped += 1
                log_debug(f"Unable to parse typelink entry {index} ({offset}): {e}")
        log_info(f"Found {len(data_vars)} types from {len(offsets)} typelinks ({skipped} skipped)")
        return data_vars

    # ------------------------------------------------------------------
    # Go 1.27 serialized descriptor walk
    # ------------------------------------------------------------------

    def collect_types_from_descriptor_walk(self, base: int = None, version: GoVersion = None) -> set:
        """
        Enumerate the type descriptors serialized in __go_type/.go.type.

        Go 1.27 replaced the typelink table with a back-to-back descriptor
        region: the walk starts at types + ptrSize, is pointer aligned and
        advances by each descriptor's DescriptorSize. It stops at
        types + typedesclen when the moduledata is available, otherwise at the
        section end (and stops as soon as a descriptor cannot be sized).
        """
        if not self.use_typelinks():
            return set()
        section = self.find_section(self.GO_TYPE_SECTIONS)
        moduledata = self.find_moduledata()
        if section is None and not (moduledata and moduledata.get('typedesclen')):
            return set()

        if moduledata and moduledata.get('types'):
            base = moduledata['types']
        if base is None:
            base = self.find_types_base()
        if not base:
            return set()

        if section is not None:
            section_end = self._section_end(section)
        else:
            # PE has no Go specific sections; the moduledata is the only bound.
            section_end = moduledata['etypes'] if moduledata else base

        if moduledata and moduledata.get('typedesclen'):
            end = min(base + moduledata['typedesclen'], section_end)
        else:
            end = section_end

        version = self.version_for_types(version)
        ptr_size = self.bv.arch.address_size
        address = base + ptr_size
        data_vars = set()

        for _ in range(self.MAX_TYPE_DESCRIPTORS):
            address = _align_up(address, ptr_size)
            if address >= end:
                break
            try:
                size = GolangType.descriptor_size_from_bv(self.bv, address, version)
            except Exception as e:
                log_debug(f"Stopping Go 1.27 descriptor walk at 0x{address:x}: {e}")
                break
            if size <= 0 or address + size > end:
                log_debug(f"Stopping Go 1.27 descriptor walk at 0x{address:x}: invalid size {size}")
                break
            data_vars.add((address, 0))
            address += size

        log_info(f"Found {len(data_vars)} types in the serialized type region")
        return data_vars

    # ------------------------------------------------------------------
    # Type recovery
    # ------------------------------------------------------------------

    def create_types(self):

        log_info(f"Creating reference types")
        go_version = self.quick_go_version()
        log_debug(f"Go Version is {go_version}")
        if go_version == GoVersion.invalid:
            # A non-Go binary would otherwise get all the base Go types defined
            # and then fail to find a types region.
            log_info("No valid Go pclntab found, skipping Go type creation")
            return set()

        types_base = self.find_types_base()
        if types_base is None:
            log_error("Unable to find the Go types region. Terminating")
            return

        self.rodata_section = self.types_section or self.preferred_rodata_section()

        already_parsed = set()
        data_vars = set()
        typed_vars = set()

        def add_to_data_vars(addr: int, parent: int = 0, force=False):
            # FIXME some destination have strange addresses :(
            if addr and addr not in already_parsed and (force or self.addr_in_types(addr)):
                data_vars.add((addr, parent))

        created = 0
        exceptions = 0

        # Create base golang type like int, map, etc...
        for type_maker in GOLAND_TYPES:
            name = type_maker.name
            new_type = type_maker().build_type(self.bv, go_version)
            if not new_type:
                log_warn(f"Unable to parse type string {name}")
                continue
            self.bv.define_user_type(name, new_type)

        golang_base_type = self.bv.get_type_by_name(GolangTypeBuilder.name)

        # target is set when the parser is called with an address
        if self.target:
            data_vars.add((self.target, 0))
        else:
            data_vars = self.collect_xrefs()
            data_vars |= self.collect_types_from_typelinks(types_base, go_version)
            data_vars |= self.collect_types_from_descriptor_walk(types_base, go_version)

        log_info("Starting type parsing")

        while len(data_vars) > 0:
            log_debug(f"Left {len(data_vars)}")
            data_var_addr, parent = data_vars.pop()
            log_debug(f"Current addr {data_var_addr:x}")

            if data_var_addr in already_parsed:
                log_debug(f"Skipping already parsed at 0x{data_var_addr:x}")
                continue
            already_parsed.add(data_var_addr)

            try:
                gotype = GolangType.from_bv(self.bv,
                                            data_var_addr,
                                            types_base,
                                            go_version
                                            )
                # Minimum sanity check
                if not gotype.is_valid(self.types_section):
                    log_debug(f"Skipping {hex(data_var_addr)} since invalid")
                    continue
                go_data_type = self.bv.get_data_var_at(data_var_addr)

                # TODO add some sanity checks to the datavar before parsing
                #  maybe checking if the equal_fn **points in the executable section or it is zero (if not fn)

                # get_data_var_at will return None on error
                # funny enough `not <void var>` is `True`
                if go_data_type is None:
                    go_data_type = self.bv.define_user_data_var(data_var_addr, golang_base_type)
                if go_data_type is None:
                    log_debug(f"Unable to define a data variable at 0x{data_var_addr:x}")
                    continue

                if gotype.kind is GolangTypeKind.STRUCT:
                    gotype = StructType.from_bv(self.bv,
                                                go_data_type.address,
                                                types_base,
                                                go_version
                                                )
                    for field in gotype.fields_list:
                        add_to_data_vars(field.type_ptr, 0)
                    new_type, name = GolangStructTypeBuilder().build_type_from_gtype(self.bv, gotype)
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type

                elif gotype.kind is GolangTypeKind.ARRAY:
                    gotype = ArrayType.from_bv(self.bv,
                                               go_data_type.address,
                                               types_base,
                                               go_version
                                               )
                    new_type, name = ArrayTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    add_to_data_vars(gotype.element_ptr)
                    add_to_data_vars(gotype.slice_ptr)
                elif gotype.kind is GolangTypeKind.CHAN:
                    gotype = ChanType.from_bv(self.bv,
                                              go_data_type.address,
                                              types_base,
                                              go_version
                                              )
                    new_type, name = ChanTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    add_to_data_vars(gotype.element_ptr)
                elif gotype.kind is GolangTypeKind.SLICE:
                    gotype = SliceTType.from_bv(self.bv,
                                                go_data_type.address,
                                                types_base,
                                                go_version
                                                )
                    new_type, name = SliceTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                    add_to_data_vars(gotype.element_ptr)
                elif gotype.kind is GolangTypeKind.FUNC:
                    # TODO check if it is possible creating a new function when we parse this type
                    #  since there are interesting information (but it might lack the function addr)
                    gotype = FuncType.from_bv(self.bv,
                                              go_data_type.address,
                                              types_base,
                                              go_version
                                              )
                    new_type, name = FuncTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                    for param in gotype.in_params + gotype.out_params:
                        add_to_data_vars(param)
                elif gotype.kind is GolangTypeKind.PTR:
                    gotype = PtrType.from_bv(self.bv,
                                             go_data_type.address,
                                             types_base,
                                             go_version
                                             )
                    new_type, name = PtrTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                    add_to_data_vars(gotype.element_ptr)
                elif gotype.kind is GolangTypeKind.MAP:
                    go127 = self.use_go127_map_layout()
                    gotype = MapType.from_bv(self.bv,
                                             go_data_type.address,
                                             types_base,
                                             go_version,
                                             go127=go127
                                             )
                    new_type, name = MapTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                    add_to_data_vars(gotype.key)
                    add_to_data_vars(gotype.elem)
                    if not gotype.go127:
                        # Pre-1.27 mapType has a Bucket type pointer; the
                        # Go 1.27 layout replaced it with Group metadata.
                        add_to_data_vars(gotype.bucket)
                    else:
                        # Keep the group/slot descriptor reachable as well.
                        add_to_data_vars(gotype.group)
                # TODO for some strange reason if i parse unsafeptr it will break the array
                elif gotype.kind is GolangTypeKind.INTERFACE:
                    gotype = InterfaceType.from_bv(self.bv,
                                                   go_data_type.address,
                                                   types_base,
                                                   go_version
                                                   )
                    new_type, name = InterfaceTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    for imethod in gotype.methods_array:
                        add_to_data_vars(imethod.resolved_typ, imethod.typ_address)
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                else:
                    # Some unhandled type, so check only for the uncommon type
                    gotype.add_uncommon_type(self.bv,
                                             go_data_type.address + gotype.size_from_bv(self.bv,
                                                                                        gotype.address,
                                                                                        go_version),
                                             )
                    gotype.add_uncommon_methods(self.bv)
                    new_type, name = GolangTypeBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)

                type_name = TypeName.from_bv(self.bv,
                                             gotype.resolved_name_addr,
                                             types_base,
                                             go_version
                                             )

                # DEBUG_kinds[gotype.kind.name].append(gotype)
            except Exception as e:
                exceptions += 1
                log_debug(f"Exception: {hex(data_var_addr)}:{e}")
                continue

            for uncommon_method in gotype.uncommon_methods:
                if uncommon_method.mtype != 0xffffffff:
                    add_to_data_vars(types_base + uncommon_method.mtype, uncommon_method.address)

            name = type_name.name
            if not name or len(name) == 0:
                log_debug("Invalid Name, skipping")
                continue

            log_debug(f"Found name at 0x{gotype.resolved_name_addr:x} with value {name}")

            sanitazed_name = sanitize_gotype_name(name)
            go_data_type.name = f"{sanitazed_name}{self.TYPE_SUFFIX}"
            # add cross-reference for convenience
            self.bv.add_user_data_ref(
                gotype.address_off('nameOff'),
                gotype.resolved_name_addr)

            if parent:
                self.bv.add_user_data_ref(
                    parent,
                    data_var_addr
                )

            name_datavar = self.bv.get_data_var_at(gotype.resolved_name_addr)
            if name_datavar is not None:
                name_datavar.name = f"{go_data_type.name}_name"

            # get any type referencing this type
            if gotype.typeOff != 0x0:
                log_debug("Found type pointing to this type, adding to set to see")
                log_debug(f"Dest will be {hex(gotype.resolved_type_off)}")
                add_to_data_vars(gotype.resolved_type_off, gotype.address_off('typeOff'))

            typed_vars.add(data_var_addr)
            created += 1

        log_info(f"Created {created} go types")
        log_debug(f"  totally parsed sites: {len(already_parsed)}")
        log_debug(f"Exceptions {exceptions}")
        return typed_vars

    # ------------------------------------------------------------------
    # xref based discovery
    # ------------------------------------------------------------------

    def _mlil_call_operations(self) -> tuple:
        operations = getattr(bn, 'MediumLevelILOperation', None)
        if operations is None:
            return ()
        result = []
        for name in ('MLIL_CALL', 'MLIL_TAILCALL', 'MLIL_CALL_UNTYPED'):
            operation = getattr(operations, name, None)
            if operation is not None:
                result.append(operation)
        return tuple(result)

    @staticmethod
    def _constant_from_mlil(expression) -> Optional[int]:
        operation = getattr(expression, 'operation', None)
        operations = getattr(bn, 'MediumLevelILOperation', None)
        if operation is None or operations is None:
            return None
        for name in ('MLIL_CONST', 'MLIL_CONST_PTR', 'MLIL_CONST_DATA'):
            if operation == getattr(operations, name, None):
                value = getattr(expression, 'constant', None)
                if isinstance(value, int):
                    return value
                # Older Binary Ninja versions expose the constant through value.value.
                inner = getattr(expression, 'value', None)
                value = getattr(inner, 'value', None)
                return value if isinstance(value, int) else None
        return None

    @staticmethod
    def _constant_from_hlil(expression) -> Optional[int]:
        operation = getattr(expression, 'operation', None)
        operations = getattr(bn, 'HighLevelILOperation', None)
        if operation is None or operations is None:
            return None
        for name in ('HLIL_CONST', 'HLIL_CONST_PTR', 'HLIL_CONST_DATA'):
            if operation == getattr(operations, name, None):
                value = getattr(expression, 'constant', None)
                return value if isinstance(value, int) else None
        return None

    def _call_argument_constants(self, caller_site) -> list:
        """
        Constants passed to a call site, preferring MLIL and using HLIL only
        when the MLIL is not available. Non constant arguments are skipped.
        """
        try:
            mlil = caller_site.mlil
        except Exception:
            mlil = None
        if mlil is not None:
            if getattr(mlil, 'operation', None) not in self._mlil_call_operations():
                return []
            constants = []
            for parameter in getattr(mlil, 'params', None) or []:
                value = self._constant_from_mlil(parameter)
                if value is not None:
                    constants.append(value)
            return constants

        try:
            hlil = caller_site.hlil
        except Exception:
            hlil = None
        if hlil is not None:
            operations = getattr(bn, 'HighLevelILOperation', None)
            call_operations = ()
            if operations is not None:
                call_operations = tuple(op for op in (getattr(operations, 'HLIL_CALL', None),
                                                      getattr(operations, 'HLIL_TAILCALL', None))
                                        if op is not None)
            if getattr(hlil, 'operation', None) not in call_operations:
                return []
            constants = []
            for parameter in getattr(hlil, 'params', None) or []:
                value = self._constant_from_hlil(parameter)
                if value is not None:
                    constants.append(value)
            return constants
        return []

    def iter_type_call_sites(self):
        """
        Yield one record for every call site that passes a Go type descriptor to
        one of the TYPED runtime functions.

        Each record is a dict with:

        * ``function_name``: the name of the typed runtime function (the name
          exposed by the recovered function, so it may be sanitized).
        * ``caller_site``: the Binary Ninja reference source of the call.
        * ``il_instruction``: the MLIL call instruction, or the HLIL instruction
          when MLIL is unavailable.
        * ``type_address``: the first constant argument that lands in the Go
          types region.

        The argument constants come from ``_call_argument_constants``, so MLIL
        is preferred and HLIL is used only as its fallback.
        """
        self.find_types_base()

        get_functions_by_name = getattr(self.bv, 'get_functions_by_name', None)
        if not callable(get_functions_by_name):
            return

        for typed_function in self.TYPED:
            functions = get_functions_by_name(typed_function)
            if not functions:
                # maybe the name was generated by `FunctionRenamer` and therefore sanitized
                sanitized_typed_function = santize_gofunc_name(typed_function)
                functions = get_functions_by_name(sanitized_typed_function)

            for function in functions:
                log_info(f"Parsing function {function.name}")
                if not getattr(function, 'parameter_vars', None):
                    continue

                # Collect direct references, since after we have to expand the list
                # with the references from typeoff
                try:
                    caller_sites = getattr(function, 'caller_sites', None) or []
                except Exception:
                    caller_sites = []
                for caller_site in caller_sites:
                    try:
                        constants = self._call_argument_constants(caller_site)
                    except Exception as e:
                        log_debug(f"Unable to parse the call site at 0x{getattr(caller_site, 'address', 0):x}: {e}")
                        continue
                    # This is very crude, since it works under the assumption that the first parameter points
                    #  to the type definition, but it generally works.
                    # Look for constants/constant pointers landing in the types section.
                    type_address = None
                    for value in constants:
                        if self.addr_in_types(value):
                            type_address = value
                            break
                    if type_address is None:
                        log_debug(f"No type argument at 0x{getattr(caller_site, 'address', 0):x}")
                        continue

                    try:
                        mlil = getattr(caller_site, 'mlil', None)
                    except Exception:
                        mlil = None
                    if mlil is not None and getattr(mlil, 'operation', None) in self._mlil_call_operations():
                        il_instruction = mlil
                    else:
                        try:
                            il_instruction = getattr(caller_site, 'hlil', None)
                        except Exception:
                            il_instruction = None

                    yield {
                        'function_name': function.name,
                        'caller_site': caller_site,
                        'il_instruction': il_instruction,
                        'type_address': type_address,
                    }

    def collect_xrefs(self) -> set:
        data_vars = set()
        log_info("Searching for functions accessing type objects")
        log_info(f"Will search for {len(self.TYPED)} functions {','.join(self.TYPED)}")

        for call_site in self.iter_type_call_sites():
            data_vars.add((call_site['type_address'], 0))

        log_info(f"Found {len(data_vars)} xrefs")
        return data_vars

    def run(self):
        self.create_types()
