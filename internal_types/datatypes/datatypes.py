import struct
from abc import ABC

from enum import IntEnum
from typing import List, Optional

import binaryninja as bn

from .constants import GoVersion, GolangTypeKind


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def _byteorder(bv: bn.BinaryView) -> str:
    endianness = getattr(bv, "endianness", None)
    if endianness is not None and "Big" in str(endianness):
        return "big"
    return "little"


def _read_uint(bv: bn.BinaryView, address: int, size: int) -> int:
    data = bv.read(address, size)
    if len(data) != size:
        raise ValueError(f"Unable to read {size} bytes at 0x{address:x}")
    return int.from_bytes(data, _byteorder(bv))


def _checked_item_size(count: int, item_size: int, limit: int, address: int) -> int:
    if count < 0 or count > limit:
        raise ValueError(f"Implausible descriptor item count {count} at 0x{address:x}")
    return count * item_size


class GolangBaseType(ABC):

    version: GoVersion = GoVersion.ver118
    address: int = 0x0
    _fields: list[tuple[str, Optional[int]]] = None
    bv: bn.BinaryView = None

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        self.bv = bv
        self.address = address
        self.rodata_start = rodata_start
        self.version = version
        self.ptr_size = ptr_size or bv.arch.address_size
        if autonit:
            self._init_from_raw()

    def field_from_bv(self, bv: bn.BinaryView, size=4, offset=0) -> int:
        if not self.address:
            raise ValueError("Address must be set!")
        data = bv.read(self.address + offset, size)
        return self.decode(size, data)

    def field(self, size=4, offset=0) -> int:
        return self.field_from_bv(self.bv, size, offset)

    @staticmethod
    def decode(size, data) -> int:
        if size == 1:
            return data[0]
        if size == 2:
            return struct.unpack("H", data)[0]
        if size == 4:
            return struct.unpack("I", data)[0]
        if size == 8:
            return struct.unpack("Q", data)[0]
        raise ValueError(f"Invalid size value of {size}")

    def __repr__(self):
        excluded = []
        excluded_types = [bytes]

        nodef_f_vals = []

        for field, value in vars(self).items():
            if field in excluded:
                continue
            if type(value) in excluded_types:
                continue
            nodef_f_vals.append((
                field,
                value
            ))
        nodef_f_repr = ", ".join(f"{name}={value}" for name, value in nodef_f_vals)
        return f"{self.__class__.__name__}({nodef_f_repr})"

    @staticmethod
    def read_varint(bv, start_addr: int) -> (int, int):
        shift = 0
        result = 0
        read = 0
        while True:
            data = bv.read(start_addr + read, 1)
            if not data:
                raise ValueError(f"Unable to read a varint at 0x{start_addr + read:x}")
            i = data[0]
            result |= (i & 0x7f) << shift
            shift += 7
            read += 1
            if not (i & 0x80):
                break
            if read > 10:
                raise ValueError(f"Varint at 0x{start_addr:x} is too long")
        return result, read

    def _init_from_raw(self):
        if self._fields:
            offset = 0
            for field, size in self._fields:
                if callable(size):
                    size = size()
                if size is None or size == '*':
                    size = self.ptr_size
                value = self.field(size, offset)
                setattr(self, field, value)
                offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        # OPT refactor to return the size read?
        ...

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        ...


class MethodType(GolangBaseType):
    name: int = 0
    mtype: int = -1
    ifn: int = -1
    tfn: int = -1

    _fields = (
        ('name', 4),
        ('mtype', 4),
        ('ifn', 4),
        ('tfn', 4),
    )

    def _init_from_raw(self):
        offset = 0
        for field, size in self._fields:
            value = self.field(size, offset)
            setattr(self, field, value)
            offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        method = cls(bv, address)
        return method

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return sum(map(lambda field: field[1], cls._fields))


class IMethodType(GolangBaseType):
    name: int = 0
    typ: int = -1

    _fields = (
        ('name', 4),
        ('typ', 4),
    )

    def _init_from_raw(self):
        offset = 0
        for field, size in self._fields:
            value = self.field(size, offset)
            setattr(self, field, value)
            offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        method = cls(bv, address, rodata_start=rodata_addr)
        return method

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return sum(map(lambda field: field[1], cls._fields))

    @property
    def resolved_typ(self) -> int:
        return self.rodata_start + self.typ

    @property
    def typ_address(self) -> int:
        return self.address + 0x4


class UncommonType(GolangBaseType):
    pkg_path: int = 0
    mcount: int = 0
    xcount: int = 0
    moff: int = 0
    unused: int = 0

    _fields = [
        ('pkg_path', 4),
        ('mcount', 2),
        ('xcount', 2),
        ('moff', 4),
        ('unused', 4)
    ]

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        super().__init__(bv, address, rodata_start, version, ptr_size, autonit)

    def _init_from_raw(self):
        offset = 0
        for field, size in self._fields:
            value = self.field(size, offset)
            setattr(self, field, value)
            offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        return cls(bv, address)

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return sum(map(lambda field: field[1], cls._fields))

    @property
    def resolved_m_offset(self):
        if self.address == 0:
            raise ValueError("Base address not set")
        return self.address + self.moff

    @property
    def has_methods(self):
        return self.mcount > 0


class SliceType(GolangBaseType):
    data_ptr: int = 0
    len: int = 0
    cap: int = 0

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        super().__init__(bv, address, rodata_start, version, ptr_size, False)

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        ptr_size = bv.arch.address_size
        slice_t = cls(bv, address)
        offset = 0
        slice_t.data_ptr = slice_t.field(ptr_size, offset)
        offset += ptr_size
        slice_t.len = slice_t.field(ptr_size, offset)
        offset += ptr_size
        slice_t.cap = slice_t.field(ptr_size, offset)
        return slice_t

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return bv.arch.address_size * 3


class StringType(GolangBaseType):
    data_ptr: int
    size: int

    def _init_from_raw(self):
        self.data_ptr = self.field(self.ptr_size)
        self.size = self.field(self.ptr_size, self.ptr_size)

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        string = cls(bv, address, rodata_addr, version)
        return string

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return bv.arch.address_size * 2


# https://github.com/golang/go/blob/2c358ffe9762ba08c8db0196942395f97775e31b/src/internal/reflectlite/type.go#L151
class GolangType(GolangBaseType):

    rodata_start: int

    size: int = 0
    ptrdata: int = 0
    hash: int = 0
    tflag: int = 0
    align: int = 0
    fieldalign: int = 0
    kind: GolangTypeKind = GolangTypeKind.INVALID
    equal_fn: int = 0
    gcData: int = 0
    nameOff: int = 0
    typeOff: int = 0
    unknown: int = 0

    direct_iface: bool = False
    gc_prog: bool = False
    no_pointers: bool = False

    ptr_size: int = 0x8

    uncommon_type: UncommonType = None
    uncommon_methods: List[MethodType] = []

    # Go 1.16+ _type layout. Kept as immutable templates: the effective field
    # layout is computed per instance (and per binary view) so a 32 bit and a
    # 64 bit view cannot overwrite each other's layout.
    _FIELDS_COMMON = (
        ('size', None),
        ('ptrdata', None),
        ('hash', 4),
        ('tflag', 1),
        ('align', 1),
        ('fieldalign', 1),
        ('kind', 1),
        ('equal_fn', None),
        ('gcData', None),
        ('nameOff', 4),
        ('typeOff', 4),
    )

    # Go 1.12-1.15 _type layout: size, ptrdata, hash, tflag, align,
    # fieldalign, kind, alg (equal_fn), gcdata, nameOff (str), typeOff
    # (ptrToThis). The prefix matches the Go 1.16+ layout; the template is kept
    # explicit so the version split stays documented.
    _FIELDS_GO12 = (
        ('size', None),
        ('ptrdata', None),
        ('hash', 4),
        ('tflag', 1),
        ('align', 1),
        ('fieldalign', 1),
        ('kind', 1),
        ('equal_fn', None),
        ('gcData', None),
        ('nameOff', 4),
        ('typeOff', 4),
    )

    _fields = None

    # Go 1.27 serialized mapType: Key, Elem, Group, Hasher, GroupSize,
    # KeysOff, KeyStride, ElemsOff, ElemStride, ElemOff + Flags (uint32).
    _MAP_TYPE_FIELDS = 10

    MAX_DESCRIPTOR_ITEMS = 1 << 20
    # Upper bound for the inline arrays parsed into objects (interface methods,
    # struct fields): malformed counts must not turn into huge loops.
    MAX_CONTAINER_ITEMS = 1 << 16

    kind_mask: int = (1 << 5) - 1
    direct_iface_mask: int = 1 << 5
    gc_prog_mask: int = 1 << 6
    no_pointers_mask: int = 1 << 7

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        self._fields = None
        self._init_fields(bv, version)
        self.address = address
        super().__init__(bv, address, rodata_start, version, ptr_size, autonit)

    @classmethod
    def fields_layout(cls, ptr_size: int, version: GoVersion = GoVersion.latest()) -> list[tuple[str, int]]:
        template = cls._FIELDS_GO12 if version == GoVersion.ver12 else cls._FIELDS_COMMON
        return [(name, size if size is not None else ptr_size) for name, size in template]

    def _init_fields(self, bv: bn.BinaryView, version: GoVersion):
        self._fields = self.fields_layout(bv.arch.address_size, version)
        return self._fields

    def _init_from_raw(self):
        offset = 0
        for field, size in self._fields:
            value = self.field(size, offset)
            if field == 'kind':
                self.direct_iface = value & self.direct_iface_mask != 0
                self.gc_prog = value & self.gc_prog_mask != 0
                self.no_pointers = value & self.no_pointers_mask != 0
                value = GolangTypeKind(value & self.kind_mask)
            setattr(self, field, value)
            offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        golang_type = cls(bv, address, rodata_addr, version)
        golang_type.address = address
        return golang_type

    def add_uncommon_type(self, bv, address):
        if not self.has_uncommon:
            return 0
        self.uncommon_type = UncommonType.from_bv(bv, address)
        self.uncommon_type.address = address
        return UncommonType.size_from_bv(bv, address)

    def add_uncommon_methods(self, bv):
        if not (self.has_uncommon and self.uncommon_type.has_methods):
            return
        methods_address = self.uncommon_type.resolved_m_offset
        self.uncommon_methods = []
        offset = 0
        for _ in range(self.uncommon_type.mcount):
            self.uncommon_methods.append(MethodType.from_bv(bv, methods_address + offset))
            offset += MethodType.size_from_bv(bv)
        return offset

    @property
    def resolved_name_addr(self) -> int:
        # nameOff is an offset from the types base for Go 1.12-1.15 as well as
        # for newer releases. The pre-Go 1.12 layout, where this field held an
        # absolute pointer to a Go string, is not supported.
        return self.rodata_start + self.nameOff

    @property
    def resolved_type_off(self) -> int:
        return self.rodata_start + self.typeOff

    def address_off(self, field: str) -> int:
        fields = self._fields or self.fields_layout(self.ptr_size or 8, self.version)
        offset = 0
        for name, size in fields:
            if field == name:
                return self.address + offset
            offset += size

    def align_offset(self, address: int, offset: int) -> int:
        if self.fieldalign:
            missalign = (address + offset) % self.fieldalign
            if missalign:
                offset += self.fieldalign - missalign
        return offset

    @staticmethod
    def _coerce_size_args(address: int, version: GoVersion) -> tuple[Optional[int], GoVersion]:
        # Older call sites pass the version as the second positional argument
        # (`super().size_from_bv(bv, version)`); keep accepting that.
        if isinstance(address, GoVersion):
            return None, address
        return address, version

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        _, version = cls._coerce_size_args(address, version)
        return sum(size for _, size in cls.fields_layout(bv.arch.address_size, version))

    @classmethod
    def descriptor_size_from_bv(cls, bv: bn.BinaryView, address: int,
                                version: GoVersion = GoVersion.latest()) -> int:
        """
        Serialized size of the Go type descriptor at ``address``.

        This mirrors ``abi.Type.DescriptorSize``: the base descriptor, the
        uncommon type when present, the kind specific inline data (function
        parameter/result pointers, interface methods, struct fields) and the
        uncommon method table. The Go 1.27 map descriptor layout is assumed;
        that is the layout used by the descriptor walk it is meant for.

        Raises ValueError when the descriptor cannot be sized safely.
        """
        if not address:
            raise ValueError("Address must be set")
        ptr_size = bv.arch.address_size
        header_size = cls.size_from_bv(bv, version=version)
        gotype = cls.from_bv(bv, address, 0, version)
        kind = GolangTypeKind.unmask(gotype.kind)
        if kind is GolangTypeKind.INVALID:
            raise ValueError(f"Invalid type descriptor at 0x{address:x}")

        if kind is GolangTypeKind.ARRAY:
            base_size = header_size + 3 * ptr_size
        elif kind is GolangTypeKind.CHAN:
            base_size = header_size + 2 * ptr_size
        elif kind is GolangTypeKind.FUNC:
            base_size = _align_up(header_size + 4, ptr_size)
        elif kind is GolangTypeKind.INTERFACE:
            base_size = header_size + 4 * ptr_size
        elif kind is GolangTypeKind.MAP:
            base_size = _align_up(header_size + cls._MAP_TYPE_FIELDS * ptr_size + 4, ptr_size)
        elif kind is GolangTypeKind.PTR:
            base_size = header_size + ptr_size
        elif kind is GolangTypeKind.SLICE:
            base_size = header_size + ptr_size
        elif kind is GolangTypeKind.STRUCT:
            base_size = header_size + 4 * ptr_size
        else:
            # bool, numbers, string, unsafe.Pointer: the common descriptor only.
            base_size = header_size

        uncommon_size = 0
        method_count = 0
        if gotype.has_uncommon:
            uncommon_size = UncommonType.size_from_bv(bv)
            method_count = _read_uint(bv, address + base_size + 4, 2)
            if method_count > cls.MAX_DESCRIPTOR_ITEMS:
                raise ValueError(f"Implausible method count {method_count} at 0x{address:x}")

        add_size = 0
        if kind is GolangTypeKind.FUNC:
            in_count = _read_uint(bv, address + header_size, 2)
            out_count = _read_uint(bv, address + header_size + 2, 2) & 0x7fff
            add_size = (in_count + out_count) * ptr_size
        elif kind is GolangTypeKind.INTERFACE:
            # interfaceType: rtype, pkgPath name (ptr), methods []imethod
            methods_len = _read_uint(bv, address + header_size + 2 * ptr_size, ptr_size)
            add_size = _checked_item_size(methods_len, 2 * 4, cls.MAX_DESCRIPTOR_ITEMS, address)
        elif kind is GolangTypeKind.STRUCT:
            # structType: rtype, pkgPath name (ptr), fields []structField
            fields_len = _read_uint(bv, address + header_size + 2 * ptr_size, ptr_size)
            add_size = _checked_item_size(fields_len, 3 * ptr_size, cls.MAX_DESCRIPTOR_ITEMS, address)

        return base_size + uncommon_size + add_size + method_count * 16

    def _is_readable(self, address: int) -> bool:
        try:
            return bool(self.bv.read(address, 1))
        except Exception:
            return False

    @property
    def has_uncommon(self):
        return self.tflag & 0x1 == 1

    @property
    def extra_star(self):
        return self.tflag & (1 << 1) != 0

    @property
    def named(self):
        return self.tflag & (1 << 2) != 0

    @property
    def regular_memory(self):
        return self.tflag & (1 << 3) != 0

    def is_valid(self, types_section: Optional[bn.Section] = None) -> bool:
        """
        Minimal sanity check for a parsed type descriptor.

        ``types_section`` is accepted for API compatibility. It is not used to
        reject descriptors: gcData is a pointer to GC metadata that may live in
        rodata (or be zero for pointer-free types), not necessarily inside the
        types region. It is validated by readability instead.
        """
        if self.kind is GolangTypeKind.INVALID:
            return False
        if self.address and not self._is_readable(self.address):
            return False
        if self.gcData and not self._is_readable(self.gcData):
            return False
        return True


class TypeName(GolangBaseType):
    # Names in real binaries are short, but malformed descriptors can declare
    # enormous lengths. Bound the read instead of allocating untrusted sizes.
    MAX_NAME_LENGTH = 1 << 20

    bitfield: int = 0
    size: int = 0
    name: str = ""

    def _init_from_raw(self):
        # Reads happen defensively: callers use from_bv on possibly malformed
        # nameOff values and a bad read must not raise here.
        try:
            data = self.bv.read(self.address, 1)
        except Exception:
            data = b""
        self.bitfield = data[0] if data else 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):
        type_name = cls(bv, address, rodata_addr, version)
        if not address:
            return type_name

        try:
            if version > GoVersion.ver116:
                # Go 1.17+: bitfield, varint length, name.
                string_len, read = cls.read_varint(bv, address + 0x1)
                name_addr = address + 0x1 + read
            else:
                # Go 1.12-1.16 encoded name: bitfield, 2 byte big endian
                # length at +1, name at +3. nameOff is relative to the types
                # base (see GolangType.resolved_name_addr); the pre-Go 1.12
                # layout that stored an absolute *string is not supported.
                raw_length = bv.read(address + 0x1, 2)
                if len(raw_length) != 2:
                    return type_name
                string_len = int.from_bytes(raw_length, "big")
                name_addr = address + 0x3
        except Exception:
            return type_name

        if string_len <= 0 or string_len > cls.MAX_NAME_LENGTH:
            return type_name

        data = bv.read(name_addr, string_len)
        type_name.size = string_len
        if data:
            # Malformed names are common in stripped binaries: never raise.
            type_name.name = data.decode("utf-8", errors="replace")
        return type_name


class StructField(GolangBaseType):
    name_ptr: int = 0
    type_ptr: int = 0
    offset: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        ptr_size = bv.arch.address_size
        struct_field = cls(bv, address)
        if version == GoVersion.ver12:
            offset = 0
            struct_field.name_ptr = struct_field.field(ptr_size, offset)
            offset += ptr_size
            # skip unk field
            offset += ptr_size
            struct_field.type_ptr = struct_field.field(ptr_size, offset)
            offset += ptr_size
            # skip unk field
            offset += ptr_size
            struct_field.offset = struct_field.field(ptr_size, offset)
        else:
            offset = 0
            struct_field.name_ptr = struct_field.field(ptr_size, offset)
            offset += ptr_size
            struct_field.type_ptr = struct_field.field(ptr_size, offset)
            offset += ptr_size
            struct_field.offset = struct_field.field(ptr_size, offset)
        return struct_field

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        if version == GoVersion.ver12:
            return bv.arch.address_size * 5
        return bv.arch.address_size * 3


class InterfaceType(GolangType):
    """
    type interfaceType struct {
	    rtype
	    pkgPath name      // import path -> it is a ptr?
	    methods []imethod // sorted by hash
    }
    """
    pkgPath: int = 0
    methods: SliceType = None
    methods_array: List[IMethodType] = None

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        super().__init__(bv, address, rodata_start, version, ptr_size, autonit)
        self.methods = SliceType(bv, address, autonit=False)
        self.methods_array = []

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):

        interface_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        offset = super().size_from_bv(bv, version=version)
        interface_type.pkgPath = interface_type.field(bv.arch.address_size, offset)
        offset += bv.arch.address_size

        interface_type.methods = SliceType.from_bv(bv, address + offset, rodata_addr, version)
        if interface_type.methods.len < 0 or interface_type.methods.len > cls.MAX_CONTAINER_ITEMS:
            raise ValueError(f"Implausible interface method count {interface_type.methods.len} at 0x{address:x}")
        offset += SliceType.size_from_bv(bv, address + offset)
        offset += interface_type.add_uncommon_type(bv, address + offset)

        array_instances_offset = 0
        methods_address = interface_type.methods.data_ptr

        for _ in range(interface_type.methods.len):
            interface_type.methods_array.append(
                IMethodType.from_bv(bv,
                                    methods_address + array_instances_offset,
                                    rodata_addr,
                                    version
                                    )
            )
            array_instances_offset += IMethodType.size_from_bv(bv, version)
            offset = interface_type.align_offset(methods_address, offset)

        interface_type.add_uncommon_methods(bv)
        return interface_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        raise NotImplementedError()


class StructType(GolangType):
    pkgPath: int = 0
    fields: SliceType = None
    uncommon_type: UncommonType = None
    fields_list: List[StructField] = None
    uncommon_methods: List[MethodType] = []

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):

        struct_type = cls(bv, address, rodata_addr, version)
        struct_type.address = address
        offset = super().size_from_bv(bv, version=version)
        struct_type.pkgPath = struct_type.field(struct_type.ptr_size, offset)
        offset += struct_type.ptr_size
        struct_type.fields = SliceType.from_bv(bv, address + offset, rodata_addr, version)
        if struct_type.fields.len < 0 or struct_type.fields.len > cls.MAX_CONTAINER_ITEMS:
            raise ValueError(f"Implausible struct field count {struct_type.fields.len} at 0x{address:x}")
        offset += SliceType.size_from_bv(bv)
        offset += struct_type.add_uncommon_type(bv, address + offset)
        if not struct_type.fields_list:
            struct_type.fields_list = []
        offset = 0
        fields_address = struct_type.fields.data_ptr
        for _ in range(struct_type.fields.len):
            struct_type.fields_list.append(
                StructField.from_bv(bv,
                                    fields_address + offset,
                                    rodata_addr,
                                    version))
            offset += StructField.size_from_bv(bv, version)
            # align  the fields
            offset = struct_type.align_offset(address, offset)

        struct_type.add_uncommon_methods(bv)
        return struct_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        # A structure size is dependant from its fields
        address, version = cls._coerce_size_args(address, version)
        if not address:
            raise ValueError("address required")
        tmp_struct = cls.from_bv(bv, address, 0x0, version)
        struct_type_size = super().size_from_bv(bv, version=version) + bv.arch.address_size * 4
        if tmp_struct.has_uncommon:
            struct_type_size += UncommonType.size_from_bv(bv)
        struct_type_size += tmp_struct.fields.len * StructField.size_from_bv(bv, version=version)
        # this is an approximation since there might be some fields which are not alligned
        return struct_type_size


class ArrayType(GolangType):
    element_ptr: int = 0
    slice_ptr: int = 0
    len: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):
        array_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        array_type.address = address
        offset = super().size_from_bv(bv, version=version)
        array_type.element_ptr = array_type.field(array_type.ptr_size, offset)
        offset += array_type.ptr_size
        array_type.slice_ptr = array_type.field(array_type.ptr_size, offset)
        offset += array_type.ptr_size
        array_type.len = array_type.field(array_type.ptr_size, offset)
        offset += array_type.ptr_size
        offset += array_type.add_uncommon_type(bv, address + offset)
        array_type.add_uncommon_methods(bv)
        return array_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        array_size = super().size_from_bv(bv, version=version) + bv.arch.address_size * 3
        return array_size


class ChanDirectionType(IntEnum):
    recv_only = 0x1
    send_only = 0x2
    send_receive = 0x3


class ChanType(GolangType):
    element_ptr: int = 0
    direction: ChanDirectionType = ChanDirectionType.recv_only

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):

        chan_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        chan_type.address = address
        offset = super().size_from_bv(bv, version=version)
        chan_type.element_ptr = chan_type.field(chan_type.ptr_size, offset)
        offset += chan_type.ptr_size
        direction = chan_type.field(chan_type.ptr_size, offset)
        chan_type.direction = ChanDirectionType(direction)
        offset += chan_type.ptr_size
        chan_type.add_uncommon_type(bv, address + offset)
        chan_type.add_uncommon_methods(bv)
        return chan_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        chan_size = super().size_from_bv(bv, version=version) + bv.arch.address_size * 2
        return chan_size


class SliceTType(GolangType):
    element_ptr: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):

        slice_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        slice_type.address = address
        offset = super().size_from_bv(bv, version=version)
        slice_type.element_ptr = slice_type.field(slice_type.ptr_size, offset)
        offset += slice_type.ptr_size
        offset += slice_type.add_uncommon_type(bv, address + offset)
        slice_type.add_uncommon_methods(bv)
        return slice_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        # sliceType keeps a single element pointer.
        slice_size = super().size_from_bv(bv, version=version) + bv.arch.address_size
        return slice_size


class PtrType(GolangType):
    element_ptr: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):
        ptr_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        ptr_type.address = address
        offset = super().size_from_bv(bv, version=version)
        ptr_type.element_ptr = ptr_type.field(ptr_type.ptr_size, offset)
        offset += ptr_type.ptr_size
        offset += ptr_type.add_uncommon_type(bv, address + offset)
        ptr_type.add_uncommon_methods(bv)
        return ptr_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        ptr_type = super().size_from_bv(bv, version=version) + bv.arch.address_size
        return ptr_type


class UnsafePtrType(PtrType):
    pkg_path: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):

        ptr_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        ptr_type.address = address
        offset = super().size_from_bv(bv, version=version)
        ptr_type.pkg_path = ptr_type.field(ptr_type.ptr_size, offset)
        offset += ptr_type.ptr_size
        offset += ptr_type.add_uncommon_type(bv, address + offset)
        ptr_type.add_uncommon_methods(bv)
        return ptr_type


class FuncType(GolangType):
    """
    type funcType struct {
	    rtype
	    inCount  uint16
	    outCount uint16 // top bit is set if last input parameter is ...
    }
    a function type with one method, one input, and one output is:
     struct {
        funcType
        uncommonType
        [2]*rtype  // [0] is in, [1] is out
    }
    """

    in_count: int = 0
    out_count: int = 0
    in_params: list[int] = None
    out_params: list[int] = None
    variadic: bool = False

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        super().__init__(bv, address, rodata_start, version, ptr_size, autonit)
        self.in_params = []
        self.out_params = []

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):

        func_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)

        func_type.address = address

        offset = super().size_from_bv(bv, version=version)
        func_type.in_count = func_type.field(2, offset)
        offset += 2
        func_type.out_count = func_type.field(2, offset)
        offset += 2

        # Top bit is set if out last param is '...'
        if func_type.out_count & (1 << 15):
            func_type.out_count = (func_type.out_count & 0x7fff)
            func_type.variadic = True

        # funcType is padded to pointer alignment before the uncommon type and
        # the inline parameter/result pointer arrays.
        offset = _align_up(offset, bv.arch.address_size)
        offset += func_type.add_uncommon_type(bv, address + offset)

        offset = func_type.align_offset(address, offset)

        for _ in range(func_type.in_count):
            func_type.in_params.append(func_type.field(
                func_type.ptr_size,
                offset))
            offset += bv.arch.address_size

        for _ in range(func_type.out_count):
            func_type.out_params.append(func_type.field(
                func_type.ptr_size,
                offset))
            offset += bv.arch.address_size

        func_type.add_uncommon_methods(bv)
        return func_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        address, version = cls._coerce_size_args(address, version)
        # Header + inCount/outCount, padded to pointer alignment.
        func_type_size = _align_up(super().size_from_bv(bv, version=version) + 4, bv.arch.address_size)
        if address:
            try:
                func_type = cls.from_bv(bv, address, 0, version)
            except Exception:
                return func_type_size
            if func_type.has_uncommon:
                func_type_size += UncommonType.size_from_bv(bv)
            func_type_size += (func_type.in_count + func_type.out_count) * bv.arch.address_size
        return func_type_size


class MapType(GolangType):
    key: int = 0
    elem: int = 0
    bucket: int = 0
    hasher: int = 0
    keysize: int = 0
    valuesize: int = 0
    bucketsize: int = 0
    flags: int = 0

    # Go 1.27 mapType fields. ``go127`` records which layout was parsed;
    # only the matching group of attributes is populated.
    go127: bool = False
    group: int = 0
    group_size: int = 0
    keys_off: int = 0
    key_stride: int = 0
    elems_off: int = 0
    elem_stride: int = 0
    elem_off: int = 0

    _additional_fields = (
        ('key', None),
        ('elem', None),
        ('bucket', None),
        ('hasher', None),
        ('keysize', 1),
        ('valuesize', 1),
        ('bucketsize', 2),
        ('flags', 4)
    )

    # Go 1.27 serialized mapType: Key, Elem, Group, Hasher, GroupSize,
    # KeysOff, KeyStride, ElemsOff, ElemStride, ElemOff (all pointer sized)
    # followed by Flags uint32.
    _additional_fields_go127 = (
        ('key', None),
        ('elem', None),
        ('group', None),
        ('hasher', None),
        ('group_size', None),
        ('keys_off', None),
        ('key_stride', None),
        ('elems_off', None),
        ('elem_stride', None),
        ('elem_off', None),
        ('flags', 4)
    )

    @classmethod
    def _layout_for(cls, go127: bool):
        return cls._additional_fields_go127 if go127 else cls._additional_fields

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118, go127: bool = False):

        map_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        map_type.address = address
        map_type.go127 = bool(go127)

        offset = super().size_from_bv(bv, version=version)
        for field, size in map_type._layout_for(map_type.go127):
            if not size:
                size = map_type.ptr_size
            value = map_type.field(size, offset)
            setattr(map_type, field, value)
            offset += size
        # Go 1.27 pads the uint32 Flags to pointer alignment before the
        # uncommon type.
        offset = _align_up(offset, bv.arch.address_size)
        offset += map_type.add_uncommon_type(bv, address + offset)
        map_type.add_uncommon_methods(bv)
        return map_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None,
                     version: GoVersion = GoVersion.latest(), go127: bool = False):
        base_size = super().size_from_bv(bv, version=version)
        additional_space = 0
        for _, size in cls._layout_for(go127):
            if not size:
                size = bv.arch.address_size
            additional_space += size
        return base_size + _align_up(additional_space, bv.arch.address_size)
