import functools
import traceback

from collections import defaultdict

from ..internal_types.binaryninja_types import *
from ..internal_types.datatypes import GoVersion, TypeName, GolangType, GolangTypeKind, FuncType

from . import TypeParser
from .common import log_error, log_info, log_debug, sanitize_gotype_name, DEBUG, time_it


def _describe_target(args) -> str:
    try:
        target = args[1] if len(args) > 1 else None
        if isinstance(target, int):
            return f"0x{target:x}"
        address = getattr(target, 'address', None)
        if isinstance(address, int):
            return f"0x{address:x}"
        return repr(target)
    except Exception:
        return "<unknown>"


def fail_gracefully(func):
    @functools.wraps(func,
                     assigned=('cache_info', 'cache_clear'))  # without the assignment the methods are not available
    def wrapped_function(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Do not mask the original failure: log its type and traceback.
            log_error(f"Fail Gracefully in {func.__name__} at {_describe_target(args)}: "
                      f"{type(e).__name__}: {e}")
            log_debug(traceback.format_exc())
            return Type.void()

    return wrapped_function


class StructRecovery(TypeParser):

    # Untrusted sizes/lengths read from the type metadata must not become huge
    # StructureBuilder widths or loops.
    MAX_NATIVE_TYPE_SIZE = 1 << 20
    MAX_ARRAY_ITEMS = 1 << 20

    def __init__(self, bv: bn.BinaryView, name: str = None, target: int = None):
        super().__init__(bv, name, target)
        self.rodata_addr: Union[int, None] = None
        self.go_version: GoVersion = GoVersion.latest()
        self.already_parsed: set[int] = set()
        self.DEBUG_MISSING_TYPES: dict[str, set] = defaultdict(set)

    @classmethod
    def _checked_native_size(cls, size, kind: str, address) -> int:
        if not isinstance(size, int) or size < 0 or size > cls.MAX_NATIVE_TYPE_SIZE:
            raise ValueError(f"Implausible {kind} size {size!r} at 0x{address:x}")
        return size

    @classmethod
    def _checked_item_count(cls, count, kind: str, address) -> int:
        if not isinstance(count, int) or count < 0 or count > cls.MAX_ARRAY_ITEMS:
            raise ValueError(f"Implausible {kind} count {count!r} at 0x{address:x}")
        return count

    def build_types(self):

        log_info("Creating base types and data types")
        data_vars = self.create_types()
        self.already_parsed = set()

        types_base = self.find_types_base()
        if types_base is None:
            log_error("Unable to find the Go types region. Terminating")
            return

        self.rodata_addr = types_base
        self.go_version = self.version_for_types()

        if not data_vars:
            log_error("No Go types were recovered")
            return

        log_info("Recovering and defining types")
        type_created = 0
        for data_var in data_vars:
            if data_var in self.already_parsed:
                log_debug(f"Skipping already parsed 0x{data_var:x}")
                continue
            self.already_parsed.add(data_var)
            self.native_type_mapping(data_var)

            type_created += 1
        log_info(f"Created {type_created} native types")

        if DEBUG:
            if  self.DEBUG_MISSING_TYPES:
                log_debug("Missing kind report: ")
            for k, v in self.DEBUG_MISSING_TYPES.items():
                log_debug(k)
                for addr in v:
                    log_debug(f" {hex(addr)}")

        self.already_parsed = set()
        self.DEBUG_MISSING_TYPES = defaultdict(set)
        self.expire_cache()

    def _has_datavar(self, go_data_type, method_name: str) -> bool:
        if go_data_type is None:
            log_debug(f"{method_name}: missing data variable, skipping")
            return False
        if isinstance(go_data_type, int):
            log_debug(f"{method_name}: expected a data variable, got address 0x{go_data_type:x}")
            return False
        return True

    @fail_gracefully
    @functools.cache
    def define_struct(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define a struct type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """
        if not self._has_datavar(go_data_type, "define_struct"):
            return Type.void()
        struct_size = self._checked_native_size(go_data_type['size'].value, "struct", go_data_type.address)
        fields_count = self._checked_item_count(go_data_type['fields']['Len'].value,
                                                "struct field", go_data_type.address)
        structure = StructureBuilder.create(width=struct_size)
        # Early define for recursive fields
        type_name = self.type_name_from_bn_type(go_data_type)
        self.bv.define_user_type(type_name, structure)

        # Future self note: you get errors when you try to `enumerate` the fields directly from `struct_fields`. Stick
        #  with `range`
        for idx in range(fields_count):
            field = go_data_type['struct_fields'][idx]
            name_addr = field['name'].value
            offset = field['offset'].value
            field_name = TypeName.from_bv(self.bv,
                                          name_addr,
                                          self.rodata_addr,
                                          self.go_version
                                          )
            type_ptr = field['typ'].value
            # TODO revise this lines of code.
            #  Since all the function are guarded by fail_gracefully this should never happen.
            #  On the other hand we would not get parsing errors so the except clause would never be called
            try:
                field_type = self.native_type_mapping(type_ptr)
                structure.insert(offset, field_type, field_name.name)
            except Exception as e:
                # use only safe fields to avoid having new exceptions
                log_debug(f"Error while parsing the field at 0x{type_ptr:x}, defining as void: {e}")
                structure.insert(offset, Type.void(), f"error_field_{idx}[{field_name}]")

            # Creating and destroying types consumes a metric ton of memory.
            # So the struct definition has been moved at the end.
            # if self.bv.get_type_by_name(type_name):
            #     self.bv.undefine_user_type(type_name)
        # We re-define the type at the end. The parsing of the fields must be safe since if any code raises we
        # lose the entire structure
        self.bv.define_user_type(type_name, structure)
        return self.bv.get_type_by_name(type_name).registered_name

    @fail_gracefully
    @functools.cache
    def define_array(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define an array type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """

        if not self._has_datavar(go_data_type, "define_array"):
            return Type.void()
        length = self._checked_item_count(go_data_type['len'].value, "array", go_data_type.address)
        go_version = self.go_version
        rodata = self.rodata_addr
        array_content_type_gotype = GolangType.from_bv(self.bv,
                                                       go_data_type['elem'].value,
                                                       rodata,
                                                       go_version
                                                       )
        array_field_type = self.native_type_mapping(array_content_type_gotype.address)
        return Type.array(array_field_type, length)

    @fail_gracefully
    @functools.cache
    def define_ptr(self, go_data_type: bn.DataVariable, type_suffix='_ptr') -> Type:
        """
        Parse and define a pointer type

        :param go_data_type: the data variable to parse
        :param type_suffix: the suffix to append at the end of the type name
        :return: a binaryninja Type of the data variable
        """

        if not self._has_datavar(go_data_type, "define_ptr"):
            return Type.void()
        go_version = self.go_version
        rodata = self.rodata_addr
        pointed_type_gotype = GolangType.from_bv(self.bv,
                                                 go_data_type['elem'].value,
                                                 rodata,
                                                 go_version
                                                 )
        pointed_type_name = self.type_name_from_gotype(pointed_type_gotype)

        # Check if we are pointing to an already defined type
        pointed_type = self.bv.get_type_by_name(pointed_type_name)

        # if the pointed type does not exist try to define it
        if not pointed_type:
            pointed_type = self.native_type_mapping(pointed_type_gotype.address)

        golang_type = PointerType.create(self.bv.arch, pointed_type)
        type_name = f"{pointed_type_name}{type_suffix}"
        self.bv.define_user_type(type_name, golang_type)
        return self.bv.get_type_by_name(type_name)

    @fail_gracefully
    @functools.cache
    def define_base_types(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define base types like strings, slices and maps

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """
        if not self._has_datavar(go_data_type, "define_base_types"):
            return Type.void()
        go_version = self.go_version
        rodata = self.rodata_addr
        gotype = GolangType.from_bv(self.bv,
                                    go_data_type.address,
                                    rodata,
                                    go_version
                                    )
        kind_unmasked = GolangTypeKind.unmask(gotype.kind)

        # if everything fails return a void ptr
        tb = PointerType.create(self.bv.arch, Type.void())
        if GolangTypeKind.base_type(kind_unmasked):
            tb = get_type_from_base_type_name(self.bv, kind_unmasked.name.lower())
        elif kind_unmasked is GolangTypeKind.STRING:
            tb = get_type_from_tb(self.bv, StringTBuilder)
        elif kind_unmasked is GolangTypeKind.SLICE:
            tb = get_type_from_tb(self.bv, SliceTBuilder)
        elif kind_unmasked is GolangTypeKind.UNSAFEPTR:
            tb = get_type_from_tb(self.bv, UnsafePtrTBuilder)
        elif kind_unmasked is GolangTypeKind.MAP:
            # Yep seems like maps are always ptr
            tb = PointerType.create(
                self.bv.arch,
                get_type_from_tb(self.bv, MapTBuilder)
            )
        else:
            DEBUG and self.DEBUG_MISSING_TYPES[kind_unmasked.name].add(go_data_type.address)

        return tb

    @fail_gracefully
    @functools.cache
    def define_interface(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define an interface type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """

        if not self._has_datavar(go_data_type, "define_interface"):
            return Type.void()
        interface_size = self._checked_native_size(go_data_type['size'].value, "interface", go_data_type.address)
        interface = StructureBuilder.create(width=interface_size)
        # TODO for now some fields of the interface struct are unknown to me
        #   For now make them void ptr to something
        ptr_size = self.bv.arch.address_size
        type_name = self.type_name_from_bn_type(go_data_type)
        # first might be pointer to type Interface
        for idx in range(interface_size // ptr_size):
            if idx == 0:
                interface.append(PointerType.create(self.bv.arch,
                                                    Type.void()),
                                 "interface_type_definition"
                                 )
            else:
                interface.append(PointerType.create(self.bv.arch,
                                                    Type.void()),
                                 f"unk_{idx}"
                                 )
        type_name = f"{type_name}_interface"
        self.bv.define_user_type(type_name, interface)
        return self.bv.get_type_by_name(type_name)

    @fail_gracefully
    @functools.cache
    def define_chan(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define a channel type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """

        if not self._has_datavar(go_data_type, "define_chan"):
            return Type.void()
        # Chan, like maps, tend to be ptr
        type_name = self.type_name_from_bn_type(go_data_type)
        type_name = f"golang_chan_{type_name}_t"
        tb = get_type_from_tb(self.bv, ChanTBuilder)
        self.bv.define_user_type(type_name, tb)
        # TODO find a better way to name the chan
        named_type = self.bv.get_type_by_name(type_name)
        return PointerType.create(self.bv.arch, named_type.registered_name)

    @fail_gracefully
    @functools.cache
    def define_func(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define a func type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """

        if not self._has_datavar(go_data_type, "define_func"):
            return Type.void()
        go_version = self.go_version
        rodata = self.rodata_addr
        gotype = FuncType.from_bv(self.bv,
                                  go_data_type.address,
                                  rodata,
                                  go_version
                                  )

        out_types = []
        for out_param in gotype.out_params:
            if not out_param or gotype.address == out_param:
                # A self pointing return type cannot be resolved recursively.
                log_debug(f"Function type self pointing, short circuiting at 0x{out_param:x}")
                continue
            out_types.append(self.native_type_mapping(out_param))

        # Binary Ninja functions have a single return value. Go can return
        # multiple values, stored back to back in memory, so expose them as a
        # named result struct.
        if not out_types:
            out_type = Type.void()
        elif len(out_types) == 1:
            out_type = out_types[0]
        else:
            result_type_name = f"golang_func_result_{go_data_type.address:x}_t"
            out_type = self.bv.get_type_by_name(result_type_name)
            if out_type is None:
                result_struct = StructureBuilder.create()
                for index, result_type in enumerate(out_types):
                    result_struct.append(result_type, f"ret{index}")
                self.bv.define_user_type(result_type_name, result_struct)
                out_type = self.bv.get_type_by_name(result_type_name) or result_struct

        in_types = []
        # TODO check variadic args
        #   For variadic functions last parameter seems to be a slice
        #   For now set the function as variadic
        for in_type in gotype.in_params:
            if not in_type or in_type == gotype.address:
                log_debug("Self pointing, short circuiting")
                continue
            in_types.append(self.native_type_mapping(in_type))

        ft = Type.function(ret=out_type,
                           params=in_types,
                           variable_arguments=gotype.variadic)
        return PointerType.create(self.bv.arch, ft)

    @fail_gracefully
    @functools.cache
    def native_type_mapping(self, address) -> Type:
        """
        Entry point for the creation ot the types. It will check and branch out calling the proper sub-parsers.
        Subparses might call this functions to define their subfield, as for example the content of an array
        or the fields of a struct

        :param address: the address of the type definition
        :return: a binaryninja Type at the address
        """

        go_version = self.go_version
        ro_start = self.rodata_addr
        if ro_start is None:
            ro_start = self.find_types_base()
            self.rodata_addr = ro_start
        if not address or ro_start is None:
            log_debug(f"native_type_mapping: invalid address 0x{address:x}" if address else "native_type_mapping: no address")
            return Type.void()

        try:
            gotype = GolangType.from_bv(self.bv,
                                        address,
                                        ro_start,
                                        go_version
                                        )
        except Exception as e:
            log_debug(f"Unable to parse the Go type at 0x{address:x}: {e}")
            return Type.void()

        go_data_type = self.bv.get_data_var_at(address)

        # We might encounter a variable which we did not define before
        # example 0x04a7380 in main-1.2
        if not go_data_type:
            log_debug(f"Datavar at 0x{address:x} does not exist. Defining it now")
            self.target = address
            self.create_types()
            go_data_type = self.bv.get_data_var_at(address)
        if go_data_type is None:
            log_debug(f"Datavar at 0x{address:x} still missing, returning void")
            return Type.void()
        kind_unmasked = GolangTypeKind.unmask(gotype.kind)

        if kind_unmasked is GolangTypeKind.ARRAY:
            return self.define_array(go_data_type)
        elif kind_unmasked is GolangTypeKind.PTR:
            return self.define_ptr(go_data_type)
        elif kind_unmasked is GolangTypeKind.STRUCT:
            return self.define_struct(go_data_type)
        elif kind_unmasked is GolangTypeKind.CHAN:
            return self.define_chan(go_data_type)
        elif kind_unmasked is GolangTypeKind.FUNC:
            return self.define_func(go_data_type)
        elif kind_unmasked is GolangTypeKind.INTERFACE:
            return self.define_interface(go_data_type)
        return self.define_base_types(go_data_type)

    def type_name_from_gotype(self, gotype: GolangType) -> str:
        if gotype is None:
            return ""
        type_name = TypeName.from_bv(self.bv,
                                     gotype.resolved_name_addr,
                                     self.rodata_addr,
                                     self.go_version
                                     )
        return sanitize_gotype_name(type_name.name)

    def type_name_from_bn_type(self, gotype: bn.DataVariable) -> str:
        if gotype is None:
            return ""
        name_offset = gotype['nameoff'].value
        # nameOff is relative to the types base for Go 1.12-1.15 and 1.16+.
        name_offset += self.rodata_addr

        type_name = TypeName.from_bv(self.bv,
                                     name_offset,
                                     self.rodata_addr,
                                     self.go_version
                                     )
        return sanitize_gotype_name(type_name.name)

    def expire_cache(self) -> int:
        cleared_count = 0

        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if callable(attr) and hasattr(attr, 'cache_clear'):
                if DEBUG and hasattr(attr, 'cache_info'):
                    cache_info = attr.cache_info()
                    log_debug(f"{attr_name}: hits={cache_info.hits}, misses={cache_info.misses}")
                attr.cache_clear()
                cleared_count += 1

        return cleared_count

    def run(self):
        self.build_types()
