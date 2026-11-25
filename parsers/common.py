import functools

import binaryninja as bn
import struct
import warnings

from binaryninja import redirect_output_to_log, BinaryView, Function
from typing import List
from uuid import uuid4

from ..internal_types.datatypes import GoMagics, GoPclnTab, GoVersion

NAME = 'GoReNinja'
GoFixLogger = bn.Logger(0, NAME)
log_debug = GoFixLogger.log_debug
log_info = GoFixLogger.log_info
log_warn = GoFixLogger.log_warn
log_error = GoFixLogger.log_error

# A pclntab is small compared to the whole binary, but the magic fallback only
# knows the end of the containing allocated range. Cap the single read so a
# corrupt or hostile range cannot allocate an arbitrary amount of memory.
MAX_PCLNTAB_SIZE = 256 * 1024 * 1024

# The 6-byte magic can occur by chance many times. Stop scanning a magic after
# this many candidates that do not carry a valid pclntab header.
MAX_MAGIC_CANDIDATES = 1024

# force logging to debug
DEBUG = False

if DEBUG:
    log_debug = log_info
redirect_output_to_log()

warnings.filterwarnings("ignore", category=DeprecationWarning)


def santize_gofunc_name(name):
    if bn.Settings().get_bool('golang_binary_parser.sanitize'):
        name = name.replace(" ", "")
        name = name.replace('.', '_')
    return name


def sanitize_gotype_name(name: str):
    name = santize_gofunc_name(name)
    if name.startswith('*'):
        name = name[1:]
    return name


def make_component_from_gofunc_name(name: str) -> List[str]:
    if not bn.Settings().get_bool('golang_binary_parser.components'):
        return []

    # There are some special cases like  : and [...]
    # replace them with a placeholder before split
    specials = (
        (':', str(uuid4())),
        ('[...]', str(uuid4()))
    )

    for k, p in specials:
        name = name.replace(k, p)

    name = name.replace('.', '/')

    end = len(name)
    # we do not want to split for dots in {} or []
    # find the lower index of { or [
    for c in ('{', '['):
        tend = name.find(c, 0, end)
        if tend > 0:
            end = tend
    splits = name.count('/', 0, end)

    result = []
    # Substitute back the specials chars
    for token in name.split('/', splits):
        for k, p in specials:
            token = token.replace(p, k)
        result.append(token)
    # Return everything a part from the last token which is the function name
    return result[:-1]


def add_to_component(bv: BinaryView, module: List[str], fn: Function):
    if not module:
        return
    component = None
    full_path = None

    parent = None
    for m in module:
        full_path = "/".join([full_path, m]) if full_path else m
        component = bv.get_component_by_path(full_path)

        if not component:
            component = bv.create_component(m, parent)

        parent = component

    component.add_function(fn)


class GoHelper(bn.plugin.BackgroundTaskThread):
    # Hard ceiling independent from the file size. Real Go binaries stay far
    # below it, but it bounds the work done for a corrupted header.
    MAX_FUNCTAB_ENTRIES = 4 * 1024 * 1024

    def __init__(self, bv: bn.BinaryView, name: str = None):
        name = f"{NAME} ({name})" if name else NAME
        super().__init__(name, True)
        self.bv = bv
        self.br = bn.binaryview.BinaryReader(bv)
        # The table is parsed on first use (see init_gopclntab) so creating a
        # task does not touch the binary until it actually runs.
        self.gopclntab = None
        self._gopclntab_initialized = False

    def init_gopclntab(self):
        """
        Return the fully initialized GoPclnTab, or None when the binary does not
        contain a usable pclntab.

        Both success and failure are cached, so callers can request the table
        again (for lazy initialization) without redoing the work. Without a
        separate flag, None would mean both "not parsed yet" and "failed", and
        every failure would restart the whole scan.
        """
        if getattr(self, 'gopclntab', None) is not None:
            return self.gopclntab
        if getattr(self, '_gopclntab_initialized', False):
            return None

        self._gopclntab_initialized = True
        self.gopclntab = None
        try:
            gopclntab = self._parse_gopclntab()
        except Exception as e:
            log_error(f"Unable to initialize .gopclntab: {type(e).__name__}: {e}")
            gopclntab = None

        self.gopclntab = gopclntab
        return gopclntab

    def _parse_gopclntab(self):
        gopclntab_section = self.get_pclntab_section()

        if gopclntab_section:
            start_addr = gopclntab_section.start
            end_addr = gopclntab_section.end
        else:
            log_debug("Failed to find .gopclntab or __gopclntab section")
            start_addr = self.find_gopclntab_by_magic()
            if start_addr is None:
                log_error("Failed to find section .gopclntab or __gopclntab")
                return None
            # We do not have an end, suppose the end of the allocated range
            end_addr = self._allocated_range_end(start_addr)
            if end_addr is None:
                log_error(f"Failed to find the end for .gopclntab found at {hex(start_addr)}")
                return None
            log_debug(f"Found .gopclntab at {hex(start_addr)}")

        if end_addr is None or end_addr <= start_addr:
            log_error(f"Invalid .gopclntab range 0x{start_addr:x}:0x{end_addr or 0:x}")
            return None

        # The magic fallback only knows the end of the allocated range, which
        # can be much larger than the pclntab. Never read more than the cap; the
        # layout validation below then works against the bytes actually read.
        if end_addr - start_addr > MAX_PCLNTAB_SIZE:
            log_warn(f"Capping the .gopclntab read at 0x{start_addr:x} to "
                     f"{MAX_PCLNTAB_SIZE} bytes (range ends at 0x{end_addr:x})")
            end_addr = start_addr + MAX_PCLNTAB_SIZE

        raw = self.bv[start_addr:end_addr]
        if not raw or len(raw) < 8:
            log_error(f"Unable to read .gopclntab at 0x{start_addr:x}")
            return None

        gopclntab = GoPclnTab(start_addr, end_addr, raw)

        if gopclntab.version == GoVersion.invalid:
            log_error(f"Unknown pclntab version (magic {raw[:6]!r}) at 0x{start_addr:x}")
            return None

        log_debug(f"Found .gopclntab  {hex(gopclntab.start)}")
        log_info(f"gopclntab version is {gopclntab.version}")

        if gopclntab.version != GoVersion.ver12:
            # Version of go different from 12 need to know the text start to calculate the function entry
            text = None
            for segment_name in ('.text', '__text'):
                text = self.get_section_by_name(segment_name)
                if text:
                    break
            if text is None:
                log_error("Unable to find .text section")
                return None

            gopclntab.textStart = text.start

        gopclntab.quantum = gopclntab.get_byte_at(6)
        gopclntab.ptrsize = gopclntab.get_byte_at(7)

        if gopclntab.ptrsize not in gopclntab.valid_ptr_sizes:
            log_error(f"Invalid ptrsize: it is {gopclntab.ptrsize} " +
                      f"but should be in {gopclntab.valid_ptr_sizes}")
            return None
        if gopclntab.quantum not in (1, 2, 4):
            log_error(f"Invalid quantum: it is {gopclntab.quantum}")
            return None

        gopclntab.nfunctab = gopclntab.offset(0)
        gopclntab.nfiletab = gopclntab.offset(1)

        if gopclntab.nfunctab <= 0:
            log_error("The pclntab does not report any function")
            return None

        if not self._init_pclntab_layout(gopclntab):
            return None

        if gopclntab.nfunctab <= 0:
            log_error("The pclntab does not contain any usable function entry")
            return None

        return gopclntab

    def _init_pclntab_layout(self, gopclntab: GoPclnTab) -> bool:
        """
        Fill the table slices according to the pclntab layout version.

        Returns False (after logging the reason) when the offsets are not
        consistent with the available bytes.
        """
        raw_size = len(gopclntab.raw)
        version = gopclntab.version

        if version in (GoVersion.ver118, GoVersion.ver120):
            offsets = [gopclntab.offset(word) for word in range(3, 8)]
            if not self._valid_table_offsets(offsets, raw_size, 8 + 8 * gopclntab.ptrsize):
                log_error(f"Invalid gopclntab offsets {offsets} for {raw_size} bytes")
                return False

            gopclntab.funcnametab = gopclntab.range(3, 4)  # This contains the names of the functions
            gopclntab.cutab = gopclntab.range(4, 5)
            gopclntab.filetab = gopclntab.range(5, 6)
            gopclntab.pctab = gopclntab.range(6, 7)
            gopclntab.funcdata = gopclntab.data(7)  # This is where the functions info are
            gopclntab.functab = gopclntab.data(7)
            self._limit_nfunctab(gopclntab)
            gopclntab.nfiletab = self._limit_nfiletab(gopclntab)
        elif version == GoVersion.ver116:
            offsets = [gopclntab.offset(word) for word in range(2, 7)]
            if not self._valid_table_offsets(offsets, raw_size, 8 + 7 * gopclntab.ptrsize):
                log_error(f"Invalid gopclntab offsets {offsets} for {raw_size} bytes")
                return False

            gopclntab.funcnametab = gopclntab.range(2, 3)
            gopclntab.cutab = gopclntab.range(3, 4)
            gopclntab.filetab = gopclntab.range(4, 5)
            gopclntab.pctab = gopclntab.range(5, 6)
            gopclntab.funcdata = gopclntab.data(6)
            gopclntab.functab = gopclntab.data(6)
            self._limit_nfunctab(gopclntab)
            gopclntab.nfiletab = self._limit_nfiletab(gopclntab)
        elif version == GoVersion.ver12:
            # Not all but it is enough to rename the functions
            gopclntab.nfunctab = gopclntab.uintptr(8)
            if gopclntab.nfunctab <= 0:
                log_error("The Go 1.2 pclntab does not report any function")
                return False
            gopclntab.funcdata = gopclntab.raw
            gopclntab.funcnametab = gopclntab.raw
            gopclntab.pctab = gopclntab.raw
            gopclntab.functab = gopclntab.data_after_offset(8 + gopclntab.ptrsize)
            self._limit_nfunctab(gopclntab)

            fileoff_position = 8 + gopclntab.ptrsize + gopclntab.functabsize
            if fileoff_position + 4 > raw_size:
                log_error("The Go 1.2 pclntab is truncated before the file table")
                return False
            fileoff = struct.unpack("I", gopclntab.raw[fileoff_position:fileoff_position + 4])[0]
            if fileoff < 0 or fileoff + 4 > raw_size:
                log_error(f"Invalid Go 1.2 file table offset 0x{fileoff:x}")
                return False

            gopclntab.filetab = gopclntab.data_after_offset(fileoff)
            nfiletab = struct.unpack("I", gopclntab.filetab[:4])[0]
            max_files = max(0, (len(gopclntab.filetab) - 4) // 4)
            if nfiletab > max_files:
                log_warn(f"gopclntab reports {nfiletab} files but only {max_files} fit in the table")
                nfiletab = max_files
            gopclntab.nfiletab = nfiletab
            gopclntab.filetab = gopclntab.filetab[:(nfiletab + 1) * 4]
        else:
            log_error(f"Unsupported gopclntab version: {version}")
            return False

        return True

    @staticmethod
    def _valid_table_offsets(offsets, raw_size: int, header_size: int) -> bool:
        if not offsets or offsets[0] < header_size:
            return False
        previous = offsets[0]
        for offset in offsets:
            if offset < previous or offset > raw_size:
                return False
            previous = offset
        return True

    def _limit_nfunctab(self, gopclntab: GoPclnTab):
        """
        Clamp the function count to the space actually available, so a corrupt
        header cannot make the caller loop over billions of entries.
        """
        functab_field_size = gopclntab.functabFieldSize()
        if functab_field_size <= 0:
            gopclntab.nfunctab = 0
            gopclntab.functabsize = 0
            gopclntab.functab = b''
            return

        max_entries = min(gopclntab.maxFuncEntries(), self.MAX_FUNCTAB_ENTRIES)

        if gopclntab.nfunctab > max_entries:
            log_warn(f"gopclntab reports {gopclntab.nfunctab} functions but only "
                     f"{max_entries} fit in {len(gopclntab.raw)} bytes; using {max_entries}")
            gopclntab.nfunctab = max_entries

        gopclntab.functabsize = (gopclntab.nfunctab * 2 + 1) * functab_field_size
        gopclntab.functab = gopclntab.functab[:gopclntab.functabsize]

    @staticmethod
    def _limit_nfiletab(gopclntab: GoPclnTab) -> int:
        max_files = gopclntab.filetab.count(b'\x00')
        if gopclntab.nfiletab > max_files:
            log_warn(f"gopclntab reports {gopclntab.nfiletab} files but only "
                     f"{max_files} are present in the file table")
            return max_files
        return gopclntab.nfiletab

    def _allocated_range_end(self, start_addr: int):
        for allocated_range in self.bv.allocated_ranges:
            start = getattr(allocated_range, 'start', None)
            end = getattr(allocated_range, 'end', None)
            if start is not None and end is not None:
                if start <= start_addr < end:
                    return end
            elif start_addr in allocated_range:
                return end
        return None

    def get_pclntab_section(self):
        # ELF binaries call it .gopclntab, Mach-O binaries __gopclntab
        for section_name in ('.gopclntab', '__gopclntab'):
            section = self.get_section_by_name(section_name)
            if section:
                return section
        return None

    def is_valid_gopclntab_header(self, start_addr):
        header = self.bv.read(start_addr, 8)
        if len(header) != 8:
            return False

        quantum, ptrsize = header[6], header[7]
        if quantum not in (1, 2, 4) or ptrsize not in (4, 8):
            return False

        nfunctab = self.bv.read(start_addr + 8, ptrsize)
        return len(nfunctab) == ptrsize and int.from_bytes(nfunctab, 'little') > 0

    def find_gopclntab_by_magic(self):
        # The magic is only 6 bytes long, so it can appear by chance in other
        # data (for example the Go 1.18 magic inside __noptrdata of a Go 1.20
        # binary). Validate every hit and keep looking for a real header, but
        # stop after a bounded number of invalid candidates per magic so a
        # crafted binary cannot turn the scan into unbounded work.
        for go_magic in GoMagics.all():
            start_addr = self.bv.start
            failed_candidates = 0
            while True:
                start_addr = self.bv.find_next_data(start_addr, go_magic)
                if start_addr is None:
                    break
                if self.is_valid_gopclntab_header(start_addr):
                    return start_addr
                failed_candidates += 1
                if failed_candidates >= MAX_MAGIC_CANDIDATES:
                    log_warn(f"Stopping the pclntab search for magic {go_magic!r} "
                             f"after {failed_candidates} invalid candidates")
                    break
                start_addr += 1
        return None

    def get_section_by_name(self, section_name):
        if section_name in self.bv.sections:
            return self.bv.sections[section_name]
        else:
            return None

    def get_pointer_at_virt(self, addr, size=None):
        size = size or self.ptr_size
        x = self.bv.read(addr, size)
        if len(x) == 8:
            return struct.unpack("Q", x)[0]
        elif len(x) == 4:
            return struct.unpack("I", x)[0]
        else:
            raise ValueError("Invalid size {} for pointer; data: {!r}"
                             .format(len(x), x))

    def get_pointer_at(self, at_addr, size=None):
        self.br.seek(at_addr)
        if size is None:
            size = self.ptr_size

        if size == 8:
            return self.br.read64()
        elif size == 4:
            return self.br.read32()
        else:
            raise ValueError(f"Unsupported ptr_size: {size}")

    def get_function_around(self, addr):
        bbl = self.bv.get_basic_blocks_at(addr)
        if not bbl:
            return None
        bb = bbl[0]
        if not bb:
            return None
        return bb.function

    @property
    def ptr_size(self):
        gopclntab = getattr(self, 'gopclntab', None)
        if gopclntab is not None:
            return gopclntab.ptrsize
        bv = getattr(self, 'bv', None)
        arch = getattr(bv, 'arch', None)
        return getattr(arch, 'address_size', 0) or 0

    def quick_go_version(self) -> GoVersion:
        gopclntab = getattr(self, 'gopclntab', None)
        if gopclntab is None:
            gopclntab = self.init_gopclntab()
        if gopclntab is None:
            log_debug("Unable to determine the Go version: no valid gopclntab")
            return GoVersion.invalid
        start_addr = gopclntab.start
        return GoVersion.from_magic(self.bv[start_addr:start_addr + 6])

    def read_varint(self, start_addr: int) -> (int, int):
        shift = 0
        result = 0
        read = 0
        while read < 5:
            data = self.bv.read(start_addr + read, 1)
            if not data:
                break
            i = data[0]
            result |= (i & 0x7f) << shift
            shift += 7
            read += 1
            if not (i & 0x80):
                break
        return result & 0xffffffff, read


def time_it(func):
    @functools.wraps(func)
    def wrapped_function(*args, **kwargs):
        import time  # I do not like to import in functions, but the import is needed only in debug
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        log_debug(f"Execution time of {func} {end_time - start_time}")
        return result


    return wrapped_function
