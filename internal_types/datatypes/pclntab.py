import struct

from typing import Optional

from .constants import GoVersion


def _repr_fields(instance, excluded=()) -> list:
    """
    Return the non-bytes attributes of a plain Python object for __repr__.

    The pclntab classes are not dataclasses, so dataclasses.fields() raises
    TypeError on them.
    """
    fields = []
    for name, value in vars(instance).items():
        if name in excluded or isinstance(value, (bytes, bytearray)):
            continue
        fields.append((name, value))
    return fields


class LineTableEntry:
    field_size: int
    raw: bytes

    ptrsize: int = 4

    def __init__(self, ptrsize: int = 4, functabFieldSize: int = 4, raw: bytes = None) -> None:
        if raw is None:
            raw = []
        self.ptrsize = ptrsize
        self.field_size = functabFieldSize
        self.raw = raw

    @property
    def size(self) -> int:
        return self.field_size * 2

    @property
    def entry(self) -> int:
        return self.value_to_uintptr(self.raw[:self.field_size])

    @property
    def funcOff(self) -> int:
        return self.value_to_uintptr(self.raw[self.field_size:])

    def value_to_uintptr(self, value: bytes) -> int:
        if len(value) < self.ptrsize:
            return 0
        if self.ptrsize == 8:
            return struct.unpack("Q", value[:8])[0]
        elif self.ptrsize == 4:
            return struct.unpack("I", value[:4])[0]
        return 0


# https://github.com/golang/go/blob/2c358ffe9762ba08c8db0196942395f97775e31b/src/runtime/runtime2.go#L882
class FuncEntry:
    raw: bytes
    ptrsize: int
    textStart: int = 0

    # Smallest number of bytes needed to read every field we expose.
    MIN_SIZE = 36

    nameOffset: int = 0
    resolvedName: str = ''

    args: int = 0
    # Legacy name for the third _func field in Go 1.2 - 1.15.
    frame: int = 0
    deferreturn: int = 0
    pcsp: int = 0
    pcfile: int = 0
    pcln: int = 0
    npcdata: int = 0
    nfuncdata: int = 0
    cuOffset: int = 0
    startLine: int = -1

    version: GoVersion = GoVersion.ver118

    def __init__(self, raw: bytes, ptrsize: int, textStart: int = 0, version: GoVersion = GoVersion.ver118):
        self.raw = raw or b''
        self.ptrsize = ptrsize
        self.version = version
        self.textStart = textStart
        self.__init_from_raw()

    def __init_from_raw(self):
        """
        Decode the _func struct.

        Go 1.2 - 1.15:
            entry, nameoff, args, frame, pcsp, pcfile, pcln, npcdata, nfuncdata

        Go 1.16+ (ver116 differs only by the entry width):
            entry, nameoff, args, deferreturn, pcsp, pcfile, pcln, npcdata,
            cuOffset, startLine
        """
        self.nameOffset = self.field(1)
        self.args = self.field(2)

        if self.version == GoVersion.ver12:
            self.frame = self.field(3)
            self.deferreturn = 0
            self.pcsp = self.field(4)
            self.pcfile = self.field(5)
            self.pcln = self.field(6)
            self.npcdata = self.field(7)
            self.nfuncdata = self.field(8)
            self.cuOffset = 0
            self.startLine = -1
            return

        entry_size = 4 if self.version >= GoVersion.ver118 else self.ptrsize
        self.deferreturn = self.field(3)
        self.pcsp = self.field(4)
        self.pcfile = self.field(5)
        self.pcln = self.field(6)
        self.npcdata = self.field(7)
        self.cuOffset = self.field(8)

        # startLine was added in Go 1.18; before that the field after cuOffset
        # contains funcID/flags followed by nfuncdata.
        if self.version >= GoVersion.ver118:
            self.startLine = self.field(9)
            nfuncdata_offset = entry_size + 9 * 4 + 3
        else:
            self.startLine = -1
            nfuncdata_offset = entry_size + 8 * 4 + 3
        self.nfuncdata = self.get_byte_at(nfuncdata_offset)

    @property
    def entry(self) -> int:
        """
        func (f *funcData) entryPC() uint64 {
        // In Go 1.18, the first field of _func changed
        // from a uintptr entry PC to a uint32 entry offset.
        if f.t.version >= ver118 {
            return uint64(f.t.binary.Uint32(f.data)) + f.t.textStart
        }
        return f.t.uintptr(f.data)
        }
        """
        if self.version >= GoVersion.ver118:
            if len(self.raw) < 4:
                return 0
            data = self.raw[:4]
            return struct.unpack("I", data)[0] + self.textStart

        if len(self.raw) < self.ptrsize:
            return 0
        data = self.raw[:self.ptrsize]
        if self.ptrsize == 8:
            return struct.unpack("Q", data)[0]
        elif self.ptrsize == 4:
            return struct.unpack("I", data)[0]
        return 0

    def field(self, idx: int) -> int:
        """
        func (f funcData) field(n uint32) uint32 {
            if n == 0 || n > 9 {
                panic("bad funcdata field")
            }
            // In Go 1.18, the first field of _func changed
            // from a uintptr entry PC to a uint32 entry offset.
            sz0 := f.t.ptrsize
            if f.t.version >= ver118 {
                sz0 = 4
            }
            off := sz0 + (n-1)*4 // subsequent fields are 4 bytes each
            data := f.data[off:]
            return f.t.binary.Uint32(data)
        }
        """
        if idx <= 0:
            return 0
        entry_field_size = self.ptrsize
        if self.version >= GoVersion.ver118:
            entry_field_size = 4

        offset_in_data = entry_field_size + (idx - 1) * 4
        data = self.raw[offset_in_data:offset_in_data + 4]
        if len(data) < 4:
            return 0
        return struct.unpack("I", data)[0]

    def get_byte_at(self, offset: int) -> int:
        if 0 <= offset < len(self.raw):
            return self.raw[offset]
        return 0

    def __repr__(self):
        nodef_f_vals = _repr_fields(self, excluded=('raw',))
        nodef_f_vals.append((
            "functionEntry",
            hex(self.entry),
        ))

        nodef_f_repr = ", ".join(f"{name}={value}" for name, value in nodef_f_vals)
        return f"{self.__class__.__name__}({nodef_f_repr})"


class GoPclnTab:
    # Hard ceiling for the parsed source-file list, so a corrupt nfiletab
    # cannot allocate an unbounded list.
    MAX_FILE_ENTRIES = 4 * 1024 * 1024

    start: int
    end: int
    raw: bytes

    quantum: int  # instruction size
    ptrsize: int  # pointer size

    valid_ptr_sizes: list

    version: GoVersion = GoVersion.ver118

    textStart: int = 0

    funcnametab: bytes = bytes()
    cutab: bytes = bytes()
    funcdata: bytes = bytes()
    functab: bytes = bytes()
    functabsize: int = 0
    nfunctab: int = 0
    filetab: bytes = bytes()
    pctab: bytes = bytes()

    nfiletab: int = 0

    _file_names = None
    _file_cache_version = None
    _file_cache_count = -1
    _file_cache_filetab = None
    _file_cache_funcdata = None

    def __init__(self, start, end, raw):
        self.start = start
        self.end = end
        self.raw = raw or b''
        self.version = GoVersion.from_magic(self.raw[:6])
        self.valid_ptr_sizes = [4, 8]
        # These are overwritten by GoHelper with the values from the header;
        # the defaults keep a standalone table usable in tests.
        self.quantum = self.get_byte_at(6) or 1
        self.ptrsize = self.get_byte_at(7) or 4

    def functabFieldSize(self) -> int:
        if self.version >= GoVersion.ver118:
            return 4
        return self.ptrsize

    def get_byte_at(self, offset: int) -> int:
        if 0 <= offset < len(self.raw):
            return self.raw[offset]
        return 0

    def offset(self, word: int) -> int:
        if word < 0:
            return 0
        off = 8 + word * self.ptrsize
        data = self.raw[off:off + self.ptrsize]

        if self.ptrsize == 8 and len(data) == 8:
            return struct.unpack("Q", data)[0]
        elif self.ptrsize == 4 and len(data) == 4:
            return struct.unpack("I", data)[0]
        return 0

    def data(self, word: int) -> bytes:
        if word < 0:
            return b''
        return self.raw[self.offset(word):]

    def data_after_offset(self, offset: int) -> bytes:
        if offset < 0:
            return b''
        return self.raw[offset:]

    def range(self, start: int, end: int) -> bytes:
        if start < 0 or end < 0:
            return b''
        ostart = self.offset(start)
        oend = self.offset(end)
        if oend < ostart:
            return b''
        return self.raw[ostart:oend]

    def uintptr(self, offset: int) -> int:
        if offset < 0:
            return 0
        value = self.raw[offset:offset + self.ptrsize]
        return self.value_to_uintptr(value)

    def value_to_uintptr(self, value: bytes) -> int:
        if len(value) < self.ptrsize:
            return 0
        if self.ptrsize == 8:
            return struct.unpack("Q", value[:8])[0]
        elif self.ptrsize == 4:
            return struct.unpack("I", value[:4])[0]
        return 0

    def uint(self, raw: bytes) -> int:
        """
        func (f funcTab) uint(b []byte) uint64 {
            if f.sz == 4 {
                return uint64(f.binary.Uint32(b))
            }
            return f.binary.Uint64(b)
        }
        """
        if self.functabFieldSize() == 4:
            if len(raw) < 4:
                return 0
            data = raw[:4]
            return struct.unpack("I", data)[0]
        if len(raw) < 8:
            return 0
        data = raw[:8]
        return struct.unpack("Q", data)[0]

    def maxFuncEntries(self) -> int:
        """
        Maximum number of function entries that can fit in the available
        functab/funcdata bytes. Callers use it to bound loops on corrupt tables.
        """
        functab_field_size = self.functabFieldSize()
        if functab_field_size <= 0:
            return 0

        by_functab = max(0, (len(self.functab) - functab_field_size) // (2 * functab_field_size))
        func_entry_size = (4 if self.version >= GoVersion.ver118 else self.ptrsize) + 8 * 4
        if func_entry_size <= 0:
            return 0
        by_funcdata = max(0, len(self.funcdata) // func_entry_size)
        return min(by_functab, by_funcdata)

    def funcOff(self, idx: int) -> int:
        """
        func (f funcTab) funcOff(i int) uint64 {
            return f.uint(f.functab[(2*i+1)*f.sz:])
        }
        """
        if idx < 0:
            return -1
        sz = self.functabFieldSize()
        start_idx = sz * (2 * idx + 1)
        end_idx = start_idx + sz
        return self.uint(self.functab[start_idx:end_idx])

    def funcAt(self, idx: int) -> Optional[FuncEntry]:
        """
        func (t *LineTable) funcData(i uint32) funcData {
            data := t.funcdata[t.funcTab().funcOff(int(i)):]
            return funcData{t: t, data: data}
        }
        """

        function_start_offset = self.funcOff(idx)
        if function_start_offset <= 0:
            return None
        """
        sizeof(funcdata_x):
            go >= 18 -> 10 * sizeof(uint32)
            go < 18 -> ptrsize + 9 * sizeof(uint32)

        the structure has only 9 fields documented but the index can go from 0 to 9

        consider worst case:
        ptrsize = 8
        sizeof(uint32) = 4
        """

        function_data_size = 8 + 9 * 4
        function_end_offset = function_start_offset + function_data_size
        data = self.funcdata[function_start_offset:function_end_offset]
        if len(data) < FuncEntry.MIN_SIZE:
            return None

        return FuncEntry(data, self.ptrsize, self.textStart, self.version)

    def go12FuncAt(self, idx: int) -> Optional[FuncEntry]:
        if idx < 0:
            return None
        line_table_entry = LineTableEntry(self.ptrsize, self.functabFieldSize())
        ostart = line_table_entry.size * idx
        oend = ostart + line_table_entry.size
        line_table_entry.raw = self.functab[ostart:oend]
        if len(line_table_entry.raw) < line_table_entry.size:
            return None

        function_start_offset = line_table_entry.funcOff
        if function_start_offset <= 0:
            return None
        function_data_size = 8 + 9 * 4
        function_end_offset = function_start_offset + function_data_size
        data = self.funcdata[function_start_offset:function_end_offset]
        if len(data) < FuncEntry.MIN_SIZE:
            return None
        return FuncEntry(data, self.ptrsize, self.textStart, self.version)

    def funcName(self, offset: int) -> str:
        """
        func (t *LineTable) funcName(off uint32) string {
        if s, ok := t.funcNames[off]; ok {
            return s
        }
        i := bytes.IndexByte(t.funcnametab[off:], 0) -> search for the 0 terminator
        s := string(t.funcnametab[off : off+uint32(i)])
        t.funcNames[off] = s
            return s
        }
        """
        if offset < 0 or offset >= len(self.funcnametab):
            return ''

        # search for the terminator '\00'
        end = self.funcnametab.find(0, offset)
        if end < 0:
            end = len(self.funcnametab)
        name_bytes = self.funcnametab[offset:end]

        return name_bytes.decode('utf-8', errors='replace')

    def funcInfo(self, idx: int) -> Optional[FuncEntry]:
        function = self.funcAt(idx)
        if function is None:
            return None
        function.resolvedName = self.funcName(function.nameOffset)
        return function

    def go12FuncInfo(self, idx: int) -> Optional[FuncEntry]:
        function = self.go12FuncAt(idx)
        if function is None:
            return None
        function.resolvedName = self.funcName(function.nameOffset)
        return function

    def fileNames(self) -> list:
        """
        Return the source file table parsed once.

        Go 1.2 stores 32-bit offsets into funcdata in filetab (the first word
        is the number of files), while newer versions store NUL-terminated
        strings directly. Entries that cannot be read are kept as empty bytes,
        which is what fileName has always returned for them.
        """
        if (self._file_names is None
                or self._file_cache_version != self.version
                or self._file_cache_count != self.nfiletab
                or self._file_cache_filetab is not self.filetab
                or (self.version == GoVersion.ver12
                    and self._file_cache_funcdata is not self.funcdata)):
            self._file_names = self._parse_file_names()
            self._file_cache_version = self.version
            self._file_cache_count = self.nfiletab
            self._file_cache_filetab = self.filetab
            self._file_cache_funcdata = self.funcdata
        return self._file_names

    def _parse_file_names(self) -> list:
        count = max(0, self.nfiletab)
        if self.version == GoVersion.ver12:
            # Index 0 of filetab stores the number of files, so there are at
            # most len(filetab) // 4 - 1 usable offset entries.
            max_entries = max(0, len(self.filetab) // 4 - 1)
        else:
            # Every entry needs at least its NUL terminator.
            max_entries = len(self.filetab)
        count = min(count, max_entries, self.MAX_FILE_ENTRIES)

        names = []
        if self.version == GoVersion.ver12:
            for idx in range(count):
                start = 4 * (idx + 1)
                offset = struct.unpack("I", self.filetab[start:start + 4])[0]
                if offset >= len(self.funcdata):
                    names.append(b'')
                    continue
                string_end = self.funcdata.find(0, offset)
                if string_end < 0:
                    names.append(b'')
                    continue
                names.append(self.funcdata[offset:string_end])
            return names

        offset = 0
        for idx in range(count):
            string_end = self.filetab.find(0, offset)
            if string_end < 0:
                names.extend([b''] * (count - idx))
                break
            names.append(self.filetab[offset:string_end])
            offset = string_end + 1
        return names

    def fileName(self, idx) -> bytes:
        if idx < 0 or idx >= self.nfiletab:
            return b''

        names = self.fileNames()
        if idx >= len(names):
            return b''
        return names[idx]

    def pc2filename(self, function: FuncEntry) -> bytes:
        """
        func (t *LineTable) go12PCToFile(pc uint64) (file string) {
            entry := f.entryPC()
            filetab := f.pcfile()
            fno := t.pcvalue(filetab, entry, pc)
            if t.version == ver12 {
                if fno <= 0 {
                    return ""
                }
                return t.string(t.binary.Uint32(t.filetab[4*fno:]))
            }
            // Go ≥ 1.16
            if fno < 0 { // 0 is valid for ≥ 1.16
                return ""
            }
            cuoff := f.cuOffset()
            if fnoff := t.binary.Uint32(t.cutab[(cuoff+uint32(fno))*4:]); fnoff != ^uint32(0) {
                return t.stringFrom(t.filetab, fnoff)
            }
            return ""
        }
        """
        if function is None:
            return b''
        entry = function.entry
        filetab = function.pcfile
        targetpc = function.entry
        offset = self.pcvalue(filetab, entry, targetpc)

        if self.version == GoVersion.ver12:
            if offset <= 0:
                return b''
            else:
                return self.fileName(offset - 1)
        if offset < 0:
            return b''

        compilation_unit_offset = function.cuOffset
        start = (compilation_unit_offset + offset) * 4
        if start < 0 or len(self.cutab[start:start + 4]) != 4:
            return b''
        offset = struct.unpack("I", self.cutab[start:start + 4])[0]
        if offset != self.make_mask(4):
            if offset >= len(self.filetab):
                return b''
            string_end = self.filetab.find(0, offset)
            if string_end < 0:
                return b''
            string = self.filetab[offset:string_end]
            return string
        return b''

    def pc2line(self, function: FuncEntry, targetpc: int = None) -> int:
        """
        Return the source line associated with targetpc (the function entry by
        default), or -1 when the table does not carry line information.
        """
        if function is None or self.version == GoVersion.ver12:
            return -1
        targetpc = function.entry if targetpc is None else targetpc
        return self.pcvalue(function.pcln, function.entry, targetpc)

    def pcvalue(self, offset: int, pc: int, targetpc: int) -> int:
        """
        func (t *LineTable) pcvalue(off uint32, entry, targetpc uint64) int32 {
            p := t.pctab[off:]

            val := int32(-1)
            pc := entry
            for t.step(&p, &pc, &val, pc == entry) {
                if targetpc < pc {
                    return val
                }
            }
            return -1
        }
        """
        if offset < 0 or offset >= len(self.pctab):
            return -1

        val = -1
        offset, pc, val, ok = self.step(self.pctab, offset, pc, val, True)
        while ok:
            if targetpc < pc:
                return val
            offset, pc, val, ok = self.step(self.pctab, offset, pc, val, False)
        return -1

    def step(self, table: bytes, offset_in_table: int, pc: int, val: int, first: bool) -> (int, int, int, bool):
        """
        // step advances to the next pc, value pair in the encoded table.
        func (t *LineTable) step(p *[]byte, pc *uint64, val *int32, first bool) bool {
            uvdelta := t.readvarint(p)
            if uvdelta == 0 && !first {
                return false
            }
            if uvdelta&1 != 0 {
                uvdelta = ^(uvdelta >> 1)
            } else {
                uvdelta >>= 1
            }
            vdelta := int32(uvdelta) -> there might be some type/sign shenanigans
            pcdelta := t.readvarint(p) * t.quantum
            *pc += uint64(pcdelta)
            *val += vdelta
            return true
        }
        """
        if offset_in_table < 0 or offset_in_table >= len(table):
            return offset_in_table, pc, val, False

        uvdelta, read = self.read_varint(table, offset_in_table)
        if read == 0:
            return offset_in_table, pc, val, False
        offset_in_table += read

        if uvdelta == 0 and not first:
            return offset_in_table, pc, val, False

        # Zig-zag encoding: odd values encode negative deltas. Go stores the
        # complement in a uint32 and converts it to int32, which in Python is
        # simply the bitwise complement of the shifted value.
        if uvdelta & 1:
            vdelta = ~(uvdelta >> 1)
        else:
            vdelta = uvdelta >> 1

        pcdelta, read = self.read_varint(table, offset_in_table)
        offset_in_table += read
        pcdelta = pcdelta * self.quantum

        new_pc = pc + pcdelta
        new_val = val + vdelta
        return offset_in_table, new_pc, new_val, True

    @staticmethod
    def read_varint(raw: bytes, offset: int = 0) -> (int, int):
        """
        Decode an unsigned LEB128 value the way debug/gosym does: at most five
        bytes, truncated when the table ends early.
        """
        result = 0
        read = 0
        for i in range(5):
            index = offset + i
            if index < 0 or index >= len(raw):
                break
            byte = raw[index]
            result |= (byte & 0x7f) << (7 * i)
            read += 1
            if not (byte & 0x80):
                break
        return result & 0xffffffff, read

    @staticmethod
    def make_mask(bytes_cnt: int) -> int:
        mask = 0
        for i in range(bytes_cnt):
            mask = mask << 8 | 0xff
        return mask

    def __repr__(self):
        nodef_f_vals = _repr_fields(self, excluded=('raw',))

        nodef_f_repr = ", ".join(f"{name}={value}" for name, value in nodef_f_vals)
        return f"{self.__class__.__name__}({nodef_f_repr})"
