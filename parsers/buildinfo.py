"""
Minimal reader for the Go build information blob.

Go 1.18 and later write the toolchain version and the module information inline
in a 32-byte header followed by two varint-prefixed strings. Older binaries use
two pointers to Go string descriptors instead. The blob is stored in the
__go_buildinfo section on Mach-O and in .go.buildinfo on ELF. Some PE binaries
(and stripped images) place it at the start of .data instead.

This module deliberately has no Binary Ninja import at module load time, so it
can be unit tested with a plain stub.
"""

from dataclasses import dataclass
from typing import Optional

BUILDINFO_MAGIC = b"\xff Go buildinf:"
BUILDINFO_HEADER_SIZE = 32

FLAG_ENDIAN_BIG = 0x1
FLAG_VERSION_INLINE = 0x2

BUILDINFO_SECTIONS = ('__go_buildinfo', '.go.buildinfo')
# PE binaries and some stripped images keep the blob at the start of a data
# section. Only the section start is checked; the whole binary is never scanned.
BUILDINFO_FALLBACK_SECTIONS = ('.data', '__data', '.rdata', '__rdata')

MAX_VERSION_LENGTH = 4 * 1024
MAX_MODULE_INFO_LENGTH = 16 * 1024 * 1024

MAX_VARINT_BYTES = 10


@dataclass
class GoBuildInfo:
    go_version: str
    module_info: str = ""
    address: int = 0
    ptr_size: int = 0
    flags: int = 0
    big_endian: bool = False

    def report(self) -> str:
        """Return a concise, human readable report."""
        lines = [f"Go version: {self.go_version}"]
        if self.module_info:
            lines.append("Module info:")
            lines.extend(self.module_info.splitlines())
        return "\n".join(lines)

    def log(self) -> None:
        """Log the report through the plugin logger."""
        try:
            from .common import log_info
        except ImportError:
            # The module can also be loaded standalone (for example by tests).
            print(self.report())
            return

        for line in self.report().splitlines():
            log_info(line)


def get_go_build_info(bv) -> Optional[GoBuildInfo]:
    """
    Read the Go build information from a BinaryView.

    Returns None when the binary does not expose a readable build info blob.
    """
    if bv is None:
        return None

    section_names = _sections_to_try(bv)

    for section_name in section_names:
        try:
            section = _get_section(bv, section_name)
            if section is None:
                continue

            start, end = _section_range(section)
            if start is None or end is None:
                continue

            build_info = _parse_build_info(bv, start, end)
            if build_info is not None:
                return build_info
        except Exception:
            # A malformed section must not take the plugin down.
            continue

    return None


def _sections_to_try(bv):
    # Prefer the dedicated sections. Only when none of them exist fall back to
    # the data sections used by PE and stripped images.
    for section_name in BUILDINFO_SECTIONS:
        if _get_section(bv, section_name) is not None:
            return BUILDINFO_SECTIONS
    return BUILDINFO_FALLBACK_SECTIONS


def _get_section(bv, section_name: str):
    sections = getattr(bv, 'sections', None)
    if sections is None:
        return None

    try:
        return sections[section_name]
    except Exception:
        return None


def _section_range(section):
    start = getattr(section, 'start', None)
    end = getattr(section, 'end', None)
    if not isinstance(start, int):
        return None, None

    if not isinstance(end, int):
        length = getattr(section, 'length', None)
        if not isinstance(length, int):
            return None, None
        end = start + length

    return start, end


def _parse_build_info(bv, start: int, end: int) -> Optional[GoBuildInfo]:
    if start < 0 or end <= start or end - start < BUILDINFO_HEADER_SIZE:
        return None

    header = _read_bytes(bv, start, BUILDINFO_HEADER_SIZE)
    if len(header) < BUILDINFO_HEADER_SIZE or not header.startswith(BUILDINFO_MAGIC):
        return None

    ptr_size = header[14]
    flags = header[15]
    if ptr_size == 0:
        return None
    big_endian = bool(flags & FLAG_ENDIAN_BIG)

    if flags & FLAG_VERSION_INLINE:
        go_version, next_address = _read_varint_string(bv,
                                                       start + BUILDINFO_HEADER_SIZE,
                                                       end,
                                                       MAX_VERSION_LENGTH)
        if not go_version:
            return None

        module_info, _ = _read_varint_string(bv,
                                             next_address,
                                             end,
                                             MAX_MODULE_INFO_LENGTH)
        module_info = module_info or ""
    else:
        if ptr_size not in (4, 8):
            return None

        version_pointer = _read_uintptr(header, 16, ptr_size, big_endian)
        module_pointer = _read_uintptr(header, 16 + ptr_size, ptr_size, big_endian)
        if version_pointer is None or not version_pointer:
            return None

        go_version = _read_go_string(bv,
                                     version_pointer,
                                     ptr_size,
                                     big_endian,
                                     MAX_VERSION_LENGTH)
        if not go_version:
            return None

        module_info = ""
        if module_pointer:
            module_info = _read_go_string(bv,
                                          module_pointer,
                                          ptr_size,
                                          big_endian,
                                          MAX_MODULE_INFO_LENGTH) or ""

    module_info = _strip_module_framing(module_info)

    return GoBuildInfo(go_version=go_version,
                       module_info=module_info,
                       address=start,
                       ptr_size=ptr_size,
                       flags=flags,
                       big_endian=big_endian)


def _strip_module_framing(module_info: str) -> str:
    """
    Remove the sentinel strings cmd/go wraps around the module information,
    mirroring debug/buildinfo.
    """
    if len(module_info) >= 33 and module_info[-17] == '\n':
        return module_info[16:-16]
    return ""


def _read_varint_string(bv, address: int, end: int, max_length: int):
    """Read a uvarint-prefixed string inside [address, end)."""
    if address < 0 or address >= end:
        return None, address

    prefix = _read_bytes(bv, address, MAX_VARINT_BYTES)
    if not prefix:
        return None, address

    length, used = _decode_uvarint(prefix)
    if used <= 0 or length < 0 or length > max_length:
        return None, address

    data_address = address + used
    if data_address + length > end:
        return None, data_address

    data = _read_bytes(bv, data_address, length)
    if len(data) != length:
        return None, data_address

    return data.decode('utf-8', errors='replace'), data_address + length


def _decode_uvarint(raw: bytes):
    value = 0
    shift = 0
    for i in range(MAX_VARINT_BYTES):
        if i >= len(raw):
            return None, 0
        byte = raw[i]
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, i + 1
        shift += 7
    return None, 0


def _read_go_string(bv, address: int, ptr_size: int, big_endian: bool, max_length: int) -> Optional[str]:
    """Read a Go string descriptor (pointer + length) at address."""
    if address <= 0:
        return None

    descriptor = _read_bytes(bv, address, ptr_size * 2)
    if len(descriptor) < ptr_size * 2:
        return None

    data_address = _read_uintptr(descriptor, 0, ptr_size, big_endian)
    length = _read_uintptr(descriptor, ptr_size, ptr_size, big_endian)
    if data_address is None or length is None:
        return None
    if length <= 0 or length > max_length:
        return None

    data = _read_bytes(bv, data_address, length)
    if len(data) != length:
        return None

    return data.decode('utf-8', errors='replace')


def _read_uintptr(raw: bytes, offset: int, ptr_size: int, big_endian: bool) -> Optional[int]:
    if ptr_size not in (4, 8) or offset < 0:
        return None
    data = raw[offset:offset + ptr_size]
    if len(data) < ptr_size:
        return None
    return int.from_bytes(data, 'big' if big_endian else 'little')


def _read_bytes(bv, address: int, size: int) -> bytes:
    if size <= 0 or address < 0:
        return b""

    try:
        data = bv.read(address, size)
    except Exception:
        return b""

    return bytes(data) if data else b""
