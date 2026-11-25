"""Tests for the standalone Go build information reader."""

import importlib.util
import io
import struct
import unittest

from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("_buildinfo_under_test",
                                               ROOT / "parsers" / "buildinfo.py")
buildinfo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(buildinfo)

MAGIC = b"\xff Go buildinf:"


def uvarint(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def frame_module(payload: bytes) -> bytes:
    # cmd/go wraps the module info with two 16-byte sentinels and its last
    # payload byte is a newline. buildinfo only validates the newline position.
    return b"P" * 16 + payload + b"S" * 16


def inline_blob(version=b"go1.22.1", module=None, ptr_size=8, flags=2):
    if module is None:
        module = frame_module(b"path\texample.com/main\n")
    header = MAGIC + bytes([ptr_size, flags]) + b"\x00" * 16
    return header + uvarint(len(version)) + version + uvarint(len(module)) + module


class FakeSection:
    def __init__(self, start, end=None, length=None):
        self.start = start
        if end is not None:
            self.end = end
        if length is not None:
            self.length = length


class FakeBinaryView:
    def __init__(self, data=b"", base=0x1000):
        self.data = bytearray(data)
        self.base = base
        self.sections = {}

    def read(self, address, size):
        offset = address - self.base
        if offset < 0 or size <= 0:
            return b""
        return bytes(self.data[offset:offset + size])

    def write(self, address, data):
        offset = address - self.base
        if offset < 0:
            raise ValueError("address before the fake view")
        if len(self.data) < offset + len(data):
            self.data.extend(b"\x00" * (offset + len(data) - len(self.data)))
        self.data[offset:offset + len(data)] = data

    def add_section(self, name, start, end=None, length=None):
        self.sections[name] = FakeSection(start, end=end, length=length)


class InlineBuildInfoTest(unittest.TestCase):
    def test_reads_inline_build_info(self):
        blob = inline_blob(version=b"go1.22.1",
                           module=frame_module(b"path\texample.com/main\n"
                                               b"build\t-buildmode=exe\n"))
        view = FakeBinaryView(blob)
        view.add_section('__go_buildinfo', view.base, view.base + len(blob))

        info = buildinfo.get_go_build_info(view)

        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.22.1")
        self.assertEqual(info.module_info,
                         "path\texample.com/main\nbuild\t-buildmode=exe\n")
        self.assertEqual(info.ptr_size, 8)
        self.assertEqual(info.flags, 2)
        self.assertFalse(info.big_endian)
        self.assertIn("go1.22.1", info.report())
        self.assertIn("example.com/main", info.report())

    def test_reads_elf_section_name(self):
        blob = inline_blob(version=b"go1.21.0")
        view = FakeBinaryView(blob)
        view.add_section('.go.buildinfo', view.base, view.base + len(blob))

        info = buildinfo.get_go_build_info(view)

        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.21.0")

    def test_reads_blob_at_data_section_start(self):
        blob = inline_blob(version=b"go1.27.0",
                           module=frame_module(b"path\texample.com/pe\n"))
        view = FakeBinaryView(blob)
        # PE-style: no dedicated build info section, the blob is at .data start.
        view.add_section('.data', view.base, view.base + len(blob))

        info = buildinfo.get_go_build_info(view)

        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.27.0")
        self.assertEqual(info.module_info, "path\texample.com/pe\n")

    def test_data_fallback_tries_sections_in_order(self):
        blob = inline_blob(version=b"go1.27.0")
        view = FakeBinaryView(base=0x1000)
        view.write(0x1000, b"\x00" * 0x40)
        view.write(0x2000, blob)
        view.add_section('.data', 0x1000, 0x1040)
        view.add_section('__rdata', 0x2000, 0x2000 + len(blob))

        info = buildinfo.get_go_build_info(view)

        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.27.0")

    def test_data_section_blob_not_at_start_is_ignored(self):
        blob = inline_blob(version=b"go1.27.0")
        view = FakeBinaryView(base=0x1000)
        view.write(0x1000, b"\x00" * 0x10 + blob)
        view.add_section('.data', 0x1000, 0x1000 + 0x10 + len(blob))

        self.assertIsNone(buildinfo.get_go_build_info(view))

    def test_section_length_fallback(self):
        blob = inline_blob()
        view = FakeBinaryView(blob)
        view.add_section('__go_buildinfo', view.base, length=len(blob))

        info = buildinfo.get_go_build_info(view)

        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.22.1")

    def test_inline_module_missing_or_unreadable(self):
        blob = inline_blob(version=b"go1.22.1", module=b"")
        view = FakeBinaryView(blob)
        view.add_section('__go_buildinfo', view.base, view.base + len(blob))
        info = buildinfo.get_go_build_info(view)
        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.22.1")
        self.assertEqual(info.module_info, "")

        # Valid version followed by a module length that runs past the section.
        header = MAGIC + bytes([8, 2]) + b"\x00" * 16
        truncated = header + uvarint(8) + b"go1.22.1" + uvarint(1000)
        view = FakeBinaryView(truncated)
        view.add_section('__go_buildinfo', view.base, view.base + len(truncated))
        info = buildinfo.get_go_build_info(view)
        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.22.1")
        self.assertEqual(info.module_info, "")

    def test_unframed_module_info_is_dropped(self):
        blob = inline_blob(version=b"go1.22.1", module=b"not-framed-module-info")
        view = FakeBinaryView(blob)
        view.add_section('__go_buildinfo', view.base, view.base + len(blob))
        info = buildinfo.get_go_build_info(view)
        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.22.1")
        self.assertEqual(info.module_info, "")

    def test_report_without_module_info(self):
        info = buildinfo.GoBuildInfo(go_version="go1.20.1")
        self.assertEqual(info.report(), "Go version: go1.20.1")

    def test_log_works_standalone(self):
        output = io.StringIO()
        with redirect_stdout(output):
            buildinfo.GoBuildInfo(go_version="go1.20.1").log()
        self.assertIn("go1.20.1", output.getvalue())


class PointerBuildInfoTest(unittest.TestCase):
    def _make_view(self, big_endian=False, with_module=True):
        version = b"go1.17.5"
        payload = b"path\texample.com/main\n"
        module = frame_module(payload)

        view = FakeBinaryView(base=0x1000)
        byte_order = ">" if big_endian else "<"
        read_ptr = lambda value: struct.pack(byte_order + "Q", value)

        version_descriptor = 0x3000
        module_descriptor = 0x3100
        header = MAGIC + bytes([8, 1 if big_endian else 0]) + b"\x00" * 16
        if with_module:
            header = header[:16] + read_ptr(version_descriptor) + read_ptr(module_descriptor)
        else:
            header = header[:16] + read_ptr(version_descriptor) + read_ptr(0)

        view.write(0x1000, header)
        view.write(version_descriptor, read_ptr(0x4000) + read_ptr(len(version)))
        view.write(0x4000, version)
        view.write(module_descriptor, read_ptr(0x4100) + read_ptr(len(module)))
        view.write(0x4100, module)
        view.add_section('__go_buildinfo', 0x1000, 0x1020)
        return view, payload

    def test_pointer_form_little_endian(self):
        view, payload = self._make_view()
        info = buildinfo.get_go_build_info(view)
        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.17.5")
        self.assertEqual(info.module_info, payload.decode())
        self.assertFalse(info.big_endian)

    def test_pointer_form_big_endian(self):
        view, payload = self._make_view(big_endian=True)
        info = buildinfo.get_go_build_info(view)
        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.17.5")
        self.assertEqual(info.module_info, payload.decode())
        self.assertTrue(info.big_endian)

    def test_pointer_form_32_bit(self):
        payload = b"path\texample.com/main\n"
        version = b"go1.17.5"
        module = frame_module(payload)
        view = FakeBinaryView(base=0x1000)
        header = MAGIC + bytes([4, 0]) + b"\x00" * 16
        header = header[:16] + struct.pack("<II", 0x2000, 0x2100)
        view.write(0x1000, header)
        view.write(0x1000 + 0x1000, struct.pack("<II", 0x3000, len(version)))
        view.write(0x3000, version)
        view.write(0x1000 + 0x1100, struct.pack("<II", 0x3100, len(module)))
        view.write(0x3100, module)
        view.add_section('__go_buildinfo', 0x1000, 0x1020)

        info = buildinfo.get_go_build_info(view)
        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.17.5")
        self.assertEqual(info.module_info, payload.decode())
        self.assertEqual(info.ptr_size, 4)

    def test_pointer_form_without_module(self):
        view, _ = self._make_view(with_module=False)
        info = buildinfo.get_go_build_info(view)
        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.17.5")
        self.assertEqual(info.module_info, "")


class MalformedBuildInfoTest(unittest.TestCase):
    def test_missing_view_or_sections(self):
        self.assertIsNone(buildinfo.get_go_build_info(None))
        self.assertIsNone(buildinfo.get_go_build_info(FakeBinaryView()))

    def test_bad_magic(self):
        blob = b"\x00" * 64
        view = FakeBinaryView(blob)
        view.add_section('__go_buildinfo', view.base, view.base + len(blob))
        self.assertIsNone(buildinfo.get_go_build_info(view))

    def test_short_section(self):
        blob = MAGIC + bytes([8, 2]) + b"\x00" * 4
        view = FakeBinaryView(blob)
        view.add_section('__go_buildinfo', view.base, view.base + len(blob))
        self.assertIsNone(buildinfo.get_go_build_info(view))

    def test_truncated_inline_version(self):
        header = MAGIC + bytes([8, 2]) + b"\x00" * 16
        blob = header + uvarint(100) + b"go1.22"
        view = FakeBinaryView(blob)
        view.add_section('__go_buildinfo', view.base, view.base + len(blob))
        self.assertIsNone(buildinfo.get_go_build_info(view))

    def test_absurd_inline_length(self):
        header = MAGIC + bytes([8, 2]) + b"\x00" * 16
        blob = header + uvarint(0xFFFFFFFF) + b"go1.22.1"
        view = FakeBinaryView(blob)
        view.add_section('__go_buildinfo', view.base, view.base + len(blob))
        self.assertIsNone(buildinfo.get_go_build_info(view))

    def test_invalid_pointer_size(self):
        header = MAGIC + bytes([3, 0]) + b"\x00" * 16
        view = FakeBinaryView(header)
        view.add_section('__go_buildinfo', view.base, view.base + len(header))
        self.assertIsNone(buildinfo.get_go_build_info(view))

    def test_zero_pointer_size(self):
        blob = inline_blob(ptr_size=0)
        view = FakeBinaryView(blob)
        view.add_section('__go_buildinfo', view.base, view.base + len(blob))
        self.assertIsNone(buildinfo.get_go_build_info(view))

    def test_unreadable_version_pointer(self):
        header = MAGIC + bytes([8, 0]) + struct.pack("<QQ", 0x900000, 0)
        view = FakeBinaryView(header)
        view.add_section('__go_buildinfo', view.base, view.base + len(header))
        self.assertIsNone(buildinfo.get_go_build_info(view))

    def test_unreadable_module_pointer_keeps_version(self):
        version = b"go1.17.5"
        header = MAGIC + bytes([8, 0]) + struct.pack("<QQ", 0x2000, 0x2100)
        view = FakeBinaryView(base=0x1000)
        view.write(0x1000, header)
        view.write(0x2000, struct.pack("<QQ", 0x3000, len(version)))
        view.write(0x3000, version)
        # The module descriptor points outside the data we provide.
        view.write(0x2100, struct.pack("<QQ", 0x900000, 20))
        view.add_section('__go_buildinfo', 0x1000, 0x1020)
        info = buildinfo.get_go_build_info(view)
        self.assertIsNotNone(info)
        self.assertEqual(info.go_version, "go1.17.5")
        self.assertEqual(info.module_info, "")


if __name__ == "__main__":
    unittest.main()
