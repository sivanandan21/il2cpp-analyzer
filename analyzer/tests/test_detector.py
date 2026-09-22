from django.test import TestCase
from pathlib import Path
import tempfile
import struct

from analyzer.services.detector import FormatDetector, IL2CPP_METADATA_MAGIC

class DetectorTests(TestCase):
    def test_detect_metadata_binary(self):
        """Test detection of synthetic global-metadata.dat."""
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
            # Header: magic (4 bytes) + version (4 bytes) + padding
            f.write(struct.pack("<II", IL2CPP_METADATA_MAGIC, 29))
            f.write(b"\x00" * 120)
            f_path = Path(f.name)

        try:
            res = FormatDetector.detect_file(f_path)
            self.assertEqual(res.metadata_type, "BINARY_DAT")
            self.assertEqual(res.metadata_version, 29)
            self.assertEqual(res.endianness, "Little Endian")
        finally:
            f_path.unlink()

    def test_detect_elf_arm64(self):
        """Test detection of synthetic ARM64 ELF header."""
        with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f:
            # ELF64 header: e_ident (16 bytes), e_type (2), e_machine=183 (ARM64)
            hdr = bytearray(64)
            hdr[0:4] = b"\x7fELF"
            hdr[4] = 2  # 64-bit
            hdr[5] = 1  # Little endian
            struct.pack_into("<H", hdr, 18, 183)  # EM_AARCH64
            f.write(hdr)
            f_path = Path(f.name)

        try:
            res = FormatDetector.detect_file(f_path)
            self.assertEqual(res.binary_format, "ELF")
            self.assertEqual(res.architecture, "ARM64")
            self.assertEqual(res.pointer_size, 8)
        finally:
            f_path.unlink()

    def test_detect_pe_x64(self):
        """Test detection of synthetic PE x64 header."""
        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            data = bytearray(512)
            data[0:2] = b"MZ"
            struct.pack_into("<I", data, 0x3C, 0x80)  # PE offset at 0x80
            data[0x80:0x84] = b"PE\x00\x00"
            struct.pack_into("<H", data, 0x84, 0x8664)  # Machine x64
            f.write(data)
            f_path = Path(f.name)

        try:
            res = FormatDetector.detect_file(f_path)
            self.assertEqual(res.binary_format, "PE")
            self.assertEqual(res.architecture, "x64")
            self.assertEqual(res.pointer_size, 8)
        finally:
            f_path.unlink()
