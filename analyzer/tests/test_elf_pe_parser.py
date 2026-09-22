from django.test import TestCase
from analyzer.services.elf_parser import ELFParser, ELFSegment
from analyzer.services.pe_parser import PEParser, PESection
import struct

class ElfPeParserTests(TestCase):
    def test_elf_segment_translation(self):
        """Test translation between Virtual Address and File Offset in ELF."""
        # Simulated PT_LOAD segment: file_offset=0x1000, vaddr=0x70001000, filesz=0x2000, memsz=0x2000
        seg = ELFSegment(
            p_type=1, p_flags=5, p_offset=0x1000, p_vaddr=0x70001000,
            p_paddr=0, p_filesz=0x2000, p_memsz=0x2000, p_align=0x1000
        )
        segments = [seg]

        # In-bounds translation
        vaddr = 0x70001500
        file_off = ELFParser.vaddr_to_file_offset(vaddr, segments)
        self.assertEqual(file_off, 0x1500)

        # Reverse translation
        rev_vaddr = ELFParser.file_offset_to_vaddr(0x1500, segments)
        self.assertEqual(rev_vaddr, 0x70001500)

        # Out-of-bounds translation
        out_vaddr = 0x70004000
        self.assertIsNone(ELFParser.vaddr_to_file_offset(out_vaddr, segments))

    def test_pe_section_translation(self):
        """Test translation between RVA and File Offset in PE."""
        sec = PESection(
            name=".text",
            virtual_size=0x3000,
            virtual_address=0x1000,  # Section RVA
            size_of_raw_data=0x3000,
            pointer_to_raw_data=0x400,  # File offset
            characteristics=0x60000020
        )
        sections = [sec]

        # RVA 0x1500 -> File offset 0x400 + (0x1500 - 0x1000) = 0x900
        file_off = PEParser.rva_to_file_offset(0x1500, sections)
        self.assertEqual(file_off, 0x900)

        # Reverse: file offset 0x900 -> RVA 0x1500
        rva = PEParser.file_offset_to_rva(0x900, sections)
        self.assertEqual(rva, 0x1500)

    def test_truncated_elf_handling(self):
        """Ensure malformed ELF binaries return warnings instead of crashing."""
        parser = ELFParser(b"\x7fELF\x02\x01")  # truncated
        res = parser.parse()
        self.assertFalse(res.is_valid)
        self.assertTrue(len(res.warnings) > 0)
