"""
Safe PE32 and PE32+ (PE64) binary parser for Windows GameAssembly.dll.
Extracts COFF headers, Optional Header, ImageBase, Section headers,
Export Address Table, and translates RVAs to file offsets.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import struct

@dataclass
class PESection:
    name: str
    virtual_size: int
    virtual_address: int  # Section RVA
    size_of_raw_data: int
    pointer_to_raw_data: int  # File offset
    characteristics: int

@dataclass
class PEExport:
    name: str
    ordinal: int
    rva: int

@dataclass
class PEParseResult:
    is_valid: bool = False
    is_64bit: bool = True
    machine: int = 0
    machine_name: str = "UNKNOWN"
    image_base: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    entry_point_rva: int = 0
    sections: List[PESection] = field(default_factory=list)
    exports: List[PEExport] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class PEParser:
    """Safe PE32/PE32+ binary parser with bounds checking."""

    IMAGE_FILE_MACHINE_I386 = 0x014C
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64

    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)

    def parse(self) -> PEParseResult:
        res = PEParseResult()
        if self.size < 0x40:
            res.warnings.append("File too small to contain DOS header")
            return res

        if not self.data.startswith(b"MZ"):
            res.warnings.append("DOS header signature mismatch (not a PE)")
            return res

        # Offset to PE Header
        pe_offset, = struct.unpack_from("<I", self.data, 0x3C)
        if pe_offset + 24 > self.size:
            res.warnings.append("PE header offset out of bounds")
            return res

        if self.data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            res.warnings.append("PE signature mismatch")
            return res

        try:
            # COFF Header (20 bytes following "PE\0\0")
            coff_offset = pe_offset + 4
            machine, num_sections, time_date_stamp, ptr_symbol_table, num_symbols, size_opt_header, characteristics = struct.unpack_from(
                "<HHIIIHH", self.data, coff_offset
            )
            res.machine = machine
            res.machine_name = self._get_machine_name(machine)

            opt_offset = coff_offset + 20
            if opt_offset + size_opt_header > self.size:
                res.warnings.append("Optional header out of bounds")
                return res

            # Optional Header Magic
            magic, = struct.unpack_from("<H", self.data, opt_offset)
            # 0x10b = PE32, 0x20b = PE32+ (64-bit)
            if magic == 0x20B:
                res.is_64bit = True
                res.entry_point_rva, = struct.unpack_from("<I", self.data, opt_offset + 16)
                res.image_base, = struct.unpack_from("<Q", self.data, opt_offset + 24)
                res.section_alignment, res.file_alignment = struct.unpack_from("<II", self.data, opt_offset + 32)
                rva_and_sizes_offset = opt_offset + 108
            elif magic == 0x10B:
                res.is_64bit = False
                res.entry_point_rva, = struct.unpack_from("<I", self.data, opt_offset + 16)
                res.image_base, = struct.unpack_from("<I", self.data, opt_offset + 28)
                res.section_alignment, res.file_alignment = struct.unpack_from("<II", self.data, opt_offset + 32)
                rva_and_sizes_offset = opt_offset + 92
            else:
                res.warnings.append(f"Unrecognized Optional Header magic: 0x{magic:04x}")
                return res

            res.is_valid = True

            # Data Directories: index 0 is Export Table
            export_table_rva = 0
            export_table_size = 0
            if rva_and_sizes_offset + 8 <= opt_offset + size_opt_header:
                export_table_rva, export_table_size = struct.unpack_from("<II", self.data, rva_and_sizes_offset)

            # Section Headers
            sec_headers_offset = opt_offset + size_opt_header
            for i in range(num_sections):
                sh_off = sec_headers_offset + (i * 40)
                if sh_off + 40 > self.size:
                    res.warnings.append(f"Section header {i} out of bounds")
                    break

                raw_name = self.data[sh_off:sh_off+8]
                sec_name = raw_name.split(b"\x00")[0].decode("ascii", errors="replace").strip()
                v_size, v_addr, raw_size, raw_ptr, _, _, _, _, _, charact = struct.unpack_from(
                    "<IIIIIIHHI", self.data, sh_off + 8
                )
                res.sections.append(PESection(
                    name=sec_name,
                    virtual_size=v_size,
                    virtual_address=v_addr,
                    size_of_raw_data=raw_size,
                    pointer_to_raw_data=raw_ptr,
                    characteristics=charact
                ))

            # Parse Export Directory if present
            if export_table_rva > 0 and export_table_size > 0:
                self._parse_exports(res, export_table_rva)

        except Exception as e:
            res.warnings.append(f"Error parsing PE binary: {e}")

        return res

    def _parse_exports(self, res: PEParseResult, export_rva: int):
        """Parse exported functions from Export Directory."""
        exp_file_off = self.rva_to_file_offset(export_rva, res.sections)
        if not exp_file_off or exp_file_off + 40 > self.size:
            return

        try:
            _, _, _, _, _, ordinal_base, num_functions, num_names, funcs_rva, names_rva, ordinals_rva = struct.unpack_from(
                "<IIIIIIIIIII", self.data, exp_file_off
            )

            funcs_off = self.rva_to_file_offset(funcs_rva, res.sections)
            names_off = self.rva_to_file_offset(names_rva, res.sections)
            ords_off = self.rva_to_file_offset(ordinals_rva, res.sections)

            if not funcs_off or not names_off or not ords_off:
                return

            for i in range(min(num_names, 1000)):
                if names_off + (i * 4) + 4 > self.size:
                    break
                name_rva, = struct.unpack_from("<I", self.data, names_off + (i * 4))
                name_file_off = self.rva_to_file_offset(name_rva, res.sections)
                if not name_file_off:
                    continue

                # Read null terminated string
                end = self.data.find(b"\x00", name_file_off)
                if end == -1:
                    end = name_file_off + 256
                fn_name = self.data[name_file_off:end].decode("ascii", errors="replace")

                # Ordinal
                ord_val, = struct.unpack_from("<H", self.data, ords_off + (i * 2))
                fn_index = ord_val
                if funcs_off + (fn_index * 4) + 4 <= self.size:
                    fn_rva, = struct.unpack_from("<I", self.data, funcs_off + (fn_index * 4))
                    res.exports.append(PEExport(name=fn_name, ordinal=ordinal_base + ord_val, rva=fn_rva))

        except Exception as e:
            res.warnings.append(f"Export directory parse error: {e}")

    @staticmethod
    def _get_machine_name(machine: int) -> str:
        machine_map = {
            0x014C: "x86",
            0x8664: "x64",
            0xAA64: "ARM64",
        }
        return machine_map.get(machine, f"Machine_0x{machine:04x}")

    @staticmethod
    def rva_to_file_offset(rva: int, sections: List[PESection]) -> Optional[int]:
        """Convert a PE Relative Virtual Address (RVA) to a physical file offset."""
        for sec in sections:
            # Note: virtual_size can be 0 or smaller than raw_size in some linkers
            sec_size = max(sec.virtual_size, sec.size_of_raw_data)
            if sec.virtual_address <= rva < sec.virtual_address + sec_size:
                offset_in_sec = rva - sec.virtual_address
                if offset_in_sec < sec.size_of_raw_data:
                    return sec.pointer_to_raw_data + offset_in_sec
        return None

    @staticmethod
    def file_offset_to_rva(file_off: int, sections: List[PESection]) -> Optional[int]:
        """Convert a physical file offset to an RVA."""
        for sec in sections:
            if sec.pointer_to_raw_data <= file_off < sec.pointer_to_raw_data + sec.size_of_raw_data:
                return sec.virtual_address + (file_off - sec.pointer_to_raw_data)
        return None
