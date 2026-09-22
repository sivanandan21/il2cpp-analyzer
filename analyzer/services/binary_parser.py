"""
Binary Parser Facade.
Coordinates native binary inspection (ELF or PE) with IL2CPP metadata,
resolving method code pointers and translating RVAs, VAs, and File Offsets.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any
from pathlib import Path
import struct

from .elf_parser import ELFParser, ELFParseResult
from .pe_parser import PEParser, PEParseResult

@dataclass
class NativeMethodAddress:
    method_index: int
    rva: Optional[int] = None
    va: Optional[int] = None
    file_offset: Optional[int] = None
    source: str = "binary analysis"
    confidence: str = "HIGH"

@dataclass
class BinaryAnalysisResult:
    is_valid: bool = False
    binary_format: str = "UNKNOWN"  # ELF or PE
    architecture: str = "UNKNOWN"
    image_base: int = 0
    pointer_size: int = 8
    sections: List[Dict[str, Any]] = field(default_factory=list)
    method_pointers: Dict[int, NativeMethodAddress] = field(default_factory=dict)
    symbols_found: int = 0
    warnings: List[str] = field(default_factory=list)


class BinaryParser:
    """High-level native binary analyzer for libil2cpp.so and GameAssembly.dll."""

    @classmethod
    def parse_binary(cls, binary_path: Path, architecture_hint: Optional[str] = None) -> BinaryAnalysisResult:
        res = BinaryAnalysisResult()
        if not binary_path.exists() or not binary_path.is_file():
            res.warnings.append(f"Binary file not found: {binary_path}")
            return res

        try:
            with open(binary_path, "rb") as f:
                data = f.read()
        except Exception as e:
            res.warnings.append(f"Failed to read binary: {e}")
            return res

        if data.startswith(b"\x7fELF"):
            return cls._analyze_elf(data, res)
        elif data.startswith(b"MZ"):
            return cls._analyze_pe(data, res)
        else:
            res.warnings.append("Binary is neither a valid ELF nor a PE executable")
            return res

    @classmethod
    def _analyze_elf(cls, data: bytes, res: BinaryAnalysisResult) -> BinaryAnalysisResult:
        elf_parser = ELFParser(data)
        elf_res = elf_parser.parse()

        res.is_valid = elf_res.is_valid
        res.binary_format = "ELF"
        res.architecture = elf_res.machine_name
        res.pointer_size = 8 if elf_res.is_64bit else 4
        res.image_base = elf_res.image_base
        res.warnings.extend(elf_res.warnings)
        res.symbols_found = len(elf_res.symbols)

        for sec in elf_res.sections:
            res.sections.append({
                "name": sec.name,
                "addr": hex(sec.sh_addr),
                "offset": hex(sec.sh_offset),
                "size": sec.sh_size,
                "type": sec.sh_type
            })

        # Scan for Assembly-CSharp Il2CppCodeGenModule or method pointer arrays
        cls._scan_elf_codegen_modules(data, elf_res, res)

        return res

    @classmethod
    def _analyze_pe(cls, data: bytes, res: BinaryAnalysisResult) -> BinaryAnalysisResult:
        pe_parser = PEParser(data)
        pe_res = pe_parser.parse()

        res.is_valid = pe_res.is_valid
        res.binary_format = "PE"
        res.architecture = pe_res.machine_name
        res.pointer_size = 8 if pe_res.is_64bit else 4
        res.image_base = pe_res.image_base
        res.warnings.extend(pe_res.warnings)
        res.symbols_found = len(pe_res.exports)

        for sec in pe_res.sections:
            res.sections.append({
                "name": sec.name,
                "addr": hex(sec.virtual_address),
                "offset": hex(sec.pointer_to_raw_data),
                "size": sec.size_of_raw_data,
                "virtual_size": sec.virtual_size
            })

        # Scan for PE method pointer structures
        cls._scan_pe_codegen_modules(data, pe_res, res)

        return res

    @classmethod
    def _scan_elf_codegen_modules(cls, data: bytes, elf_res: ELFParseResult, res: BinaryAnalysisResult):
        """Locate Il2CppCodeGenModule structures in ELF."""
        # Search for string "Assembly-CSharp.dll"
        target_str = b"Assembly-CSharp.dll\x00"
        str_offset = data.find(target_str)
        if str_offset == -1:
            res.warnings.append("Assembly-CSharp.dll string identifier not found in binary")
            return

        str_vaddr = ELFParser.file_offset_to_vaddr(str_offset, elf_res.segments)
        if str_vaddr is None:
            return

        ptr_size = res.pointer_size
        pack_fmt = "<Q" if ptr_size == 8 else "<I"
        ptr_bytes = struct.pack(pack_fmt, str_vaddr)

        # Look for pointers pointing to the string
        pos = 0
        while pos < len(data) - ptr_size:
            idx = data.find(ptr_bytes, pos)
            if idx == -1:
                break

            # In Il2CppCodeGenModule:
            # struct Il2CppCodeGenModule {
            #    const char* moduleName; // at offset 0
            #    uint32_t methodPointerCount; // at offset ptr_size
            #    const Il2CppMethodPointer* methodPointers; // at offset ptr_size + 4 or aligned
            # }
            try:
                m_count_off = idx + ptr_size
                m_count, = struct.unpack_from("<I", data, m_count_off)

                # Pointer to methodPointers table
                m_ptrs_field_off = m_count_off + (8 if ptr_size == 8 else 4)
                if ptr_size == 8 and (m_count_off % 8 != 0):
                    m_ptrs_field_off = ((m_count_off + 7) // 8) * 8

                if m_ptrs_field_off + ptr_size <= len(data):
                    m_ptrs_vaddr, = struct.unpack_from(pack_fmt, data, m_ptrs_field_off)
                    m_ptrs_file_off = ELFParser.vaddr_to_file_offset(m_ptrs_vaddr, elf_res.segments)

                    if m_ptrs_file_off and 0 < m_count < 200000:
                        # Valid method pointers array found!
                        for m_idx in range(min(m_count, 50000)):
                            entry_off = m_ptrs_file_off + (m_idx * ptr_size)
                            if entry_off + ptr_size > len(data):
                                break
                            fn_vaddr, = struct.unpack_from(pack_fmt, data, entry_off)
                            if fn_vaddr != 0:
                                fn_file_off = ELFParser.vaddr_to_file_offset(fn_vaddr, elf_res.segments)
                                fn_rva = fn_vaddr - res.image_base
                                res.method_pointers[m_idx] = NativeMethodAddress(
                                    method_index=m_idx,
                                    rva=fn_rva,
                                    va=fn_vaddr,
                                    file_offset=fn_file_off,
                                    source="libil2cpp.so (Il2CppCodeGenModule)",
                                    confidence="HIGH"
                                )
                        break
            except Exception:
                pass

            pos = idx + ptr_size

    @classmethod
    def _scan_pe_codegen_modules(cls, data: bytes, pe_res: PEParseResult, res: BinaryAnalysisResult):
        """Locate method pointer tables in Windows PE."""
        target_str = b"Assembly-CSharp.dll\x00"
        str_offset = data.find(target_str)
        if str_offset == -1:
            res.warnings.append("Assembly-CSharp.dll identifier not found in PE binary")
            return

        str_rva = PEParser.file_offset_to_rva(str_offset, pe_res.sections)
        if str_rva is None:
            return

        ptr_size = res.pointer_size
        pack_fmt = "<Q" if ptr_size == 8 else "<I"
        str_va = res.image_base + str_rva
        ptr_bytes = struct.pack(pack_fmt, str_va)

        pos = 0
        while pos < len(data) - ptr_size:
            idx = data.find(ptr_bytes, pos)
            if idx == -1:
                break

            try:
                m_count_off = idx + ptr_size
                m_count, = struct.unpack_from("<I", data, m_count_off)

                m_ptrs_field_off = m_count_off + (8 if ptr_size == 8 else 4)
                if ptr_size == 8 and (m_count_off % 8 != 0):
                    m_ptrs_field_off = ((m_count_off + 7) // 8) * 8

                if m_ptrs_field_off + ptr_size <= len(data):
                    m_ptrs_va, = struct.unpack_from(pack_fmt, data, m_ptrs_field_off)
                    m_ptrs_rva = m_ptrs_va - res.image_base
                    m_ptrs_file_off = PEParser.rva_to_file_offset(m_ptrs_rva, pe_res.sections)

                    if m_ptrs_file_off and 0 < m_count < 200000:
                        for m_idx in range(min(m_count, 50000)):
                            entry_off = m_ptrs_file_off + (m_idx * ptr_size)
                            if entry_off + ptr_size > len(data):
                                break
                            fn_va, = struct.unpack_from(pack_fmt, data, entry_off)
                            if fn_va != 0:
                                fn_rva = fn_va - res.image_base
                                fn_file_off = PEParser.rva_to_file_offset(fn_rva, pe_res.sections)
                                res.method_pointers[m_idx] = NativeMethodAddress(
                                    method_index=m_idx,
                                    rva=fn_rva,
                                    va=fn_va,
                                    file_offset=fn_file_off,
                                    source="GameAssembly.dll (Il2CppCodeGenModule)",
                                    confidence="HIGH"
                                )
                        break
            except Exception:
                pass

            pos = idx + ptr_size
