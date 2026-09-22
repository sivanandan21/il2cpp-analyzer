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
        """Locate Il2CppCodeGenModule structures in ELF via direct pointers and dynamic relocations."""
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

        # Check for relocation sections (.rela.dyn or .rel.dyn)
        rela_sec = next((s for s in elf_res.sections if s.name in ('.rela.dyn', '.rel.dyn')), None)

        if rela_sec:
            is_rela = (rela_sec.name == '.rela.dyn')
            entry_sz = 24 if (elf_res.is_64bit and is_rela) else (12 if is_rela else 8)
            count = rela_sec.sh_size // entry_sz

            codegen_module_vaddr = None

            # Find Il2CppCodeGenModule.moduleName relocation
            for i in range(count):
                off = rela_sec.sh_offset + i * entry_sz
                if elf_res.is_64bit and is_rela:
                    r_off, _, r_addend = struct.unpack_from('<QQq', data, off)
                    if r_addend == str_vaddr:
                        codegen_module_vaddr = r_off
                        break
                elif not elf_res.is_64bit and not is_rela:
                    r_off, _ = struct.unpack_from('<II', data, off)
                    foff = ELFParser.vaddr_to_file_offset(r_off, elf_res.segments)
                    if foff and foff + 4 <= len(data):
                        val, = struct.unpack_from('<I', data, foff)
                        if val == str_vaddr:
                            codegen_module_vaddr = r_off
                            break

            if codegen_module_vaddr:
                mod_file_off = ELFParser.vaddr_to_file_offset(codegen_module_vaddr, elf_res.segments)
                if mod_file_off and mod_file_off + 24 <= len(data):
                    m_count, = struct.unpack_from('<I', data, mod_file_off + ptr_size)
                    ptrs_table_field_vaddr = codegen_module_vaddr + (16 if ptr_size == 8 else 8)

                    # Look up ptrs_table_field_vaddr in relocations
                    table_vaddr = None
                    for i in range(count):
                        off = rela_sec.sh_offset + i * entry_sz
                        if elf_res.is_64bit and is_rela:
                            r_off, _, r_addend = struct.unpack_from('<QQq', data, off)
                            if r_off == ptrs_table_field_vaddr:
                                table_vaddr = r_addend
                                break

                    if table_vaddr and 0 < m_count < 250000:
                        table_end = table_vaddr + (m_count * ptr_size)
                        for i in range(count):
                            off = rela_sec.sh_offset + i * entry_sz
                            if elf_res.is_64bit and is_rela:
                                r_off, _, r_addend = struct.unpack_from('<QQq', data, off)
                                if table_vaddr <= r_off < table_end:
                                    m_idx = (r_off - table_vaddr) // ptr_size
                                    if r_addend != 0:
                                        fn_file_off = ELFParser.vaddr_to_file_offset(r_addend, elf_res.segments)
                                        res.method_pointers[m_idx] = NativeMethodAddress(
                                            method_index=m_idx,
                                            rva=r_addend - res.image_base,
                                            va=r_addend,
                                            file_offset=fn_file_off,
                                            source="libil2cpp.so (.rela.dyn)",
                                            confidence="HIGH"
                                        )
                        if len(res.method_pointers) > 0:
                            return

        # Fallback: scan raw binary data for pointer to string
        ptr_bytes = struct.pack(pack_fmt, str_vaddr)
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
                    m_ptrs_vaddr, = struct.unpack_from(pack_fmt, data, m_ptrs_field_off)
                    m_ptrs_file_off = ELFParser.vaddr_to_file_offset(m_ptrs_vaddr, elf_res.segments)

                    if m_ptrs_file_off and 0 < m_count < 200000:
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
                                    source="libil2cpp.so (raw Il2CppCodeGenModule)",
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
