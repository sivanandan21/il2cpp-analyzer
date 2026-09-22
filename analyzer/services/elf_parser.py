"""
Safe ELF32 and ELF64 binary parser.
Extracts program headers, PT_LOAD segments, sections, virtual addresses,
file offsets, and dynamic symbols when present.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
import struct

@dataclass
class ELFSegment:
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

@dataclass
class ELFSection:
    name: str
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int

@dataclass
class ELFSymbol:
    name: str
    value: int
    size: int
    info: int
    other: int
    shndx: int
    is_function: bool = False

@dataclass
class ELFParseResult:
    is_valid: bool = False
    is_64bit: bool = True
    endian_char: str = "<"
    machine: int = 0
    machine_name: str = "UNKNOWN"
    entry: int = 0
    segments: List[ELFSegment] = field(default_factory=list)
    sections: List[ELFSection] = field(default_factory=list)
    symbols: List[ELFSymbol] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    image_base: int = 0  # In ELF shared objects, default base is usually 0


class ELFParser:
    """Safe ELF binary reader with strict bounds checking."""

    PT_LOAD = 1
    PT_DYNAMIC = 2
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_DYNSYM = 11

    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)

    def parse(self) -> ELFParseResult:
        res = ELFParseResult()
        if self.size < 52:
            res.warnings.append("File too small to be a valid ELF binary")
            return res

        if not self.data.startswith(b"\x7fELF"):
            res.warnings.append("Magic signature mismatch (not an ELF)")
            return res

        ei_class = self.data[4]
        ei_data = self.data[5]

        if ei_class not in (1, 2):
            res.warnings.append(f"Invalid ELF class: {ei_class}")
            return res

        res.is_64bit = (ei_class == 2)
        res.endian_char = "<" if ei_data == 1 else ">"
        enc = res.endian_char

        try:
            if res.is_64bit:
                if self.size < 64:
                    res.warnings.append("ELF64 header truncated")
                    return res
                _, _, _, res.entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    f"{enc}HHIQQQIHHHHHH", self.data, 16
                )
                res.machine = struct.unpack_from(f"{enc}H", self.data, 18)[0]
            else:
                _, _, _, res.entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    f"{enc}HHIIIIIHHHHHH", self.data, 16
                )
                res.machine = struct.unpack_from(f"{enc}H", self.data, 18)[0]

            res.is_valid = True
            res.machine_name = self._get_machine_name(res.machine)

            # Parse Program Headers (Segments)
            if e_phoff > 0 and e_phnum > 0 and e_phentsize >= (56 if res.is_64bit else 32):
                for i in range(e_phnum):
                    ph_offset = e_phoff + (i * e_phentsize)
                    if ph_offset + e_phentsize > self.size:
                        res.warnings.append(f"Program header {i} out of bounds")
                        break
                    if res.is_64bit:
                        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                            f"{enc}IIQQQQQQ", self.data, ph_offset
                        )
                    else:
                        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                            f"{enc}IIIIIIII", self.data, ph_offset
                        )
                    res.segments.append(ELFSegment(
                        p_type=p_type, p_flags=p_flags, p_offset=p_offset,
                        p_vaddr=p_vaddr, p_paddr=p_paddr, p_filesz=p_filesz,
                        p_memsz=p_memsz, p_align=p_align
                    ))

            # Parse Section Headers if available
            if e_shoff > 0 and e_shnum > 0 and e_shentsize >= (64 if res.is_64bit else 40):
                # First pass: read raw sections
                raw_sections = []
                for i in range(e_shnum):
                    sh_offset = e_shoff + (i * e_shentsize)
                    if sh_offset + e_shentsize > self.size:
                        res.warnings.append(f"Section header {i} out of bounds")
                        break
                    if res.is_64bit:
                        sh_name, sh_type, sh_flags, sh_addr, sh_offset_val, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                            f"{enc}IIQQQQIIQQ", self.data, sh_offset
                        )
                    else:
                        sh_name, sh_type, sh_flags, sh_addr, sh_offset_val, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                            f"{enc}IIIIIIIIII", self.data, sh_offset
                        )
                    raw_sections.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset_val, sh_size, sh_link, sh_info, sh_addralign, sh_entsize))

                # Section name string table
                shstrtab_data = b""
                if 0 <= e_shstrndx < len(raw_sections):
                    _, _, _, _, s_off, s_sz, _, _, _, _ = raw_sections[e_shstrndx]
                    if s_off + s_sz <= self.size:
                        shstrtab_data = self.data[s_off:s_off+s_sz]

                for raw in raw_sections:
                    s_name_idx, s_type, s_flags, s_addr, s_off, s_sz, s_link, s_info, s_align, s_entsz = raw
                    sec_name = self._read_str_from_tab(shstrtab_data, s_name_idx)
                    res.sections.append(ELFSection(
                        name=sec_name, sh_name=s_name_idx, sh_type=s_type,
                        sh_flags=s_flags, sh_addr=s_addr, sh_offset=s_off,
                        sh_size=s_sz, sh_link=s_link, sh_info=s_info,
                        sh_addralign=s_align, sh_entsize=s_entsz
                    ))

                # Parse dynamic symbols if present
                self._parse_symbols(res)

        except Exception as e:
            res.warnings.append(f"Error parsing ELF binary: {e}")

        return res

    def _parse_symbols(self, res: ELFParseResult):
        """Parse symbols from .dynsym or .symtab if available."""
        sym_sec = None
        str_sec = None
        for sec in res.sections:
            if sec.sh_type in (self.SHT_DYNSYM, self.SHT_SYMTAB):
                sym_sec = sec
                if 0 <= sec.sh_link < len(res.sections):
                    str_sec = res.sections[sec.sh_link]
                break

        if not sym_sec or not str_sec:
            res.warnings.append("Binary symbols stripped or symbol table not found")
            return

        if sym_sec.sh_offset + sym_sec.sh_size > self.size or str_sec.sh_offset + str_sec.sh_size > self.size:
            res.warnings.append("Symbol table sections out of bounds")
            return

        strtab_data = self.data[str_sec.sh_offset:str_sec.sh_offset+str_sec.sh_size]
        enc = res.endian_char
        ent_sz = 24 if res.is_64bit else 16
        num_syms = sym_sec.sh_size // ent_sz

        for i in range(min(num_syms, 10000)):  # Cap at 10,000 to prevent unbounded parsing
            off = sym_sec.sh_offset + (i * ent_sz)
            if res.is_64bit:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                    f"{enc}IBBHQQ", self.data, off
                )
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    f"{enc}IIIBBH", self.data, off
                )

            name = self._read_str_from_tab(strtab_data, st_name)
            if name:
                st_type = st_info & 0xF
                is_fn = (st_type == 2)  # STT_FUNC
                res.symbols.append(ELFSymbol(
                    name=name, value=st_value, size=st_size,
                    info=st_info, other=st_other, shndx=st_shndx,
                    is_function=is_fn
                ))

    @staticmethod
    def _read_str_from_tab(tab: bytes, offset: int) -> str:
        if offset >= len(tab):
            return ""
        end = tab.find(b"\x00", offset)
        if end == -1:
            end = len(tab)
        try:
            return tab[offset:end].decode("utf-8", errors="replace")
        except Exception:
            return ""

    @staticmethod
    def _get_machine_name(machine: int) -> str:
        machine_map = {
            3: "x86",
            40: "ARMv7",
            62: "x64",
            183: "ARM64",
        }
        return machine_map.get(machine, f"Machine_{machine}")

    @staticmethod
    def vaddr_to_file_offset(vaddr: int, segments: List[ELFSegment]) -> Optional[int]:
        """Translate a Virtual Address to a physical file offset via PT_LOAD segments."""
        for seg in segments:
            if seg.p_type == 1:  # PT_LOAD
                if seg.p_vaddr <= vaddr < (seg.p_vaddr + seg.p_filesz):
                    return seg.p_offset + (vaddr - seg.p_vaddr)
        return None

    @staticmethod
    def file_offset_to_vaddr(file_off: int, segments: List[ELFSegment]) -> Optional[int]:
        """Translate a physical file offset to a Virtual Address via PT_LOAD segments."""
        for seg in segments:
            if seg.p_type == 1:  # PT_LOAD
                if seg.p_offset <= file_off < (seg.p_offset + seg.p_filesz):
                    return seg.p_vaddr + (file_off - seg.p_offset)
        return None
