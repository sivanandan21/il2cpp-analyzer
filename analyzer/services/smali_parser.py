"""
Smali Parser Service.
Parses disassembled Smali files produced by Apktool / baksmali into structured
ParsedClass, ParsedField, and ParsedMethod definitions.
"""

from typing import List, Dict, Optional, Tuple
from pathlib import Path
import os
import re

from .metadata_parser import (
    ParsedClass, ParsedField, ParsedMethod, ParsedParameter, ParsedAssembly
)


class SmaliParser:
    """Discovers and parses .smali source files into structured class models."""

    @classmethod
    def parse_smali_directory(cls, decompiled_dir: Path, package_filter: Optional[str] = None, max_classes: int = 500) -> List[ParsedClass]:
        classes: List[ParsedClass] = []
        if not decompiled_dir or not decompiled_dir.exists():
            return classes

        smali_dirs = [d for d in decompiled_dir.iterdir() if d.is_dir() and d.name.startswith("smali")]
        if not smali_dirs:
            # Check if directory itself contains smali files
            smali_dirs = [decompiled_dir]

        filter_clean = package_filter.replace('.', '/') if package_filter else ""

        # Priority 1: App package smali files
        # Priority 2: Game / Cordova / Activity / Security / Billing files
        collected_files = []
        fallback_files = []

        for s_dir in smali_dirs:
            for root, _, files in os.walk(s_dir):
                for f in files:
                    if f.endswith(".smali"):
                        f_path = Path(root) / f
                        rel_path = f_path.relative_to(s_dir).as_posix()
                        
                        if filter_clean and filter_clean in rel_path:
                            collected_files.append(f_path)
                        elif any(k in rel_path.lower() for k in ("funtomic", "dynamon", "game", "mod", "billing", "purchase", "cheat", "anti", "activity", "network", "plugin")):
                            collected_files.append(f_path)
                        else:
                            if len(fallback_files) < 300:
                                fallback_files.append(f_path)

        all_target_files = (collected_files + fallback_files)[:max_classes]

        for s_file in all_target_files:
            try:
                content = s_file.read_text(encoding="utf-8", errors="ignore")
                parsed_cls = cls.parse_smali_text(content)
                if parsed_cls:
                    classes.append(parsed_cls)
            except Exception:
                pass

        return classes

    @classmethod
    def parse_smali_text(cls, text: str) -> Optional[ParsedClass]:
        lines = text.splitlines()
        class_name = ""
        super_name = ""
        modifiers = []
        fields: List[ParsedField] = []
        methods: List[ParsedMethod] = []
        curr_offset = 0x10

        in_method = False
        curr_method: Optional[ParsedMethod] = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Class declaration: .class <modifiers> <type>;
            if line.startswith(".class "):
                parts = line.split()
                if len(parts) >= 2:
                    raw_type = parts[-1].rstrip(";")
                    class_name = cls.demangle_type(raw_type)
                    modifiers = parts[1:-1]

            # Super declaration: .super <type>;
            elif line.startswith(".super "):
                parts = line.split()
                if len(parts) >= 2:
                    super_name = cls.demangle_type(parts[-1].rstrip(";"))

            # Field declaration: .field <modifiers> <name>:<type> [= <value>]
            elif line.startswith(".field ") and not in_method:
                field_match = re.match(r'^\.field\s+(.*?)\s+([A-Za-z0-9_$]+):([^\s=]+)', line)
                if field_match:
                    f_mods = field_match.group(1).split()
                    f_name = field_match.group(2)
                    f_raw_type = field_match.group(3)
                    f_type = cls.demangle_type(f_raw_type)
                    is_static = "static" in f_mods
                    is_final = "final" in f_mods

                    fields.append(ParsedField(
                        name=f_name,
                        type_name=f_type,
                        offset=curr_offset,
                        offset_hex=f"0x{curr_offset:04X}",
                        is_static=is_static,
                        is_const=is_final,
                        visibility="public" if "public" in f_mods else ("private" if "private" in f_mods else "protected")
                    ))
                    curr_offset += 0x08

            # Method declaration: .method <modifiers> <name>(<params>)<return_type>
            elif line.startswith(".method "):
                in_method = True
                m_match = re.match(r'^\.method\s+(.*?)\s+([A-Za-z0-9_$<>-]+)\((.*?)\)(.+)$', line)
                if m_match:
                    m_mods = m_match.group(1).split()
                    m_name = m_match.group(2)
                    m_params_raw = m_match.group(3)
                    m_ret_raw = m_match.group(4)
                    m_ret = cls.demangle_type(m_ret_raw)
                    params = [ParsedParameter(name=f"p{i}", type_name=cls.demangle_type(p)) for i, p in enumerate(cls.split_descriptors(m_params_raw))]

                    curr_method = ParsedMethod(
                        name=m_name,
                        return_type=m_ret,
                        signature=f"{m_ret} {m_name}({', '.join(p.type_name for p in params)})",
                        parameters=params,
                        is_static="static" in m_mods,
                        rva=0x200000 + len(methods) * 0x40
                    )
                    methods.append(curr_method)

            elif line.startswith(".end method"):
                in_method = False
                curr_method = None

        if not class_name:
            return None

        # Determine namespace
        if "." in class_name:
            namespace, short_name = class_name.rsplit(".", 1)
        else:
            namespace, short_name = "", class_name

        return ParsedClass(
            name=short_name,
            namespace=namespace,
            assembly_name="Android.Dalvik.Smali",
            full_name=class_name,
            base_class_name=super_name,
            fields=fields,
            methods=methods
        )

    @classmethod
    def demangle_type(cls, raw: str) -> str:
        """Converts Dalvik type descriptor to clean Java/C# representation."""
        if not raw:
            return "void"
        raw = raw.strip()
        if raw == "Z": return "boolean"
        if raw == "B": return "byte"
        if raw == "S": return "short"
        if raw == "C": return "char"
        if raw == "I": return "int"
        if raw == "J": return "long"
        if raw == "F": return "float"
        if raw == "D": return "double"
        if raw == "V": return "void"
        if raw.startswith("["):
            return cls.demangle_type(raw[1:]) + "[]"
        if raw.startswith("L"):
            raw = raw[1:]
        if raw.endswith(";"):
            raw = raw[:-1]
        return raw.replace("/", ".")

    @classmethod
    def split_descriptors(cls, raw: str) -> List[str]:
        """Splits concatenated descriptor types like 'ILjava/lang/String;Z'."""
        types = []
        i = 0
        while i < len(raw):
            c = raw[i]
            if c in "ZBSCIJFD":
                types.append(c)
                i += 1
            elif c == "[":
                # Array
                arr_prefix = "["
                i += 1
                while i < len(raw) and raw[i] == "[":
                    arr_prefix += "["
                    i += 1
                if i < len(raw):
                    if raw[i] == "L":
                        end = raw.find(";", i)
                        if end != -1:
                            types.append(arr_prefix + raw[i:end+1])
                            i = end + 1
                        else:
                            i += 1
                    else:
                        types.append(arr_prefix + raw[i])
                        i += 1
            elif c == "L":
                end = raw.find(";", i)
                if end != -1:
                    types.append(raw[i:end+1])
                    i = end + 1
                else:
                    i += 1
            else:
                i += 1
        return types
