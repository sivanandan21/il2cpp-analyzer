"""
IL2CPP Metadata Parser.
Supports:
1. Binary parsing of 'global-metadata.dat' (IL2CPP metadata versions 16 to 31).
2. Text parsing of 'dump.cs' (Il2CppDumper output).
3. JSON/CSV dump inputs.
Includes strict bounds checking, offset validation, length validation, and malformed input detection.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
import struct
import re
import json
import csv
from io import StringIO
from pathlib import Path

IL2CPP_METADATA_MAGIC = 0xFAB11BAF

# Metadata header offsets and sizes (Version 24-31 common structure)
HEADER_FIELDS = [
    "sanity", "version", "stringLiteralOffset", "stringLiteralSize",
    "stringLiteralDataOffset", "stringLiteralDataSize",
    "stringOffset", "stringSize", "eventsOffset", "eventsSize",
    "propertiesOffset", "propertiesSize", "methodsOffset", "methodsSize",
    "parameterDefaultValuesOffset", "parameterDefaultValuesSize",
    "fieldDefaultValuesOffset", "fieldDefaultValuesSize",
    "fieldAndParameterDefaultValueDataOffset", "fieldAndParameterDefaultValueDataSize",
    "fieldMarshaledSizesOffset", "fieldMarshaledSizesSize",
    "parametersOffset", "parametersSize", "fieldsOffset", "fieldsSize",
    "genericParametersOffset", "genericParametersSize",
    "genericParameterConstraintsOffset", "genericParameterConstraintsSize",
    "genericContainersOffset", "genericContainersSize",
    "nestedTypesOffset", "nestedTypesSize", "interfacesOffset", "interfacesSize",
    "vtableMethodsOffset", "vtableMethodsSize",
    "interfaceOffsetsOffset", "interfaceOffsetsSize",
    "typeDefinitionsOffset", "typeDefinitionsSize",
    "imagesOffset", "imagesSize", "assembliesOffset", "assembliesSize"
]

@dataclass
class ParsedParameter:
    name: str
    type_name: str
    position: int = 0
    default_value: Optional[str] = None

@dataclass
class ParsedField:
    name: str
    type_name: str
    offset: Optional[int] = None
    is_static: bool = False
    is_const: bool = False
    visibility: str = "public"
    offset_hex: str = ""

@dataclass
class ParsedMethod:
    name: str
    return_type: str = "void"
    signature: str = ""
    parameters: List[ParsedParameter] = field(default_factory=list)
    rva: Optional[int] = None
    va: Optional[int] = None
    file_offset: Optional[int] = None
    is_static: bool = False
    is_virtual: bool = False
    is_abstract: bool = False
    token: Optional[int] = None
    method_index: Optional[int] = None

@dataclass
class ParsedProperty:
    name: str
    type_name: str
    getter: Optional[str] = None
    setter: Optional[str] = None

@dataclass
class ParsedEnumItem:
    name: str
    value: Any

@dataclass
class ParsedClass:
    name: str
    namespace: str = ""
    assembly_name: str = "Assembly-CSharp"
    full_name: str = ""
    base_class_name: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    nested_in: Optional[str] = None
    is_value_type: bool = False
    is_enum: bool = False
    is_interface: bool = False
    is_abstract: bool = False
    token: Optional[int] = None
    type_index: Optional[int] = None
    fields: List[ParsedField] = field(default_factory=list)
    methods: List[ParsedMethod] = field(default_factory=list)
    properties: List[ParsedProperty] = field(default_factory=list)
    enum_items: List[ParsedEnumItem] = field(default_factory=list)
    raw_attributes: List[str] = field(default_factory=list)

@dataclass
class ParsedAssembly:
    name: str
    class_count: int = 0
    token: Optional[int] = None

@dataclass
class ParsedMetadataResult:
    is_valid: bool = False
    source_type: str = "UNKNOWN"
    metadata_version: Optional[int] = None
    assemblies: List[ParsedAssembly] = field(default_factory=list)
    classes: List[ParsedClass] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=lambda: {
        "classes": 0, "methods": 0, "fields": 0, "properties": 0, "enums": 0
    })


class MetadataParser:
    """Universal parser for IL2CPP metadata binaries and dump files."""

    @classmethod
    def parse_file(cls, file_path: Path) -> ParsedMetadataResult:
        if not file_path.exists():
            res = ParsedMetadataResult()
            res.warnings.append(f"File not found: {file_path}")
            return res

        filename_lower = file_path.name.lower()
        if filename_lower.endswith(".dat"):
            with open(file_path, "rb") as f:
                return cls.parse_binary_dat(f.read())
        elif filename_lower.endswith(".cs") or "dump" in filename_lower:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return cls.parse_dump_cs(f.read())
        elif filename_lower.endswith(".json"):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return cls.parse_json_dump(f.read())
        elif filename_lower.endswith(".csv"):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return cls.parse_csv_dump(f.read())
        else:
            # Try sniffing first 8 bytes
            with open(file_path, "rb") as f:
                header = f.read(8)
                if len(header) >= 8 and struct.unpack_from("<I", header, 0)[0] == IL2CPP_METADATA_MAGIC:
                    f.seek(0)
                    return cls.parse_binary_dat(f.read())
            # Fallback to text dump parsing
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return cls.parse_dump_cs(f.read())

    # =========================================================================
    # 1. Binary global-metadata.dat Parser
    # =========================================================================
    @classmethod
    def parse_binary_dat(cls, data: bytes) -> ParsedMetadataResult:
        res = ParsedMetadataResult(source_type="global-metadata.dat")
        if len(data) < 128:
            res.warnings.append("Metadata file too small to contain valid header")
            return res

        magic, version = struct.unpack_from("<II", data, 0)
        endian = "<"
        if magic != IL2CPP_METADATA_MAGIC:
            # Check big-endian
            magic_be, version_be = struct.unpack_from(">II", data, 0)
            if magic_be == IL2CPP_METADATA_MAGIC:
                magic, version = magic_be, version_be
                endian = ">"
            else:
                res.warnings.append(f"Invalid metadata magic: 0x{magic:08x} (expected 0x{IL2CPP_METADATA_MAGIC:08x})")
                return res

        res.metadata_version = version
        res.is_valid = True

        # Header unpacking
        hdr_count = min(len(HEADER_FIELDS), (len(data) // 4))
        raw_hdr = struct.unpack_from(f"{endian}{hdr_count}I", data, 0)
        hdr = dict(zip(HEADER_FIELDS[:hdr_count], raw_hdr))

        def get_string(str_offset: int) -> str:
            base = hdr.get("stringOffset", 0)
            pos = base + str_offset
            if pos >= len(data) or pos < 0:
                return ""
            end = data.find(b"\x00", pos)
            if end == -1:
                end = min(pos + 256, len(data))
            try:
                return data[pos:end].decode("utf-8", errors="replace")
            except Exception:
                return ""

        def validate_table(off_key: str, sz_key: str, item_size: int) -> Tuple[int, int]:
            off = hdr.get(off_key, 0)
            sz = hdr.get(sz_key, 0)
            if off < 0 or off + sz > len(data):
                res.warnings.append(f"Table {off_key} (offset {off}, size {sz}) out of bounds")
                return 0, 0
            if item_size <= 0:
                return off, 0
            count = sz // item_size
            return off, count

        try:
            # Parse Images
            # Il2CppImageDefinition struct size in v24-v31 is typically 40 bytes (or 32 in older)
            img_item_sz = 40 if version >= 24 else 32
            images_off, images_count = validate_table("imagesOffset", "imagesSize", img_item_sz)

            # Parse TypeDefinitions
            # Il2CppTypeDefinition size: v24-v29 is 88-96 bytes
            type_def_sz = 96 if version >= 29 else (88 if version >= 24 else 72)
            types_off, types_count = validate_table("typeDefinitionsOffset", "typeDefinitionsSize", type_def_sz)

            # Parse Methods
            # Il2CppMethodDefinition size: ~32-36 bytes
            method_item_sz = 36 if version >= 24 else 32
            methods_off, methods_count = validate_table("methodsOffset", "methodsSize", method_item_sz)

            # Parse Fields
            # Il2CppFieldDefinition size: ~12-16 bytes
            field_item_sz = 16 if version >= 24 else 12
            fields_off, fields_count = validate_table("fieldsOffset", "fieldsSize", field_item_sz)

            # Parse Parameters
            # Il2CppParameterDefinition size: ~12-16 bytes
            param_item_sz = 16 if version >= 24 else 12
            params_off, params_count = validate_table("parametersOffset", "parametersSize", param_item_sz)

            # Assemblies list
            asm_map = {}
            for i in range(min(images_count, 500)):
                ioff = images_off + (i * img_item_sz)
                name_idx, = struct.unpack_from(f"{endian}i", data, ioff)
                img_name = get_string(name_idx)
                type_start, type_cnt = struct.unpack_from(f"{endian}II", data, ioff + 8)
                parsed_asm = ParsedAssembly(name=img_name, class_count=type_cnt, token=i)
                res.assemblies.append(parsed_asm)
                asm_map[i] = img_name

            # Read types
            for t_idx in range(min(types_count, 50000)):
                toff = types_off + (t_idx * type_def_sz)
                name_idx, ns_idx, custom_attr_idx, val_idx, flags, byval_idx, type_idx = struct.unpack_from(
                    f"{endian}iiiiiii", data, toff
                )
                t_name = get_string(name_idx)
                t_ns = get_string(ns_idx)

                # Field / Method offsets within type
                # In Il2CppTypeDefinition:
                # fieldStart, methodStart, eventStart, propertyStart, nestedTypesStart, interfacesStart, vtableStart, interfaceOffsetsStart, methodCount, propertyCount, fieldCount
                # Layout varies slightly by version; safely unpack standard indices:
                field_start = 0
                field_cnt = 0
                method_start = 0
                method_cnt = 0
                try:
                    # In v24+:
                    # fieldStart (int32 at offset 36), methodStart (int32 at 40), methodCount (uint16 at 60), fieldCount (uint16 at 64)
                    field_start, method_start = struct.unpack_from(f"{endian}ii", data, toff + 36)
                    method_cnt, = struct.unpack_from(f"{endian}H", data, toff + 60)
                    field_cnt, = struct.unpack_from(f"{endian}H", data, toff + 64)
                except Exception:
                    pass

                full_name = f"{t_ns}.{t_name}" if t_ns else t_name
                is_val = bool(flags & 0x01)
                is_enum_flag = bool(flags & 0x02)

                cls_obj = ParsedClass(
                    name=t_name or f"Type_{t_idx}",
                    namespace=t_ns,
                    full_name=full_name,
                    assembly_name="Assembly-CSharp",
                    is_value_type=is_val,
                    is_enum=is_enum_flag,
                    token=t_idx,
                    type_index=t_idx
                )

                # Read Fields for this type
                if fields_off > 0 and 0 <= field_start < fields_count:
                    for f_i in range(min(field_cnt, 200)):
                        actual_f_idx = field_start + f_i
                        if actual_f_idx >= fields_count:
                            break
                        foff = fields_off + (actual_f_idx * field_item_sz)
                        fname_idx, = struct.unpack_from(f"{endian}i", data, foff)
                        fname = get_string(fname_idx)
                        cls_obj.fields.append(ParsedField(
                            name=fname or f"field_{f_i}",
                            type_name="object",
                            visibility="public"
                        ))

                # Read Methods for this type
                if methods_off > 0 and 0 <= method_start < methods_count:
                    for m_i in range(min(method_cnt, 500)):
                        actual_m_idx = method_start + m_i
                        if actual_m_idx >= methods_count:
                            break
                        moff = methods_off + (actual_m_idx * method_item_sz)
                        mname_idx, = struct.unpack_from(f"{endian}i", data, moff)
                        mname = get_string(mname_idx)
                        cls_obj.methods.append(ParsedMethod(
                            name=mname or f"method_{m_i}",
                            method_index=actual_m_idx
                        ))

                res.classes.append(cls_obj)

        except Exception as e:
            res.warnings.append(f"Error reading metadata tables: {e}")

        cls._compute_stats(res)
        return res

    # =========================================================================
    # 2. Text dump.cs Parser
    # =========================================================================
    @classmethod
    def parse_dump_cs(cls, text: str) -> ParsedMetadataResult:
        res = ParsedMetadataResult(source_type="dump.cs", is_valid=True)

        # Regex patterns for dump.cs comments and definitions
        re_image = re.compile(r"//\s*Image\s*\d+:\s*([^\s]+)")
        re_namespace = re.compile(r"namespace\s+([\w\.]+)")
        re_class = re.compile(
            r"//\s*Namespace:\s*(?P<ns>[\w\.]*)\s*\n"
            r"(?://[^\n]*\n)*"
            r"(?:public|private|protected|internal)?\s*(?:static|abstract|sealed)?\s*(?P<kind>class|struct|interface|enum)\s+(?P<name>\w+)(?:<[^>]+>)?(?:\s*:\s*(?P<base>[^{\n]+))?",
            re.MULTILINE
        )

        current_assembly = "Assembly-CSharp.dll"
        lines = text.splitlines()

        current_class: Optional[ParsedClass] = None
        current_namespace = ""
        pending_ns = ""
        in_enum = False

        # Pre-scan for Unity version
        v_match = re.search(r"//\s*Unity\s*version\s*:\s*([^\n\r]+)", text, re.IGNORECASE)
        if v_match:
            res.warnings.append(f"Unity Version found in header: {v_match.group(1).strip()}")

        i = 0
        num_lines = len(lines)

        while i < num_lines:
            line = lines[i].strip()

            # Track image
            if line.startswith("// Image"):
                m_img = re_image.search(line)
                if m_img:
                    current_assembly = m_img.group(1).strip()
                    if not any(a.name == current_assembly for a in res.assemblies):
                        res.assemblies.append(ParsedAssembly(name=current_assembly))

            # Track namespace block
            if line.startswith("namespace ") and "{" in line:
                m_ns = re_namespace.search(line)
                if m_ns:
                    current_namespace = m_ns.group(1).strip()

            # Class header comment: Namespace: ...
            if line.startswith("// Namespace:"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    pending_ns = parts[1].strip()

            # Detect Class / Struct / Interface / Enum declaration
            # Examples:
            # public class PlayerStats : MonoBehaviour // TypeDefIndex: 1234
            # public enum GameState
            if any(k in line for k in ["class ", "struct ", "interface ", "enum "]) and not line.startswith("//"):
                m_cls = re.search(
                    r"(?:public|private|protected|internal)?\s*(?:static|abstract|sealed)?\s*(class|struct|interface|enum)\s+(\w+)(?:<[^>]+>)?(?:\s*:\s*([^{\r\n]+))?",
                    line
                )
                if m_cls:
                    kind = m_cls.group(1)
                    cls_name = m_cls.group(2)
                    base_raw = m_cls.group(3)

                    base_class = None
                    interfaces = []
                    if base_raw:
                        tokens = [t.strip() for t in base_raw.split(",") if t.strip()]
                        if tokens:
                            base_class = tokens[0]
                            interfaces = tokens[1:]

                    cls_ns = pending_ns or current_namespace
                    full_name = f"{cls_ns}.{cls_name}" if cls_ns else cls_name
                    in_enum = (kind == "enum")

                    current_class = ParsedClass(
                        name=cls_name,
                        namespace=cls_ns,
                        assembly_name=current_assembly,
                        full_name=full_name,
                        base_class_name=base_class,
                        interfaces=interfaces,
                        is_value_type=(kind in ["struct", "enum"]),
                        is_enum=in_enum,
                        is_interface=(kind == "interface")
                    )
                    res.classes.append(current_class)
                    pending_ns = ""
                    i += 1
                    continue

            if current_class is not None:
                # If we hit closing brace of class
                if line == "}":
                    current_class = None
                    in_enum = False
                    i += 1
                    continue

                if in_enum:
                    # Enum value line, e.g. None = 0, or Idle = 1,
                    m_enum = re.search(r"(\w+)\s*=\s*(-?\d+|0x[0-9a-fA-F]+)", line)
                    if m_enum:
                        val_str = m_enum.group(2)
                        val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
                        current_class.enum_items.append(ParsedEnumItem(name=m_enum.group(1), value=val))
                    i += 1
                    continue

                # Parse Field
                # Examples:
                # public float currentHealth; // 0x18
                # private int maxScore; // 0x1C
                # public static bool IsAlive; // 0x0
                # const int MaxLevel = 100;
                if ";" in line and ("// 0x" in line or "// Offset: 0x" in line or "const " in line):
                    # Check for offset comment
                    offset_val = None
                    offset_hex = ""
                    m_off = re.search(r"//\s*(?:Offset:\s*)?(0x[0-9a-fA-F]+)", line)
                    if m_off:
                        offset_hex = m_off.group(1)
                        try:
                            offset_val = int(offset_hex, 16)
                        except ValueError:
                            offset_val = None

                    decl = line.split("//")[0].strip().rstrip(";")
                    is_static = "static " in decl
                    is_const = "const " in decl

                    # Visibility
                    vis = "private"
                    for v in ["public", "protected", "internal", "private"]:
                        if v in decl:
                            vis = v
                            break

                    # Strip modifiers to extract type and field name
                    clean_decl = re.sub(r"\b(public|private|protected|internal|static|readonly|const|volatile)\b", "", decl).strip()
                    tokens = clean_decl.split()
                    if len(tokens) >= 2:
                        type_name = " ".join(tokens[:-1])
                        field_name = tokens[-1]
                        # Clean default assignments e.g. `int count = 5`
                        if "=" in field_name:
                            field_name = field_name.split("=")[0].strip()

                        current_class.fields.append(ParsedField(
                            name=field_name,
                            type_name=type_name,
                            offset=offset_val,
                            offset_hex=offset_hex,
                            is_static=is_static,
                            is_const=is_const,
                            visibility=vis
                        ))

                # Parse Method
                # Examples:
                # // RVA: 0x123456 Offset: 0x123456 VA: 0x7123456
                # public void TakeDamage(float amount) { }
                if line.startswith("// RVA:") or line.startswith("// Offset:"):
                    # Method comment line
                    rva_val = None
                    off_val = None
                    va_val = None

                    m_rva = re.search(r"\bRVA:\s*(0x[0-9a-fA-F]+)", line)
                    if m_rva:
                        try: rva_val = int(m_rva.group(1), 16)
                        except ValueError: pass

                    m_file_off = re.search(r"\bOffset:\s*(0x[0-9a-fA-F]+)", line)
                    if m_file_off:
                        try: off_val = int(m_file_off.group(1), 16)
                        except ValueError: pass

                    m_va = re.search(r"\bVA:\s*(0x[0-9a-fA-F]+)", line)
                    if m_va:
                        try: va_val = int(m_va.group(1), 16)
                        except ValueError: pass

                    # The next non-comment line is usually the method signature
                    j = i + 1
                    sig_line = ""
                    while j < num_lines and lines[j].strip().startswith("//"):
                        j += 1
                    if j < num_lines:
                        sig_line = lines[j].strip()

                    if "(" in sig_line and ")" in sig_line:
                        clean_sig = sig_line.split("{")[0].strip().rstrip(";")
                        is_static = "static " in clean_sig
                        is_virtual = "virtual " in clean_sig
                        is_abstract = "abstract " in clean_sig

                        # Extract name and parameters
                        m_mname = re.search(r"([\w\.<>]+)\s*\((.*?)\)", clean_sig)
                        if m_mname:
                            full_mname = m_mname.group(1)
                            mname = full_mname.split(".")[-1]
                            raw_params = m_mname.group(2).strip()

                            # Return type
                            left_part = clean_sig[:m_mname.start(1)].strip()
                            clean_left = re.sub(r"\b(public|private|protected|internal|static|virtual|override|abstract|async)\b", "", left_part).strip()
                            ret_type = clean_left if clean_left else "void"

                            # Parameters
                            param_objs = []
                            if raw_params:
                                p_list = raw_params.split(",")
                                for p_idx, p_str in enumerate(p_list):
                                    p_tokens = p_str.strip().split()
                                    if len(p_tokens) >= 2:
                                        p_type = " ".join(p_tokens[:-1])
                                        p_name = p_tokens[-1]
                                        param_objs.append(ParsedParameter(name=p_name, type_name=p_type, position=p_idx))

                            current_class.methods.append(ParsedMethod(
                                name=mname,
                                return_type=ret_type,
                                signature=clean_sig,
                                parameters=param_objs,
                                rva=rva_val,
                                va=va_val,
                                file_offset=off_val,
                                is_static=is_static,
                                is_virtual=is_virtual,
                                is_abstract=is_abstract
                            ))
                            i = j  # Fast forward

                # Parse Properties
                # Example: public int Health { get; set; }
                if ("{ get;" in line or "{ set;" in line) and "(" not in line:
                    clean_prop = line.split("{")[0].strip()
                    tokens = clean_prop.split()
                    if len(tokens) >= 2:
                        p_name = tokens[-1]
                        p_type = tokens[-2]
                        current_class.properties.append(ParsedProperty(name=p_name, type_name=p_type))

            i += 1

        cls._compute_stats(res)
        return res

    # =========================================================================
    # 3. JSON Dump Parser (classes.json, metadata.json)
    # =========================================================================
    @classmethod
    def parse_json_dump(cls, json_text: str) -> ParsedMetadataResult:
        res = ParsedMetadataResult(source_type="JSON Dump", is_valid=True)
        try:
            data = json.loads(json_text)
        except Exception as e:
            res.warnings.append(f"Invalid JSON: {e}")
            return res

        # Check if list of classes or root dict
        class_list = data if isinstance(data, list) else data.get("classes", data.get("Types", []))

        for c_data in class_list:
            if not isinstance(c_data, dict):
                continue
            c_name = c_data.get("name", c_data.get("Name", "UnnamedClass"))
            c_ns = c_data.get("namespace", c_data.get("Namespace", ""))
            c_asm = c_data.get("assembly", c_data.get("Assembly", "Assembly-CSharp"))
            full_name = f"{c_ns}.{c_name}" if c_ns else c_name

            cls_obj = ParsedClass(
                name=c_name,
                namespace=c_ns,
                assembly_name=c_asm,
                full_name=full_name,
                base_class_name=c_data.get("base", c_data.get("BaseClass")),
                is_value_type=bool(c_data.get("is_value_type", False)),
                is_enum=bool(c_data.get("is_enum", False))
            )

            # Fields
            for f_data in c_data.get("fields", c_data.get("Fields", [])):
                fname = f_data.get("name", f_data.get("Name", ""))
                ftype = f_data.get("type", f_data.get("Type", "object"))
                foff = f_data.get("offset", f_data.get("Offset"))
                off_val = None
                off_hex = ""
                if foff is not None:
                    if isinstance(foff, str):
                        off_hex = foff
                        off_val = int(foff, 16) if foff.startswith("0x") else int(foff)
                    else:
                        off_val = int(foff)
                        off_hex = hex(off_val)

                cls_obj.fields.append(ParsedField(
                    name=fname,
                    type_name=ftype,
                    offset=off_val,
                    offset_hex=off_hex,
                    is_static=bool(f_data.get("is_static", False)),
                    visibility=f_data.get("visibility", "public")
                ))

            # Methods
            for m_data in c_data.get("methods", c_data.get("Methods", [])):
                mname = m_data.get("name", m_data.get("Name", ""))
                mrva = m_data.get("rva", m_data.get("RVA"))
                mva = m_data.get("va", m_data.get("VA"))
                m_off = m_data.get("offset", m_data.get("FileOffset"))

                rva_val = int(mrva, 16) if isinstance(mrva, str) and mrva.startswith("0x") else (int(mrva) if mrva is not None else None)
                va_val = int(mva, 16) if isinstance(mva, str) and mva.startswith("0x") else (int(mva) if mva is not None else None)
                file_off_val = int(m_off, 16) if isinstance(m_off, str) and m_off.startswith("0x") else (int(m_off) if m_off is not None else None)

                cls_obj.methods.append(ParsedMethod(
                    name=mname,
                    return_type=m_data.get("return_type", "void"),
                    rva=rva_val,
                    va=va_val,
                    file_offset=file_off_val,
                    is_static=bool(m_data.get("is_static", False))
                ))

            res.classes.append(cls_obj)

        cls._compute_stats(res)
        return res

    # =========================================================================
    # 4. CSV Dump Parser (fields.csv, methods.csv)
    # =========================================================================
    @classmethod
    def parse_csv_dump(cls, csv_text: str) -> ParsedMetadataResult:
        res = ParsedMetadataResult(source_type="CSV Dump", is_valid=True)
        try:
            reader = csv.DictReader(StringIO(csv_text))
            class_map = {}

            for row in reader:
                # Try finding class and field/method
                c_name = row.get("Class", row.get("class", row.get("ClassName", "GlobalClass")))
                c_ns = row.get("Namespace", row.get("namespace", ""))
                full_name = f"{c_ns}.{c_name}" if c_ns else c_name

                if full_name not in class_map:
                    class_map[full_name] = ParsedClass(name=c_name, namespace=c_ns, full_name=full_name)
                    res.classes.append(class_map[full_name])

                cls_obj = class_map[full_name]

                # If field CSV
                if "Field" in row or "field" in row:
                    fname = row.get("Field", row.get("field", ""))
                    ftype = row.get("Type", row.get("type", "object"))
                    foff_raw = row.get("Offset", row.get("offset", ""))
                    off_val = None
                    off_hex = ""
                    if foff_raw:
                        off_hex = foff_raw
                        off_val = int(foff_raw, 16) if foff_raw.startswith("0x") else int(foff_raw)
                    cls_obj.fields.append(ParsedField(name=fname, type_name=ftype, offset=off_val, offset_hex=off_hex))

                # If method CSV
                if "Method" in row or "method" in row:
                    mname = row.get("Method", row.get("method", ""))
                    mrva_raw = row.get("RVA", row.get("rva", ""))
                    rva_val = int(mrva_raw, 16) if mrva_raw.startswith("0x") else (int(mrva_raw) if mrva_raw else None)
                    cls_obj.methods.append(ParsedMethod(name=mname, rva=rva_val))

        except Exception as e:
            res.warnings.append(f"CSV parse error: {e}")

        cls._compute_stats(res)
        return res

    @staticmethod
    def _compute_stats(res: ParsedMetadataResult):
        res.stats["classes"] = len(res.classes)
        f_count = 0
        m_count = 0
        p_count = 0
        e_count = 0
        for c in res.classes:
            f_count += len(c.fields)
            m_count += len(c.methods)
            p_count += len(c.properties)
            if c.is_enum or c.enum_items:
                e_count += 1
        res.stats["fields"] = f_count
        res.stats["methods"] = m_count
        res.stats["properties"] = p_count
        res.stats["enums"] = e_count
