"""
APK Inspector & Decompilation Engine.
Provides automated Android APK extraction, binary AndroidManifest.xml string decoding,
Unity engine version detection, IL2CPP component identification (global-metadata.dat & libil2cpp.so),
and gameplay asset categorization without requiring heavy external dependencies.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
import zipfile
import struct
import re
import os


@dataclass
class ApkInspectionReport:
    is_valid_apk: bool = False
    package_name: str = ""
    app_label: str = ""
    version_name: str = ""
    version_code: str = ""
    main_activity: str = ""
    target_sdk: str = ""
    min_sdk: str = ""
    permissions: List[str] = field(default_factory=list)
    engine_type: str = "UNKNOWN"  # Unity (IL2CPP), Unity (Mono), Unreal Engine, Native Android
    unity_version: str = "UNKNOWN"
    platform: str = "Android"
    architecture: str = "UNKNOWN"  # ARM64, ARMv7, x86_64
    metadata_path: Optional[Path] = None
    binary_path: Optional[Path] = None
    all_libraries: List[str] = field(default_factory=list)
    detected_files: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ApkInspector:
    """Safe, high-performance APK inspection and IL2CPP component extractor."""

    @classmethod
    def inspect_and_extract(cls, apk_path: Path, output_dir: Path) -> ApkInspectionReport:
        report = ApkInspectionReport()

        if not apk_path.exists() or not zipfile.is_zipfile(apk_path):
            report.warnings.append(f"File is not a valid APK archive: {apk_path.name}")
            return report

        report.is_valid_apk = True
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                namelist = zf.namelist()
                namelist_lower = {n.lower(): n for n in namelist}

                # 1. Inspect AndroidManifest.xml if present
                if "androidmanifest.xml" in namelist_lower:
                    try:
                        manifest_name = namelist_lower["androidmanifest.xml"]
                        manifest_bytes = zf.read(manifest_name)
                        manifest_info = cls.parse_android_manifest(manifest_bytes)
                        report.package_name = manifest_info.get("package_name", "")
                        report.app_label = manifest_info.get("app_label", "")
                        report.version_name = manifest_info.get("version_name", "")
                        report.version_code = manifest_info.get("version_code", "")
                        report.main_activity = manifest_info.get("main_activity", "")
                        report.permissions = manifest_info.get("permissions", [])
                    except Exception as e:
                        report.warnings.append(f"AndroidManifest parsing notice: {e}")

                # 2. Check for Unity Engine version in assets
                report.unity_version = cls.detect_unity_version(zf, namelist)

                # 3. Identify all native shared libraries (.so)
                so_files = [n for n in namelist if n.lower().endswith(".so")]
                report.all_libraries = [Path(s).name for s in so_files]

                # 4. Check Engine Type (IL2CPP vs Mono vs Unreal vs Godot vs Native)
                has_global_metadata = any("global-metadata.dat" in n.lower() for n in namelist)
                has_libil2cpp = any("libil2cpp.so" in n.lower() for n in namelist)
                has_mono_assemblies = any("assembly-csharp.dll" in n.lower() for n in namelist)
                has_unreal = any("libue4.so" in n.lower() or "libunreal.so" in n.lower() for n in namelist)
                has_godot = any("libgodot_android.so" in n.lower() for n in namelist)

                if has_global_metadata or has_libil2cpp:
                    report.engine_type = "Unity (IL2CPP)"
                elif has_mono_assemblies:
                    report.engine_type = "Unity (Mono)"
                elif has_unreal:
                    report.engine_type = "Unreal Engine"
                elif has_godot:
                    report.engine_type = "Godot Engine"
                else:
                    report.engine_type = "Native Android / Other"

                # 5. Locate best libil2cpp.so (prioritize ARM64 > ARMv7 > x86_64)
                libil2cpp_entry = None
                arch_candidates = [
                    ("lib/arm64-v8a/libil2cpp.so", "ARM64"),
                    ("lib/armeabi-v7a/libil2cpp.so", "ARMv7"),
                    ("lib/x86_64/libil2cpp.so", "x86_64"),
                    ("lib/x86/libil2cpp.so", "x86"),
                ]

                for path_candidate, arch in arch_candidates:
                    if path_candidate.lower() in namelist_lower:
                        libil2cpp_entry = namelist_lower[path_candidate.lower()]
                        report.architecture = arch
                        break

                if not libil2cpp_entry:
                    for n in namelist:
                        if n.lower().endswith("libil2cpp.so"):
                            libil2cpp_entry = n
                            if "arm64" in n.lower():
                                report.architecture = "ARM64"
                            elif "v7a" in n.lower() or "armeabi" in n.lower():
                                report.architecture = "ARMv7"
                            elif "x86_64" in n.lower():
                                report.architecture = "x86_64"
                            else:
                                report.architecture = "ARM64"
                            break

                # 6. Locate global-metadata.dat or dump.cs
                metadata_entry = None
                meta_candidates = [
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                    "assets/bin/Data/Managed/global-metadata.dat",
                    "Data/Managed/Metadata/global-metadata.dat",
                ]

                for cand in meta_candidates:
                    if cand.lower() in namelist_lower:
                        metadata_entry = namelist_lower[cand.lower()]
                        break

                if not metadata_entry:
                    for n in namelist:
                        if n.lower().endswith("global-metadata.dat") or n.lower().endswith("dump.cs"):
                            metadata_entry = n
                            break

                # 7. Extract target components safely into isolated work directory
                extract_candidates = []
                if metadata_entry:
                    extract_candidates.append(metadata_entry)
                if libil2cpp_entry:
                    extract_candidates.append(libil2cpp_entry)

                # Also extract dump.cs or string files if present
                for n in namelist:
                    n_lower = n.lower()
                    if n_lower.endswith((".cs", ".json", ".csv")) and n not in extract_candidates:
                        extract_candidates.append(n)

                for entry in extract_candidates:
                    target_file = (output_dir / Path(entry).name).resolve()
                    with zf.open(entry) as src, open(target_file, 'wb') as dst:
                        dst.write(src.read())

                    if entry == metadata_entry:
                        report.metadata_path = target_file
                        report.detected_files.append({"name": target_file.name, "type": "global-metadata.dat"})
                    elif entry == libil2cpp_entry:
                        report.binary_path = target_file
                        report.detected_files.append({"name": target_file.name, "type": "libil2cpp.so"})

                if not report.architecture or report.architecture == "UNKNOWN":
                    report.architecture = "ARM64"

        except Exception as e:
            report.warnings.append(f"APK extraction exception: {e}")

        return report

    @classmethod
    def parse_android_manifest(cls, data: bytes) -> Dict[str, Any]:
        """Parse Android Binary XML (AXML) string pool and extract package / activity info."""
        info: Dict[str, Any] = {
            "package_name": "",
            "version_name": "",
            "version_code": "",
            "app_label": "",
            "main_activity": "",
            "permissions": []
        }

        if len(data) < 36:
            return info

        try:
            # Check AXML Magic (0x00080003)
            magic = struct.unpack('<I', data[:4])[0]
            if magic != 0x00080003:
                return info

            # String pool chunk header at offset 8
            chunk_type, chunk_size, string_count, style_count, flags, strings_start, styles_start = struct.unpack(
                '<IIIIIII', data[8:36]
            )

            is_utf8 = bool(flags & (1 << 8))
            offsets = struct.unpack(f'<{string_count}I', data[36 : 36 + string_count * 4])
            base = 8 + strings_start
            extracted_strings = []

            for off in offsets:
                pos = base + off
                if pos >= len(data):
                    continue
                if is_utf8:
                    length = data[pos]
                    pos += 1
                    if length & 0x80:
                        pos += 1
                    if pos >= len(data):
                        continue
                    byte_len = data[pos]
                    pos += 1
                    if byte_len & 0x80:
                        pos += 1
                    s = data[pos : pos + byte_len].decode('utf-8', 'ignore')
                else:
                    if pos + 2 > len(data):
                        continue
                    char_len = struct.unpack('<H', data[pos : pos + 2])[0]
                    pos += 2
                    s = data[pos : pos + char_len * 2].decode('utf-16le', 'ignore')
                extracted_strings.append(s)

            # Discover package name: reverse domain pattern (e.g. com.company.game)
            package_candidates = []
            for s in extracted_strings:
                s_strip = s.strip()
                if re.match(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*){2,}$', s_strip):
                    if not s_strip.startswith(('android.', 'androidx.', 'com.google.', 'com.unity3d.')):
                        package_candidates.append(s_strip)
                if s_strip.startswith('android.permission.'):
                    info["permissions"].append(s_strip.replace('android.permission.', ''))

            if package_candidates:
                info["package_name"] = package_candidates[0]
            elif any(s.count('.') >= 1 for s in extracted_strings):
                for s in extracted_strings:
                    if '.' in s and not s.startswith(('android', 'androidx', 'http')):
                        info["package_name"] = s
                        break

            # Discover Version Name & Code
            for idx, s in enumerate(extracted_strings):
                if s == "versionName" and idx + 1 < len(extracted_strings):
                    info["version_name"] = extracted_strings[idx + 1]
                elif s == "versionCode" and idx + 1 < len(extracted_strings):
                    info["version_code"] = extracted_strings[idx + 1]
                elif s.endswith("Activity") and not info["main_activity"]:
                    info["main_activity"] = s

            # Infer user-friendly app label from package name if not explicitly set
            if info["package_name"]:
                parts = info["package_name"].split('.')
                clean_name = parts[-1].replace('_', ' ').replace('-', ' ').title()
                info["app_label"] = clean_name

        except Exception:
            pass

        return info

    @classmethod
    def detect_unity_version(cls, zf: zipfile.ZipFile, namelist: List[str]) -> str:
        """Scan Unity data files inside APK archive for engine version string."""
        target_entries = [
            "assets/bin/Data/globalgamemanagers",
            "assets/bin/Data/data.unity3d",
            "assets/bin/Data/unity_builtin_extra",
            "assets/bin/Data/settings.xml"
        ]

        namelist_lower = {n.lower(): n for n in namelist}

        for target in target_entries:
            if target.lower() in namelist_lower:
                real_name = namelist_lower[target.lower()]
                try:
                    with zf.open(real_name) as f:
                        header_bytes = f.read(512)
                        match = re.search(rb"(20\d{2}\.\d+\.\d+[a-z0-9]+)", header_bytes)
                        if match:
                            return match.group(1).decode('ascii', 'ignore')
                except Exception:
                    pass

        # Fallback: inspect any file in assets/bin/Data/
        for n in namelist:
            if n.startswith("assets/bin/Data/") and not n.endswith("/"):
                try:
                    with zf.open(n) as f:
                        header = f.read(256)
                        match = re.search(rb"(20\d{2}\.\d+\.\d+[a-z0-9]+)", header)
                        if match:
                            return match.group(1).decode('ascii', 'ignore')
                except Exception:
                    pass

        return "UNKNOWN"
