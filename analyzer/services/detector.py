"""
Detection service for IL2CPP binaries, metadata files, platform, and architecture.
Safely inspects file magic bytes and directory structures without executing files.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any
import struct
import zipfile
import os

IL2CPP_METADATA_MAGIC = 0xFAB11BAF

@dataclass
class DetectionResult:
    platform: str = "UNKNOWN"
    architecture: str = "UNKNOWN"
    binary_format: str = "UNKNOWN"  # ELF, PE, UNKNOWN
    binary_name: str = "NOT DETECTED"
    binary_path: Optional[str] = None
    metadata_type: str = "NOT DETECTED"  # BINARY_DAT, DUMP_CS, JSON, CSV
    metadata_name: str = "NOT DETECTED"
    metadata_path: Optional[str] = None
    metadata_version: Optional[int] = None
    pointer_size: Optional[int] = None  # 4 or 8
    endianness: str = "UNKNOWN"  # Little Endian, Big Endian
    unity_version: str = "UNKNOWN"
    detected_files: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "architecture": self.architecture,
            "binary_format": self.binary_format,
            "binary_name": self.binary_name,
            "binary_path": self.binary_path,
            "metadata_type": self.metadata_type,
            "metadata_name": self.metadata_name,
            "metadata_path": self.metadata_path,
            "metadata_version": self.metadata_version if self.metadata_version is not None else "UNRESOLVED",
            "pointer_size": f"{self.pointer_size} bytes" if self.pointer_size else "UNRESOLVED",
            "endianness": self.endianness,
            "unity_version": self.unity_version,
            "detected_files": self.detected_files,
            "warnings": self.warnings
        }


class FormatDetector:
    """Safe format, platform, and architecture detector."""

    ELF_MAGIC = b"\x7fELF"
    PE_MAGIC = b"MZ"

    # Known Android library paths
    ANDROID_SO_CANDIDATES = [
        "lib/arm64-v8a/libil2cpp.so",
        "lib/armeabi-v7a/libil2cpp.so",
        "lib/x86_64/libil2cpp.so",
        "lib/x86/libil2cpp.so",
    ]

    # Known Android metadata paths
    ANDROID_METADATA_CANDIDATES = [
        "assets/bin/Data/Managed/Metadata/global-metadata.dat",
        "assets/bin/Data/Managed/global-metadata.dat",
        "Data/Managed/Metadata/global-metadata.dat",
    ]

    @classmethod
    def detect_file(cls, file_path: Path) -> DetectionResult:
        """Inspect a single uploaded file (zip, binary, dat, or text dump)."""
        result = DetectionResult()
        if not file_path.exists() or not file_path.is_file():
            result.warnings.append(f"File not found: {file_path}")
            return result

        # Check if file is a zip/apk archive
        if zipfile.is_zipfile(file_path):
            return cls.detect_archive(file_path)

        # Otherwise inspect raw file bytes
        cls._inspect_single_file(file_path, result)
        return result

    @classmethod
    def detect_archive(cls, archive_path: Path) -> DetectionResult:
        """Inspect an APK or ZIP archive without extracting entire archive."""
        result = DetectionResult()
        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                namelist = zf.namelist()
                namelist_lower = {name.lower(): name for name in namelist}

                # Look for global-metadata.dat
                for candidate in cls.ANDROID_METADATA_CANDIDATES:
                    if candidate.lower() in namelist_lower:
                        real_name = namelist_lower[candidate.lower()]
                        result.metadata_name = "global-metadata.dat"
                        result.metadata_type = "BINARY_DAT"
                        result.metadata_path = real_name
                        result.detected_files.append({"name": real_name, "type": "global-metadata.dat"})
                        # Peek at metadata header
                        try:
                            with zf.open(real_name) as mf:
                                header_data = mf.read(128)
                                cls._inspect_metadata_bytes(header_data, result)
                        except Exception as e:
                            result.warnings.append(f"Error reading metadata from archive: {e}")
                        break

                # Look for Android libil2cpp.so
                found_so = None
                for candidate in cls.ANDROID_SO_CANDIDATES:
                    if candidate.lower() in namelist_lower:
                        found_so = namelist_lower[candidate.lower()]
                        break

                # If not found in standard paths, search all entries for libil2cpp.so
                if not found_so:
                    for name in namelist:
                        if name.endswith("libil2cpp.so"):
                            found_so = name
                            break

                if found_so:
                    result.binary_name = Path(found_so).name
                    result.binary_path = found_so
                    result.platform = "Android"
                    result.detected_files.append({"name": found_so, "type": "libil2cpp.so"})
                    try:
                        with zf.open(found_so) as bf:
                            header_data = bf.read(64)
                            cls._inspect_elf_bytes(header_data, result)
                    except Exception as e:
                        result.warnings.append(f"Error inspecting ELF inside archive: {e}")

                # Look for Windows GameAssembly.dll inside zip
                for name in namelist:
                    if name.lower().endswith("gameassembly.dll"):
                        result.binary_name = Path(name).name
                        result.binary_path = name
                        result.platform = "Windows"
                        result.detected_files.append({"name": name, "type": "GameAssembly.dll"})
                        try:
                            with zf.open(name) as bf:
                                header_data = bf.read(1024)
                                cls._inspect_pe_bytes(header_data, result)
                        except Exception as e:
                            result.warnings.append(f"Error inspecting PE inside archive: {e}")
                        break

                # Look for dump.cs
                for name in namelist:
                    if name.lower().endswith("dump.cs"):
                        result.metadata_name = Path(name).name
                        result.metadata_type = "DUMP_CS"
                        result.metadata_path = name
                        result.detected_files.append({"name": name, "type": "dump.cs"})
                        break

        except Exception as e:
            result.warnings.append(f"Failed to inspect zip archive: {e}")

        return result

    @classmethod
    def _inspect_single_file(cls, file_path: Path, result: DetectionResult):
        """Inspect a raw file on disk."""
        filename = file_path.name
        filename_lower = filename.lower()
        size = file_path.stat().st_size

        with open(file_path, "rb") as f:
            head = f.read(min(size, 4096))

        # Check for global-metadata.dat
        if len(head) >= 8:
            magic, version = struct.unpack_from("<II", head, 0)
            if magic == IL2CPP_METADATA_MAGIC:
                result.metadata_name = filename
                result.metadata_type = "BINARY_DAT"
                result.metadata_path = str(file_path)
                result.metadata_version = version
                result.endianness = "Little Endian"
                result.detected_files.append({"name": filename, "type": "global-metadata.dat"})
                return

        # Check for ELF
        if head.startswith(cls.ELF_MAGIC):
            result.binary_name = filename
            result.binary_path = str(file_path)
            cls._inspect_elf_bytes(head, result)
            if result.platform == "UNKNOWN":
                result.platform = "Android" if "so" in filename_lower else "Linux"
            result.detected_files.append({"name": filename, "type": "ELF Binary"})
            return

        # Check for PE (MZ)
        if head.startswith(cls.PE_MAGIC) and len(head) >= 0x40:
            result.binary_name = filename
            result.binary_path = str(file_path)
            result.platform = "Windows"
            cls._inspect_pe_bytes(head, result)
            result.detected_files.append({"name": filename, "type": "PE Binary"})
            return

        # Check for dump.cs or text files
        if filename_lower.endswith(".cs") or filename_lower == "dump.cs":
            result.metadata_name = filename
            result.metadata_type = "DUMP_CS"
            result.metadata_path = str(file_path)
            result.detected_files.append({"name": filename, "type": "dump.cs"})
            # Check text for architecture or version hints
            cls._inspect_text_dump(head, result)
            return

        # Check for JSON/CSV metadata
        if filename_lower.endswith(".json"):
            result.metadata_name = filename
            result.metadata_type = "JSON"
            result.metadata_path = str(file_path)
            result.detected_files.append({"name": filename, "type": "JSON Metadata"})
            return

        if filename_lower.endswith(".csv"):
            result.metadata_name = filename
            result.metadata_type = "CSV"
            result.metadata_path = str(file_path)
            result.detected_files.append({"name": filename, "type": "CSV Metadata"})
            return

        result.warnings.append(f"Unrecognized file format for: {filename}")

    @classmethod
    def _inspect_metadata_bytes(cls, data: bytes, result: DetectionResult):
        if len(data) >= 8:
            magic, version = struct.unpack_from("<II", data, 0)
            if magic == IL2CPP_METADATA_MAGIC:
                result.metadata_version = version
                result.endianness = "Little Endian"
            else:
                # Check big endian
                magic_be, version_be = struct.unpack_from(">II", data, 0)
                if magic_be == IL2CPP_METADATA_MAGIC:
                    result.metadata_version = version_be
                    result.endianness = "Big Endian"

    @classmethod
    def _inspect_elf_bytes(cls, head: bytes, result: DetectionResult):
        if len(head) < 52:
            return
        result.binary_format = "ELF"
        ei_class = head[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = head[5]   # 1 = Little Endian, 2 = Big Endian
        result.endianness = "Little Endian" if ei_data == 1 else "Big Endian"
        endian_char = "<" if ei_data == 1 else ">"

        if ei_class == 1:
            result.pointer_size = 4
            e_machine, = struct.unpack_from(f"{endian_char}H", head, 18)
        else:
            result.pointer_size = 8
            e_machine, = struct.unpack_from(f"{endian_char}H", head, 18)

        # Machine architecture map
        # EM_386 = 3 (x86), EM_ARM = 40 (ARMv7), EM_X86_64 = 62 (x86_64), EM_AARCH64 = 183 (ARM64)
        if e_machine == 183:
            result.architecture = "ARM64"
        elif e_machine == 40:
            result.architecture = "ARMv7"
        elif e_machine == 62:
            result.architecture = "x64"
        elif e_machine == 3:
            result.architecture = "x86"
        else:
            result.architecture = f"EM_{e_machine}"

    @classmethod
    def _inspect_pe_bytes(cls, head: bytes, result: DetectionResult):
        if len(head) < 0x40:
            return
        result.binary_format = "PE"
        result.endianness = "Little Endian"
        try:
            pe_offset, = struct.unpack_from("<I", head, 0x3C)
            if pe_offset + 24 <= len(head):
                pe_sig = head[pe_offset:pe_offset+4]
                if pe_sig == b"PE\x00\x00":
                    machine, = struct.unpack_from("<H", head, pe_offset + 4)
                    # IMAGE_FILE_MACHINE_I386 = 0x014c
                    # IMAGE_FILE_MACHINE_AMD64 = 0x8664
                    # IMAGE_FILE_MACHINE_ARM64 = 0xAA64
                    if machine == 0x8664:
                        result.architecture = "x64"
                        result.pointer_size = 8
                    elif machine == 0x014c:
                        result.architecture = "x86"
                        result.pointer_size = 4
                    elif machine == 0xAA64:
                        result.architecture = "ARM64"
                        result.pointer_size = 8
                    else:
                        result.architecture = f"PE_0x{machine:04x}"
        except Exception as e:
            result.warnings.append(f"PE header inspect error: {e}")

    @classmethod
    def _inspect_text_dump(cls, head: bytes, result: DetectionResult):
        try:
            text = head.decode("utf-8", errors="ignore")
            # Check for architecture hints
            if "arm64" in text.lower():
                result.architecture = "ARM64"
                result.pointer_size = 8
            elif "armeabi" in text.lower() or "armv7" in text.lower():
                result.architecture = "ARMv7"
                result.pointer_size = 4
            elif "x86_64" in text.lower() or "x64" in text.lower():
                result.architecture = "x64"
                result.pointer_size = 8
            elif "x86" in text.lower():
                result.architecture = "x86"
                result.pointer_size = 4

            # Check for Unity version string like 'Unity 2021.3.15f1'
            import re
            m = re.search(r"Unity\s+([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9]*)", text)
            if m:
                result.unity_version = m.group(1)
        except Exception:
            pass
