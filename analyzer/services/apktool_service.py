"""
Apktool Service.
Automates real APK decompilation using bundled/downloaded Apktool (v3.0.3+),
decodes AndroidManifest.xml, Dalvik bytecode into Smali, resources, and asset directories.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path
import subprocess
import shutil
import urllib.request
import os
import re

APKTOOL_DOWNLOAD_URL = "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar"


@dataclass
class ApktoolResult:
    success: bool = False
    decompiled_dir: Optional[Path] = None
    manifest_path: Optional[Path] = None
    apktool_yml_path: Optional[Path] = None
    package_name: str = ""
    app_version: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    log_output: str = ""
    error_message: str = ""


class ApktoolService:
    """Manages Apktool lifecycle, binary resolution, and automated decompile execution."""

    @classmethod
    def get_java_binary(cls) -> Optional[str]:
        """Locates installed java executable on host system."""
        java_cmd = shutil.which("java")
        if java_cmd:
            return java_cmd

        # Check typical Windows Java paths
        win_candidates = [
            r"C:\Program Files\Common Files\Oracle\Java\javapath\java.exe",
            r"C:\Program Files\Java\jdk-24\bin\java.exe",
            r"C:\Program Files\Java\jdk-21\bin\java.exe",
            r"C:\Program Files\Java\jdk-17\bin\java.exe",
        ]
        for c in win_candidates:
            if Path(c).exists():
                return c
        return None

    @classmethod
    def get_apktool_jar(cls) -> Path:
        """Returns path to apktool.jar, auto-downloading if necessary."""
        base_dir = Path(__file__).resolve().parent.parent / "bin"
        base_dir.mkdir(parents=True, exist_ok=True)
        jar_path = base_dir / "apktool.jar"

        if not jar_path.exists() or jar_path.stat().st_size < 1000000:
            try:
                req = urllib.request.Request(APKTOOL_DOWNLOAD_URL, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=30) as resp, open(jar_path, "wb") as f:
                    shutil.copyfileobj(resp, f)
            except Exception as e:
                pass

        return jar_path

    @classmethod
    def decompile(cls, apk_path: Path, output_dir: Path, decompile_sources: bool = True) -> ApktoolResult:
        """Decompiles an APK using official apktool.jar."""
        result = ApktoolResult()
        java_bin = cls.get_java_binary()
        if not java_bin:
            result.error_message = "Java runtime (JRE/JDK) is not installed or not found in system PATH."
            return result

        jar_path = cls.get_apktool_jar()
        if not jar_path.exists():
            result.error_message = f"Apktool JAR could not be located at {jar_path}"
            return result

        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            java_bin,
            "-Xmx2048m",
            "-jar",
            str(jar_path),
            "d",
            str(apk_path),
            "-o",
            str(output_dir),
            "-f",  # force overwrite
            "-r"   # keep raw resources (fastest, prevents aapt resource decoding failures)
        ]

        if not decompile_sources:
            cmd.append("-s")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,  # 3 minutes maximum timeout
                check=False
            )
            result.log_output = (proc.stdout or "") + "\n" + (proc.stderr or "")

            if proc.returncode == 0 and output_dir.exists():
                result.success = True
                result.decompiled_dir = output_dir

                manifest = output_dir / "AndroidManifest.xml"
                if manifest.exists():
                    result.manifest_path = manifest
                    cls._parse_manifest_xml(manifest, result)

                apktool_yml = output_dir / "apktool.yml"
                if apktool_yml.exists():
                    result.apktool_yml_path = apktool_yml
                    cls._parse_apktool_yml(apktool_yml, result)
            else:
                result.error_message = f"Apktool exited with code {proc.returncode}: {result.log_output[-500:]}"
        except subprocess.TimeoutExpired:
            result.error_message = "Apktool decompilation timed out after 180 seconds."
        except Exception as e:
            result.error_message = f"Apktool invocation failed: {e}"

        return result

    @classmethod
    def _parse_manifest_xml(cls, manifest_path: Path, result: ApktoolResult):
        try:
            text = manifest_path.read_text(encoding="utf-8", errors="ignore")
            pkg_match = re.search(r'package="([^"]+)"', text)
            if pkg_match and not result.package_name:
                result.package_name = pkg_match.group(1)

            ver_match = re.search(r'android:versionName="([^"]+)"', text)
            if ver_match and not result.app_version:
                result.app_version = ver_match.group(1)
        except Exception:
            pass

    @classmethod
    def _parse_apktool_yml(cls, yml_path: Path, result: ApktoolResult):
        try:
            text = yml_path.read_text(encoding="utf-8", errors="ignore")
            min_sdk_match = re.search(r'minSdkVersion:\s*\'?([0-9]+)\'?', text)
            if min_sdk_match:
                result.min_sdk = min_sdk_match.group(1)

            target_sdk_match = re.search(r'targetSdkVersion:\s*\'?([0-9]+)\'?', text)
            if target_sdk_match:
                result.target_sdk = target_sdk_match.group(1)

            ver_match = re.search(r'versionName:\s*\'?([^\'\r\n]+)\'?', text)
            if ver_match and not result.app_version:
                result.app_version = ver_match.group(1).strip()
        except Exception:
            pass
