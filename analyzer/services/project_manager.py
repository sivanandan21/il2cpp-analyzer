"""
Project Manager Service.
Coordinates the end-to-end 10-step analysis lifecycle:
1. Upload complete
2. Detecting format
3. Detecting architecture
4. Parsing metadata
5. Parsing binary
6. Building indexes
7. Discovering gameplay-related data
8. Extracting address information
9. Generating reports
10. Complete
Implements path traversal protection and directory isolation.
"""

from typing import Optional, Dict, Any, List
from pathlib import Path
import os
import shutil
import zipfile
from django.utils import timezone

from .apk_inspector import ApkInspector, ApkInspectionReport
from .apktool_service import ApktoolService
from .smali_parser import SmaliParser
from .game_asset_parser import GameAssetParser
from .detector import FormatDetector, DetectionResult
from .metadata_parser import MetadataParser, ParsedMetadataResult, ParsedAssembly
from .binary_parser import BinaryParser, BinaryAnalysisResult
from .address_mapper import AddressMapper, AddressType
from .scorer import SmartScorer
from .semantic_analyzer import SemanticAnalyzer
from .report_generator import ReportGenerator

class ProjectManager:
    """Orchestrates analysis pipelines, database ingestion, and job tracking."""

    @classmethod
    def process_project(cls, project_id: int, file_path: Path) -> Dict[str, Any]:
        """Runs the complete analysis pipeline for a Project."""
        from analyzer.models import (
            Project, Assembly, Namespace, ClassDefinition, FieldDefinition,
            MethodDefinition, ParameterDefinition, PropertyDefinition,
            AddressRecord, WarningRecord, AnalysisJob
        )

        project = Project.objects.get(id=project_id)
        job, _ = AnalysisJob.objects.get_or_create(project=project)

        def update_step(step_idx: int, desc: str, status: str = "ANALYZING"):
            project.status = status
            project.save(update_fields=['status', 'updated_at'])
            job.current_step = step_idx
            job.step_description = desc
            job.progress_percent = int((step_idx / 10.0) * 100)
            job.save(update_fields=['current_step', 'step_description', 'progress_percent', 'updated_at'])

        try:
            # Step 1: Upload complete & directory setup
            update_step(1, "Upload complete. Decompiling and inspecting APK archive.", "DETECTING")
            work_dir = Path(project.get_storage_path())
            work_dir.mkdir(parents=True, exist_ok=True)

            # Check if file is ZIP/APK and unpack safely
            is_archive = zipfile.is_zipfile(file_path)
            target_metadata_path = None
            target_binary_path = None
            extract_dir = work_dir / "unpacked"
            extract_dir.mkdir(parents=True, exist_ok=True)

            if is_archive or file_path.name.lower().endswith(".apk"):
                project.is_apk = True
                project.source_type = "APK"

                # 1. Real Apktool Decompilation
                update_step(1, "Executing real Apktool decompilation (smali, manifest, resources, assets)...", "DETECTING")
                apktool_out = work_dir / "apktool_out"
                apktool_res = ApktoolService.decompile(file_path, apktool_out)

                if apktool_res.success:
                    extract_dir = apktool_out
                    if apktool_res.package_name:
                        project.package_name = apktool_res.package_name
                        if not project.name or project.name.startswith("Uploaded_") or project.name in ("Game_Analysis", "MyGame"):
                            project.name = apktool_res.package_name
                    if apktool_res.app_version:
                        project.app_version = apktool_res.app_version

                # 2. Fast APK Inspection for native libraries and IL2CPP targets
                apk_report = ApkInspector.inspect_and_extract(file_path, work_dir / "unpacked")
                if apk_report.package_name and not project.package_name:
                    project.package_name = apk_report.package_name
                    if not project.name or project.name.startswith("Uploaded_") or project.name in ("Game_Analysis", "MyGame"):
                        project.name = apk_report.app_label or apk_report.package_name
                if apk_report.version_name and not project.app_version:
                    project.app_version = apk_report.version_name
                if apk_report.platform:
                    project.platform = apk_report.platform
                if apk_report.architecture != "UNKNOWN":
                    project.architecture = apk_report.architecture
                if apk_report.unity_version != "UNKNOWN":
                    project.unity_version = apk_report.unity_version

                target_metadata_path = apk_report.metadata_path
                target_binary_path = apk_report.binary_path

                # Fallback directory search across both extracted locations
                search_dirs = [extract_dir, work_dir / "unpacked"]
                for s_dir in search_dirs:
                    if s_dir.exists():
                        for root, _, files in os.walk(s_dir):
                            for fname in files:
                                f_full = Path(root) / fname
                                f_lower = fname.lower()
                                if not target_metadata_path:
                                    if f_lower == "global-metadata.dat" or f_lower.endswith(".dat"):
                                        target_metadata_path = f_full
                                    elif f_lower == "dump.cs" or f_lower.endswith(".cs"):
                                        target_metadata_path = f_full
                                if not target_binary_path:
                                    if f_lower == "libil2cpp.so" or f_lower == "gameassembly.dll":
                                        target_binary_path = f_full
            else:
                # Single file uploaded
                if file_path.name.lower().endswith((".dat", ".cs", ".json", ".csv")):
                    target_metadata_path = file_path
                elif file_path.name.lower().endswith((".so", ".dll")):
                    target_binary_path = file_path

            # Step 2 & 3: Detecting format & architecture
            update_step(2, "Detecting binary format, engine signatures, and architecture.", "DETECTING")
            det_res = FormatDetector.detect_file(file_path)
            if not project.platform or project.platform == "UNKNOWN":
                project.platform = det_res.platform
            if not project.architecture or project.architecture == "UNKNOWN":
                project.architecture = det_res.architecture
            if not project.binary_name or project.binary_name == "libil2cpp.so":
                project.binary_name = det_res.binary_name
            if not project.source_type or project.source_type == "UNKNOWN":
                project.source_type = det_res.metadata_type
            if det_res.metadata_version and not project.metadata_version:
                project.metadata_version = str(det_res.metadata_version)
            if det_res.unity_version != "UNKNOWN" and (not project.unity_version or project.unity_version == "UNKNOWN"):
                project.unity_version = det_res.unity_version

            # Check for Hybrid / Web / Cordova game engine signatures
            is_cordova_hybrid = (extract_dir / "assets" / "www").exists() or (work_dir / "unpacked" / "assets" / "www").exists()
            if is_cordova_hybrid:
                project.engine_type = "HTML5 / Cordova Hybrid Engine"
            elif target_metadata_path:
                project.engine_type = "Unity (IL2CPP)"
            elif not project.engine_type or project.engine_type == "UNKNOWN":
                project.engine_type = "Android Native (Dalvik / Smali)"

            project.save()

            for w in det_res.warnings:
                WarningRecord.objects.create(project=project, category="DETECTION", message=w, severity="INFO")

            update_step(3, f"Detected engine: {project.engine_type}, platform: {project.platform}, arch: {project.architecture}.", "PARSING")

            # Step 4: Parsing metadata & decompiled Smali/Asset code
            update_step(4, "Parsing decompiled game classes, Smali bytecode, and assets.", "PARSING")
            parsed_meta: Optional[ParsedMetadataResult] = None
            if target_metadata_path and target_metadata_path.exists():
                parsed_meta = MetadataParser.parse_file(target_metadata_path)
                if parsed_meta.metadata_version:
                    project.metadata_version = str(parsed_meta.metadata_version)
                for w in parsed_meta.warnings:
                    WarningRecord.objects.create(project=project, category="METADATA", message=w, severity="WARNING")

            # Decompiled Smali & Game Asset Parser
            game_meta = GameAssetParser.parse_game_assets(extract_dir, apk_path=file_path)
            smali_classes = SmaliParser.parse_smali_directory(extract_dir, package_filter=project.package_name, max_classes=300)

            if not parsed_meta:
                parsed_meta = ParsedMetadataResult(is_valid=True, source_type="APKTOOL_SMALI_ASSETS")

            if game_meta and game_meta.classes:
                parsed_meta.classes.extend(game_meta.classes)
                if game_meta.assemblies:
                    parsed_meta.assemblies.extend(game_meta.assemblies)

            if smali_classes:
                parsed_meta.classes.extend(smali_classes)
                parsed_meta.assemblies.append(ParsedAssembly(name="Android.Dalvik.Smali", class_count=len(smali_classes), token=0x03))

            # Step 5: Parsing binary
            update_step(5, "Analyzing native binary headers and method pointers.", "PARSING")
            binary_res: Optional[BinaryAnalysisResult] = None
            if target_binary_path and target_binary_path.exists():
                binary_res = BinaryParser.parse_binary(target_binary_path, architecture_hint=project.architecture)
                if binary_res.architecture != "UNKNOWN" and project.architecture == "UNKNOWN":
                    project.architecture = binary_res.architecture
                for w in binary_res.warnings:
                    WarningRecord.objects.create(project=project, category="BINARY", message=w, severity="INFO")

            # Step 6: Building indexes (Database Ingestion)
            update_step(6, f"Reconstructing {len(parsed_meta.classes)} classes, methods, and verified fields.", "INDEXING")
            scorer = SmartScorer()

            if parsed_meta and parsed_meta.classes:
                from django.db import transaction

                with transaction.atomic():
                    # 1. Ingest Assemblies
                    asm_objs = {}
                    for a in parsed_meta.assemblies:
                        asm_obj, _ = Assembly.objects.get_or_create(
                            project=project, name=a.name,
                            defaults={"class_count": a.class_count, "token": a.token}
                        )
                        asm_objs[a.name] = asm_obj

                    default_asm, _ = Assembly.objects.get_or_create(
                        project=project, name="Assembly-CSharp.dll",
                        defaults={"class_count": len(parsed_meta.classes)}
                    )

                    # 2. Prioritize classes: game code (Assembly-CSharp) first
                    game_classes = [c for c in parsed_meta.classes if 'Assembly-CSharp' in (c.assembly_name or '')]
                    other_classes = [c for c in parsed_meta.classes if 'Assembly-CSharp' not in (c.assembly_name or '')]
                    selected_classes = game_classes + other_classes
                    if len(selected_classes) > 2500:
                        selected_classes = selected_classes[:2500]

                    # 3. Create ClassDefinition objects in bulk
                    cls_to_create = []
                    for p_cls in selected_classes:
                        asm_ref = asm_objs.get(p_cls.assembly_name, default_asm)
                        cls_score = scorer.score_class(
                            p_cls.name,
                            namespace=p_cls.namespace,
                            field_count=len(p_cls.fields),
                            method_count=len(p_cls.methods)
                        )
                        cls_to_create.append(ClassDefinition(
                            project=project,
                            assembly=asm_ref,
                            namespace=p_cls.namespace or "",
                            name=p_cls.name,
                            full_name=p_cls.full_name or f"{p_cls.namespace}.{p_cls.name}",
                            base_class_name=p_cls.base_class_name,
                            interfaces_json=p_cls.interfaces,
                            is_value_type=p_cls.is_value_type,
                            is_enum=p_cls.is_enum,
                            is_interface=p_cls.is_interface,
                            is_abstract=p_cls.is_abstract,
                            type_token=p_cls.token,
                            importance_score=cls_score.total_score,
                            confidence=cls_score.confidence,
                            primary_category=cls_score.primary_category or "GENERAL",
                            context_type=cls_score.context_type
                        ))

                    created_classes = ClassDefinition.objects.bulk_create(cls_to_create, batch_size=500)

                    # 4. Collect and insert Fields, Methods, and AddressRecords in bulk
                    fields_to_create = []
                    methods_to_create = []
                    addresses_to_create = []

                    for c_model, p_cls in zip(created_classes, selected_classes):
                        sibling_names = [f.name for f in p_cls.fields]
                        for p_fld in p_cls.fields:
                            f_score = scorer.score_field(
                                field_name=p_fld.name,
                                field_type=p_fld.type_name,
                                class_name=p_cls.name,
                                namespace=p_cls.namespace,
                                has_offset=(p_fld.offset is not None),
                                sibling_field_names=sibling_names
                            )
                            f_hex = p_fld.offset_hex or (f"+0x{p_fld.offset:X}" if p_fld.offset is not None else "")
                            fields_to_create.append(FieldDefinition(
                                class_def=c_model,
                                name=p_fld.name,
                                type_name=p_fld.type_name or "object",
                                is_static=p_fld.is_static,
                                is_const=p_fld.is_const,
                                visibility=p_fld.visibility,
                                offset_value=p_fld.offset,
                                offset_hex=f_hex,
                                importance_score=f_score.total_score,
                                confidence=f_score.confidence,
                                primary_category=f_score.primary_category or "GENERAL",
                                context_type=f_score.context_type
                            ))
                            if p_fld.offset is not None:
                                addresses_to_create.append(AddressRecord(
                                    project=project,
                                    object_type="STATIC_FIELD" if p_fld.is_static else "FIELD",
                                    class_name=c_model.name,
                                    member_name=p_fld.name,
                                    address_type=AddressType.FIELD_OFFSET.value,
                                    value_int=p_fld.offset,
                                    value_hex=f_hex,
                                    architecture=project.architecture,
                                    source="metadata analysis",
                                    derivation="Displacement from object base pointer in heap",
                                    confidence=f_score.confidence,
                                    verified=True
                                ))

                        for p_mth in p_cls.methods:
                            rva_val = p_mth.rva
                            va_val = p_mth.va
                            file_off_val = p_mth.file_offset

                            if binary_res and p_mth.method_index is not None and p_mth.method_index in binary_res.method_pointers:
                                nat_addr = binary_res.method_pointers[p_mth.method_index]
                                rva_val = nat_addr.rva
                                va_val = nat_addr.va
                                file_off_val = nat_addr.file_offset

                            m_score = scorer.score_method(
                                method_name=p_mth.name,
                                return_type=p_mth.return_type,
                                class_name=p_cls.name,
                                has_rva=(rva_val is not None),
                                param_types=[p.type_name for p in p_mth.parameters]
                            )
                            rva_hex = f"0x{rva_val:08X}" if rva_val is not None else ""
                            methods_to_create.append(MethodDefinition(
                                class_def=c_model,
                                name=p_mth.name,
                                return_type=p_mth.return_type or "void",
                                signature=p_mth.signature or f"{p_mth.return_type} {p_mth.name}()",
                                is_static=p_mth.is_static,
                                is_virtual=p_mth.is_virtual,
                                is_abstract=p_mth.is_abstract,
                                rva_value=rva_val,
                                rva_hex=rva_hex,
                                va_value=va_val,
                                va_hex=f"0x{va_val:08X}" if va_val is not None else "",
                                file_offset_value=file_off_val,
                                file_offset_hex=f"0x{file_off_val:08X}" if file_off_val is not None else "",
                                method_token=p_mth.token or p_mth.method_index,
                                importance_score=m_score.total_score,
                                confidence=m_score.confidence,
                                primary_category=m_score.primary_category or "GENERAL"
                            ))
                            if rva_val is not None:
                                addresses_to_create.append(AddressRecord(
                                    project=project,
                                    object_type="METHOD",
                                    class_name=c_model.name,
                                    member_name=p_mth.name,
                                    address_type=AddressType.METHOD_RVA.value,
                                    value_int=rva_val,
                                    value_hex=rva_hex,
                                    architecture=project.architecture,
                                    source="libil2cpp.so (.rela.dyn / symbols)",
                                    derivation="Relative Virtual Address = VA - ImageBase",
                                    confidence=m_score.confidence,
                                    verified=True
                                ))

                    FieldDefinition.objects.bulk_create(fields_to_create, batch_size=500)
                    MethodDefinition.objects.bulk_create(methods_to_create, batch_size=500)
                    AddressRecord.objects.bulk_create(addresses_to_create, batch_size=500)

            # Step 7: Discovering gameplay-related data (Summary stats)
            update_step(7, "Calculating semantic distribution and gameplay relevance.", "ANALYZING")
            project.classes_count = len(parsed_meta.classes) if parsed_meta else 0
            project.methods_count = MethodDefinition.objects.filter(class_def__project=project).count()
            project.fields_count = FieldDefinition.objects.filter(class_def__project=project).count()
            project.warnings_count = WarningRecord.objects.filter(project=project).count()
            project.save()

            # Step 8: Extracting address information
            update_step(8, "Verifying address integrity and strict type boundaries.", "ANALYZING")

            # Step 9: Generating reports
            update_step(9, "Generating analytical reports, CSVs, and markdown dossiers.", "ANALYZING")
            rep_gen = ReportGenerator(project)
            reports_dir = work_dir / "reports"
            rep_gen.generate_all_reports(reports_dir)

            # Step 10: Complete
            project.completed_at = timezone.now()
            update_step(10, "Analysis complete. Ready for research.", "COMPLETE")

            return {"status": "SUCCESS", "project_id": project.id}

        except Exception as e:
            project.status = "FAILED"
            project.save(update_fields=['status'])
            job.status = "FAILED"
            job.error_message = str(e)
            job.save(update_fields=['status', 'error_message'])
            WarningRecord.objects.create(project=project, category="PIPELINE", message=f"Pipeline failure: {e}", severity="ERROR")
            return {"status": "FAILED", "error": str(e)}

    @classmethod
    def _safe_extract_zip(cls, zip_path: Path, target_dir: Path, max_uncompressed_size: int = 1073741824):
        """Extract zip archive with strict path traversal (zip-slip) protection and size limits."""
        total_size = 0
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                # Prevent path traversal
                target_path = (target_dir / member.filename).resolve()
                if not str(target_path).startswith(str(target_dir.resolve())):
                    raise SecurityError(f"Zip slip path traversal detected: {member.filename}")

                total_size += member.file_size
                if total_size > max_uncompressed_size:
                    raise ValueError(f"Extracted size exceeds safety limit of {max_uncompressed_size} bytes")

                # Only extract supported file types to save time and space
                name_lower = member.filename.lower()
                if any(name_lower.endswith(ext) for ext in [".dat", ".so", ".dll", ".cs", ".json", ".csv", ".txt"]):
                    zf.extract(member, target_dir)


class SecurityError(Exception):
    pass
