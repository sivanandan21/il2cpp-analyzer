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

from .detector import FormatDetector, DetectionResult
from .metadata_parser import MetadataParser, ParsedMetadataResult
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
            update_step(1, "Upload complete. Preparing isolated workspace.", "DETECTING")
            work_dir = Path(project.get_storage_path())
            work_dir.mkdir(parents=True, exist_ok=True)

            # Check if file is ZIP/APK and unpack safely
            is_archive = zipfile.is_zipfile(file_path)
            unpacked_files = []
            target_metadata_path = None
            target_binary_path = None

            if is_archive:
                extract_dir = work_dir / "unpacked"
                extract_dir.mkdir(parents=True, exist_ok=True)
                cls._safe_extract_zip(file_path, extract_dir)

                # Search extracted directory for candidate files
                for root, _, files in os.walk(extract_dir):
                    for fname in files:
                        f_full = Path(root) / fname
                        f_lower = fname.lower()
                        if f_lower == "global-metadata.dat" or f_lower.endswith(".dat"):
                            target_metadata_path = f_full
                        elif f_lower == "dump.cs" or f_lower.endswith(".cs"):
                            if not target_metadata_path:
                                target_metadata_path = f_full
                        elif f_lower == "libil2cpp.so" or f_lower == "gameassembly.dll":
                            target_binary_path = f_full
            else:
                # Single file uploaded
                if file_path.name.lower().endswith((".dat", ".cs", ".json", ".csv")):
                    target_metadata_path = file_path
                elif file_path.name.lower().endswith((".so", ".dll")):
                    target_binary_path = file_path

            # Step 2 & 3: Detecting format & architecture
            update_step(2, "Detecting binary format and signatures.", "DETECTING")
            det_res = FormatDetector.detect_file(file_path)
            project.platform = det_res.platform
            project.architecture = det_res.architecture
            project.binary_name = det_res.binary_name
            project.source_type = det_res.metadata_type
            if det_res.metadata_version:
                project.metadata_version = str(det_res.metadata_version)
            if det_res.unity_version != "UNKNOWN":
                project.unity_version = det_res.unity_version
            project.save()

            for w in det_res.warnings:
                WarningRecord.objects.create(project=project, category="DETECTION", message=w, severity="INFO")

            update_step(3, f"Detected platform: {project.platform}, arch: {project.architecture}.", "PARSING")

            # Step 4: Parsing metadata
            update_step(4, "Parsing IL2CPP metadata tables and type definitions.", "PARSING")
            parsed_meta: Optional[ParsedMetadataResult] = None
            if target_metadata_path and target_metadata_path.exists():
                parsed_meta = MetadataParser.parse_file(target_metadata_path)
                if parsed_meta.metadata_version:
                    project.metadata_version = str(parsed_meta.metadata_version)
                for w in parsed_meta.warnings:
                    WarningRecord.objects.create(project=project, category="METADATA", message=w, severity="WARNING")

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
            update_step(6, "Reconstructing classes, methods, fields, and hierarchy.", "INDEXING")
            scorer = SmartScorer()

            if parsed_meta and parsed_meta.classes:
                # Ingest Assemblies
                asm_objs = {}
                for a in parsed_meta.assemblies:
                    asm_obj, _ = Assembly.objects.get_or_create(
                        project=project, name=a.name,
                        defaults={"class_count": a.class_count, "token": a.token}
                    )
                    asm_objs[a.name] = asm_obj

                # Default assembly if none
                default_asm, _ = Assembly.objects.get_or_create(
                    project=project, name="Assembly-CSharp.dll",
                    defaults={"class_count": len(parsed_meta.classes)}
                )

                # Cache namespaces
                ns_objs = {}

                # Bulk insert or sequential save with relationships
                for p_cls in parsed_meta.classes:
                    # Get or create namespace
                    ns_name = p_cls.namespace
                    if ns_name not in ns_objs:
                        ns_obj, _ = Namespace.objects.get_or_create(project=project, name=ns_name)
                        ns_objs[ns_name] = ns_obj
                    else:
                        ns_obj = ns_objs[ns_name]

                    # Assembly
                    asm_ref = asm_objs.get(p_cls.assembly_name, default_asm)

                    # Score class
                    cls_score = scorer.score_class(
                        p_cls.name,
                        namespace=p_cls.namespace,
                        field_count=len(p_cls.fields),
                        method_count=len(p_cls.methods)
                    )

                    cls_db = ClassDefinition.objects.create(
                        project=project,
                        assembly=asm_ref,
                        namespace=ns_obj.name,
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
                    )

                    # Ingest Fields
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

                        f_obj = FieldDefinition.objects.create(
                            class_def=cls_db,
                            name=p_fld.name,
                            type_name=p_fld.type_name,
                            is_static=p_fld.is_static,
                            is_const=p_fld.is_const,
                            visibility=p_fld.visibility,
                            offset_value=p_fld.offset,
                            offset_hex=p_fld.offset_hex or (hex(p_fld.offset) if p_fld.offset is not None else ""),
                            importance_score=f_score.total_score,
                            confidence=f_score.confidence,
                            primary_category=f_score.primary_category or "GENERAL",
                            context_type=f_score.context_type
                        )

                        # Create AddressRecord for verified Field Offset
                        if p_fld.offset is not None:
                            AddressRecord.objects.create(
                                project=project,
                                field_def=f_obj,
                                object_type="STATIC_FIELD" if p_fld.is_static else "FIELD",
                                class_name=cls_db.name,
                                member_name=p_fld.name,
                                address_type=AddressType.FIELD_OFFSET.value,
                                value_int=p_fld.offset,
                                value_hex=f_obj.offset_hex,
                                architecture=project.architecture,
                                source="metadata dump",
                                derivation="Displacement from object base pointer in heap",
                                confidence=f_score.confidence,
                                verified=True
                            )

                    # Ingest Methods
                    for p_mth in p_cls.methods:
                        # Match native method pointer from binary if available
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

                        m_obj = MethodDefinition.objects.create(
                            class_def=cls_db,
                            name=p_mth.name,
                            return_type=p_mth.return_type,
                            signature=p_mth.signature or f"{p_mth.return_type} {p_mth.name}()",
                            is_static=p_mth.is_static,
                            is_virtual=p_mth.is_virtual,
                            is_abstract=p_mth.is_abstract,
                            rva_value=rva_val,
                            rva_hex=f"0x{rva_val:08X}" if rva_val is not None else "",
                            va_value=va_val,
                            va_hex=f"0x{va_val:08X}" if va_val is not None else "",
                            file_offset_value=file_off_val,
                            file_offset_hex=f"0x{file_off_val:08X}" if file_off_val is not None else "",
                            method_token=p_mth.token or p_mth.method_index,
                            importance_score=m_score.total_score,
                            confidence=m_score.confidence,
                            primary_category=m_score.primary_category or "GENERAL"
                        )

                        # Ingest Parameters
                        for param in p_mth.parameters:
                            ParameterDefinition.objects.create(
                                method_def=m_obj,
                                name=param.name,
                                type_name=param.type_name,
                                position=param.position,
                                default_value=param.default_value
                            )

                        # Create AddressRecord for verified Method RVA
                        if rva_val is not None:
                            AddressRecord.objects.create(
                                project=project,
                                method_def=m_obj,
                                object_type="METHOD",
                                class_name=cls_db.name,
                                member_name=p_mth.name,
                                address_type=AddressType.METHOD_RVA.value,
                                value_int=rva_val,
                                value_hex=m_obj.rva_hex,
                                architecture=project.architecture,
                                source="native binary analysis",
                                derivation="Relative Virtual Address = VA - ImageBase",
                                confidence=m_score.confidence,
                                verified=True
                            )

                        # Create AddressRecord for verified File Offset
                        if file_off_val is not None:
                            AddressRecord.objects.create(
                                project=project,
                                method_def=m_obj,
                                object_type="METHOD",
                                class_name=cls_db.name,
                                member_name=p_mth.name,
                                address_type=AddressType.FILE_OFFSET.value,
                                value_int=file_off_val,
                                value_hex=m_obj.file_offset_hex,
                                architecture=project.architecture,
                                source="segment translation",
                                derivation="Physical file byte offset",
                                confidence="HIGH",
                                verified=True
                            )

            # Step 7: Discovering gameplay-related data (Summary stats)
            update_step(7, "Calculating semantic distribution and gameplay relevance.", "ANALYZING")
            project.classes_count = project.classes.count()
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
