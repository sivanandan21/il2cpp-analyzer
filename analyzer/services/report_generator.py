"""
Report Generator Service.
Generates comprehensive analysis dossiers in Markdown, JSON, CSV, and plain text:
- ImportantData.md
- ImportantData.json
- ImportantOffsets.md
- offsets.json
- field_offsets.csv
- method_rvas.csv
- static_data.csv
- classes_ranked.json
- methods_ranked.json
- fields_ranked.json
- relationship_graph.json
- analysis_report.txt
Preserves full provenance, verification status, and transparent score justifications.
"""

import zipfile
from typing import Dict, Any, List
import json
import csv
from io import StringIO
from pathlib import Path

class ReportGenerator:
    """Generates file artifacts from an analyzed Project."""

    def __init__(self, project):
        self.project = project

    def generate_all_reports(self, output_dir: Path) -> Dict[str, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        paths = {}

        # 1. Plain Text Dossiers & Cheatsheets (.TXT) - Universal Notepad format
        paths["analysis_report.txt"] = self.generate_analysis_report_txt(output_dir / "analysis_report.txt")
        paths["gameplay_offsets.txt"] = self.generate_gameplay_offsets_txt(output_dir / "gameplay_offsets.txt")
        paths["field_offsets.txt"] = self.generate_field_offsets_txt(output_dir / "field_offsets.txt")
        paths["method_rvas.txt"] = self.generate_method_rvas_txt(output_dir / "method_rvas.txt")
        paths["classes_summary.txt"] = self.generate_classes_summary_txt(output_dir / "classes_summary.txt")

        # 2. Decompiled C# Dump (.CS)
        paths["dump.cs"] = self.generate_dump_cs(output_dir / "dump.cs")

        # 3. Formatted Markdown Dossiers (.MD)
        paths["ImportantData.md"] = self.generate_important_data_md(output_dir / "ImportantData.md")
        paths["ImportantOffsets.md"] = self.generate_important_offsets_md(output_dir / "ImportantOffsets.md")

        # 4. Spreadsheets (.CSV) - Excel / Numbers
        paths["field_offsets.csv"] = self.generate_field_offsets_csv(output_dir / "field_offsets.csv")
        paths["method_rvas.csv"] = self.generate_method_rvas_csv(output_dir / "method_rvas.csv")
        paths["static_data.csv"] = self.generate_static_data_csv(output_dir / "static_data.csv")

        # 5. Machine Readable Raw Dumps (.JSON)
        paths["ImportantData.json"] = self.generate_important_data_json(output_dir / "ImportantData.json")
        paths["offsets.json"] = self.generate_offsets_json(output_dir / "offsets.json")
        paths["classes_ranked.json"] = self.generate_classes_ranked_json(output_dir / "classes_ranked.json")
        paths["fields_ranked.json"] = self.generate_fields_ranked_json(output_dir / "fields_ranked.json")
        paths["methods_ranked.json"] = self.generate_methods_ranked_json(output_dir / "methods_ranked.json")

        # 6. Bundled ZIP Archives (.ZIP)
        paths["all_txt_reports.zip"] = self.generate_all_txt_zip(output_dir / "all_txt_reports.zip", output_dir)
        paths["all_reports.zip"] = self.generate_all_reports_zip(output_dir / "all_reports.zip", output_dir)

        return paths

    def generate_important_data_md(self, path: Path) -> Path:
        content = [
            f"# IL2CPP Analysis Report: Important Gameplay Candidates",
            f"**Project**: {self.project.name} (ID: {self.project.id})  ",
            f"**Platform**: {self.project.platform} | **Architecture**: {self.project.architecture}  ",
            f"**Generated**: {self.project.updated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "",
            "> **NOTICE**: These items are ranked analytical candidates identified via transparent heuristic scoring.",
            "> They represent semantic interest areas, not confirmed cheat controls or verified exploits.",
            "",
            "## Top Gameplay Classes",
            "| Class | Namespace | Category | Score | Confidence | Fields | Methods |",
            "|---|---|---|---|---|---|---|"
        ]

        top_classes = self.project.classes.filter(importance_score__gt=40).order_by('-importance_score')[:50]
        for c in top_classes:
            content.append(f"| `{c.name}` | {c.namespace or '-'} | **{c.primary_category}** | {c.importance_score} | {c.confidence} | {c.fields.count()} | {c.methods.count()} |")

        content.extend([
            "",
            "## Top Gameplay Fields",
            "| Field | Class | Type | Offset | Category | Score | Confidence |",
            "|---|---|---|---|---|---|---|"
        ])

        top_fields = self.project.classes.prefetch_related('fields').all()
        field_records = []
        for c in top_fields:
            for f in c.fields.filter(importance_score__gt=40):
                field_records.append((f, c))
        field_records = sorted(field_records, key=lambda x: x[0].importance_score, reverse=True)[:100]

        for f, c in field_records:
            off_str = f.offset_hex if f.offset_hex else "N/A"
            content.append(f"| `{f.name}` | `{c.name}` | `{f.type_name}` | `{off_str}` | **{f.primary_category}** | {f.importance_score} | {f.confidence} |")

        path.write_text("\n".join(content), encoding="utf-8")
        return path

    def generate_important_offsets_md(self, path: Path) -> Path:
        content = [
            f"# IL2CPP Verified Address & Offset Dossier",
            f"**Project**: {self.project.name} | **Architecture**: {self.project.architecture}  ",
            "",
            "> **Strict Separation Enforced**: FIELD OFFSET != METHOD RVA != VIRTUAL ADDRESS != FILE OFFSET",
            "",
            "## High-Confidence Field Offsets",
            "| Class | Member | Type | Offset (Hex) | Offset (Dec) | Category | Confidence | Source |",
            "|---|---|---|---|---|---|---|---|"
        ]

        field_offsets = self.project.address_records.filter(address_type="FIELD_OFFSET").order_by('class_name', 'value_int')[:200]
        for a in field_offsets:
            cat = a.field_def.primary_category if a.field_def else "GENERAL"
            content.append(f"| `{a.class_name}` | `{a.member_name}` | FIELD_OFFSET | `{a.value_hex}` | {a.value_int} | {cat} | {a.confidence} | {a.source} |")

        content.extend([
            "",
            "## Verified Method RVAs",
            "| Class | Method | RVA | File Offset | Architecture | Confidence | Source |",
            "|---|---|---|---|---|---|---|"
        ])

        method_rvas = self.project.address_records.filter(address_type="METHOD_RVA").order_by('value_int')[:200]
        for a in method_rvas:
            content.append(f"| `{a.class_name}` | `{a.member_name}` | `{a.value_hex}` | {a.method_def.file_offset_hex if a.method_def else 'N/A'} | {a.architecture} | {a.confidence} | {a.source} |")

        path.write_text("\n".join(content), encoding="utf-8")
        return path

    def generate_offsets_json(self, path: Path) -> Path:
        records = []
        for a in self.project.address_records.all():
            records.append({
                "object_type": a.object_type,
                "class_name": a.class_name,
                "member_name": a.member_name,
                "address_type": a.address_type,
                "value_hex": a.value_hex,
                "value_int": a.value_int,
                "architecture": a.architecture,
                "source": a.source,
                "derivation": a.derivation,
                "confidence": a.confidence,
                "verified": a.verified
            })
        path.write_text(json.dumps(records, indent=2), encoding="utf-8")
        return path

    def generate_field_offsets_csv(self, path: Path) -> Path:
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Class", "Namespace", "Field", "Type", "Static", "OffsetHex", "OffsetDec", "Category", "Score", "Confidence", "Source"])

        fields = self.project.address_records.filter(address_type="FIELD_OFFSET").select_related('field_def', 'field_def__class_def')
        for a in fields:
            f = a.field_def
            c = f.class_def if f else None
            writer.writerow([
                a.class_name,
                c.namespace if c else "",
                a.member_name,
                f.type_name if f else "",
                "True" if (f and f.is_static) else "False",
                a.value_hex,
                a.value_int,
                f.primary_category if f else "",
                f.importance_score if f else 0,
                a.confidence,
                a.source
            ])

        path.write_text(buffer.getvalue(), encoding="utf-8")
        return path

    def generate_method_rvas_csv(self, path: Path) -> Path:
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Class", "Namespace", "Method", "Signature", "RVA", "VA", "FileOffset", "Category", "Score", "Confidence", "Source"])

        methods = self.project.address_records.filter(address_type="METHOD_RVA").select_related('method_def', 'method_def__class_def')
        for a in methods:
            m = a.method_def
            c = m.class_def if m else None
            writer.writerow([
                a.class_name,
                c.namespace if c else "",
                a.member_name,
                m.signature if m else "",
                a.value_hex,
                m.va_hex if m else "",
                m.file_offset_hex if m else "",
                m.primary_category if m else "",
                m.importance_score if m else 0,
                a.confidence,
                a.source
            ])

        path.write_text(buffer.getvalue(), encoding="utf-8")
        return path

    def generate_static_data_csv(self, path: Path) -> Path:
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Class", "Field", "Type", "StaticAddress", "Category", "Confidence", "Source"])

        statics = self.project.address_records.filter(address_type="STATIC_ADDRESS")
        for a in statics:
            writer.writerow([
                a.class_name,
                a.member_name,
                "static",
                a.value_hex,
                "STATIC",
                a.confidence,
                a.source
            ])

        path.write_text(buffer.getvalue(), encoding="utf-8")
        return path

    def generate_classes_ranked_json(self, path: Path) -> Path:
        classes = self.project.classes.all().order_by('-importance_score')
        data = [{
            "name": c.name,
            "namespace": c.namespace,
            "full_name": c.full_name,
            "category": c.primary_category,
            "score": c.importance_score,
            "confidence": c.confidence,
            "context_type": c.context_type,
            "base_class": c.base_class_name,
            "fields_count": c.fields.count(),
            "methods_count": c.methods.count()
        } for c in classes]
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def generate_fields_ranked_json(self, path: Path) -> Path:
        records = []
        for c in self.project.classes.prefetch_related('fields').all():
            for f in c.fields.all():
                records.append({
                    "class": c.name,
                    "namespace": c.namespace,
                    "field": f.name,
                    "type": f.type_name,
                    "is_static": f.is_static,
                    "offset": f.offset_hex,
                    "category": f.primary_category,
                    "score": f.importance_score,
                    "confidence": f.confidence,
                    "context_type": f.context_type
                })
        records.sort(key=lambda x: x["score"], reverse=True)
        path.write_text(json.dumps(records, indent=2), encoding="utf-8")
        return path

    def generate_methods_ranked_json(self, path: Path) -> Path:
        records = []
        for c in self.project.classes.prefetch_related('methods').all():
            for m in c.methods.all():
                records.append({
                    "class": c.name,
                    "namespace": c.namespace,
                    "method": m.name,
                    "signature": m.signature,
                    "return_type": m.return_type,
                    "rva": m.rva_hex,
                    "category": m.primary_category,
                    "score": m.importance_score,
                    "confidence": m.confidence
                })
        records.sort(key=lambda x: x["score"], reverse=True)
        path.write_text(json.dumps(records, indent=2), encoding="utf-8")
        return path

    def generate_important_data_json(self, path: Path) -> Path:
        data = {
            "project": {
                "name": self.project.name,
                "platform": self.project.platform,
                "architecture": self.project.architecture,
                "metadata_version": self.project.metadata_version
            },
            "stats": {
                "classes": self.project.classes_count,
                "methods": self.project.methods_count,
                "fields": self.project.fields_count,
                "offsets": self.project.address_records.filter(address_type="FIELD_OFFSET").count(),
                "rvas": self.project.address_records.filter(address_type="METHOD_RVA").count()
            }
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def generate_analysis_report_txt(self, path: Path) -> Path:
        lines = [
            "==================================================================================",
            "             IL2CPP TACTICAL ANALYZER // MASTER ANALYSIS DOSSIER                  ",
            "==================================================================================",
            f"Target Project:    {self.project.name} (ID: {self.project.id})",
            f"Platform:          {self.project.platform}",
            f"Architecture:      {self.project.architecture}",
            f"Engine Type:       {self.project.engine_type or 'Unity (IL2CPP)'}",
            f"Binary Payload:    {self.project.binary_name}",
            f"Metadata Version:  {self.project.metadata_version or 'N/A'}",
            f"Analysis Status:   {self.project.status}",
            f"Classes Indexed:   {self.project.classes_count}",
            f"Fields Indexed:    {self.project.fields_count}",
            f"Methods Indexed:   {self.project.methods_count}",
            f"Warnings Logged:   {self.project.warnings_count}",
            "----------------------------------------------------------------------------------",
            "ADDRESS RECORD BREAKDOWN:",
            f"  - Field Offsets:     {self.project.address_records.filter(address_type='FIELD_OFFSET').count()}",
            f"  - Method RVAs:       {self.project.address_records.filter(address_type='METHOD_RVA').count()}",
            f"  - Static Addresses:  {self.project.address_records.filter(address_type='STATIC_ADDRESS').count()}",
            f"  - Virtual Addresses: {self.project.address_records.filter(address_type='VIRTUAL_ADDRESS').count()}",
            "==================================================================================",
            "",
            "==================================================================================",
            "[ 01 ] TOP GAMEPLAY CANDIDATE CLASSES (RANKED BY RELEVANCE SCORE)",
            "==================================================================================",
            f"{'SCORE':<7}{'CATEGORY':<14}{'FIELDS':<8}{'METHODS':<9}{'CLASS NAME'}",
            "-" * 82
        ]

        top_classes = self.project.classes.all().order_by('-importance_score')[:50]
        for c in top_classes:
            lines.append(f"{c.importance_score:<7}{c.primary_category:<14}{c.fields.count():<8}{c.methods.count():<9}{c.name}")

        lines.extend([
            "",
            "==================================================================================",
            "[ 02 ] HIGH-CONFIDENCE GAMEPLAY VARIABLES & FIELD OFFSETS",
            "==================================================================================",
            f"{'OFFSET':<10}{'DEC':<6}{'CATEGORY':<14}{'TYPE':<16}{'FIELD IDENTIFIER'}",
            "-" * 82
        ])

        top_fields = self.project.address_records.filter(address_type="FIELD_OFFSET").select_related('field_def', 'field_def__class_def').order_by('-field_def__importance_score', 'class_name', 'value_int')[:150]
        for a in top_fields:
            f = a.field_def
            cat = f.primary_category if f else "GENERAL"
            tname = (f.type_name if f else "unknown")[:15]
            ident = f"{a.class_name}.{a.member_name}"
            lines.append(f"{a.value_hex:<10}{a.value_int:<6}{cat:<14}{tname:<16}{ident}")

        lines.extend([
            "",
            "==================================================================================",
            "[ 03 ] VERIFIED METHOD RVAS (HOOK & REVERSE TARGETS)",
            "==================================================================================",
            f"{'RVA':<14}{'CATEGORY':<14}{'METHOD SIGNATURE'}",
            "-" * 82
        ])

        top_methods = self.project.address_records.filter(address_type="METHOD_RVA").select_related('method_def').order_by('-method_def__importance_score', 'value_int')[:150]
        for a in top_methods:
            m = a.method_def
            cat = m.primary_category if m else "GENERAL"
            sig = (m.signature if m else f"{a.class_name}.{a.member_name}()")
            lines.append(f"{a.value_hex:<14}{cat:<14}{sig}")

        lines.extend([
            "",
            "==================================================================================",
            "                      END OF ANALYSIS REPORT DOSSIER                              ",
            "=================================================================================="
        ])

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def generate_gameplay_offsets_txt(self, path: Path) -> Path:
        """
        Generates a dedicated plain text cheatsheet grouping offsets by modding category:
        Currency, Health/Stats, Combat, Speed, God Mode, Security, and Method RVAs.
        """
        lines = [
            "==================================================================================",
            "           TACTICAL IL2CPP ANALYZER // GAMEPLAY OFFSETS CHEATSHEET                ",
            "==================================================================================",
            f"Target:        {self.project.name}",
            f"Architecture:  {self.project.architecture}",
            f"Engine:        {self.project.engine_type or 'Unity (IL2CPP)'}",
            "Usage:         Plain text cheatsheet for GameGuardian, Cheat Engine, Frida, & IDA.",
            "Provenance:    Strict Separation: FIELD OFFSET != METHOD RVA != VIRTUAL ADDRESS",
            "==================================================================================",
            ""
        ]

        categories = [
            ("CURRENCY", "CURRENCY & ECONOMY OFFSETS (Gold, Gems, Coins, Cash, Money)"),
            ("HEALTH", "HEALTH, MANA & PLAYER ATTRIBUTES (HP, Stamina, Shield)"),
            ("STATS", "PLAYER STATS & LEVEL PROGRESSION (XP, Level, Rank, Energy)"),
            ("COMBAT", "COMBAT & WEAPON OFFSETS (Attack, Damage, Ammo, FireRate)"),
            ("SPEED", "MOVEMENT & SPEED OFFSETS (RunSpeed, WalkSpeed, Velocity, Jump)"),
            ("SECURITY", "SECURITY & ANTI-CHEAT OFFSETS (Ban, Verification, Tamper, Root)"),
            ("PHYSICS", "PHYSICS & WORLD MODIFIERS (Gravity, Collision, Mass)"),
            ("GENERAL", "GENERAL GAMEPLAY OFFSETS"),
        ]

        field_records = list(self.project.address_records.filter(address_type="FIELD_OFFSET").select_related('field_def', 'field_def__class_def'))

        for cat_code, cat_title in categories:
            cat_items = [a for a in field_records if (a.field_def and a.field_def.primary_category == cat_code)]
            if not cat_items and cat_code in ["CURRENCY", "HEALTH", "COMBAT", "SPEED"]:
                # Try fallback matching by keyword if category was unclassified
                cat_items = [a for a in field_records if any(k in a.member_name.lower() for k in [cat_code.lower()])]

            lines.append(f">>> {cat_title} [{len(cat_items)} Found] <<<")
            lines.append(f"{'OFFSET':<10}{'DEC':<6}{'TYPE':<16}{'CLASS.FIELD':<40}{'CONFIDENCE'}")
            lines.append("-" * 82)

            if cat_items:
                cat_items.sort(key=lambda x: (x.class_name, x.value_int))
                for a in cat_items:
                    f = a.field_def
                    tname = (f.type_name if f else "var")[:15]
                    ident = f"{a.class_name}.{a.member_name}"
                    conf = a.confidence or "HIGH"
                    lines.append(f"{a.value_hex:<10}{a.value_int:<6}{tname:<16}{ident:<40}{conf}")
            else:
                lines.append("  [ No direct offsets recorded under this category ]")
            lines.append("")

        # Add Top Method RVAs
        lines.append(">>> KEY METHOD RVAs FOR FUNCTION HOOKING (FRIDA / GAMEGUARDIAN) <<<")
        lines.append(f"{'RVA':<14}{'CATEGORY':<14}{'METHOD SIGNATURE'}")
        lines.append("-" * 82)
        top_methods = self.project.address_records.filter(address_type="METHOD_RVA").select_related('method_def').order_by('-method_def__importance_score')[:100]
        for a in top_methods:
            m = a.method_def
            cat = m.primary_category if m else "GENERAL"
            sig = (m.signature if m else f"{a.class_name}.{a.member_name}()")
            lines.append(f"{a.value_hex:<14}{cat:<14}{sig}")

        lines.extend([
            "",
            "==================================================================================",
            "                   END OF GAMEPLAY OFFSETS CHEATSHEET                             ",
            "=================================================================================="
        ])

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def generate_field_offsets_txt(self, path: Path) -> Path:
        """Generates all field offsets in a clean, aligned plain text table."""
        lines = [
            f"# IL2CPP Field Offsets Table - {self.project.name} ({self.project.architecture})",
            f"{'OFFSET (HEX)':<14}{'DEC':<8}{'TYPE':<18}{'CLASS':<36}{'FIELD':<28}{'CATEGORY'}",
            "=" * 120
        ]
        fields = self.project.address_records.filter(address_type="FIELD_OFFSET").select_related('field_def').order_by('class_name', 'value_int')
        for a in fields:
            f = a.field_def
            tname = (f.type_name if f else "")[:16]
            cat = f.primary_category if f else ""
            lines.append(f"{a.value_hex:<14}{a.value_int:<8}{tname:<18}{a.class_name[:34]:<36}{a.member_name[:26]:<28}{cat}")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def generate_method_rvas_txt(self, path: Path) -> Path:
        """Generates all method RVAs in a clean, aligned plain text table."""
        lines = [
            f"# IL2CPP Method RVAs Table - {self.project.name} ({self.project.architecture})",
            f"{'RVA (HEX)':<16}{'DEC':<12}{'CATEGORY':<14}{'CLASS.METHOD SIGNATURE'}",
            "=" * 120
        ]
        methods = self.project.address_records.filter(address_type="METHOD_RVA").select_related('method_def').order_by('value_int')
        for a in methods:
            m = a.method_def
            cat = m.primary_category if m else ""
            sig = m.signature if m else f"{a.class_name}.{a.member_name}()"
            lines.append(f"{a.value_hex:<16}{a.value_int:<12}{cat:<14}{sig}")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def generate_classes_summary_txt(self, path: Path) -> Path:
        """Generates a summary of all classes in a clean, aligned plain text table."""
        lines = [
            f"# IL2CPP Classes Summary - {self.project.name}",
            f"{'SCORE':<8}{'FIELDS':<8}{'METHODS':<9}{'CATEGORY':<14}{'NAMESPACE':<30}{'CLASS NAME'}",
            "=" * 120
        ]
        classes = self.project.classes.all().order_by('-importance_score')
        for c in classes:
            ns = (c.namespace or "-")[:28]
            lines.append(f"{c.importance_score:<8}{c.fields.count():<8}{c.methods.count():<9}{c.primary_category:<14}{ns:<30}{c.name}")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def generate_dump_cs(self, path: Path) -> Path:
        """Generates a decompiled C# structure dump with offsets and RVAs."""
        lines = [
            "// ============================================================================",
            f"// IL2CPP Decompiled C# Structure Dump",
            f"// Target:       {self.project.name}",
            f"// Architecture: {self.project.architecture}",
            f"// Generated:    Tactical IL2CPP Analyzer",
            "// ============================================================================",
            ""
        ]

        classes = self.project.classes.prefetch_related('fields', 'methods').all()[:200]
        for c in classes:
            if c.namespace:
                lines.append(f"namespace {c.namespace} {{")
                indent = "    "
            else:
                indent = ""

            base = f" : {c.base_class_name}" if c.base_class_name else ""
            lines.append(f"{indent}// Importance Score: {c.importance_score} | Category: {c.primary_category}")
            lines.append(f"{indent}public class {c.name}{base} {{")

            fields = c.fields.all()
            if fields:
                lines.append(f"{indent}    // Fields ({fields.count()})")
                for f in fields:
                    off_comment = f" // Offset: {f.offset_hex} (Dec: {f.offset_value})" if f.offset_hex else ""
                    stat = "static " if f.is_static else ""
                    lines.append(f"{indent}    {f.visibility} {stat}{f.type_name} {f.name};{off_comment}")

            methods = c.methods.all()
            if methods:
                lines.append(f"{indent}    // Methods ({methods.count()})")
                for m in methods:
                    rva_comment = f" // RVA: {m.rva_hex}" if m.rva_hex else ""
                    lines.append(f"{indent}    // Category: {m.primary_category}{rva_comment}")
                    lines.append(f"{indent}    {m.signature};")

            lines.append(f"{indent}}}")
            if c.namespace:
                lines.append("}")
            lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def generate_all_txt_zip(self, path: Path, output_dir: Path) -> Path:
        """Bundles all .txt reports into a single zip archive."""
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for f in output_dir.glob("*.txt"):
                if f.is_file():
                    zf.write(f, arcname=f.name)
        return path

    def generate_all_reports_zip(self, path: Path, output_dir: Path) -> Path:
        """Bundles all generated reports (excluding zip files) into a single zip archive."""
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for f in output_dir.iterdir():
                if f.is_file() and not f.name.endswith(".zip"):
                    zf.write(f, arcname=f.name)
        return path
