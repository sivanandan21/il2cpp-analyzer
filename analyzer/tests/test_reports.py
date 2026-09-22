from django.test import TestCase
from pathlib import Path
import tempfile
import shutil

from analyzer.models import Project, ClassDefinition, FieldDefinition, AddressRecord
from analyzer.services.report_generator import ReportGenerator

class ReportGeneratorTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name="ReportTestProject",
            platform="Android",
            architecture="ARM64",
            status="COMPLETE"
        )
        self.cls = ClassDefinition.objects.create(
            project=self.project,
            name="SampleStats",
            primary_category="HEALTH",
            importance_score=95,
            confidence="HIGH"
        )
        self.fld = FieldDefinition.objects.create(
            class_def=self.cls,
            name="hp",
            type_name="float",
            offset_value=0x18,
            offset_hex="0x18",
            primary_category="HEALTH",
            importance_score=95,
            confidence="HIGH"
        )
        self.addr = AddressRecord.objects.create(
            project=self.project,
            field_def=self.fld,
            class_name="SampleStats",
            member_name="hp",
            address_type="FIELD_OFFSET",
            value_int=0x18,
            value_hex="0x18",
            architecture="ARM64",
            source="test dump"
        )

    def test_generate_all_reports(self):
        temp_dir = Path(tempfile.mkdtemp())
        try:
            gen = ReportGenerator(self.project)
            paths = gen.generate_all_reports(temp_dir)

            self.assertIn("ImportantData.md", paths)
            self.assertIn("offsets.json", paths)
            self.assertIn("field_offsets.csv", paths)

            # Check markdown content
            md_text = paths["ImportantData.md"].read_text(encoding="utf-8")
            self.assertIn("SampleStats", md_text)
            self.assertIn("hp", md_text)

            # Check CSV content
            csv_text = paths["field_offsets.csv"].read_text(encoding="utf-8")
            self.assertIn("0x18", csv_text)
            self.assertIn("SampleStats", csv_text)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
