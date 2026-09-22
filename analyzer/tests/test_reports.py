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
            self.assertIn("analysis_report.txt", paths)
            self.assertIn("gameplay_offsets.txt", paths)
            self.assertIn("dump.cs", paths)
            self.assertIn("all_reports.zip", paths)

            # Check markdown content
            md_text = paths["ImportantData.md"].read_text(encoding="utf-8")
            self.assertIn("SampleStats", md_text)
            self.assertIn("hp", md_text)

            # Check CSV content
            csv_text = paths["field_offsets.csv"].read_text(encoding="utf-8")
            self.assertIn("0x18", csv_text)
            self.assertIn("SampleStats", csv_text)

            # Check Plain Text content
            txt_report = paths["analysis_report.txt"].read_text(encoding="utf-8")
            self.assertIn("SampleStats", txt_report)
            self.assertIn("0x18", txt_report)

            gameplay_txt = paths["gameplay_offsets.txt"].read_text(encoding="utf-8")
            self.assertIn("0x18", gameplay_txt)
            self.assertIn("SampleStats.hp", gameplay_txt)

            # Check C# dump content
            cs_dump = paths["dump.cs"].read_text(encoding="utf-8")
            self.assertIn("public class SampleStats", cs_dump)
            self.assertIn("0x18", cs_dump)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_download_report_endpoint(self):
        from django.test import Client
        client = Client()
        # Test download without trailing slash
        response = client.get(f'/reports/{self.project.id}/gameplay_offsets.txt')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('Content-Type'), 'text/plain; charset=utf-8')
        self.assertIn('gameplay_offsets.txt', response.headers.get('Content-Disposition'))
        self.assertIn("filename*=UTF-8''gameplay_offsets.txt", response.headers.get('Content-Disposition'))

        # Test download with trailing slash fallback
        response_slash = client.get(f'/reports/{self.project.id}/analysis_report.txt/')
        self.assertEqual(response_slash.status_code, 200)
        self.assertEqual(response_slash.headers.get('Content-Type'), 'text/plain; charset=utf-8')
        self.assertIn('analysis_report.txt', response_slash.headers.get('Content-Disposition'))

