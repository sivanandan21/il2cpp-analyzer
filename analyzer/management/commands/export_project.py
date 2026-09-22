"""
Management command to export a project's analysis reports to a local directory.
Usage:
    python manage.py export_project PROJECT_ID --outdir=./exports
"""

from django.core.management.base import BaseCommand, CommandError
from pathlib import Path
from analyzer.models import Project
from analyzer.services.report_generator import ReportGenerator

class Command(BaseCommand):
    help = "Generate all Markdown, JSON, CSV, and text reports for a Project."

    def add_arguments(self, parser):
        parser.add_argument('project_id', type=int, help="ID of the Project to export")
        parser.add_argument('--outdir', type=str, default="", help="Custom output directory")

    def handle(self, *args, **options):
        pid = options['project_id']
        try:
            project = Project.objects.get(id=pid)
        except Project.DoesNotExist:
            raise CommandError(f"Project with ID {pid} does not exist.")

        out_path = Path(options['outdir']) if options['outdir'] else Path(project.get_storage_path()) / "reports"
        out_path.mkdir(parents=True, exist_ok=True)

        self.stdout.write(f"Generating reports for '{project.name}' into {out_path}...")
        rep_gen = ReportGenerator(project)
        generated = rep_gen.generate_all_reports(out_path)

        for name, p in generated.items():
            self.stdout.write(f"  Exported: {name}")

        self.stdout.write(self.style.SUCCESS(f"Done! {len(generated)} report artifacts created."))
