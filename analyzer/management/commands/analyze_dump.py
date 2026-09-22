"""
Management command to analyze an IL2CPP dump or binary from the CLI.
Usage:
    python manage.py analyze_dump /path/to/dump.cs --name="MyGame"
"""

from django.core.management.base import BaseCommand, CommandError
from pathlib import Path
from analyzer.models import Project
from analyzer.services.project_manager import ProjectManager

class Command(BaseCommand):
    help = "Ingest and analyze an IL2CPP metadata file, binary, or archive via CLI."

    def add_arguments(self, parser):
        parser.add_argument('path', type=str, help="Absolute or relative path to the target file or archive")
        parser.add_argument('--name', type=str, default="", help="Custom project name")
        parser.add_argument('--desc', type=str, default="", help="Project description")

    def handle(self, *args, **options):
        target_path = Path(options['path']).resolve()
        if not target_path.exists():
            raise CommandError(f"Target file does not exist: {target_path}")

        proj_name = options['name'] or target_path.stem
        self.stdout.write(self.style.NOTICE(f"Creating project '{proj_name}' from {target_path.name}..."))

        project = Project.objects.create(
            name=proj_name,
            description=options['desc'],
            status="UPLOADED"
        )

        res = ProjectManager.process_project(project.id, target_path)

        if res.get("status") == "SUCCESS":
            project.refresh_from_db()
            self.stdout.write(self.style.SUCCESS(f"Analysis complete! Project ID: {project.id}"))
            self.stdout.write(f"  Classes: {project.classes_count}")
            self.stdout.write(f"  Methods: {project.methods_count}")
            self.stdout.write(f"  Fields:  {project.fields_count}")
            self.stdout.write(f"  Offsets: {project.address_records.count()}")
        else:
            self.stderr.write(self.style.ERROR(f"Analysis failed: {res.get('error')}"))
