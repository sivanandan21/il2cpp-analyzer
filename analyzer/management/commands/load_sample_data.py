from django.core.management.base import BaseCommand
from analyzer.models import Project


class Command(BaseCommand):
    help = "Deprecated: Sample data removed to provide direct APK upload."

    def handle(self, *args, **options):
        # Ensure any old synthetic sample projects are purged
        deleted = Project.objects.filter(name__icontains='synthetic').delete()
        self.stdout.write(f"Sample data disabled. Purged any old synthetic data: {deleted}")
