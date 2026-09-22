"""
Management command to recalculate semantic heuristic scores for a project.
Usage:
    python manage.py rebuild_scores PROJECT_ID
"""

from django.core.management.base import BaseCommand, CommandError
from analyzer.models import Project, ClassDefinition, FieldDefinition, MethodDefinition
from analyzer.services.scorer import SmartScorer

class Command(BaseCommand):
    help = "Recalculate heuristic scores and confidence for all entities in a project."

    def add_arguments(self, parser):
        parser.add_argument('project_id', type=int, help="ID of the Project to rebuild")

    def handle(self, *args, **options):
        pid = options['project_id']
        try:
            project = Project.objects.get(id=pid)
        except Project.DoesNotExist:
            raise CommandError(f"Project with ID {pid} does not exist.")

        self.stdout.write(f"Rebuilding heuristic scores for '{project.name}' (ID: {pid})...")
        scorer = SmartScorer()

        # Update classes
        classes = project.classes.prefetch_related('fields', 'methods').all()
        for c in classes:
            c_score = scorer.score_class(c.name, c.namespace, c.fields.count(), c.methods.count())
            c.importance_score = c_score.total_score
            c.confidence = c_score.confidence
            c.primary_category = c_score.primary_category or "GENERAL"
            c.context_type = c_score.context_type
            c.save(update_fields=['importance_score', 'confidence', 'primary_category', 'context_type'])

            # Update fields
            sibling_names = [f.name for f in c.fields.all()]
            for f in c.fields.all():
                f_score = scorer.score_field(f.name, f.type_name, c.name, c.namespace, bool(f.offset_value), sibling_names)
                f.importance_score = f_score.total_score
                f.confidence = f_score.confidence
                f.primary_category = f_score.primary_category or "GENERAL"
                f.context_type = f_score.context_type
                f.save(update_fields=['importance_score', 'confidence', 'primary_category', 'context_type'])

            # Update methods
            for m in c.methods.all():
                m_score = scorer.score_method(m.name, m.return_type, c.name, bool(m.rva_value))
                m.importance_score = m_score.total_score
                m.confidence = m_score.confidence
                m.primary_category = m_score.primary_category or "GENERAL"
                m.save(update_fields=['importance_score', 'confidence', 'primary_category'])

        self.stdout.write(self.style.SUCCESS(f"Successfully rebuilt scores for {classes.count()} classes."))
