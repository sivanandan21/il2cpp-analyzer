from django.db import migrations

def delete_sample_data(apps, schema_editor):
    Project = apps.get_model('analyzer', 'Project')
    # Permanently delete any synthetic sample projects from database
    Project.objects.filter(name__icontains='synthetic').delete()
    Project.objects.filter(description__icontains='SYNTHETIC').delete()
    Project.objects.filter(source_type='SYNTHETIC DUMP').delete()

class Migration(migrations.Migration):
    dependencies = [
        ('analyzer', '0002_project_app_version_project_engine_type_and_more'),
    ]

    operations = [
        migrations.RunPython(delete_sample_data, reverse_code=migrations.RunPython.noop),
    ]
