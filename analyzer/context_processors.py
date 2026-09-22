"""
Global context processor for IL2CPP Analyzer.
Provides active_project, all_projects list, and system statistics to all templates.
"""

from typing import Dict, Any


def global_project_context(request) -> Dict[str, Any]:
    try:
        from .models import Project
        from .views import get_active_project

        active_proj = get_active_project(request)
        all_projs = list(Project.objects.all().order_by("-created_at")[:15])

        return {
            "active_project": active_proj,
            "all_projects": all_projs,
            "total_projects_count": len(all_projs),
        }
    except Exception:
        return {
            "active_project": None,
            "all_projects": [],
            "total_projects_count": 0,
        }
