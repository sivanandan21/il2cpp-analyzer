"""
Views for IL2CPP Game Data & Offset Analyzer.
Includes dashboard, upload, explorer, offset center, graph, dump viewer,
comparison, reports, rules, and RESTful JSON APIs.
"""

from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from django.db.models import Count, Q, Avg
from django.conf import settings
from pathlib import Path
import json
import os

from .models import (
    Project, Assembly, Namespace, ClassDefinition, FieldDefinition,
    MethodDefinition, ParameterDefinition, PropertyDefinition, EnumDefinition,
    AddressRecord, Category, AnalysisResult, Rule, Profile, Relationship,
    AnalysisJob, WarningRecord, AddressTypeChoices, ConfidenceChoices
)
from .forms import ProjectUploadForm, RuleForm, ProjectCompareForm
from .services.project_manager import ProjectManager
from .services.search_engine import SearchEngine
from .services.relationship_engine import RelationshipEngine
from .services.export_manager import ExportManager
from .services.semantic_analyzer import GAMEPLAY_CATEGORIES


def get_active_project(request):
    """Helper to retrieve explicitly selected project. Does not auto-fallback to sample data."""
    if request.GET.get('new') == '1' or request.GET.get('upload') == '1':
        request.session.pop('active_project_id', None)
        return None

    project_id = request.GET.get('project_id') or request.session.get('active_project_id')
    if project_id:
        try:
            p = Project.objects.exclude(name__icontains='synthetic').get(id=project_id)
            request.session['active_project_id'] = p.id
            return p
        except Project.DoesNotExist:
            request.session.pop('active_project_id', None)
    return None


# =============================================================================
# Dashboard & Project Management
# =============================================================================

def dashboard(request):
    if request.method == 'POST':
        uploaded_file = request.FILES.get('file')
        if uploaded_file:
            name = request.POST.get('name', '').strip()
            if not name:
                name = Path(uploaded_file.name).stem.replace('_', ' ').replace('-', ' ').title()
            description = request.POST.get('description', '').strip()

            project = Project.objects.create(
                name=name,
                description=description,
                status="UPLOADED",
                is_apk=uploaded_file.name.lower().endswith('.apk')
            )

            save_dir = Path(project.get_storage_path())
            save_dir.mkdir(parents=True, exist_ok=True)
            saved_file_path = save_dir / uploaded_file.name

            with open(saved_file_path, 'wb+') as dest:
                for chunk in uploaded_file.chunks():
                    dest.write(chunk)

            # Initiate analysis immediately
            res = ProjectManager.process_project(project.id, saved_file_path)
            request.session['active_project_id'] = project.id

            is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', '')
            if res.get("status") == "FAILED":
                if is_ajax:
                    return JsonResponse({"status": "ERROR", "message": res.get("error", "Analysis failed.")}, status=400)

            if is_ajax:
                return JsonResponse({
                    "status": "SUCCESS",
                    "project_id": project.id,
                    "redirect_url": f"/?project_id={project.id}"
                })

            return redirect(f"/?project_id={project.id}")
        else:
            is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', '')
            if is_ajax:
                return JsonResponse({"status": "ERROR", "message": "No file was selected for upload."}, status=400)

    active_proj = get_active_project(request)
    all_projects = Project.objects.all()[:10]

    # Overall or active project statistics
    stats = {
        "projects_count": Project.objects.count(),
        "classes_count": ClassDefinition.objects.filter(project=active_proj).count() if active_proj else 0,
        "methods_count": MethodDefinition.objects.filter(class_def__project=active_proj).count() if active_proj else 0,
        "fields_count": FieldDefinition.objects.filter(class_def__project=active_proj).count() if active_proj else 0,
        "field_offsets_count": AddressRecord.objects.filter(project=active_proj, address_type="FIELD_OFFSET").count() if active_proj else 0,
        "method_rvas_count": AddressRecord.objects.filter(project=active_proj, address_type="METHOD_RVA").count() if active_proj else 0,
        "static_addresses_count": AddressRecord.objects.filter(project=active_proj, address_type="STATIC_ADDRESS").count() if active_proj else 0,
        "virtual_addresses_count": AddressRecord.objects.filter(project=active_proj, address_type="VIRTUAL_ADDRESS").count() if active_proj else 0,
        "file_offsets_count": AddressRecord.objects.filter(project=active_proj, address_type="FILE_OFFSET").count() if active_proj else 0,
    }

    category_stats = []
    gameplay_dossier = {
        "currencies": [],
        "stats": [],
        "combat": [],
        "speed": [],
        "security": []
    }

    if active_proj:
        cat_counts = (
            ClassDefinition.objects.filter(project=active_proj)
            .values('primary_category')
            .annotate(count=Count('id'))
            .order_by('-count')[:8]
        )
        for c in cat_counts:
            category_stats.append({
                "name": c['primary_category'],
                "count": c['count']
            })

        # Query top game data with category and keyword matching
        gameplay_dossier["currencies"] = list(FieldDefinition.objects.filter(
            Q(class_def__project=active_proj) &
            (Q(primary_category__in=['CURRENCY', 'ECONOMY', 'REWARDS']) |
             Q(name__iregex=r'(coin|gem|gold|money|cash|currency|token|diamond|credit|balance|wallet|reward|price|cost|star)'))
        ).select_related('class_def').order_by('-importance_score')[:12])

        gameplay_dossier["stats"] = list(FieldDefinition.objects.filter(
            Q(class_def__project=active_proj) &
            (Q(primary_category__in=['HEALTH', 'PLAYER', 'ENERGY', 'STAMINA', 'EXPERIENCE']) |
             Q(name__iregex=r'(hp|health|life|mana|energy|stamina|exp|level|score|player|avatar|rank)'))
        ).select_related('class_def').order_by('-importance_score')[:12])

        gameplay_dossier["combat"] = list(FieldDefinition.objects.filter(
            Q(class_def__project=active_proj) &
            (Q(primary_category__in=['DAMAGE', 'COMBAT', 'WEAPON', 'AMMO', 'COOLDOWN']) |
             Q(name__iregex=r'(damage|atk|attack|crit|defense|weapon|gun|bullet|ammo|cooldown|shield|armor)'))
        ).select_related('class_def').order_by('-importance_score')[:12])

        gameplay_dossier["speed"] = list(FieldDefinition.objects.filter(
            Q(class_def__project=active_proj) &
            (Q(primary_category__in=['SPEED', 'PHYSICS']) |
             Q(name__iregex=r'(speed|velocity|move|jump|accel|gravity|dash|friction)'))
        ).select_related('class_def').order_by('-importance_score')[:10])

        gameplay_dossier["security"] = list(MethodDefinition.objects.filter(
            Q(class_def__project=active_proj) &
            (Q(primary_category__in=['SECURITY', 'NETWORK', 'ENCRYPTION']) |
             Q(name__iregex=r'(anti|cheat|ban|security|verify|protect|token|tamper|auth|signature|integrity)'))
        ).select_related('class_def').order_by('-importance_score')[:10])

    upload_form = ProjectUploadForm()

    return render(request, 'analyzer/dashboard.html', {
        'active_project': active_proj,
        'projects': all_projects,
        'stats': stats,
        'category_stats': category_stats,
        'gameplay_dossier': gameplay_dossier,
        'upload_form': upload_form,
    })


def project_list(request):
    projects = Project.objects.all().order_by('-created_at')
    return render(request, 'analyzer/projects.html', {'projects': projects})


def project_detail(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    request.session['active_project_id'] = project.id

    address_stats = {
        "field_offsets": project.address_records.filter(address_type="FIELD_OFFSET").count(),
        "method_rvas": project.address_records.filter(address_type="METHOD_RVA").count(),
        "static_addrs": project.address_records.filter(address_type="STATIC_ADDRESS").count(),
        "virtual_addrs": project.address_records.filter(address_type="VIRTUAL_ADDRESS").count(),
        "file_offsets": project.address_records.filter(address_type="FILE_OFFSET").count(),
    }

    warnings = project.warnings.all()[:20]

    return render(request, 'analyzer/project_detail.html', {
        'project': project,
        'address_stats': address_stats,
        'warnings': warnings,
    })


def upload_view(request):
    if request.method == 'POST':
        uploaded_file = request.FILES.get('file')
        if uploaded_file:
            name = request.POST.get('name', '').strip()
            if not name:
                name = Path(uploaded_file.name).stem.replace('_', ' ').replace('-', ' ').title()
            description = request.POST.get('description', '').strip()

            project = Project.objects.create(
                name=name,
                description=description,
                status="UPLOADED",
                is_apk=uploaded_file.name.lower().endswith('.apk')
            )

            save_dir = Path(project.get_storage_path())
            save_dir.mkdir(parents=True, exist_ok=True)
            saved_file_path = save_dir / uploaded_file.name

            with open(saved_file_path, 'wb+') as dest:
                for chunk in uploaded_file.chunks():
                    dest.write(chunk)

            # Initiate analysis synchronously
            res = ProjectManager.process_project(project.id, saved_file_path)
            request.session['active_project_id'] = project.id

            is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', '')
            if res.get("status") == "FAILED":
                if is_ajax:
                    return JsonResponse({"status": "ERROR", "message": res.get("error", "Analysis failed.")}, status=400)

            if is_ajax:
                return JsonResponse({
                    "status": "SUCCESS",
                    "project_id": project.id,
                    "redirect_url": f"/?project_id={project.id}"
                })

            return redirect(f"/?project_id={project.id}")
        else:
            is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', '')
            if is_ajax:
                return JsonResponse({"status": "ERROR", "message": "No file selected."}, status=400)
    else:
        form = ProjectUploadForm()

    return render(request, 'analyzer/upload.html', {'form': form})


def project_status_api(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    job = getattr(project, 'job', None)
    return JsonResponse({
        "project_id": project.id,
        "status": project.status,
        "step": job.current_step if job else 0,
        "step_description": job.step_description if job else "Initializing",
        "progress_percent": job.progress_percent if job else 0,
        "error": job.error_message if job else "",
    })


def project_delete(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    if request.method == 'POST':
        storage_path = Path(project.get_storage_path())
        if storage_path.exists():
            import shutil
            shutil.rmtree(storage_path, ignore_errors=True)
        project.delete()
        return redirect('project_list')
    return render(request, 'analyzer/project_confirm_delete.html', {'project': project})


# =============================================================================
# Explorers (Classes, Fields, Methods)
# =============================================================================

def class_list(request):
    project = get_active_project(request)
    if not project:
        return redirect('upload')

    qs = ClassDefinition.objects.filter(project=project)

    # Filters
    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(namespace__icontains=q))

    category = request.GET.get('category', '').strip()
    if category and category.upper() != 'ALL':
        qs = qs.filter(primary_category__iexact=category)

    confidence = request.GET.get('confidence', '').strip()
    if confidence:
        qs = qs.filter(confidence=confidence)

    min_score = request.GET.get('min_score', '').strip()
    if min_score.isdigit():
        qs = qs.filter(importance_score__gte=int(min_score))

    sort = request.GET.get('sort', '-importance_score')
    qs = qs.order_by(sort)

    paginator = Paginator(qs, 40)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'analyzer/classes.html', {
        'project': project,
        'page_obj': page_obj,
        'categories': GAMEPLAY_CATEGORIES,
        'current_category': category,
        'current_q': q,
        'current_sort': sort,
    })


def class_detail(request, class_id):
    class_obj = get_object_or_404(ClassDefinition.objects.select_related('project', 'assembly'), id=class_id)
    fields = class_obj.fields.all().order_by('offset_value', 'name')
    methods = class_obj.methods.all().order_by('-importance_score', 'name')
    properties = class_obj.properties.all()
    address_records = AddressRecord.objects.filter(project=class_obj.project, class_name=class_obj.name)

    return render(request, 'analyzer/class_detail.html', {
        'class_obj': class_obj,
        'fields': fields,
        'methods': methods,
        'properties': properties,
        'address_records': address_records,
    })


def field_list(request):
    project = get_active_project(request)
    if not project:
        return redirect('upload')

    qs = FieldDefinition.objects.filter(class_def__project=project).select_related('class_def')

    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(class_def__name__icontains=q) | Q(type_name__icontains=q))

    category = request.GET.get('category', '').strip()
    if category and category.upper() != 'ALL':
        qs = qs.filter(primary_category__iexact=category)

    only_offsets = request.GET.get('has_offset', '')
    if only_offsets == '1':
        qs = qs.filter(offset_value__isnull=False)

    is_static = request.GET.get('is_static', '')
    if is_static in ('0', '1'):
        qs = qs.filter(is_static=(is_static == '1'))

    sort = request.GET.get('sort', '-importance_score')
    qs = qs.order_by(sort)

    paginator = Paginator(qs, 50)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'analyzer/fields.html', {
        'project': project,
        'page_obj': page_obj,
        'categories': GAMEPLAY_CATEGORIES,
        'current_category': category,
        'current_q': q,
    })


def field_detail(request, field_id):
    field_obj = get_object_or_404(FieldDefinition.objects.select_related('class_def', 'class_def__project'), id=field_id)
    address_record = AddressRecord.objects.filter(field_def=field_obj).first()

    return render(request, 'analyzer/field_detail.html', {
        'field_obj': field_obj,
        'address_record': address_record,
    })


def method_list(request):
    project = get_active_project(request)
    if not project:
        return redirect('upload')

    qs = MethodDefinition.objects.filter(class_def__project=project).select_related('class_def')

    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(class_def__name__icontains=q) | Q(signature__icontains=q))

    category = request.GET.get('category', '').strip()
    if category and category.upper() != 'ALL':
        qs = qs.filter(primary_category__iexact=category)

    only_rva = request.GET.get('has_rva', '')
    if only_rva == '1':
        qs = qs.filter(rva_value__isnull=False)

    sort = request.GET.get('sort', '-importance_score')
    qs = qs.order_by(sort)

    paginator = Paginator(qs, 50)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'analyzer/methods.html', {
        'project': project,
        'page_obj': page_obj,
        'categories': GAMEPLAY_CATEGORIES,
        'current_category': category,
        'current_q': q,
    })


def method_detail(request, method_id):
    method_obj = get_object_or_404(MethodDefinition.objects.select_related('class_def', 'class_def__project'), id=method_id)
    parameters = method_obj.parameters.all()
    address_record = AddressRecord.objects.filter(method_def=method_obj).first()

    return render(request, 'analyzer/method_detail.html', {
        'method_obj': method_obj,
        'parameters': parameters,
        'address_record': address_record,
    })


# =============================================================================
# Dedicated Offset Center & Important Offsets
# =============================================================================

def offset_center(request):
    project = get_active_project(request)
    if not project:
        return redirect('upload')

    qs = AddressRecord.objects.filter(project=project)

    # Address Type Tab
    tab = request.GET.get('tab', 'ALL').upper()
    if tab != 'ALL':
        if tab in AddressTypeChoices.values:
            qs = qs.filter(address_type=tab)

    category = request.GET.get('category', '').strip()
    if category and category.upper() != 'ALL':
        qs = qs.filter(
            Q(field_def__primary_category__iexact=category) |
            Q(method_def__primary_category__iexact=category)
        )

    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(Q(class_name__icontains=q) | Q(member_name__icontains=q) | Q(value_hex__icontains=q))

    counts = {
        "all": project.address_records.count(),
        "field_offsets": project.address_records.filter(address_type="FIELD_OFFSET").count(),
        "method_rvas": project.address_records.filter(address_type="METHOD_RVA").count(),
        "static_addrs": project.address_records.filter(address_type="STATIC_ADDRESS").count(),
        "virtual_addrs": project.address_records.filter(address_type="VIRTUAL_ADDRESS").count(),
        "file_offsets": project.address_records.filter(address_type="FILE_OFFSET").count(),
    }

    paginator = Paginator(qs.order_by('address_type', 'class_name', 'value_int'), 50)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'analyzer/offsets.html', {
        'project': project,
        'page_obj': page_obj,
        'counts': counts,
        'current_tab': tab,
        'current_q': q,
        'categories': GAMEPLAY_CATEGORIES,
    })


def important_offsets(request):
    project = get_active_project(request)
    if not project:
        return redirect('upload')

    # Ranked address records via semantic scoring
    field_records = (
        AddressRecord.objects.filter(project=project, address_type="FIELD_OFFSET", field_def__importance_score__gte=40)
        .select_related('field_def', 'field_def__class_def')
        .order_by('-field_def__importance_score')[:100]
    )

    method_records = (
        AddressRecord.objects.filter(project=project, address_type="METHOD_RVA", method_def__importance_score__gte=40)
        .select_related('method_def', 'method_def__class_def')
        .order_by('-method_def__importance_score')[:100]
    )

    return render(request, 'analyzer/important_offsets.html', {
        'project': project,
        'field_records': field_records,
        'method_records': method_records,
    })


def offset_detail(request, offset_id):
    addr = get_object_or_404(AddressRecord.objects.select_related('project', 'field_def', 'method_def'), id=offset_id)
    return render(request, 'analyzer/offset_detail.html', {'addr': addr})


def static_data_view(request):
    project = get_active_project(request)
    if not project:
        return redirect('upload')

    qs = AddressRecord.objects.filter(project=project, address_type="STATIC_ADDRESS")
    paginator = Paginator(qs, 50)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'analyzer/static_data.html', {
        'project': project,
        'page_obj': page_obj
    })


# =============================================================================
# Categories, Graph, Dump Viewer, Search
# =============================================================================

def category_dashboard(request):
    project = get_active_project(request)
    if not project:
        return redirect('upload')

    # Aggregations for each of the 24 categories
    cat_data = []
    for cat in GAMEPLAY_CATEGORIES:
        c_count = ClassDefinition.objects.filter(project=project, primary_category__iexact=cat).count()
        f_count = FieldDefinition.objects.filter(class_def__project=project, primary_category__iexact=cat).count()
        m_count = MethodDefinition.objects.filter(class_def__project=project, primary_category__iexact=cat).count()
        total = c_count + f_count + m_count
        cat_data.append({
            "name": cat,
            "total": total,
            "classes_count": c_count,
            "fields_count": f_count,
            "methods_count": m_count
        })

    cat_data.sort(key=lambda x: x['total'], reverse=True)
    return render(request, 'analyzer/categories.html', {
        'project': project,
        'categories': cat_data
    })


def category_detail(request, category_name):
    project = get_active_project(request)
    cat_upper = category_name.upper()

    classes = ClassDefinition.objects.filter(project=project, primary_category__iexact=cat_upper).order_by('-importance_score')[:50]
    fields = FieldDefinition.objects.filter(class_def__project=project, primary_category__iexact=cat_upper).select_related('class_def').order_by('-importance_score')[:50]
    methods = MethodDefinition.objects.filter(class_def__project=project, primary_category__iexact=cat_upper).select_related('class_def').order_by('-importance_score')[:50]

    return render(request, 'analyzer/category_detail.html', {
        'project': project,
        'category_name': cat_upper,
        'classes': classes,
        'fields': fields,
        'methods': methods
    })


def global_search_view(request):
    project = get_active_project(request)
    query = request.GET.get('q', '').strip()
    results = None
    if project and query:
        results = SearchEngine.search(project.id, query)

    return render(request, 'analyzer/search.html', {
        'project': project,
        'query': query,
        'results': results
    })


def graph_view(request):
    project = get_active_project(request)
    return render(request, 'analyzer/graph.html', {
        'project': project,
        'categories': GAMEPLAY_CATEGORIES
    })


def dump_viewer(request):
    project = get_active_project(request)
    if not project:
        return redirect('upload')

    storage_dir = Path(project.get_storage_path())
    dump_file = None

    # Search for dump.cs
    for root, _, files in os.walk(storage_dir):
        for f in files:
            if f.lower().endswith(".cs") or "dump" in f.lower():
                dump_file = Path(root) / f
                break
        if dump_file:
            break

    code_lines = []
    if dump_file and dump_file.exists():
        with open(dump_file, 'r', encoding='utf-8', errors='ignore') as f:
            for idx, line in enumerate(f):
                if idx > 5000:  # Truncate viewer preview for DOM performance
                    code_lines.append((idx + 1, "// ... [Preview capped at 5000 lines for high performance] ..."))
                    break
                code_lines.append((idx + 1, line.rstrip()))
    else:
        # Generate synthetic C# dump representation from indexed DB
        classes = project.classes.prefetch_related('fields', 'methods')[:100]
        line_num = 1
        code_lines.append((line_num, f"// IL2CPP Dump Generated from Indexed Database for {project.name}"))
        line_num += 1
        for c in classes:
            code_lines.append((line_num, f"// Namespace: {c.namespace}"))
            line_num += 1
            code_lines.append((line_num, f"public class {c.name} : {c.base_class_name or 'System.Object'} {{"))
            line_num += 1
            for f in c.fields.all():
                off_comment = f" // {f.offset_hex}" if f.offset_hex else ""
                code_lines.append((line_num, f"    {f.visibility} {f.type_name} {f.name};{off_comment}"))
                line_num += 1
            for m in c.methods.all():
                rva_comment = f" // RVA: {m.rva_hex}" if m.rva_hex else ""
                code_lines.append((line_num, f"    {m.signature};{rva_comment}"))
                line_num += 1
            code_lines.append((line_num, "}"))
            line_num += 1
            code_lines.append((line_num, ""))
            line_num += 1

    return render(request, 'analyzer/dump_viewer.html', {
        'project': project,
        'code_lines': code_lines,
    })


def project_compare(request):
    form = ProjectCompareForm(request.GET or None)
    diff_results = None

    if form.is_valid():
        proj_a = form.cleaned_data['project_a']
        proj_b = form.cleaned_data['project_b']

        # Compare classes
        classes_a = {c.name: c for c in proj_a.classes.all()}
        classes_b = {c.name: c for c in proj_b.classes.all()}

        added_classes = [c for name, c in classes_b.items() if name not in classes_a]
        removed_classes = [c for name, c in classes_a.items() if name not in classes_b]

        # Compare field offsets
        changed_offsets = []
        for name, c_a in classes_a.items():
            if name in classes_b:
                c_b = classes_b[name]
                fields_a = {f.name: f for f in c_a.fields.all()}
                fields_b = {f.name: f for f in c_b.fields.all()}
                for fname, f_a in fields_a.items():
                    if fname in fields_b:
                        f_b = fields_b[fname]
                        if f_a.offset_hex != f_b.offset_hex and (f_a.offset_hex or f_b.offset_hex):
                            changed_offsets.append({
                                "class": name,
                                "field": fname,
                                "old_offset": f_a.offset_hex or "N/A",
                                "new_offset": f_b.offset_hex or "N/A",
                                "status": "CHANGED"
                            })

        # Compare method RVAs
        changed_rvas = []
        for name, c_a in classes_a.items():
            if name in classes_b:
                c_b = classes_b[name]
                m_a = {m.name: m for m in c_a.methods.all()}
                m_b = {m.name: m for m in c_b.methods.all()}
                for mname, meth_a in m_a.items():
                    if mname in m_b:
                        meth_b = m_b[mname]
                        if meth_a.rva_hex != meth_b.rva_hex and (meth_a.rva_hex or meth_b.rva_hex):
                            changed_rvas.append({
                                "class": name,
                                "method": mname,
                                "old_rva": meth_a.rva_hex or "N/A",
                                "new_rva": meth_b.rva_hex or "N/A",
                                "status": "CHANGED"
                            })

        diff_results = {
            "proj_a": proj_a,
            "proj_b": proj_b,
            "added_classes": added_classes,
            "removed_classes": removed_classes,
            "changed_offsets": changed_offsets,
            "changed_rvas": changed_rvas,
        }

    return render(request, 'analyzer/compare.html', {
        'form': form,
        'diff': diff_results,
    })


def rule_list(request):
    rules = Rule.objects.all()
    if request.method == 'POST':
        form = RuleForm(request.POST)
        if form.is_valid():
            rule = form.save(commit=False)
            kw = [k.strip() for k in form.cleaned_data['keywords_text'].split(',') if k.strip()]
            ty = [t.strip() for t in form.cleaned_data['types_text'].split(',') if t.strip()]
            rule.keywords_json = kw
            rule.types_json = ty
            rule.save()
            return redirect('rule_list')
    else:
        form = RuleForm()

    return render(request, 'analyzer/rules.html', {
        'rules': rules,
        'form': form
    })


def rule_delete(request, rule_id):
    rule = get_object_or_404(Rule, id=rule_id)
    rule.delete()
    return redirect('rule_list')


def reports_view(request):
    project = get_active_project(request)
    if not project:
        return redirect('upload')

    reports_dir = Path(project.get_storage_path()) / "reports"
    reports_list = []
    if reports_dir.exists():
        for f in reports_dir.iterdir():
            if f.is_file():
                reports_list.append({
                    "name": f.name,
                    "size_kb": round(f.stat().st_size / 1024, 1),
                    "path": f.name
                })

    return render(request, 'analyzer/reports.html', {
        'project': project,
        'reports': reports_list
    })


def download_report(request, project_id, filename):
    project = get_object_or_404(Project, id=project_id)
    file_path = Path(project.get_storage_path()) / "reports" / filename

    # Prevent directory traversal
    if not str(file_path.resolve()).startswith(str(Path(project.get_storage_path()).resolve())):
        raise Http404("Access denied")

    if not file_path.exists():
        raise Http404("Report not found")

    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type="application/octet-stream")
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


# =============================================================================
# RESTful JSON APIs
# =============================================================================

def api_projects(request):
    projects = Project.objects.all()
    data = [{
        "id": p.id,
        "name": p.name,
        "platform": p.platform,
        "architecture": p.architecture,
        "status": p.status,
        "classes_count": p.classes_count,
        "methods_count": p.methods_count,
        "fields_count": p.fields_count
    } for p in projects]
    return JsonResponse({"projects": data})


def api_project_detail(request, project_id):
    p = get_object_or_404(Project, id=project_id)
    return JsonResponse({
        "id": p.id,
        "name": p.name,
        "platform": p.platform,
        "architecture": p.architecture,
        "status": p.status,
        "unity_version": p.unity_version,
        "metadata_version": p.metadata_version,
        "classes_count": p.classes_count,
        "methods_count": p.methods_count,
        "fields_count": p.fields_count,
        "warnings_count": p.warnings_count
    })


def api_classes(request):
    project = get_active_project(request)
    if not project:
        return JsonResponse({"classes": []})

    qs = ClassDefinition.objects.filter(project=project)
    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(name__icontains=q)
    category = request.GET.get('category', '').strip()
    if category:
        qs = qs.filter(primary_category__iexact=category)

    data = [{
        "id": c.id,
        "name": c.name,
        "namespace": c.namespace,
        "category": c.primary_category,
        "score": c.importance_score,
        "confidence": c.confidence
    } for c in qs[:100]]
    return JsonResponse({"classes": data})


def api_class_detail(request, class_id):
    c = get_object_or_404(ClassDefinition, id=class_id)
    fields = [{
        "name": f.name,
        "type": f.type_name,
        "offset": f.offset_hex,
        "score": f.importance_score
    } for f in c.fields.all()]
    methods = [{
        "name": m.name,
        "return_type": m.return_type,
        "rva": m.rva_hex,
        "score": m.importance_score
    } for m in c.methods.all()]

    return JsonResponse({
        "id": c.id,
        "name": c.name,
        "namespace": c.namespace,
        "score": c.importance_score,
        "confidence": c.confidence,
        "category": c.primary_category,
        "fields": fields,
        "methods": methods
    })


def api_fields(request):
    project = get_active_project(request)
    if not project:
        return JsonResponse({"fields": []})

    qs = FieldDefinition.objects.filter(class_def__project=project)
    data = [{
        "id": f.id,
        "name": f.name,
        "class": f.class_def.name,
        "type": f.type_name,
        "offset": f.offset_hex,
        "score": f.importance_score,
        "category": f.primary_category
    } for f in qs[:100]]
    return JsonResponse({"fields": data})


def api_methods(request):
    project = get_active_project(request)
    if not project:
        return JsonResponse({"methods": []})

    qs = MethodDefinition.objects.filter(class_def__project=project)
    data = [{
        "id": m.id,
        "name": m.name,
        "class": m.class_def.name,
        "rva": m.rva_hex,
        "score": m.importance_score,
        "category": m.primary_category
    } for m in qs[:100]]
    return JsonResponse({"methods": data})


def api_offsets(request):
    project = get_active_project(request)
    if not project:
        return JsonResponse({"offsets": []})

    qs = AddressRecord.objects.filter(project=project)
    addr_type = request.GET.get('type')
    if addr_type:
        qs = qs.filter(address_type=addr_type)

    data = [{
        "id": a.id,
        "class_name": a.class_name,
        "member_name": a.member_name,
        "address_type": a.address_type,
        "value_hex": a.value_hex,
        "confidence": a.confidence
    } for a in qs[:100]]
    return JsonResponse({"offsets": data})


def api_search(request):
    project = get_active_project(request)
    q = request.GET.get('q', '').strip()
    if not project or not q:
        return JsonResponse({"results": {}})
    res = SearchEngine.search(project.id, q, limit_per_type=10)
    return JsonResponse(res.to_dict())


def api_graph(request):
    project = get_active_project(request)
    if not project:
        return JsonResponse({"nodes": [], "edges": []})

    category = request.GET.get('category')
    min_score = int(request.GET.get('min_score', 0))
    classes = project.classes.prefetch_related('fields').all()

    graph = RelationshipEngine.build_graph(classes, min_score=min_score, category_filter=category)
    return JsonResponse(graph.to_dict())
