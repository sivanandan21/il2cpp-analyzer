"""
URL Configuration for analyzer app.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Dashboard & Projects
    path('', views.dashboard, name='dashboard'),
    path('projects/', views.project_list, name='project_list'),
    path('projects/<int:project_id>/', views.project_detail, name='project_detail'),
    path('projects/<int:project_id>/status/', views.project_status_api, name='project_status_api'),
    path('projects/<int:project_id>/delete/', views.project_delete, name='project_delete'),
    path('upload/', views.upload_view, name='upload'),

    # Explorers
    path('classes/', views.class_list, name='class_list'),
    path('classes/<int:class_id>/', views.class_detail, name='class_detail'),
    path('fields/', views.field_list, name='field_list'),
    path('fields/<int:field_id>/', views.field_detail, name='field_detail'),
    path('methods/', views.method_list, name='method_list'),
    path('methods/<int:method_id>/', views.method_detail, name='method_detail'),

    # Address & Offset Center
    path('offsets/', views.offset_center, name='offset_center'),
    path('offsets/important/', views.important_offsets, name='important_offsets'),
    path('offsets/<int:offset_id>/', views.offset_detail, name='offset_detail'),
    path('static-data/', views.static_data_view, name='static_data_view'),

    # Categories & Search
    path('categories/', views.category_dashboard, name='category_dashboard'),
    path('categories/<str:category_name>/', views.category_detail, name='category_detail'),
    path('search/', views.global_search_view, name='global_search'),

    # Graph, Dump Viewer, Comparison, Rules & Reports
    path('graph/', views.graph_view, name='graph_view'),
    path('dump/', views.dump_viewer, name='dump_viewer'),
    path('compare/', views.project_compare, name='project_compare'),
    path('rules/', views.rule_list, name='rule_list'),
    path('rules/<int:rule_id>/delete/', views.rule_delete, name='rule_delete'),
    path('reports/', views.reports_view, name='reports_view'),
    path('reports/<int:project_id>/<str:filename>/', views.download_report, name='download_report'),

    # REST APIs
    path('api/projects/', views.api_projects, name='api_projects'),
    path('api/projects/<int:project_id>/', views.api_project_detail, name='api_project_detail'),
    path('api/classes/', views.api_classes, name='api_classes'),
    path('api/classes/<int:class_id>/', views.api_class_detail, name='api_class_detail'),
    path('api/fields/', views.api_fields, name='api_fields'),
    path('api/methods/', views.api_methods, name='api_methods'),
    path('api/offsets/', views.api_offsets, name='api_offsets'),
    path('api/search/', views.api_search, name='api_search'),
    path('api/graph/', views.api_graph, name='api_graph'),
]
