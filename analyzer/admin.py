from django.contrib import admin
from .models import (
    Project, Assembly, Namespace, ClassDefinition, FieldDefinition,
    MethodDefinition, ParameterDefinition, PropertyDefinition, EnumDefinition,
    AddressRecord, Category, AnalysisResult, Rule, Profile, Relationship,
    AnalysisJob, WarningRecord
)

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'platform', 'architecture', 'status', 'classes_count', 'methods_count', 'fields_count', 'created_at')
    list_filter = ('platform', 'architecture', 'status')
    search_fields = ('name', 'description')

@admin.register(ClassDefinition)
class ClassDefinitionAdmin(admin.ModelAdmin):
    list_display = ('name', 'namespace', 'primary_category', 'importance_score', 'confidence', 'context_type')
    list_filter = ('primary_category', 'confidence', 'context_type', 'is_value_type', 'is_enum')
    search_fields = ('name', 'full_name', 'namespace')

@admin.register(FieldDefinition)
class FieldDefinitionAdmin(admin.ModelAdmin):
    list_display = ('name', 'class_def', 'type_name', 'offset_hex', 'primary_category', 'importance_score', 'confidence')
    list_filter = ('primary_category', 'confidence', 'is_static')
    search_fields = ('name', 'type_name', 'class_def__name')

@admin.register(MethodDefinition)
class MethodDefinitionAdmin(admin.ModelAdmin):
    list_display = ('name', 'class_def', 'return_type', 'rva_hex', 'primary_category', 'importance_score', 'confidence')
    list_filter = ('primary_category', 'confidence', 'is_static')
    search_fields = ('name', 'signature', 'class_def__name')

@admin.register(AddressRecord)
class AddressRecordAdmin(admin.ModelAdmin):
    list_display = ('class_name', 'member_name', 'address_type', 'value_hex', 'architecture', 'confidence', 'verified')
    list_filter = ('address_type', 'confidence', 'verified', 'architecture')
    search_fields = ('class_name', 'member_name', 'value_hex')

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'color_code')
    prepopulated_fields = {'slug': ('name',)}

@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ('category', 'weight', 'is_active')
    list_filter = ('is_active',)

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_builtin')

@admin.register(WarningRecord)
class WarningRecordAdmin(admin.ModelAdmin):
    list_display = ('project', 'category', 'severity', 'message', 'created_at')
    list_filter = ('severity', 'category')
    search_fields = ('message', 'target_object')

admin.site.register(Assembly)
admin.site.register(Namespace)
admin.site.register(ParameterDefinition)
admin.site.register(PropertyDefinition)
admin.site.register(EnumDefinition)
admin.site.register(AnalysisResult)
admin.site.register(Relationship)
admin.site.register(AnalysisJob)
