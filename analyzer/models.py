"""
Django Models for IL2CPP Game Data & Offset Analyzer.
Relational representation of projects, assemblies, classes, fields, methods,
normalized address records, categories, rules, and background analysis jobs.
"""

from django.db import models
from django.utils import timezone
from django.conf import settings
from pathlib import Path
import json

class ProjectStatus(models.TextChoices):
    UPLOADED = "UPLOADED", "Uploaded"
    DETECTING = "DETECTING", "Detecting"
    PARSING = "PARSING", "Parsing"
    INDEXING = "INDEXING", "Indexing"
    ANALYZING = "ANALYZING", "Analyzing"
    COMPLETE = "COMPLETE", "Complete"
    FAILED = "FAILED", "Failed"


class AddressTypeChoices(models.TextChoices):
    FIELD_OFFSET = "FIELD_OFFSET", "Field Offset"
    METHOD_RVA = "METHOD_RVA", "Method RVA"
    VIRTUAL_ADDRESS = "VIRTUAL_ADDRESS", "Virtual Address"
    FILE_OFFSET = "FILE_OFFSET", "File Offset"
    STATIC_ADDRESS = "STATIC_ADDRESS", "Static Address"
    POINTER = "POINTER", "Pointer"
    UNKNOWN = "UNKNOWN", "Unknown"


class ConfidenceChoices(models.TextChoices):
    HIGH = "HIGH", "High"
    MEDIUM = "MEDIUM", "Medium"
    LOW = "LOW", "Low"


class ContextTypeChoices(models.TextChoices):
    STATE = "STATE", "State"
    DATA = "DATA", "Data"
    UI = "UI", "UI"
    VISUAL = "VISUAL", "Visual"
    AUDIO = "AUDIO", "Audio"
    ANIMATION = "ANIMATION", "Animation"
    NETWORK = "NETWORK", "Network"


class Project(models.Model):
    name = models.CharField(max_length=255, db_index=True)
    description = models.TextField(blank=True, default="")
    source_type = models.CharField(max_length=50, default="UNKNOWN")  # BINARY_DAT, DUMP_CS, JSON, APK, ZIP
    package_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    app_version = models.CharField(max_length=100, blank=True, default="")
    engine_type = models.CharField(max_length=100, default="Unity (IL2CPP)")
    target_sdk = models.CharField(max_length=50, blank=True, default="")
    is_apk = models.BooleanField(default=False)
    platform = models.CharField(max_length=50, default="UNKNOWN", db_index=True)  # Android, Windows, Linux
    architecture = models.CharField(max_length=50, default="UNKNOWN", db_index=True)  # ARM64, ARMv7, x86, x64
    unity_version = models.CharField(max_length=100, default="UNKNOWN")
    metadata_version = models.CharField(max_length=50, blank=True, null=True)
    binary_name = models.CharField(max_length=255, default="libil2cpp.so")
    status = models.CharField(
        max_length=50,
        choices=ProjectStatus.choices,
        default=ProjectStatus.UPLOADED,
        db_index=True
    )
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Statistics counters
    classes_count = models.IntegerField(default=0)
    methods_count = models.IntegerField(default=0)
    fields_count = models.IntegerField(default=0)
    properties_count = models.IntegerField(default=0)
    enums_count = models.IntegerField(default=0)
    warnings_count = models.IntegerField(default=0)
    errors_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['name', 'status']),
            models.Index(fields=['platform', 'architecture']),
        ]

    def __str__(self):
        return f"{self.name} ({self.platform}/{self.architecture}) [{self.status}]"

    def get_storage_path(self) -> Path:
        return settings.MEDIA_ROOT / "projects" / f"proj_{self.id}"


class Assembly(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="assemblies")
    name = models.CharField(max_length=255, db_index=True)
    token = models.IntegerField(null=True, blank=True)
    class_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['name']
        unique_together = ('project', 'name')

    def __str__(self):
        return f"{self.name} ({self.class_count} types)"


class Namespace(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="namespaces")
    name = models.CharField(max_length=255, db_index=True, blank=True)

    class Meta:
        ordering = ['name']
        unique_together = ('project', 'name')

    def __str__(self):
        return self.name or "<Global>"


class ClassDefinition(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="classes")
    assembly = models.ForeignKey(Assembly, on_delete=models.CASCADE, related_name="classes", null=True, blank=True)
    namespace = models.CharField(max_length=255, blank=True, default="", db_index=True)
    name = models.CharField(max_length=255, db_index=True)
    full_name = models.CharField(max_length=512, db_index=True)
    base_class_name = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    interfaces_json = models.JSONField(default=list, blank=True)

    is_value_type = models.BooleanField(default=False)
    is_enum = models.BooleanField(default=False)
    is_interface = models.BooleanField(default=False)
    is_abstract = models.BooleanField(default=False)
    type_token = models.IntegerField(null=True, blank=True)

    # Heuristic scoring
    importance_score = models.IntegerField(default=0, db_index=True)
    confidence = models.CharField(max_length=20, choices=ConfidenceChoices.choices, default=ConfidenceChoices.LOW)
    primary_category = models.CharField(max_length=50, default="GENERAL", db_index=True)
    context_type = models.CharField(max_length=20, choices=ContextTypeChoices.choices, default=ContextTypeChoices.STATE)

    class Meta:
        ordering = ['-importance_score', 'name']
        indexes = [
            models.Index(fields=['project', 'name']),
            models.Index(fields=['project', 'primary_category']),
            models.Index(fields=['project', 'importance_score']),
        ]

    def __str__(self):
        return self.full_name


class FieldDefinition(models.Model):
    class_def = models.ForeignKey(ClassDefinition, on_delete=models.CASCADE, related_name="fields")
    name = models.CharField(max_length=255, db_index=True)
    type_name = models.CharField(max_length=255, db_index=True)
    is_static = models.BooleanField(default=False, db_index=True)
    is_const = models.BooleanField(default=False)
    visibility = models.CharField(max_length=20, default="public")

    # Offset data
    offset_value = models.IntegerField(null=True, blank=True, db_index=True)
    offset_hex = models.CharField(max_length=32, blank=True, default="", db_index=True)

    # Heuristic scoring
    importance_score = models.IntegerField(default=0, db_index=True)
    confidence = models.CharField(max_length=20, choices=ConfidenceChoices.choices, default=ConfidenceChoices.LOW)
    primary_category = models.CharField(max_length=50, default="GENERAL", db_index=True)
    context_type = models.CharField(max_length=20, choices=ContextTypeChoices.choices, default=ContextTypeChoices.STATE)

    class Meta:
        ordering = ['offset_value', 'name']
        indexes = [
            models.Index(fields=['name', 'primary_category']),
            models.Index(fields=['offset_value', 'is_static']),
        ]

    def __str__(self):
        off = f" [{self.offset_hex}]" if self.offset_hex else ""
        return f"{self.class_def.name}.{self.name}{off}"


class MethodDefinition(models.Model):
    class_def = models.ForeignKey(ClassDefinition, on_delete=models.CASCADE, related_name="methods")
    name = models.CharField(max_length=255, db_index=True)
    return_type = models.CharField(max_length=255, default="void")
    signature = models.TextField(blank=True, default="")
    is_static = models.BooleanField(default=False)
    is_virtual = models.BooleanField(default=False)
    is_abstract = models.BooleanField(default=False)

    # Address data
    rva_value = models.BigIntegerField(null=True, blank=True, db_index=True)
    rva_hex = models.CharField(max_length=32, blank=True, default="", db_index=True)
    va_value = models.BigIntegerField(null=True, blank=True)
    va_hex = models.CharField(max_length=32, blank=True, default="")
    file_offset_value = models.BigIntegerField(null=True, blank=True)
    file_offset_hex = models.CharField(max_length=32, blank=True, default="")

    method_token = models.IntegerField(null=True, blank=True)

    # Heuristic scoring
    importance_score = models.IntegerField(default=0, db_index=True)
    confidence = models.CharField(max_length=20, choices=ConfidenceChoices.choices, default=ConfidenceChoices.LOW)
    primary_category = models.CharField(max_length=50, default="GENERAL", db_index=True)

    class Meta:
        ordering = ['-importance_score', 'name']
        indexes = [
            models.Index(fields=['name', 'primary_category']),
            models.Index(fields=['rva_value']),
        ]

    def __str__(self):
        rva = f" [{self.rva_hex}]" if self.rva_hex else ""
        return f"{self.class_def.name}.{self.name}(){rva}"


class ParameterDefinition(models.Model):
    method_def = models.ForeignKey(MethodDefinition, on_delete=models.CASCADE, related_name="parameters")
    name = models.CharField(max_length=255)
    type_name = models.CharField(max_length=255)
    position = models.IntegerField(default=0)
    default_value = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        ordering = ['position']

    def __str__(self):
        return f"{self.type_name} {self.name}"


class PropertyDefinition(models.Model):
    class_def = models.ForeignKey(ClassDefinition, on_delete=models.CASCADE, related_name="properties")
    name = models.CharField(max_length=255, db_index=True)
    type_name = models.CharField(max_length=255)
    getter_name = models.CharField(max_length=255, blank=True, null=True)
    setter_name = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.class_def.name}.{self.name} {{ get; set; }}"


class EnumDefinition(models.Model):
    class_def = models.OneToOneField(ClassDefinition, on_delete=models.CASCADE, related_name="enum_info")
    name = models.CharField(max_length=255)
    underlying_type = models.CharField(max_length=50, default="int")
    items_json = models.JSONField(default=list)

    def __str__(self):
        return f"enum {self.name}"


class AddressRecord(models.Model):
    """Normalized, strictly separated address ledger."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="address_records")
    field_def = models.ForeignKey(FieldDefinition, on_delete=models.SET_NULL, null=True, blank=True, related_name="address_records")
    method_def = models.ForeignKey(MethodDefinition, on_delete=models.SET_NULL, null=True, blank=True, related_name="address_records")

    object_type = models.CharField(max_length=50, default="FIELD")  # CLASS, FIELD, METHOD, STATIC_FIELD
    class_name = models.CharField(max_length=255, db_index=True)
    member_name = models.CharField(max_length=255, db_index=True)
    address_type = models.CharField(
        max_length=30,
        choices=AddressTypeChoices.choices,
        default=AddressTypeChoices.UNKNOWN,
        db_index=True
    )
    value_hex = models.CharField(max_length=32, db_index=True)
    value_int = models.BigIntegerField(db_index=True)
    architecture = models.CharField(max_length=50, default="UNKNOWN")
    source = models.CharField(max_length=255, default="Analysis")
    derivation = models.TextField(blank=True, default="")
    confidence = models.CharField(max_length=20, choices=ConfidenceChoices.choices, default=ConfidenceChoices.HIGH)
    verified = models.BooleanField(default=True)

    class Meta:
        ordering = ['address_type', 'class_name', 'value_int']
        indexes = [
            models.Index(fields=['project', 'address_type']),
            models.Index(fields=['class_name', 'member_name']),
            models.Index(fields=['value_int', 'address_type']),
        ]

    def __str__(self):
        return f"[{self.address_type}] {self.class_name}.{self.member_name} = {self.value_hex}"


class Category(models.Model):
    name = models.CharField(max_length=50, unique=True)
    slug = models.SlugField(max_length=50, unique=True)
    icon = models.CharField(max_length=50, default="tag")  # Bootstrap icon name
    description = models.TextField(blank=True, default="")
    color_code = models.CharField(max_length=20, default="#3b82f6")

    class Meta:
        verbose_name_plural = "Categories"
        ordering = ['name']

    def __str__(self):
        return self.name


class AnalysisResult(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="analysis_results")
    target_type = models.CharField(max_length=20)  # CLASS, FIELD, METHOD
    target_id = models.IntegerField()
    name = models.CharField(max_length=255, db_index=True)
    category = models.CharField(max_length=50, db_index=True)
    score = models.IntegerField(default=0, db_index=True)
    confidence = models.CharField(max_length=20, choices=ConfidenceChoices.choices)
    context_type = models.CharField(max_length=20, default="STATE")
    score_reasons_json = models.JSONField(default=list)

    class Meta:
        ordering = ['-score']
        indexes = [
            models.Index(fields=['project', 'category', 'score']),
        ]

    def __str__(self):
        return f"{self.target_type} {self.name} - Score: {self.score} ({self.confidence})"


class Rule(models.Model):
    category = models.CharField(max_length=50, db_index=True)
    keywords_json = models.JSONField(default=list)
    types_json = models.JSONField(default=list, blank=True)
    exclusions_json = models.JSONField(default=list, blank=True)
    weight = models.IntegerField(default=10)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Rule: {self.category} (Weight: {self.weight})"


class Profile(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, default="")
    config_json = models.JSONField(default=dict)
    is_builtin = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Relationship(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="relationships")
    source_class = models.CharField(max_length=255, db_index=True)
    target_class = models.CharField(max_length=255, db_index=True)
    relation_type = models.CharField(max_length=50)  # INHERITS, IMPLEMENTS, HAS_FIELD, RETURNS, ACCEPTS

    class Meta:
        indexes = [
            models.Index(fields=['project', 'source_class', 'target_class']),
        ]

    def __str__(self):
        return f"{self.source_class} --({self.relation_type})--> {self.target_class}"


class AnalysisJob(models.Model):
    project = models.OneToOneField(Project, on_delete=models.CASCADE, related_name="job")
    status = models.CharField(max_length=50, default="PENDING")
    current_step = models.IntegerField(default=0)
    step_description = models.CharField(max_length=255, default="Queued")
    progress_percent = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Job for {self.project.name}: Step {self.current_step}/10 ({self.progress_percent}%)"


class WarningRecord(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="warnings")
    category = models.CharField(max_length=50, default="GENERAL")
    message = models.TextField()
    target_object = models.CharField(max_length=255, blank=True, default="")
    severity = models.CharField(max_length=20, default="WARNING")  # INFO, WARNING, ERROR
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.category}: {self.message[:60]}"
