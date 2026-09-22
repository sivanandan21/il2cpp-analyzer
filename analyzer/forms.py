"""
Django Forms for file upload, rule management, and project comparison.
"""

from django import forms
from .models import Project, Rule, Profile

class ProjectUploadForm(forms.ModelForm):
    file = forms.FileField(
        label="Select IL2CPP File or Archive",
        help_text="Supports .apk, .zip, global-metadata.dat, dump.cs, libil2cpp.so, GameAssembly.dll, .json, .csv",
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'id': 'fileUploadInput',
            'accept': '.apk,.zip,.dat,.so,.dll,.cs,.json,.csv'
        })
    )
    profile = forms.ModelChoiceField(
        queryset=Profile.objects.all(),
        required=False,
        empty_label="Generic IL2CPP (Default)",
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    class Meta:
        model = Project
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. MyGame_v1.0_Arm64'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 2, 'placeholder': 'Optional analysis notes...'}),
        }


class RuleForm(forms.ModelForm):
    keywords_text = forms.CharField(
        label="Keywords (comma-separated)",
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'health, hp, hitpoint, life'}),
        required=False
    )
    types_text = forms.CharField(
        label="Relevant Types (comma-separated)",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'int, float, double'}),
        required=False
    )

    class Meta:
        model = Rule
        fields = ['category', 'weight', 'is_active']
        widgets = {
            'category': forms.TextInput(attrs={'class': 'form-control'}),
            'weight': forms.NumberInput(attrs={'class': 'form-control'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }


class ProjectCompareForm(forms.Form):
    project_a = forms.ModelChoiceField(
        queryset=Project.objects.filter(status='COMPLETE'),
        label="Base Build (Project A)",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    project_b = forms.ModelChoiceField(
        queryset=Project.objects.filter(status='COMPLETE'),
        label="Target Build (Project B)",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
