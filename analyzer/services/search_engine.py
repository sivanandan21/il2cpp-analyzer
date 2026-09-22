"""
Global Search Engine.
Provides instant multi-table searching across classes, fields, methods,
properties, enums, offsets, and RVAs with category aggregations.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

@dataclass
class SearchResultGroup:
    total_matches: int = 0
    items: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class GlobalSearchResults:
    query: str
    total_count: int = 0
    classes: SearchResultGroup = field(default_factory=SearchResultGroup)
    fields: SearchResultGroup = field(default_factory=SearchResultGroup)
    methods: SearchResultGroup = field(default_factory=SearchResultGroup)
    properties: SearchResultGroup = field(default_factory=SearchResultGroup)
    offsets: SearchResultGroup = field(default_factory=SearchResultGroup)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "total_count": self.total_count,
            "counts": {
                "classes": self.classes.total_matches,
                "fields": self.fields.total_matches,
                "methods": self.methods.total_matches,
                "properties": self.properties.total_matches,
                "offsets": self.offsets.total_matches,
            },
            "results": {
                "classes": self.classes.items,
                "fields": self.fields.items,
                "methods": self.methods.items,
                "properties": self.properties.items,
                "offsets": self.offsets.items,
            }
        }


class SearchEngine:
    """Fast ORM-backed query executor."""

    @classmethod
    def search(cls, project_id: int, query: str, limit_per_type: int = 25) -> GlobalSearchResults:
        from analyzer.models import (
            ClassDefinition, FieldDefinition, MethodDefinition,
            PropertyDefinition, AddressRecord
        )
        from django.db.models import Q

        res = GlobalSearchResults(query=query)
        q = query.strip()
        if not q:
            return res

        # 1. Search Classes
        cls_qs = ClassDefinition.objects.filter(
            project_id=project_id
        ).filter(
            Q(name__icontains=q) |
            Q(namespace__icontains=q) |
            Q(primary_category__icontains=q)
        ).order_by('-importance_score')

        res.classes.total_matches = cls_qs.count()
        for c in cls_qs[:limit_per_type]:
            res.classes.items.append({
                "id": c.id,
                "name": c.name,
                "namespace": c.namespace,
                "full_name": c.full_name,
                "category": c.primary_category,
                "score": c.importance_score,
                "confidence": c.confidence,
                "url": f"/classes/{c.id}/"
            })

        # 2. Search Fields
        fld_qs = FieldDefinition.objects.filter(
            class_def__project_id=project_id
        ).filter(
            Q(name__icontains=q) |
            Q(type_name__icontains=q) |
            Q(primary_category__icontains=q) |
            Q(offset_hex__icontains=q)
        ).select_related('class_def').order_by('-importance_score')

        res.fields.total_matches = fld_qs.count()
        for f in fld_qs[:limit_per_type]:
            res.fields.items.append({
                "id": f.id,
                "name": f.name,
                "class_name": f.class_def.name,
                "type_name": f.type_name,
                "offset_hex": f.offset_hex,
                "category": f.primary_category,
                "score": f.importance_score,
                "confidence": f.confidence,
                "url": f"/fields/{f.id}/"
            })

        # 3. Search Methods
        mth_qs = MethodDefinition.objects.filter(
            class_def__project_id=project_id
        ).filter(
            Q(name__icontains=q) |
            Q(signature__icontains=q) |
            Q(primary_category__icontains=q) |
            Q(rva_hex__icontains=q)
        ).select_related('class_def').order_by('-importance_score')

        res.methods.total_matches = mth_qs.count()
        for m in mth_qs[:limit_per_type]:
            res.methods.items.append({
                "id": m.id,
                "name": m.name,
                "class_name": m.class_def.name,
                "return_type": m.return_type,
                "rva_hex": m.rva_hex,
                "category": m.primary_category,
                "score": m.importance_score,
                "confidence": m.confidence,
                "url": f"/methods/{m.id}/"
            })

        # 4. Search Properties
        prp_qs = PropertyDefinition.objects.filter(
            class_def__project_id=project_id
        ).filter(
            Q(name__icontains=q) |
            Q(type_name__icontains=q)
        ).select_related('class_def')

        res.properties.total_matches = prp_qs.count()
        for p in prp_qs[:limit_per_type]:
            res.properties.items.append({
                "id": p.id,
                "name": p.name,
                "class_name": p.class_def.name,
                "type_name": p.type_name,
                "url": f"/classes/{p.class_def.id}/"
            })

        # 5. Search Addresses / Offsets
        addr_qs = AddressRecord.objects.filter(
            project_id=project_id
        ).filter(
            Q(member_name__icontains=q) |
            Q(class_name__icontains=q) |
            Q(value_hex__icontains=q) |
            Q(address_type__icontains=q)
        ).order_by('address_type', 'value_int')

        res.offsets.total_matches = addr_qs.count()
        for a in addr_qs[:limit_per_type]:
            res.offsets.items.append({
                "id": a.id,
                "class_name": a.class_name,
                "member_name": a.member_name,
                "address_type": a.address_type,
                "value_hex": a.value_hex,
                "confidence": a.confidence,
                "url": f"/offsets/{a.id}/"
            })

        res.total_count = (
            res.classes.total_matches +
            res.fields.total_matches +
            res.methods.total_matches +
            res.properties.total_matches +
            res.offsets.total_matches
        )

        return res
