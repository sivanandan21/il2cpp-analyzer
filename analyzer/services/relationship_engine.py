"""
Relationship Engine.
Discovers structural and semantic links between classes:
- Inheritance (is-a)
- Interface implementations
- Field type references (has-a)
- Method parameter & return type dependencies
- Member interaction density
Generates node-link graphs for visualization.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Any, Optional

@dataclass
class GraphNode:
    id: str
    label: str
    category: str = "DEFAULT"
    score: int = 0
    node_type: str = "CLASS"  # CLASS, METHOD, FIELD
    group: str = "General"
    url: str = ""

@dataclass
class GraphEdge:
    source: str
    target: str
    label: str  # INHERITS, IMPLEMENTS, HAS_FIELD, RETURNS, ACCEPTS, CALLS
    weight: int = 1

@dataclass
class NetworkGraph:
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "edges": self.edges
        }


class RelationshipEngine:
    """Builds and queries class relationship networks."""

    @classmethod
    def build_graph(
        cls,
        classes: List[Any],
        min_score: int = 0,
        category_filter: Optional[str] = None,
        max_nodes: int = 300
    ) -> NetworkGraph:
        """Constructs a filtered node-edge graph for rendering in JavaScript."""
        graph = NetworkGraph()
        node_ids: Set[str] = set()
        class_name_map: Dict[str, Any] = {}

        # First pass: Filter candidate classes
        candidates = []
        for c in classes:
            c_name = getattr(c, "name", "")
            c_score = getattr(c, "importance_score", 0)
            c_cat = getattr(c, "primary_category", "DEFAULT") or "DEFAULT"

            if c_score < min_score:
                continue
            if category_filter and category_filter.upper() != "ALL" and c_cat.upper() != category_filter.upper():
                continue

            candidates.append(c)
            class_name_map[c_name] = c

        # Sort by score and cap
        candidates = sorted(candidates, key=lambda x: getattr(x, "importance_score", 0), reverse=True)[:max_nodes]

        for c in candidates:
            c_name = getattr(c, "name", "")
            c_score = getattr(c, "importance_score", 0)
            c_cat = getattr(c, "primary_category", "DEFAULT") or "DEFAULT"
            c_id = f"class_{getattr(c, 'id', c_name)}"

            if c_id not in node_ids:
                node_ids.add(c_id)
                graph.nodes.append({
                    "id": c_id,
                    "label": c_name,
                    "type": "CLASS",
                    "category": c_cat,
                    "score": c_score,
                    "url": f"/classes/{getattr(c, 'id', '')}/" if hasattr(c, "id") else "#"
                })

        # Second pass: Build edges
        for c in candidates:
            c_id = f"class_{getattr(c, 'id', c.name)}"

            # 1. Base Class Edge
            base_name = getattr(c, "base_class_name", None)
            if base_name and base_name in class_name_map:
                target_obj = class_name_map[base_name]
                target_id = f"class_{getattr(target_obj, 'id', base_name)}"
                if target_id in node_ids:
                    graph.edges.append({
                        "source": c_id,
                        "target": target_id,
                        "label": "INHERITS",
                        "weight": 3
                    })

            # 2. Interfaces
            interfaces = getattr(c, "interfaces", []) or []
            if isinstance(interfaces, list):
                for iface in interfaces:
                    if iface in class_name_map:
                        target_obj = class_name_map[iface]
                        target_id = f"class_{getattr(target_obj, 'id', iface)}"
                        if target_id in node_ids:
                            graph.edges.append({
                                "source": c_id,
                                "target": target_id,
                                "label": "IMPLEMENTS",
                                "weight": 2
                            })

            # 3. Field Types
            fields = getattr(c, "fields", None)
            if fields:
                field_list = fields.all() if hasattr(fields, "all") else fields
                for fld in field_list:
                    f_type = getattr(fld, "type_name", "")
                    clean_type = f_type.replace("[]", "").replace("List<", "").replace(">", "").strip()
                    if clean_type in class_name_map and clean_type != c.name:
                        target_obj = class_name_map[clean_type]
                        target_id = f"class_{getattr(target_obj, 'id', clean_type)}"
                        if target_id in node_ids:
                            graph.edges.append({
                                "source": c_id,
                                "target": target_id,
                                "label": f"HAS_{getattr(fld, 'name', '')}",
                                "weight": 1
                            })

        return graph
