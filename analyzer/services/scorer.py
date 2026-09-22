"""
Smart Scoring & Confidence Engine.
Calculates transparent 0-100 heuristic scores with itemized mathematical explanations.
Evaluates independent confidence levels (HIGH, MEDIUM, LOW) based on structural verification.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from .semantic_analyzer import SemanticAnalyzer, SemanticMatch

NUMERIC_TYPES = {
    "int", "int32", "system.int32", "uint", "uint32", "system.uint32",
    "long", "int64", "system.int64", "ulong", "uint64",
    "float", "single", "system.single", "double", "system.double",
    "bool", "boolean", "system.boolean", "byte", "sbyte", "short", "int16"
}

@dataclass
class ScoreBreakdown:
    total_score: int
    confidence: str  # HIGH, MEDIUM, LOW
    reasons: List[str] = field(default_factory=list)
    primary_category: Optional[str] = None
    context_type: str = "STATE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_score": self.total_score,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "primary_category": self.primary_category,
            "context_type": self.context_type
        }


class SmartScorer:
    """Computes transparent scores and confidence metrics."""

    def __init__(self, semantic_analyzer: Optional[SemanticAnalyzer] = None):
        self.analyzer = semantic_analyzer or SemanticAnalyzer()

    def score_field(
        self,
        field_name: str,
        field_type: str,
        class_name: str,
        namespace: str = "",
        has_offset: bool = False,
        sibling_field_names: Optional[List[str]] = None
    ) -> ScoreBreakdown:
        score = 0
        reasons: List[str] = []
        sibling_field_names = sibling_field_names or []

        # 1. Semantic Analysis on Field Name
        f_match = self.analyzer.analyze_identifier(field_name)
        c_match = self.analyzer.analyze_identifier(class_name)

        primary_cat = f_match.primary_category or c_match.primary_category
        context_type = f_match.context_type

        # Keyword & Synonym Hits
        if f_match.keyword_hits:
            score += 25
            reasons.append(f"+25 exact keyword match ({', '.join(f_match.keyword_hits[:2])})")
        elif f_match.synonym_hits:
            score += 15
            reasons.append(f"+15 synonym match ({', '.join(f_match.synonym_hits[:2])})")

        # 2. Type Relevance
        clean_type = field_type.lower().strip()
        if clean_type in NUMERIC_TYPES:
            score += 20
            reasons.append(f"+20 numeric game-state type ({clean_type})")
        elif "list" in clean_type or "dictionary" in clean_type or "[]" in clean_type:
            score += 10
            reasons.append(f"+10 collection type ({field_type})")

        # 3. Class Name Relevance
        if c_match.matched_categories:
            score += 18
            reasons.append(f"+18 relevant class context ({class_name})")

        # 4. Sibling Relationship (e.g. maxHealth next to currentHealth)
        f_tokens = [t.lower() for t in self.analyzer.tokenize(field_name)]
        if "current" in f_tokens or "cur" in f_tokens:
            expected_counterpart = [s for s in sibling_field_names if "max" in s.lower()]
            if expected_counterpart:
                score += 15
                reasons.append(f"+15 related counterpart field detected ({expected_counterpart[0]})")
        elif "max" in f_tokens:
            expected_counterpart = [s for s in sibling_field_names if "current" in s.lower() or "cur" in s.lower()]
            if expected_counterpart:
                score += 15
                reasons.append(f"+15 related current-state field detected ({expected_counterpart[0]})")

        # 5. Namespace Relevance
        if namespace:
            ns_match = self.analyzer.analyze_identifier(namespace)
            if ns_match.matched_categories:
                score += 10
                reasons.append(f"+10 relevant namespace ({namespace})")

        # 6. False-Positive Penalty (UI, VFX, Audio)
        if f_match.is_ui_or_visual or c_match.is_ui_or_visual:
            score -= 30
            context_type = f_match.context_type if f_match.is_ui_or_visual else c_match.context_type
            reasons.append(f"-30 false-positive reduction ({context_type} context)")

        # Clamp Score 0 - 100
        score = max(0, min(100, score))

        # Confidence Calculation (Independent from Score)
        # HIGH: Structural offset present + valid type + non-UI
        # MEDIUM: Strong semantic match but offset unresolved OR slight ambiguity
        # LOW: Substring match only or UI context
        if has_offset and not f_match.is_ui_or_visual and (f_match.keyword_hits or c_match.keyword_hits):
            confidence = "HIGH"
        elif f_match.keyword_hits or c_match.keyword_hits:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return ScoreBreakdown(
            total_score=score,
            confidence=confidence,
            reasons=reasons,
            primary_category=primary_cat,
            context_type=context_type
        )

    def score_method(
        self,
        method_name: str,
        return_type: str,
        class_name: str,
        has_rva: bool = False,
        param_types: Optional[List[str]] = None
    ) -> ScoreBreakdown:
        score = 0
        reasons: List[str] = []
        param_types = param_types or []

        m_match = self.analyzer.analyze_identifier(method_name)
        c_match = self.analyzer.analyze_identifier(class_name)

        primary_cat = m_match.primary_category or c_match.primary_category
        context_type = m_match.context_type

        # Keyword match
        if m_match.keyword_hits:
            score += 25
            reasons.append(f"+25 method keyword match ({', '.join(m_match.keyword_hits[:2])})")
        elif m_match.synonym_hits:
            score += 15
            reasons.append(f"+15 method synonym match ({', '.join(m_match.synonym_hits[:2])})")

        # Class relevance
        if c_match.matched_categories:
            score += 18
            reasons.append(f"+18 relevant class context ({class_name})")

        # Return / Parameter types
        if return_type.lower() in NUMERIC_TYPES:
            score += 15
            reasons.append(f"+15 numeric return type ({return_type})")

        for p_t in param_types:
            if p_t.lower() in NUMERIC_TYPES:
                score += 10
                reasons.append(f"+10 numeric parameter ({p_t})")
                break

        # False-positive reduction
        if m_match.is_ui_or_visual or c_match.is_ui_or_visual:
            score -= 30
            context_type = m_match.context_type if m_match.is_ui_or_visual else c_match.context_type
            reasons.append(f"-30 false-positive reduction ({context_type} context)")

        score = max(0, min(100, score))

        if has_rva and not m_match.is_ui_or_visual and (m_match.keyword_hits or c_match.keyword_hits):
            confidence = "HIGH"
        elif m_match.keyword_hits or c_match.keyword_hits:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return ScoreBreakdown(
            total_score=score,
            confidence=confidence,
            reasons=reasons,
            primary_category=primary_cat,
            context_type=context_type
        )

    def score_class(
        self,
        class_name: str,
        namespace: str = "",
        field_count: int = 0,
        method_count: int = 0
    ) -> ScoreBreakdown:
        score = 0
        reasons: List[str] = []

        c_match = self.analyzer.analyze_identifier(class_name)
        primary_cat = c_match.primary_category
        context_type = c_match.context_type

        if c_match.keyword_hits:
            score += 35
            reasons.append(f"+35 class name keyword match ({', '.join(c_match.keyword_hits[:2])})")
        elif c_match.synonym_hits:
            score += 20
            reasons.append(f"+20 class name synonym match ({', '.join(c_match.synonym_hits[:2])})")

        if field_count > 0:
            score += min(20, field_count * 2)
            reasons.append(f"+{min(20, field_count * 2)} member density ({field_count} fields)")

        if namespace:
            ns_match = self.analyzer.analyze_identifier(namespace)
            if ns_match.matched_categories:
                score += 15
                reasons.append(f"+15 game namespace ({namespace})")

        if c_match.is_ui_or_visual:
            score -= 30
            reasons.append(f"-30 false-positive reduction ({context_type} context)")

        score = max(0, min(100, score))
        confidence = "HIGH" if (field_count > 0 and c_match.keyword_hits and not c_match.is_ui_or_visual) else ("MEDIUM" if c_match.keyword_hits else "LOW")

        return ScoreBreakdown(
            total_score=score,
            confidence=confidence,
            reasons=reasons,
            primary_category=primary_cat,
            context_type=context_type
        )
