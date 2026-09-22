from django.test import TestCase
from analyzer.services.scorer import SmartScorer
from analyzer.services.semantic_analyzer import SemanticAnalyzer

class ScorerTests(TestCase):
    def setUp(self):
        self.scorer = SmartScorer()

    def test_gameplay_field_scores_high(self):
        """Ensure core gameplay fields receive high scores and HIGH confidence when offset is present."""
        res = self.scorer.score_field(
            field_name="currentHealth",
            field_type="float",
            class_name="PlayerStats",
            namespace="Game.Combat",
            has_offset=True,
            sibling_field_names=["maxHealth", "attackPower"]
        )
        self.assertGreaterEqual(res.total_score, 80)
        self.assertEqual(res.confidence, "HIGH")
        self.assertEqual(res.primary_category, "HEALTH")
        self.assertEqual(res.context_type, "STATE")
        self.assertTrue(any("+25" in r for r in res.reasons))

    def test_false_positive_reduction(self):
        """Ensure UI elements receive context penalties and score significantly lower than gameplay state."""
        # UI Element: HealthBar
        ui_res = self.scorer.score_field(
            field_name="healthBar",
            field_type="Slider",
            class_name="PlayerHUDView",
            namespace="Game.UI",
            has_offset=True
        )

        # State Element: currentHealth
        state_res = self.scorer.score_field(
            field_name="currentHealth",
            field_type="float",
            class_name="PlayerStats",
            namespace="Game.Combat",
            has_offset=True
        )

        self.assertEqual(ui_res.context_type, "UI")
        self.assertLess(ui_res.total_score, state_res.total_score)
        self.assertTrue(any("reduction" in r.lower() for r in ui_res.reasons))

    def test_confidence_independent_from_score(self):
        """Ensure confidence reflects structural evidence (e.g. missing offset lowers confidence)."""
        res_no_offset = self.scorer.score_field(
            field_name="currentHealth",
            field_type="float",
            class_name="PlayerStats",
            has_offset=False
        )
        self.assertEqual(res_no_offset.confidence, "MEDIUM")

        res_with_offset = self.scorer.score_field(
            field_name="currentHealth",
            field_type="float",
            class_name="PlayerStats",
            has_offset=True
        )
        self.assertEqual(res_with_offset.confidence, "HIGH")
