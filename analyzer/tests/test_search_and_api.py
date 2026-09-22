from django.test import TestCase, Client
from django.urls import reverse
from analyzer.models import Project, ClassDefinition, FieldDefinition, AddressRecord
from analyzer.services.search_engine import SearchEngine

class SearchAndApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(
            name="TestProject",
            platform="Android",
            architecture="ARM64",
            status="COMPLETE"
        )
        self.cls = ClassDefinition.objects.create(
            project=self.project,
            name="BattleManager",
            namespace="Game.Battle",
            full_name="Game.Battle.BattleManager",
            primary_category="COMBAT",
            importance_score=90,
            confidence="HIGH"
        )
        self.fld = FieldDefinition.objects.create(
            class_def=self.cls,
            name="currentDamage",
            type_name="float",
            offset_value=0x20,
            offset_hex="0x20",
            primary_category="DAMAGE",
            importance_score=88,
            confidence="HIGH"
        )
        self.addr = AddressRecord.objects.create(
            project=self.project,
            field_def=self.fld,
            class_name="BattleManager",
            member_name="currentDamage",
            address_type="FIELD_OFFSET",
            value_int=0x20,
            value_hex="0x20",
            architecture="ARM64"
        )

    def test_search_engine_results(self):
        res = SearchEngine.search(self.project.id, "damage")
        self.assertGreaterEqual(res.total_count, 1)
        self.assertTrue(any(f["name"] == "currentDamage" for f in res.fields.items))

    def test_api_projects_endpoint(self):
        resp = self.client.get(reverse('api_projects'))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(len(data.get("projects", [])) >= 1)

    def test_api_search_endpoint(self):
        resp = self.client.get(f"{reverse('api_search')}?q=Battle")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("results", data)

    def test_search_view_url_reversals(self):
        self.assertEqual(reverse('global_search'), '/search/')
        self.assertEqual(reverse('search_view'), '/search-view/')

    def test_dashboard_with_active_project_renders_ok(self):
        resp = self.client.get(f"/?project_id={self.project.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "BattleManager")

