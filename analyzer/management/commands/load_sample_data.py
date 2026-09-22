"""
Management command to populate an artificial, synthetic IL2CPP analysis project.
Contains synthetic classes, fields, methods, and verified address records clearly labeled as:
SYNTHETIC TEST DATA.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from analyzer.models import (
    Project, Assembly, Namespace, ClassDefinition, FieldDefinition,
    MethodDefinition, ParameterDefinition, AddressRecord, WarningRecord
)

class Command(BaseCommand):
    help = "Populate an artificial sample IL2CPP project for research and automated testing."

    def handle(self, *args, **options):
        self.stdout.write("Generating synthetic sample project (SYNTHETIC TEST DATA)...")

        # Create or update synthetic project
        project, created = Project.objects.get_or_create(
            name="Synthetic_IL2CPP_Sample_v1.0",
            defaults={
                "description": "SYNTHETIC TEST DATA: Artificial reference project demonstrating verified field offsets, method RVAs, and semantic gameplay scoring.",
                "source_type": "SYNTHETIC DUMP",
                "platform": "Android",
                "architecture": "ARM64",
                "binary_name": "libil2cpp.so",
                "unity_version": "Unity 2021.3.18f1",
                "metadata_version": "29",
                "status": "COMPLETE",
                "completed_at": timezone.now()
            }
        )

        if not created:
            self.stdout.write("Existing sample project found. Refreshing entities...")
            project.classes.all().delete()
            project.address_records.all().delete()

        asm, _ = Assembly.objects.get_or_create(project=project, name="Assembly-CSharp.dll", defaults={"class_count": 7})
        ns_game, _ = Namespace.objects.get_or_create(project=project, name="Game.Core")
        ns_battle, _ = Namespace.objects.get_or_create(project=project, name="Game.Battle")

        # 1. SamplePlayer
        c_player = ClassDefinition.objects.create(
            project=project, assembly=asm, namespace=ns_game.name,
            name="SamplePlayer", full_name="Game.Core.SamplePlayer",
            base_class_name="UnityEngine.MonoBehaviour",
            importance_score=92, confidence="HIGH", primary_category="PLAYER", context_type="STATE"
        )
        f_p_id = FieldDefinition.objects.create(
            class_def=c_player, name="playerId", type_name="string",
            offset_value=0x18, offset_hex="0x18", importance_score=80,
            confidence="HIGH", primary_category="PLAYER", context_type="DATA"
        )
        f_p_lvl = FieldDefinition.objects.create(
            class_def=c_player, name="playerLevel", type_name="int",
            offset_value=0x20, offset_hex="0x20", importance_score=94,
            confidence="HIGH", primary_category="LEVEL", context_type="STATE"
        )
        m_p_init = MethodDefinition.objects.create(
            class_def=c_player, name="InitializePlayer", return_type="void",
            signature="public void InitializePlayer(string id, int lvl)",
            rva_value=0x00100000, rva_hex="0x00100000",
            importance_score=85, confidence="HIGH", primary_category="PLAYER"
        )

        # 2. SamplePlayerStats
        c_stats = ClassDefinition.objects.create(
            project=project, assembly=asm, namespace=ns_game.name,
            name="SamplePlayerStats", full_name="Game.Core.SamplePlayerStats",
            base_class_name="UnityEngine.MonoBehaviour",
            importance_score=96, confidence="HIGH", primary_category="HEALTH", context_type="STATE"
        )
        f_hp = FieldDefinition.objects.create(
            class_def=c_stats, name="currentHealth", type_name="float",
            offset_value=0x120, offset_hex="0x120", importance_score=98,
            confidence="HIGH", primary_category="HEALTH", context_type="STATE"
        )
        f_maxhp = FieldDefinition.objects.create(
            class_def=c_stats, name="maxHealth", type_name="float",
            offset_value=0x124, offset_hex="0x124", importance_score=95,
            confidence="HIGH", primary_category="HEALTH", context_type="STATE"
        )
        f_atk = FieldDefinition.objects.create(
            class_def=c_stats, name="attackPower", type_name="int",
            offset_value=0x128, offset_hex="0x128", importance_score=94,
            confidence="HIGH", primary_category="DAMAGE", context_type="STATE"
        )
        m_dmg = MethodDefinition.objects.create(
            class_def=c_stats, name="ApplyDamage", return_type="void",
            signature="public void ApplyDamage(float amount)",
            rva_value=0x00105000, rva_hex="0x00105000",
            importance_score=96, confidence="HIGH", primary_category="DAMAGE"
        )

        # 3. SampleCreature
        c_creature = ClassDefinition.objects.create(
            project=project, assembly=asm, namespace=ns_game.name,
            name="SampleCreature", full_name="Game.Core.SampleCreature",
            base_class_name="UnityEngine.MonoBehaviour",
            importance_score=90, confidence="HIGH", primary_category="CREATURE", context_type="STATE"
        )
        f_c_id = FieldDefinition.objects.create(
            class_def=c_creature, name="creatureSpeciesId", type_name="int",
            offset_value=0x10, offset_hex="0x10", importance_score=88,
            confidence="HIGH", primary_category="CREATURE", context_type="DATA"
        )
        f_c_exp = FieldDefinition.objects.create(
            class_def=c_creature, name="experiencePoints", type_name="long",
            offset_value=0x18, offset_hex="0x18", importance_score=92,
            confidence="HIGH", primary_category="XP", context_type="STATE"
        )

        # 4. SampleBattleManager
        c_battle = ClassDefinition.objects.create(
            project=project, assembly=asm, namespace=ns_battle.name,
            name="SampleBattleManager", full_name="Game.Battle.SampleBattleManager",
            base_class_name="UnityEngine.MonoBehaviour",
            importance_score=95, confidence="HIGH", primary_category="COMBAT", context_type="STATE"
        )
        m_calc = MethodDefinition.objects.create(
            class_def=c_battle, name="CalculateDamage", return_type="float",
            signature="public float CalculateDamage(int attackerAtk, int defenderDef)",
            rva_value=0x00123456, rva_hex="0x00123456",
            importance_score=94, confidence="HIGH", primary_category="COMBAT"
        )
        m_win = MethodDefinition.objects.create(
            class_def=c_battle, name="ResolveVictory", return_type="bool",
            signature="public bool ResolveVictory(int winnerTeam)",
            rva_value=0x00123800, rva_hex="0x00123800",
            importance_score=91, confidence="HIGH", primary_category="COMBAT"
        )

        # 5. SampleInventory
        c_inv = ClassDefinition.objects.create(
            project=project, assembly=asm, namespace=ns_game.name,
            name="SampleInventory", full_name="Game.Core.SampleInventory",
            importance_score=88, confidence="HIGH", primary_category="INVENTORY", context_type="DATA"
        )
        f_gold = FieldDefinition.objects.create(
            class_def=c_inv, name="goldCoins", type_name="int",
            offset_value=0x30, offset_hex="0x30", importance_score=97,
            confidence="HIGH", primary_category="CURRENCY", context_type="STATE"
        )
        f_gems = FieldDefinition.objects.create(
            class_def=c_inv, name="diamondGems", type_name="int",
            offset_value=0x34, offset_hex="0x34", importance_score=97,
            confidence="HIGH", primary_category="CURRENCY", context_type="STATE"
        )

        # 6. SampleRewardManager
        c_reward = ClassDefinition.objects.create(
            project=project, assembly=asm, namespace=ns_game.name,
            name="SampleRewardManager", full_name="Game.Core.SampleRewardManager",
            importance_score=86, confidence="HIGH", primary_category="REWARDS", context_type="STATE"
        )

        # 7. SampleArenaManager
        c_arena = ClassDefinition.objects.create(
            project=project, assembly=asm, namespace=ns_battle.name,
            name="SampleArenaManager", full_name="Game.Battle.SampleArenaManager",
            importance_score=89, confidence="HIGH", primary_category="ARENA", context_type="STATE"
        )
        f_rank = FieldDefinition.objects.create(
            class_def=c_arena, name="arenaRankPoints", type_name="int",
            offset_value=0x40, offset_hex="0x40", importance_score=93,
            confidence="HIGH", primary_category="ARENA", context_type="STATE"
        )

        # Address Records (Strictly verified and labeled as SYNTHETIC TEST DATA)
        test_source = "SYNTHETIC TEST DATA (Sample Fixture)"
        addrs = [
            (f_p_id, "FIELD_OFFSET", 0x18, "0x18", "FIELD"),
            (f_p_lvl, "FIELD_OFFSET", 0x20, "0x20", "FIELD"),
            (f_hp, "FIELD_OFFSET", 0x120, "0x120", "FIELD"),
            (f_maxhp, "FIELD_OFFSET", 0x124, "0x124", "FIELD"),
            (f_atk, "FIELD_OFFSET", 0x128, "0x128", "FIELD"),
            (f_c_id, "FIELD_OFFSET", 0x10, "0x10", "FIELD"),
            (f_c_exp, "FIELD_OFFSET", 0x18, "0x18", "FIELD"),
            (f_gold, "FIELD_OFFSET", 0x30, "0x30", "FIELD"),
            (f_gems, "FIELD_OFFSET", 0x34, "0x34", "FIELD"),
            (f_rank, "FIELD_OFFSET", 0x40, "0x40", "FIELD"),
        ]

        for f_obj, a_type, v_int, v_hex, obj_type in addrs:
            AddressRecord.objects.create(
                project=project, field_def=f_obj, object_type=obj_type,
                class_name=f_obj.class_def.name, member_name=f_obj.name,
                address_type=a_type, value_int=v_int, value_hex=v_hex,
                architecture="ARM64", source=test_source,
                derivation="SYNTHETIC TEST DATA: Object instance byte offset",
                confidence="HIGH", verified=True
            )

        method_addrs = [
            (m_p_init, 0x00100000, "0x00100000"),
            (m_dmg, 0x00105000, "0x00105000"),
            (m_calc, 0x00123456, "0x00123456"),
            (m_win, 0x00123800, "0x00123800"),
        ]

        for m_obj, v_int, v_hex in method_addrs:
            AddressRecord.objects.create(
                project=project, method_def=m_obj, object_type="METHOD",
                class_name=m_obj.class_def.name, member_name=m_obj.name,
                address_type="METHOD_RVA", value_int=v_int, value_hex=v_hex,
                architecture="ARM64", source=test_source,
                derivation="SYNTHETIC TEST DATA: Relative Virtual Address (RVA = VA - ImageBase)",
                confidence="HIGH", verified=True
            )

        # Update summary counts
        project.classes_count = project.classes.count()
        project.methods_count = MethodDefinition.objects.filter(class_def__project=project).count()
        project.fields_count = FieldDefinition.objects.filter(class_def__project=project).count()
        project.save()

        self.stdout.write(self.style.SUCCESS(
            f"Successfully loaded '{project.name}' (ID: {project.id}) with "
            f"{project.classes_count} classes, {project.fields_count} fields, "
            f"{project.methods_count} methods, and {project.address_records.count()} address records."
        ))
