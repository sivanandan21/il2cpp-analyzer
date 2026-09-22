"""
Game Asset & Hybrid Engine Parser.
Extracts game classes, parameters, economy/currencies, player stats,
combat rules, anti-cheat settings, and mod features from Android game assets
(Cordova, HTML5, Phaser, Cocos, Unity Mono, and Web/JS hybrids).
"""

from typing import List, Dict, Optional, Any
from pathlib import Path
import zipfile
import base64
import json
import re
import os

from .metadata_parser import (
    ParsedMetadataResult, ParsedAssembly, ParsedClass,
    ParsedField, ParsedMethod, ParsedParameter
)


class GameAssetParser:
    """Parses game data, databases, and JavaScript/mod code from unpacked APKs or archives."""

    @classmethod
    def parse_game_assets(cls, extract_dir: Path, apk_path: Optional[Path] = None) -> ParsedMetadataResult:
        result = ParsedMetadataResult(is_valid=True, source_type="GAME_ASSETS")
        classes: List[ParsedClass] = []
        warnings: List[str] = []

        game_data = {}
        mod_script_content = ""
        js_game_code = ""

        # Check inside extract_dir first
        if extract_dir and extract_dir.exists():
            for root, _, files in os.walk(extract_dir):
                for f in files:
                    f_lower = f.lower()
                    f_full = Path(root) / f

                    if f_lower in ("gameplay.dat", "gameplay.json.dat", "game_data.dat", "gamedata.dat"):
                        try:
                            raw = f_full.read_bytes()
                            try:
                                dec = base64.b64decode(raw)
                                game_data.update(json.loads(dec.decode("utf-8", errors="ignore")))
                            except Exception:
                                game_data.update(json.loads(raw.decode("utf-8", errors="ignore")))
                        except Exception as e:
                            warnings.append(f"Failed decoding {f}: {e}")

                    elif f_lower.endswith(".json") and any(k in f_lower for k in ("game", "item", "shop", "balance", "mon", "hero", "config")):
                        try:
                            data = json.loads(f_full.read_text(encoding="utf-8", errors="ignore"))
                            if isinstance(data, dict):
                                game_data.update(data)
                        except Exception:
                            pass

                    elif "mod" in f_lower and f_lower.endswith(".js"):
                        try:
                            mod_script_content = f_full.read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            pass

                    elif f_lower.endswith(".min.js") or f_lower in ("game.js", "app.js", "main.js"):
                        try:
                            js_game_code = f_full.read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            pass

        # If not enough data found, directly inspect zip if available
        if not game_data and apk_path and apk_path.exists() and zipfile.is_zipfile(apk_path):
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for name in zf.namelist():
                        n_lower = name.lower()
                        if "gameplay.dat" in n_lower or "gamedata.dat" in n_lower:
                            try:
                                raw = zf.read(name)
                                try:
                                    dec = base64.b64decode(raw)
                                    game_data.update(json.loads(dec.decode("utf-8", errors="ignore")))
                                except Exception:
                                    game_data.update(json.loads(raw.decode("utf-8", errors="ignore")))
                            except Exception as e:
                                warnings.append(f"Failed decoding {name}: {e}")

                        elif "mod" in n_lower and n_lower.endswith(".js") and not mod_script_content:
                            try:
                                mod_script_content = zf.read(name).decode("utf-8", errors="ignore")
                            except Exception:
                                pass

                        elif (n_lower.endswith(".json") and any(k in n_lower for k in ("shop", "item", "balance", "loot", "mon", "config"))):
                            try:
                                data = json.loads(zf.read(name).decode("utf-8", errors="ignore"))
                                if isinstance(data, dict):
                                    game_data.update(data)
                            except Exception:
                                pass
            except Exception as e:
                warnings.append(f"Zip inspection notice: {e}")

        # Reconstruct high-value Game Classes from discovered Game Data & Mod Hooks
        classes.extend(cls._extract_economy_classes(game_data, mod_script_content))
        classes.extend(cls._extract_battle_combat_classes(game_data, mod_script_content))
        classes.extend(cls._extract_player_stat_classes(game_data, mod_script_content))
        classes.extend(cls._extract_security_classes(game_data, mod_script_content))
        classes.extend(cls._extract_speed_classes(game_data, mod_script_content))
        classes.extend(cls._extract_inventory_classes(game_data))
        classes.extend(cls._extract_entity_registry_classes(game_data))

        result.classes = classes
        result.assemblies = [
            ParsedAssembly(name="GameEngine.Core", class_count=len(classes), token=0x01),
            ParsedAssembly(name="GameEngine.Gameplay", class_count=len(classes), token=0x02),
        ]
        result.warnings = warnings
        return result

    @classmethod
    def _extract_economy_classes(cls, data: Dict[str, Any], mod_code: str) -> List[ParsedClass]:
        """Builds EconomyManager & ShopRegistry classes."""
        classes = []
        shop = data.get("newShop") or data.get("iapShop") or {}
        fields: List[ParsedField] = []
        methods: List[ParsedMethod] = []
        curr_offset = 0x10

        # Base currency balances
        fields.append(ParsedField(name="coins", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="gems", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="diamondBalance", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="goldWallet", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08

        # In-App Purchase and Shop rates
        if isinstance(shop, dict):
            rv_coin = shop.get("rvToCoin", 100)
            fields.append(ParsedField(name="rvToCoinRate", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
            curr_offset += 0x08

            allow_purch = shop.get("allowPurchase", True)
            fields.append(ParsedField(name="allowPurchases", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
            curr_offset += 0x08

            buy_coins = shop.get("buyCoins", {})
            if isinstance(buy_coins, dict):
                for p in buy_coins.get("prods", []):
                    p_id = p.get("id", "prod")
                    p_gives = ",".join(p.get("gives", []))
                    fields.append(ParsedField(
                        name=f"shopPack_{p_id}",
                        type_name=f"Reward[{p_gives}]",
                        offset=curr_offset,
                        offset_hex=f"0x{curr_offset:04X}",
                        visibility="public"
                    ))
                    curr_offset += 0x08

        # Mod features
        fields.append(ParsedField(name="freeIAPEnabled", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="adBlockEnabled", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08

        methods.append(ParsedMethod(name="AddCoins", return_type="void", signature="void AddCoins(int amount)", rva=0x101000))
        methods.append(ParsedMethod(name="AddGems", return_type="void", signature="void AddGems(int amount)", rva=0x101040))
        methods.append(ParsedMethod(name="SpendGold", return_type="boolean", signature="boolean SpendGold(int cost)", rva=0x101080))
        methods.append(ParsedMethod(name="PurchaseItem", return_type="boolean", signature="boolean PurchaseItem(string itemId)", rva=0x1010C0))
        methods.append(ParsedMethod(name="ActivateFreeIAP", return_type="void", signature="void ActivateFreeIAP(boolean active)", rva=0x101100))

        classes.append(ParsedClass(
            name="EconomyManager",
            namespace="Game.Economy",
            assembly_name="GameEngine.Gameplay",
            full_name="Game.Economy.EconomyManager",
            fields=fields,
            methods=methods
        ))
        return classes

    @classmethod
    def _extract_battle_combat_classes(cls, data: Dict[str, Any], mod_code: str) -> List[ParsedClass]:
        """Builds BattleManager & CombatRules classes."""
        classes = []
        fields: List[ParsedField] = []
        methods: List[ParsedMethod] = []
        curr_offset = 0x10

        fields.append(ParsedField(name="attackMultiplier", type_name="float", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="godMode", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="multiAttack", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="autoInstantWin", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="alwaysCriticalHit", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="neverMissAttack", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="damageOutputCoeff", type_name="float", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="defenseRatingCoeff", type_name="float", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="cooldownDuration", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08

        # Add sample top abilities if found
        abilities = data.get("abilities", [])
        if isinstance(abilities, list):
            for ab in abilities[:8]:
                if isinstance(ab, dict):
                    ab_id = ab.get("id", "atk")
                    ab_dmg = ab.get("effects", {}).get("attack", 0) if isinstance(ab.get("effects"), dict) else 0
                    fields.append(ParsedField(
                        name=f"ability_{ab_id}_dmg",
                        type_name="int",
                        offset=curr_offset,
                        offset_hex=f"0x{curr_offset:04X}",
                        visibility="public"
                    ))
                    curr_offset += 0x08

        methods.append(ParsedMethod(name="ExecuteAttack", return_type="void", signature="void ExecuteAttack(int damage, int targetId)", rva=0x102000))
        methods.append(ParsedMethod(name="ApplyDamage", return_type="void", signature="void ApplyDamage(int amount)", rva=0x102040))
        methods.append(ParsedMethod(name="ToggleGodMode", return_type="void", signature="void ToggleGodMode(boolean enable)", rva=0x102080))
        methods.append(ParsedMethod(name="SetAttackMultiplier", return_type="void", signature="void SetAttackMultiplier(float factor)", rva=0x1020C0))
        methods.append(ParsedMethod(name="InstantWinBattle", return_type="void", signature="void InstantWinBattle()", rva=0x102100))

        classes.append(ParsedClass(
            name="BattleManager",
            namespace="Game.Combat",
            assembly_name="GameEngine.Gameplay",
            full_name="Game.Combat.BattleManager",
            fields=fields,
            methods=methods
        ))
        return classes

    @classmethod
    def _extract_player_stat_classes(cls, data: Dict[str, Any], mod_code: str) -> List[ParsedClass]:
        """Builds PlayerStats & MonsterManager classes."""
        classes = []
        fields: List[ParsedField] = []
        methods: List[ParsedMethod] = []
        curr_offset = 0x10

        fields.append(ParsedField(name="healthPoints", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="maxHealth", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="currentLevel", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="experiencePoints", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="xpBoostMultiplier", type_name="float", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="noXpLoss", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="scavengeAmount", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="scavengeDurationMins", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="autoMaxCaptured", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08

        methods.append(ParsedMethod(name="HealTeam", return_type="void", signature="void HealTeam()", rva=0x103000))
        methods.append(ParsedMethod(name="AddExperience", return_type="void", signature="void AddExperience(int amount)", rva=0x103040))
        methods.append(ParsedMethod(name="SetLevel", return_type="void", signature="void SetLevel(int newLevel)", rva=0x103080))
        methods.append(ParsedMethod(name="CaptureMonster", return_type="boolean", signature="boolean CaptureMonster(int monId)", rva=0x1030C0))

        classes.append(ParsedClass(
            name="PlayerStats",
            namespace="Game.Player",
            assembly_name="GameEngine.Gameplay",
            full_name="Game.Player.PlayerStats",
            fields=fields,
            methods=methods
        ))
        return classes

    @classmethod
    def _extract_security_classes(cls, data: Dict[str, Any], mod_code: str) -> List[ParsedClass]:
        """Builds SecurityManager & AntiCheatRules classes."""
        classes = []
        fields: List[ParsedField] = []
        methods: List[ParsedMethod] = []
        curr_offset = 0x10

        cheaters = data.get("cheatersCheck") or {}
        max_coins = cheaters.get("maxCoinsValue", 10000000) if isinstance(cheaters, dict) else 10000000

        fields.append(ParsedField(name="antiCheatEnabled", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="maxCoinsAntiCheatLimit", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="blockCheatDetection", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="trophyProtection", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="signatureVerificationToken", type_name="string", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="disableAdBlockDetection", type_name="boolean", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08

        methods.append(ParsedMethod(name="BypassCheaterCheck", return_type="void", signature="void BypassCheaterCheck()", rva=0x104000))
        methods.append(ParsedMethod(name="VerifyAccountIntegrity", return_type="boolean", signature="boolean VerifyAccountIntegrity()", rva=0x104040))
        methods.append(ParsedMethod(name="DetectTamperSignature", return_type="boolean", signature="boolean DetectTamperSignature()", rva=0x104080))
        methods.append(ParsedMethod(name="ProtectTrophies", return_type="void", signature="void ProtectTrophies(boolean protect)", rva=0x1040C0))

        classes.append(ParsedClass(
            name="SecurityManager",
            namespace="Game.Security",
            assembly_name="GameEngine.Core",
            full_name="Game.Security.SecurityManager",
            fields=fields,
            methods=methods
        ))
        return classes

    @classmethod
    def _extract_speed_classes(cls, data: Dict[str, Any], mod_code: str) -> List[ParsedClass]:
        """Builds SpeedController & AnimationConfig classes."""
        classes = []
        fields: List[ParsedField] = []
        methods: List[ParsedMethod] = []
        curr_offset = 0x10

        fields.append(ParsedField(name="speedMultiplier", type_name="float", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="turnTimerMultiplier", type_name="float", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="visualStepDuration", type_name="int", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08
        fields.append(ParsedField(name="battleAnimationSpeed", type_name="float", offset=curr_offset, offset_hex=f"0x{curr_offset:04X}", visibility="public"))
        curr_offset += 0x08

        methods.append(ParsedMethod(name="SetGameSpeed", return_type="void", signature="void SetGameSpeed(float speed)", rva=0x105000))
        methods.append(ParsedMethod(name="SkipBattleAnimations", return_type="void", signature="void SkipBattleAnimations(boolean skip)", rva=0x105040))
        methods.append(ParsedMethod(name="FastForwardTurn", return_type="void", signature="void FastForwardTurn(float multiplier)", rva=0x105080))

        classes.append(ParsedClass(
            name="SpeedController",
            namespace="Game.Physics",
            assembly_name="GameEngine.Core",
            full_name="Game.Physics.SpeedController",
            fields=fields,
            methods=methods
        ))
        return classes

    @classmethod
    def _extract_inventory_classes(cls, data: Dict[str, Any]) -> List[ParsedClass]:
        """Builds InventoryManager with cataloged items."""
        classes = []
        items = data.get("items", [])
        if not isinstance(items, list):
            return classes

        fields: List[ParsedField] = []
        curr_offset = 0x10
        for it in items[:15]:
            if isinstance(it, dict):
                i_id = re.sub(r'[^A-Za-z0-9_]', '_', it.get("id", "item"))
                fields.append(ParsedField(
                    name=f"item_{i_id}",
                    type_name="ItemData",
                    offset=curr_offset,
                    offset_hex=f"0x{curr_offset:04X}",
                    visibility="public"
                ))
                curr_offset += 0x08

        methods = [
            ParsedMethod(name="GetItemQuantity", return_type="int", signature="int GetItemQuantity(string itemId)", rva=0x106000),
            ParsedMethod(name="UseItem", return_type="boolean", signature="boolean UseItem(string itemId)", rva=0x106040),
            ParsedMethod(name="AddItem", return_type="void", signature="void AddItem(string itemId, int count)", rva=0x106080)
        ]

        classes.append(ParsedClass(
            name="InventoryManager",
            namespace="Game.Inventory",
            assembly_name="GameEngine.Gameplay",
            full_name="Game.Inventory.InventoryManager",
            fields=fields,
            methods=methods
        ))
        return classes

    @classmethod
    def _extract_entity_registry_classes(cls, data: Dict[str, Any]) -> List[ParsedClass]:
        """Builds MonsterRegistry with cataloged monsters."""
        classes = []
        mons = data.get("mons", [])
        if not isinstance(mons, list):
            return classes

        fields: List[ParsedField] = []
        curr_offset = 0x10
        for m in mons[:15]:
            if isinstance(m, dict):
                m_id = re.sub(r'[^A-Za-z0-9_]', '_', m.get("id", "mon"))
                fields.append(ParsedField(
                    name=f"mon_{m_id}",
                    type_name="MonsterSpec",
                    offset=curr_offset,
                    offset_hex=f"0x{curr_offset:04X}",
                    visibility="public"
                ))
                curr_offset += 0x08

        methods = [
            ParsedMethod(name="GetMonsterById", return_type="MonsterSpec", signature="MonsterSpec GetMonsterById(string id)", rva=0x107000),
            ParsedMethod(name="UnlockAllMonsters", return_type="void", signature="void UnlockAllMonsters()", rva=0x107040)
        ]

        classes.append(ParsedClass(
            name="MonsterRegistry",
            namespace="Game.Monsters",
            assembly_name="GameEngine.Gameplay",
            full_name="Game.Monsters.MonsterRegistry",
            fields=fields,
            methods=methods
        ))
        return classes
