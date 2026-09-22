"""
Semantic Analysis Engine & Synonym Dictionary.
Analyzes class names, namespaces, field names, types, method names, and properties
to detect gameplay relevance across 24 analytical categories and classify contexts
(STATE, DATA, UI, VISUAL, AUDIO, ANIMATION, NETWORK).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
import re

GAMEPLAY_CATEGORIES = [
    "COMBAT", "HEALTH", "DAMAGE", "ATTACK", "DEFENSE",
    "SPEED", "CRITICAL", "ACCURACY", "CAPTURE", "CREATURE",
    "PLAYER", "XP", "LEVEL", "CURRENCY", "INVENTORY",
    "REWARDS", "ARENA", "ABILITIES", "EVOLUTION", "PROGRESSION",
    "QUESTS", "STATS", "ENERGY", "COOLDOWN"
]

DEFAULT_SYNONYMS: Dict[str, List[str]] = {
    "HEALTH": ["health", "hp", "hitpoint", "hitpoints", "life", "vitality", "currenthp", "maxhp"],
    "DAMAGE": ["damage", "dmg", "attackdamage", "attack_power", "damageamount", "hurt", "wound", "dps"],
    "ATTACK": ["attack", "atk", "offensive", "strike", "slash", "punch", "assault"],
    "DEFENSE": ["defense", "def", "armor", "armour", "shield", "resist", "resistance", "reduction"],
    "SPEED": ["speed", "spd", "velocity", "movespeed", "attackspeed", "agility", "haste"],
    "CRITICAL": ["critical", "crit", "critrate", "critdmg", "critdamage", "criticalchance", "multiplier"],
    "ACCURACY": ["accuracy", "acc", "aim", "precision", "hitrate", "missrate", "evasion", "dodge"],
    "CAPTURE": ["capture", "catch", "tame", "catchrate", "ball", "trap", "snare"],
    "CREATURE": ["creature", "monster", "dynamon", "pokemon", "beast", "pet", "minion", "unit", "character"],
    "PLAYER": ["player", "user", "hero", "avatar", "account", "profile", "localplayer"],
    "XP": ["xp", "exp", "experience", "experiencepoints", "currentexp", "maxexp"],
    "LEVEL": ["level", "lvl", "stage", "grade", "rank", "characterlevel", "playerlevel"],
    "CURRENCY": ["currency", "coin", "coins", "gold", "gem", "gems", "diamond", "diamonds", "money", "cash", "token", "tokens", "credit", "credits"],
    "INVENTORY": ["inventory", "bag", "item", "items", "stash", "storage", "backpack", "equipment", "gear", "loot"],
    "REWARDS": ["reward", "rewards", "prize", "gift", "drop", "bonus", "chest", "crate"],
    "ARENA": ["arena", "pvp", "ladder", "matchmaking", "colosseum", "tournament", "leaderboard"],
    "ABILITIES": ["ability", "skill", "spell", "magic", "talent", "ultimate", "passive", "power"],
    "EVOLUTION": ["evolution", "evolve", "mutation", "ascend", "ascension", "awakening", "transform"],
    "PROGRESSION": ["progression", "progress", "milestone", "achievement", "unlock", "story", "chapter"],
    "QUESTS": ["quest", "mission", "bounty", "task", "objective", "campaign"],
    "STATS": ["stat", "stats", "attribute", "attributes", "parameter", "parameters", "status"],
    "ENERGY": ["energy", "mana", "mp", "stamina", "ap", "actionpoints", "charge", "fuel"],
    "COOLDOWN": ["cooldown", "cd", "recharge", "delay", "cooldowntime", "timer", "interval"],
    "COMBAT": ["combat", "battle", "fight", "match", "duel", "war", "skirmish", "encounter"]
}

# Negative keywords indicating UI/Visual/Audio rather than game-state
UI_INDICATORS = ["bar", "icon", "text", "label", "button", "slider", "panel", "view", "hud", "canvas", "ui", "display", "popup", "dialog", "widget"]
VISUAL_INDICATORS = ["effect", "vfx", "particle", "renderer", "mesh", "material", "texture", "shader", "color", "tint", "glow", "sprite"]
AUDIO_INDICATORS = ["audio", "sound", "sfx", "music", "clip", "volume", "voice", "listener"]
ANIMATION_INDICATORS = ["anim", "animation", "animator", "clip", "controller", "motion", "skeleton", "bone"]
NETWORK_INDICATORS = ["packet", "socket", "network", "rpc", "client", "server", "message", "protocol", "sync"]


@dataclass
class SemanticMatch:
    matched_categories: List[str] = field(default_factory=list)
    primary_category: Optional[str] = None
    context_type: str = "STATE"  # STATE, DATA, UI, VISUAL, AUDIO, ANIMATION, NETWORK
    keyword_hits: List[str] = field(default_factory=list)
    synonym_hits: List[str] = field(default_factory=list)
    is_ui_or_visual: bool = False


class SemanticAnalyzer:
    """Semantic parser and classification engine."""

    def __init__(self, custom_synonyms: Optional[Dict[str, List[str]]] = None):
        self.synonyms = dict(DEFAULT_SYNONYMS)
        if custom_synonyms:
            for cat, words in custom_synonyms.items():
                if cat in self.synonyms:
                    self.synonyms[cat] = list(set(self.synonyms[cat] + words))
                else:
                    self.synonyms[cat] = words

    def analyze_identifier(self, identifier: str, surrounding_context: str = "") -> SemanticMatch:
        """Classifies an identifier (class name, field name, method name)."""
        result = SemanticMatch()
        if not identifier:
            return result

        # Tokenize camelCase, snake_case, PascalCase
        tokens = self.tokenize(identifier)
        tokens_lower = [t.lower() for t in tokens]
        full_lower = identifier.lower()

        # Context detection
        if any(ui in tokens_lower for ui in UI_INDICATORS) or any(full_lower.endswith(ui) for ui in UI_INDICATORS):
            result.context_type = "UI"
            result.is_ui_or_visual = True
        elif any(v in tokens_lower for v in VISUAL_INDICATORS):
            result.context_type = "VISUAL"
            result.is_ui_or_visual = True
        elif any(a in tokens_lower for a in AUDIO_INDICATORS):
            result.context_type = "AUDIO"
            result.is_ui_or_visual = True
        elif any(an in tokens_lower for an in ANIMATION_INDICATORS):
            result.context_type = "ANIMATION"
            result.is_ui_or_visual = True
        elif any(net in tokens_lower for net in NETWORK_INDICATORS):
            result.context_type = "NETWORK"
        else:
            # Check if it represents concrete state vs data
            result.context_type = "STATE"

        # Match categories
        cat_scores: Dict[str, int] = {}

        for cat, words in self.synonyms.items():
            for word in words:
                w_lower = word.lower()
                # Exact token match
                if w_lower in tokens_lower:
                    cat_scores[cat] = cat_scores.get(cat, 0) + 10
                    result.keyword_hits.append(f"{cat}:{w_lower}")
                # Substring match if length > 3
                elif len(w_lower) >= 4 and w_lower in full_lower:
                    cat_scores[cat] = cat_scores.get(cat, 0) + 5
                    result.synonym_hits.append(f"{cat}:{w_lower}")

        if cat_scores:
            # Sort categories by score
            sorted_cats = sorted(cat_scores.items(), key=lambda x: x[1], reverse=True)
            result.matched_categories = [c[0] for c in sorted_cats]
            result.primary_category = sorted_cats[0][0]

        return result

    @staticmethod
    def tokenize(identifier: str) -> List[str]:
        """Split camelCase, PascalCase, snake_case, and digits into tokens."""
        # Replace underscores with spaces
        s = identifier.replace("_", " ")
        # Insert space before capital letters preceded by lowercase
        s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", s)
        # Insert space before consecutive capitals followed by lowercase
        s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
        tokens = [t.strip() for t in s.split() if t.strip()]
        return tokens
