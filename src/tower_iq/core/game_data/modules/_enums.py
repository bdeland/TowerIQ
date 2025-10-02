from enum import Enum, IntEnum

"""
This file defines all core enumerations for the game's static data.
It acts as the single source of truth for categories like module types,
rarities, and substat effects, providing type safety and preventing errors
from typos or "magic strings".
"""

class ModuleType(Enum):
    """Enumeration for the four core module types."""
    ARMOR = "Armor"
    CANNON = "Cannon"
    CORE = "Core"
    GENERATOR = "Generator"

class Rarity(IntEnum):
    """
    Enumeration for all module rarity tiers.
    Using IntEnum provides a natural hierarchy for comparisons.
    """
    COMMON = 1
    RARE = 2
    RARE_PLUS = 3
    EPIC = 4
    EPIC_PLUS = 5
    LEGENDARY = 6
    LEGENDARY_PLUS = 7
    MYTHIC = 8
    MYTHIC_PLUS = 9
    ANCESTRAL = 10
    ANCESTRAL1 = 11
    ANCESTRAL2 = 12
    ANCESTRAL3 = 13
    ANCESTRAL4 = 14
    ANCESTRAL5 = 15

    @property
    def display_name(self) -> str:
        """Get the display name for the rarity (for backward compatibility)."""
        rarity_names = {
            Rarity.COMMON: "Common",
            Rarity.RARE: "Rare",
            Rarity.RARE_PLUS: "RarePlus",
            Rarity.EPIC: "Epic",
            Rarity.EPIC_PLUS: "EpicPlus",
            Rarity.LEGENDARY: "Legendary",
            Rarity.LEGENDARY_PLUS: "LegendaryPlus",
            Rarity.MYTHIC: "Mythic",
            Rarity.MYTHIC_PLUS: "MythicPlus",
            Rarity.ANCESTRAL: "Ancestral",
            Rarity.ANCESTRAL1: "Ancestral1",
            Rarity.ANCESTRAL2: "Ancestral2",
            Rarity.ANCESTRAL3: "Ancestral3",
            Rarity.ANCESTRAL4: "Ancestral4",
            Rarity.ANCESTRAL5: "Ancestral5",
        }
        return rarity_names.get(self, str(self.value))

# Mapping for max levels (moved from MaxLevel enum)
RARITY_TO_MAX_LEVEL = {
    Rarity.COMMON: 20,
    Rarity.RARE: 30,
    Rarity.RARE_PLUS: 40,
    Rarity.EPIC: 60,
    Rarity.EPIC_PLUS: 80,
    Rarity.LEGENDARY: 100,
    Rarity.LEGENDARY_PLUS: 120,
    Rarity.MYTHIC: 140,
    Rarity.MYTHIC_PLUS: 160,
    Rarity.ANCESTRAL: 200,
    Rarity.ANCESTRAL1: 220,
    Rarity.ANCESTRAL2: 240,
    Rarity.ANCESTRAL3: 260,
    Rarity.ANCESTRAL4: 280,
    Rarity.ANCESTRAL5: 300,
}

class Substat(IntEnum):
    """
    Enumeration for every possible substat effect.

    Using IntEnum allows these members to be used interchangeably with their
    integer IDs (e.g., Substat.ATTACK_SPEED == 1), which is perfect for
    replacing the magic numbers used in the lookup file and data models.
    """
    # Cannon Substats
    ATTACK_SPEED = 1
    CRITICAL_CHANCE = 2
    CRITICAL_FACTOR = 3
    ATTACK_RANGE = 4
    DAMAGE_PER_METER = 5
    MULTISHOT_CHANCE = 6
    MULTISHOT_TARGETS = 7
    RAPID_FIRE_CHANCE = 8
    RAPID_FIRE_DURATION = 9
    BOUNCE_SHOT_CHANCE = 10
    BOUNCE_SHOT_TARGETS = 11
    BOUNCE_SHOT_RANGE = 12
    SUPER_CRITICAL_CHANCE = 13
    SUPER_CRITICAL_FACTOR = 14
    REND_ARMOR_CHANCE = 15
    REND_ARMOR_MULT = 16
    REND_ARMOR_MAX = 17

    # Armor Substats
    HEALTH_REGEN = 18
    DEFENSE_PERCENT = 19
    DEFENSE_ABSOLUTE = 20
    THORN_DAMAGE = 21
    LIFESTEAL = 22
    KNOCKBACK_CHANCE = 23
    KNOCKBACK_FORCE = 24
    ORB_SPEED = 25
    ORBS = 26
    SHOCKWAVE_SIZE = 27
    SHOCKWAVE_FREQUENCY = 28
    LAND_MINE_CHANCE = 29
    LAND_MINE_DAMAGE = 30
    LAND_MINE_RADIUS = 31
    DEATH_DEFY = 32
    WALL_HEALTH = 33
    WALL_REBUILD = 34

    # Generator Substats
    CASH_BONUS = 35
    CASH_PER_WAVE = 36
    COINS_PER_KILL = 37
    COINS_PER_WAVE = 38
    FREE_ATTACK_UPGRADE = 39
    FREE_DEFENSE_UPGRADE = 40
    FREE_UTILITY_UPGRADE = 41
    INTEREST_PER_WAVE = 42
    RECOVERY_AMOUNT = 43
    MAX_RECOVERY = 44
    PACKAGE_CHANCE = 45
    ENEMY_ATTACK_LEVEL_SKIP = 46
    ENEMY_HEALTH_LEVEL_SKIP = 47

    # Core Substats
    CHAIN_LIGHTNING_DAMAGE = 48
    CHAIN_LIGHTNING_QUANTITY = 49
    CHAIN_LIGHTNING_CHANCE = 50
    SMART_MISSILES_DAMAGE = 51
    SMART_MISSILES_QUANTITY = 52
    SMART_MISSILES_COOLDOWN = 53
    DEATH_WAVE_DAMAGE = 54
    DEATH_WAVE_QUANTITY = 55
    DEATH_WAVE_COOLDOWN = 56
    CHRONO_FIELD_DURATION = 57
    CHRONO_FIELD_SPEED_REDUCTION = 58
    CHRONO_FIELD_COOLDOWN = 59
    INNER_LAND_MINES_DAMAGE = 60
    INNER_LAND_MINES_QUANTITY = 61
    INNER_LAND_MINES_COOLDOWN = 62
    GOLDEN_TOWER_BONUS = 63
    GOLDEN_TOWER_DURATION = 64
    GOLDEN_TOWER_COOLDOWN = 65
    POISON_SWAMP_DAMAGE = 66
    POISON_SWAMP_DURATION = 67
    POISON_SWAMP_COOLDOWN = 68
    BLACK_HOLE_SIZE = 69
    BLACK_HOLE_DURATION = 70
    BLACK_HOLE_COOLDOWN = 71
    SPOTLIGHT_BONUS = 72
    SPOTLIGHT_ANGLE = 73
    SPOTLIGHT_QUANTITY = 74
