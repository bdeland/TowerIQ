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

class MaxLevel(IntEnum):
    """Enumeration for the maximum level of a module."""
    COMMON = 20
    RARE = 30
    RARE_PLUS = 40
    EPIC = 60
    EPIC_PLUS = 80
    LEGENDARY = 100
    LEGENDARY_PLUS = 120
    MYTHIC = 140
    MYTHIC_PLUS = 160
    ANCESTRAL = 200
    ANCESTRAL1 = 220
    ANCESTRAL2 = 240
    ANCESTRAL3 = 260
    ANCESTRAL4 = 280
    ANCESTRAL5 = 300

class Rarity(Enum):
    """
    Enumeration for all module rarity tiers.
    The string value should match what's used in data lookups.
    """
    COMMON = "Common"
    RARE = "Rare"
    RARE_PLUS = "RarePlus"
    EPIC = "Epic"
    EPIC_PLUS = "EpicPlus"
    LEGENDARY = "Legendary"
    LEGENDARY_PLUS = "LegendaryPlus"
    MYTHIC = "Mythic"
    MYTHIC_PLUS = "MythicPlus"
    ANCESTRAL = "Ancestral"
    ANCESTRAL1 = "Ancestral1"
    ANCESTRAL2 = "Ancestral2"
    ANCESTRAL3 = "Ancestral3"
    ANCESTRAL4 = "Ancestral4"
    ANCESTRAL5 = "Ancestral5"


# Rarity hierarchy for comparison and substat rolling
RARITY_HIERARCHY = {
    Rarity.COMMON: 1,
    Rarity.RARE: 2,
    Rarity.RARE_PLUS: 2,  # Same as RARE for substat purposes
    Rarity.EPIC: 3,
    Rarity.EPIC_PLUS: 3,  # Same as EPIC for substat purposes
    Rarity.LEGENDARY: 4,
    Rarity.LEGENDARY_PLUS: 4,  # Same as LEGENDARY for substat purposes
    Rarity.MYTHIC: 5,
    Rarity.MYTHIC_PLUS: 5,  # Same as MYTHIC for substat purposes
    Rarity.ANCESTRAL: 6,
    Rarity.ANCESTRAL1: 6,  # Same as ANCESTRAL for substat purposes
    Rarity.ANCESTRAL2: 6,  # Same as ANCESTRAL for substat purposes
    Rarity.ANCESTRAL3: 6,  # Same as ANCESTRAL for substat purposes
    Rarity.ANCESTRAL4: 6,  # Same as ANCESTRAL for substat purposes
    Rarity.ANCESTRAL5: 6,  # Same as ANCESTRAL for substat purposes
}

# Simplified rarity tiers for substat rolling (5 tiers)
SUBSTAT_RARITY_TIERS = {
    Rarity.COMMON: 1,
    Rarity.RARE: 2,
    Rarity.RARE_PLUS: 2,
    Rarity.EPIC: 3,
    Rarity.EPIC_PLUS: 3,
    Rarity.LEGENDARY: 4,
    Rarity.LEGENDARY_PLUS: 4,
    Rarity.MYTHIC: 5,
    Rarity.MYTHIC_PLUS: 5,
    Rarity.ANCESTRAL: 6,
    Rarity.ANCESTRAL1: 6,
    Rarity.ANCESTRAL2: 6,
    Rarity.ANCESTRAL3: 6,
    Rarity.ANCESTRAL4: 6,
    Rarity.ANCESTRAL5: 6,
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