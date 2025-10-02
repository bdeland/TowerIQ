from ._enums import Rarity, ModuleType
from .module_dataclass import SubstatInfo

# Cannon Substats
ATTACK_SPEED = SubstatInfo(
    enum_id=1,
    name="Attack Speed",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.COMMON: 2,
        Rarity.RARE: 4,
        Rarity.EPIC: 8,
        Rarity.LEGENDARY: 12,
        Rarity.MYTHIC: 20,
        Rarity.ANCESTRAL: 30,
    }
)

CRITICAL_CHANCE = SubstatInfo(
    enum_id=2,
    name="Critical Chance",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.COMMON: 2,
        Rarity.RARE: 3,
        Rarity.EPIC: 4,
        Rarity.LEGENDARY: 6,
        Rarity.MYTHIC: 8,
        Rarity.ANCESTRAL: 10
    }
)

CRITICAL_FACTOR = SubstatInfo(
    enum_id=3,
    name="Critical Factor",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.COMMON: 2,
        Rarity.RARE: 4,
        Rarity.EPIC: 6,
        Rarity.LEGENDARY: 8,
        Rarity.MYTHIC: 12,
        Rarity.ANCESTRAL: 15
    }
)

ATTACK_RANGE = SubstatInfo(
    enum_id=4,
    name="Attack Range",
    applies_to=ModuleType.CANNON,
    unit="m",
    values={
        Rarity.COMMON: 2,
        Rarity.RARE: 4,
        Rarity.EPIC: 8,
        Rarity.LEGENDARY: 12,
        Rarity.MYTHIC: 20,
        Rarity.ANCESTRAL: 30
    }
)

DAMAGE_PER_METER = SubstatInfo(
    enum_id=5,
    name="Damage Per Meter",
    applies_to=ModuleType.CANNON,
    unit="m",
    values={
        Rarity.COMMON: 0.005,
        Rarity.RARE: 0.01,
        Rarity.EPIC: 0.025,
        Rarity.LEGENDARY: 0.04,
        Rarity.MYTHIC: 0.075,
        Rarity.ANCESTRAL: 0.15
    }
)

MULTISHOT_CHANCE = SubstatInfo(
    enum_id=6,
    name="Multishot Chance",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.RARE: 3,
        Rarity.EPIC: 5,
        Rarity.LEGENDARY: 7,
        Rarity.MYTHIC: 10,
        Rarity.ANCESTRAL: 13
    }
)

MULTISHOT_TARGETS = SubstatInfo(
    enum_id=7,
    name="Multishot Targets",
    applies_to=ModuleType.CANNON,
    unit="",
    values={
        Rarity.EPIC: 1,
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 3,
        Rarity.ANCESTRAL: 4
    }
)

RAPID_FIRE_CHANCE = SubstatInfo(
    enum_id=8,
    name="Rapid Fire Chance",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.RARE: 2,
        Rarity.EPIC: 4,
        Rarity.LEGENDARY: 6,
        Rarity.MYTHIC: 9,
        Rarity.ANCESTRAL: 12
    }
)

RAPID_FIRE_DURATION = SubstatInfo(
    enum_id=9,
    name="Rapid Fire Duration",
    applies_to=ModuleType.CANNON,
    unit="s",
    values={
        Rarity.RARE: 0.4,
        Rarity.EPIC: 0.8,
        Rarity.LEGENDARY: 1.4,
        Rarity.MYTHIC: 2.5,
        Rarity.ANCESTRAL: 3.5
    }
)

BOUNCE_SHOT_CHANCE = SubstatInfo(
    enum_id=10,
    name="Bounce Shot Chance",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.RARE: 2,
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 5,
        Rarity.MYTHIC: 9,
        Rarity.ANCESTRAL: 12
    }
)

BOUNCE_SHOT_TARGETS = SubstatInfo(
    enum_id=11,
    name="Bounce Shot Targets",
    applies_to=ModuleType.CANNON,
    unit="",
    values={
        Rarity.EPIC: 1,
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 3,
        Rarity.ANCESTRAL: 4
    }
)

BOUNCE_SHOT_RANGE = SubstatInfo(
    enum_id=12,
    name="Bounce Shot Range",
    applies_to=ModuleType.CANNON,
    unit="m",
    values={
        Rarity.RARE: 0.5,
        Rarity.EPIC: 0.8,
        Rarity.LEGENDARY: 1.2,
        Rarity.MYTHIC: 1.8,
        Rarity.ANCESTRAL: 2.0
    }
)

SUPER_CRITICAL_CHANCE = SubstatInfo(
    enum_id=13,
    name="Super Critical Chance",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 5,
        Rarity.MYTHIC: 7,
        Rarity.ANCESTRAL: 10
    }
)

SUPER_CRITICAL_FACTOR = SubstatInfo(
    enum_id=14,
    name="Super Critical Factor",
    applies_to=ModuleType.CANNON,
    unit="",
    values={
        Rarity.EPIC: 2,
        Rarity.LEGENDARY: 3,
        Rarity.MYTHIC: 5,
        Rarity.ANCESTRAL: 7
    }
)

REND_ARMOR_CHANCE = SubstatInfo(
    enum_id=15,
    name="Rend Armor Chance",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 5,
        Rarity.ANCESTRAL: 8
    }
)

REND_ARMOR_MULT = SubstatInfo(
    enum_id=16,
    name="Rend Armor Mult",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 5,
        Rarity.ANCESTRAL: 8
    }
)

REND_ARMOR_MAX = SubstatInfo(
    enum_id=17,
    name="Rend Armor Max",
    applies_to=ModuleType.CANNON,
    unit="%",
    values={
        Rarity.LEGENDARY: 200,
        Rarity.MYTHIC: 300,
        Rarity.ANCESTRAL: 500
    }
)

# Armor Substats
HEALTH_REGEN = SubstatInfo(
    enum_id=18,
    name="Health Regen",
    applies_to=ModuleType.ARMOR,
    unit="%",
    values={
        Rarity.COMMON: 20,
        Rarity.RARE: 40,
        Rarity.EPIC: 60,
        Rarity.LEGENDARY: 100,
        Rarity.MYTHIC: 200,
        Rarity.ANCESTRAL: 400
    }
)

DEFENSE_PERCENT = SubstatInfo(
    enum_id=19,
    name="Defense Percent",
    applies_to=ModuleType.ARMOR,
    unit="%",
    values={
        Rarity.COMMON: 1,
        Rarity.RARE: 2,
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 5,
        Rarity.MYTHIC: 6,
        Rarity.ANCESTRAL: 8
    }
)

DEFENSE_ABSOLUTE = SubstatInfo(
    enum_id=20,
    name="Defense Absolute",
    applies_to=ModuleType.ARMOR,
    unit="%",
    values={
        Rarity.COMMON: 15,
        Rarity.RARE: 25,
        Rarity.EPIC: 40,
        Rarity.LEGENDARY: 100,
        Rarity.MYTHIC: 500,
        Rarity.ANCESTRAL: 1000
    }
)

THORN_DAMAGE = SubstatInfo(
    enum_id=21,
    name="Thorn Damage",
    applies_to=ModuleType.ARMOR,
    unit="",
    values={
        Rarity.EPIC: 2,
        Rarity.LEGENDARY: 4,
        Rarity.MYTHIC: 7,
        Rarity.ANCESTRAL: 10
    }
)

LIFESTEAL = SubstatInfo(
    enum_id=22,
    name="Lifesteal",
    applies_to=ModuleType.ARMOR,
    unit="%",
    values={
        Rarity.EPIC: 0.3,
        Rarity.LEGENDARY: 0.5,
        Rarity.MYTHIC: 1.5,
        Rarity.ANCESTRAL: 2
    }
)

KNOCKBACK_CHANCE = SubstatInfo(
    enum_id=23,
    name="Knockback Chance",
    applies_to=ModuleType.ARMOR,
    unit="%",
    values={
        Rarity.EPIC: 2,
        Rarity.LEGENDARY: 4,
        Rarity.MYTHIC: 6,
        Rarity.ANCESTRAL: 9
    }
)

KNOCKBACK_FORCE = SubstatInfo(
    enum_id=24,
    name="Knockback Force",
    applies_to=ModuleType.ARMOR,
    unit="",
    values={
        Rarity.EPIC: 0.1,
        Rarity.LEGENDARY: 0.4,
        Rarity.MYTHIC: 0.9,
        Rarity.ANCESTRAL: 1.5
    }
)

ORB_SPEED = SubstatInfo(
    enum_id=25,
    name="Orb Speed",
    applies_to=ModuleType.ARMOR,
    unit="",
    values={
        Rarity.EPIC: 1,
        Rarity.LEGENDARY: 1.5,
        Rarity.MYTHIC: 2,
        Rarity.ANCESTRAL: 3
    }
)

ORBS = SubstatInfo(
    enum_id=26,
    name="Orbs",
    applies_to=ModuleType.ARMOR,
    unit="",
    values={
        Rarity.MYTHIC: 1,
        Rarity.ANCESTRAL: 2
    }
)

SHOCKWAVE_SIZE = SubstatInfo(
    enum_id=27,
    name="Shockwave Size",
    applies_to=ModuleType.ARMOR,
    unit="",
    values={
        Rarity.EPIC: 0.1,
        Rarity.LEGENDARY: 0.3,
        Rarity.MYTHIC: 0.7,
        Rarity.ANCESTRAL: 1
    }
)

SHOCKWAVE_FREQUENCY = SubstatInfo(
    enum_id=28,
    name="Shockwave Frequency",
    applies_to=ModuleType.ARMOR,
    unit="s",
    values={
        Rarity.EPIC: -1,
        Rarity.LEGENDARY: -2,
        Rarity.MYTHIC: -3,
        Rarity.ANCESTRAL: -4
    }
)

LAND_MINE_CHANCE = SubstatInfo(
    enum_id=29,
    name="Land Mine Chance",
    applies_to=ModuleType.ARMOR,
    unit="%",
    values={
        Rarity.RARE: 1.5,
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 6,
        Rarity.MYTHIC: 9,
        Rarity.ANCESTRAL: 12
    }
)

LAND_MINE_DAMAGE = SubstatInfo(
    enum_id=30,
    name="Land Mine Damage",
    applies_to=ModuleType.ARMOR,
    unit="%",
    values={
        Rarity.RARE: 30,
        Rarity.EPIC: 50,
        Rarity.LEGENDARY: 150,
        Rarity.MYTHIC: 500,
        Rarity.ANCESTRAL: 800
    }
)

LAND_MINE_RADIUS = SubstatInfo(
    enum_id=31,
    name="Land Mine Radius",
    applies_to=ModuleType.ARMOR,
    unit="",
    values={
        Rarity.RARE: 0.1,
        Rarity.EPIC: 0.15,
        Rarity.LEGENDARY: 0.3,
        Rarity.MYTHIC: 0.75,
        Rarity.ANCESTRAL: 1
    }
)

DEATH_DEFY = SubstatInfo(
    enum_id=32,
    name="Death Defy",
    applies_to=ModuleType.ARMOR,
    unit="%",
    values={
        Rarity.LEGENDARY: 1.5,
        Rarity.MYTHIC: 3.5,
        Rarity.ANCESTRAL: 5
    }
)

WALL_HEALTH = SubstatInfo(
    enum_id=33,
    name="Wall Health",
    applies_to=ModuleType.ARMOR,
    unit="%",
    values={
        Rarity.EPIC: 20,
        Rarity.LEGENDARY: 40,
        Rarity.MYTHIC: 90,
        Rarity.ANCESTRAL: 120
    }
)

WALL_REBUILD = SubstatInfo(
    enum_id=34,
    name="Wall Rebuild",
    applies_to=ModuleType.ARMOR,
    unit="s",
    values={
        Rarity.EPIC: -20,
        Rarity.LEGENDARY: -40,
        Rarity.MYTHIC: -80,
        Rarity.ANCESTRAL: -100
    }
)

# Generator Substats
CASH_BONUS = SubstatInfo(
    enum_id=35,
    name="Cash Bonus",
    applies_to=ModuleType.GENERATOR,
    unit="x",
    values={
        Rarity.COMMON: 0.1,
        Rarity.RARE: 0.2,
        Rarity.EPIC: 0.3,
        Rarity.LEGENDARY: 0.5,
        Rarity.MYTHIC: 1.2,
        Rarity.ANCESTRAL: 2.5
    }
)

CASH_PER_WAVE = SubstatInfo(
    enum_id=36,
    name="Cash Per Wave",
    applies_to=ModuleType.GENERATOR,
    unit="",
    values={
        Rarity.COMMON: 30,
        Rarity.RARE: 50,
        Rarity.EPIC: 100,
        Rarity.LEGENDARY: 200,
        Rarity.MYTHIC: 500,
        Rarity.ANCESTRAL: 1000
    }
)

COINS_PER_KILL = SubstatInfo(
    enum_id=37,
    name="Coins Per Kill",
    applies_to=ModuleType.GENERATOR,
    unit="x",
    values={
        Rarity.COMMON: 0.1,
        Rarity.RARE: 0.2,
        Rarity.EPIC: 0.3,
        Rarity.LEGENDARY: 0.4,
        Rarity.MYTHIC: 0.5,
        Rarity.ANCESTRAL: 0.6
    }
)

COINS_PER_WAVE = SubstatInfo(
    enum_id=38,
    name="Coins Per Wave",
    applies_to=ModuleType.GENERATOR,
    unit="",
    values={
        Rarity.COMMON: 20,
        Rarity.RARE: 35,
        Rarity.EPIC: 60,
        Rarity.LEGENDARY: 120,
        Rarity.MYTHIC: 200,
        Rarity.ANCESTRAL: 350
    }
)

FREE_ATTACK_UPGRADE = SubstatInfo(
    enum_id=39,
    name="Free Attack Upgrade",
    applies_to=ModuleType.GENERATOR,
    unit="%",
    values={
        Rarity.COMMON: 2,
        Rarity.RARE: 4,
        Rarity.EPIC: 6,
        Rarity.LEGENDARY: 8,
        Rarity.MYTHIC: 10,
        Rarity.ANCESTRAL: 12
    }
)

FREE_DEFENSE_UPGRADE = SubstatInfo(
    enum_id=40,
    name="Free Defense Upgrade",
    applies_to=ModuleType.GENERATOR,
    unit="%",
    values={
        Rarity.COMMON: 2,
        Rarity.RARE: 4,
        Rarity.EPIC: 6,
        Rarity.LEGENDARY: 8,
        Rarity.MYTHIC: 10,
        Rarity.ANCESTRAL: 12
    }
)

FREE_UTILITY_UPGRADE = SubstatInfo(
    enum_id=41,
    name="Free Utility Upgrade",
    applies_to=ModuleType.GENERATOR,
    unit="%",
    values={
        Rarity.COMMON: 2,
        Rarity.RARE: 4,
        Rarity.EPIC: 6,
        Rarity.LEGENDARY: 8,
        Rarity.MYTHIC: 10,
        Rarity.ANCESTRAL: 12
    }
)

INTEREST_PER_WAVE = SubstatInfo(
    enum_id=42,
    name="Interest Per Wave",
    applies_to=ModuleType.GENERATOR,
    unit="%",
    values={
        Rarity.EPIC: 2,
        Rarity.LEGENDARY: 4,
        Rarity.MYTHIC: 6,
        Rarity.ANCESTRAL: 8
    }
)

RECOVERY_AMOUNT = SubstatInfo(
    enum_id=43,
    name="Recovery Amount",
    applies_to=ModuleType.GENERATOR,
    unit="%",
    values={
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 5,
        Rarity.MYTHIC: 7,
        Rarity.ANCESTRAL: 10
    }
)

MAX_RECOVERY = SubstatInfo(
    enum_id=44,
    name="Max Recovery",
    applies_to=ModuleType.GENERATOR,
    unit="",
    values={
        Rarity.EPIC: 0.4,
        Rarity.LEGENDARY: 0.7,
        Rarity.MYTHIC: 1,
        Rarity.ANCESTRAL: 1.5
    }
)

PACKAGE_CHANCE = SubstatInfo(
    enum_id=45,
    name="Package Chance",
    applies_to=ModuleType.GENERATOR,
    unit="%",
    values={
        Rarity.EPIC: 5,
        Rarity.LEGENDARY: 8,
        Rarity.MYTHIC: 11,
        Rarity.ANCESTRAL: 15
    }
)

ENEMY_ATTACK_LEVEL_SKIP = SubstatInfo(
    enum_id=46,
    name="Enemy Attack Level Skip",
    applies_to=ModuleType.GENERATOR,
    unit="%",
    values={
        Rarity.EPIC: 2,
        Rarity.LEGENDARY: 4,
        Rarity.MYTHIC: 6,
        Rarity.ANCESTRAL: 8
    }
)

ENEMY_HEALTH_LEVEL_SKIP = SubstatInfo(
    enum_id=47,
    name="Enemy Health Level Skip",
    applies_to=ModuleType.GENERATOR,
    unit="%",
    values={
        Rarity.EPIC: 2,
        Rarity.LEGENDARY: 4,
        Rarity.MYTHIC: 6,
        Rarity.ANCESTRAL: 8
    }
)

# Core Substats
CHAIN_LIGHTNING_DAMAGE = SubstatInfo(
    enum_id=48,
    name="Chain Lightning Damage",
    applies_to=ModuleType.CORE,
    unit="x",
    values={
        Rarity.COMMON: 8,
        Rarity.RARE: 15,
        Rarity.EPIC: 25,
        Rarity.LEGENDARY: 50,
        Rarity.MYTHIC: 100,
        Rarity.ANCESTRAL: 250
    }
)

CHAIN_LIGHTNING_QUANTITY = SubstatInfo(
    enum_id=49,
    name="Chain Lightning Quantity",
    applies_to=ModuleType.CORE,
    unit="",
    values={
        Rarity.EPIC: 1,
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 3,
        Rarity.ANCESTRAL: 4
    }
)

CHAIN_LIGHTNING_CHANCE = SubstatInfo(
    enum_id=50,
    name="Chain Lightning Chance",
    applies_to=ModuleType.CORE,
    unit="%",
    values={
        Rarity.COMMON: 2,
        Rarity.RARE: 4,
        Rarity.EPIC: 6,
        Rarity.LEGENDARY: 9,
        Rarity.MYTHIC: 12,
        Rarity.ANCESTRAL: 15
    }
)

SMART_MISSILES_DAMAGE = SubstatInfo(
    enum_id=51,
    name="Smart Missiles Damage",
    applies_to=ModuleType.CORE,
    unit="",
    values={
        Rarity.COMMON: 8,
        Rarity.RARE: 15,
        Rarity.EPIC: 25,
        Rarity.LEGENDARY: 50,
        Rarity.MYTHIC: 100,
        Rarity.ANCESTRAL: 250
    }
)

SMART_MISSILES_QUANTITY = SubstatInfo(
    enum_id=52,
    name="Smart Missiles Quantity",
    applies_to=ModuleType.CORE,
    unit="",
    values={
        Rarity.EPIC: 1,
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 4,
        Rarity.ANCESTRAL: 5
    }
)

SMART_MISSILES_COOLDOWN = SubstatInfo(
    enum_id=53,
    name="Smart Missiles Cooldown",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.LEGENDARY: -2,
        Rarity.MYTHIC: -4,
        Rarity.ANCESTRAL: -6
    }
)

DEATH_WAVE_DAMAGE = SubstatInfo(
    enum_id=54,
    name="Death Wave Damage",
    applies_to=ModuleType.CORE,
    unit="x",
    values={
        Rarity.COMMON: 8,
        Rarity.RARE: 15,
        Rarity.EPIC: 25,
        Rarity.LEGENDARY: 50,
        Rarity.MYTHIC: 100,
        Rarity.ANCESTRAL: 250
    }
)

DEATH_WAVE_QUANTITY = SubstatInfo(
    enum_id=55,
    name="Death Wave Quantity",
    applies_to=ModuleType.CORE,
    unit="",
    values={
        Rarity.LEGENDARY: 1,
        Rarity.MYTHIC: 2,
        Rarity.ANCESTRAL: 3
    }
)

DEATH_WAVE_COOLDOWN = SubstatInfo(
    enum_id=56,
    name="Death Wave Cooldown",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.LEGENDARY: -6,
        Rarity.MYTHIC: -10,
        Rarity.ANCESTRAL: -13
    }
)

CHRONO_FIELD_DURATION = SubstatInfo(
    enum_id=57,
    name="Chrono Field Duration",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.LEGENDARY: 4,
        Rarity.MYTHIC: 7,
        Rarity.ANCESTRAL: 10
    }
)

CHRONO_FIELD_SPEED_REDUCTION = SubstatInfo(
    enum_id=58,
    name="Chrono Field Speed Reduction",
    applies_to=ModuleType.CORE,
    unit="%",
    values={
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 8,
        Rarity.MYTHIC: 11,
        Rarity.ANCESTRAL: 15
    }
)

CHRONO_FIELD_COOLDOWN = SubstatInfo(
    enum_id=59,
    name="Chrono Field Cooldown",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.LEGENDARY: -4,
        Rarity.MYTHIC: -7,
        Rarity.ANCESTRAL: -10
    }
)

INNER_LAND_MINES_DAMAGE = SubstatInfo(
    enum_id=60,
    name="Inner Land Mines Damage",
    applies_to=ModuleType.CORE,
    unit="x",
    values={
        Rarity.COMMON: 8,
        Rarity.RARE: 15,
        Rarity.EPIC: 25,
        Rarity.LEGENDARY: 50,
        Rarity.MYTHIC: 100,
        Rarity.ANCESTRAL: 250
    }
)

INNER_LAND_MINES_QUANTITY = SubstatInfo(
    enum_id=61,
    name="Inner Land Mines Quantity",
    applies_to=ModuleType.CORE,
    unit="",
    values={
        Rarity.LEGENDARY: 1,
        Rarity.MYTHIC: 2,
        Rarity.ANCESTRAL: 3
    }
)

INNER_LAND_MINES_COOLDOWN = SubstatInfo(
    enum_id=62,
    name="Inner Land Mines Cooldown",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.EPIC: -5,
        Rarity.LEGENDARY: -8,
        Rarity.MYTHIC: -10,
        Rarity.ANCESTRAL: -13
    }
)

GOLDEN_TOWER_BONUS = SubstatInfo(
    enum_id=63,
    name="Golden Tower Bonus",
    applies_to=ModuleType.CORE,
    unit="",
    values={
        Rarity.EPIC: 1,
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 3,
        Rarity.ANCESTRAL: 4
    }
)

GOLDEN_TOWER_DURATION = SubstatInfo(
    enum_id=64,
    name="Golden Tower Duration",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 4,
        Rarity.ANCESTRAL: 7
    }
)

GOLDEN_TOWER_COOLDOWN = SubstatInfo(
    enum_id=65,
    name="Golden Tower Cooldown",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.LEGENDARY: -5,
        Rarity.MYTHIC: -8,
        Rarity.ANCESTRAL: -12
    }
)

POISON_SWAMP_DAMAGE = SubstatInfo(
    enum_id=66,
    name="Poison Swamp Damage",
    applies_to=ModuleType.CORE,
    unit="x",
    values={
        Rarity.COMMON: 8,
        Rarity.RARE: 15,
        Rarity.EPIC: 25,
        Rarity.LEGENDARY: 50,
        Rarity.MYTHIC: 100,
        Rarity.ANCESTRAL: 250
    }
)

POISON_SWAMP_DURATION = SubstatInfo(
    enum_id=67,
    name="Poison Swamp Duration",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 5,
        Rarity.ANCESTRAL: 10
    }
)

POISON_SWAMP_COOLDOWN = SubstatInfo(
    enum_id=68,
    name="Poison Swamp Cooldown",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.RARE: -2,
        Rarity.EPIC: -4,
        Rarity.LEGENDARY: -6,
        Rarity.MYTHIC: -8,
        Rarity.ANCESTRAL: -10
    }
)

BLACK_HOLE_SIZE = SubstatInfo(
    enum_id=69,
    name="Black Hole Size",
    applies_to=ModuleType.CORE,
    unit="m",
    values={
        Rarity.COMMON: 2,
        Rarity.RARE: 4,
        Rarity.EPIC: 6,
        Rarity.LEGENDARY: 8,
        Rarity.MYTHIC: 10,
        Rarity.ANCESTRAL: 12
    }
)

BLACK_HOLE_DURATION = SubstatInfo(
    enum_id=70,
    name="Black Hole Duration",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 3,
        Rarity.ANCESTRAL: 4
    }
)

BLACK_HOLE_COOLDOWN = SubstatInfo(
    enum_id=71,
    name="Black Hole Cooldown",
    applies_to=ModuleType.CORE,
    unit="s",
    values={
        Rarity.LEGENDARY: -2,
        Rarity.MYTHIC: -3,
        Rarity.ANCESTRAL: -4
    }
)

SPOTLIGHT_BONUS = SubstatInfo(
    enum_id=72,
    name="Spotlight Bonus",
    applies_to=ModuleType.CORE,
    unit="",
    values={
        Rarity.COMMON: 1.2,
        Rarity.RARE: 2.5,
        Rarity.EPIC: 3.5,
        Rarity.LEGENDARY: 10,
        Rarity.MYTHIC: 15,
        Rarity.ANCESTRAL: 20
    }
)

SPOTLIGHT_ANGLE = SubstatInfo(
    enum_id=73,
    name="Spotlight Angle",
    applies_to=ModuleType.CORE,
    unit="",
    values={
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 6,
        Rarity.MYTHIC: 11,
        Rarity.ANCESTRAL: 15
    }
)

SPOTLIGHT_QUANTITY = SubstatInfo(
    enum_id=74,
    name="Spotlight Quantity",
    applies_to=ModuleType.CORE,
    unit="",
    values={
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 6,
        Rarity.MYTHIC: 11,
        Rarity.ANCESTRAL: 15
    }
)

# All substats list
ALL_SUBSTATS = [
    # Cannon Substats (1-17)
    ATTACK_SPEED, CRITICAL_CHANCE, CRITICAL_FACTOR, ATTACK_RANGE, DAMAGE_PER_METER,
    MULTISHOT_CHANCE, MULTISHOT_TARGETS, RAPID_FIRE_CHANCE, RAPID_FIRE_DURATION,
    BOUNCE_SHOT_CHANCE, BOUNCE_SHOT_TARGETS, BOUNCE_SHOT_RANGE, SUPER_CRITICAL_CHANCE,
    SUPER_CRITICAL_FACTOR, REND_ARMOR_CHANCE, REND_ARMOR_MULT, REND_ARMOR_MAX,

    # Armor Substats (18-34)
    HEALTH_REGEN, DEFENSE_PERCENT, DEFENSE_ABSOLUTE, THORN_DAMAGE, LIFESTEAL,
    KNOCKBACK_CHANCE, KNOCKBACK_FORCE, ORB_SPEED, ORBS, SHOCKWAVE_SIZE,
    SHOCKWAVE_FREQUENCY, LAND_MINE_CHANCE, LAND_MINE_DAMAGE, LAND_MINE_RADIUS,
    DEATH_DEFY, WALL_HEALTH, WALL_REBUILD,

    # Generator Substats (35-47)
    CASH_BONUS, CASH_PER_WAVE, COINS_PER_KILL, COINS_PER_WAVE, FREE_ATTACK_UPGRADE,
    FREE_DEFENSE_UPGRADE, FREE_UTILITY_UPGRADE, INTEREST_PER_WAVE, RECOVERY_AMOUNT,
    MAX_RECOVERY, PACKAGE_CHANCE, ENEMY_ATTACK_LEVEL_SKIP, ENEMY_HEALTH_LEVEL_SKIP,

    # Core Substats (48-74)
    CHAIN_LIGHTNING_DAMAGE, CHAIN_LIGHTNING_QUANTITY, CHAIN_LIGHTNING_CHANCE,
    SMART_MISSILES_DAMAGE, SMART_MISSILES_QUANTITY, SMART_MISSILES_COOLDOWN,
    DEATH_WAVE_DAMAGE, DEATH_WAVE_QUANTITY, DEATH_WAVE_COOLDOWN,
    CHRONO_FIELD_DURATION, CHRONO_FIELD_SPEED_REDUCTION, CHRONO_FIELD_COOLDOWN,
    INNER_LAND_MINES_DAMAGE, INNER_LAND_MINES_QUANTITY, INNER_LAND_MINES_COOLDOWN,
    GOLDEN_TOWER_BONUS, GOLDEN_TOWER_DURATION, GOLDEN_TOWER_COOLDOWN,
    POISON_SWAMP_DAMAGE, POISON_SWAMP_DURATION, POISON_SWAMP_COOLDOWN,
    BLACK_HOLE_SIZE, BLACK_HOLE_DURATION, BLACK_HOLE_COOLDOWN,
    SPOTLIGHT_BONUS, SPOTLIGHT_ANGLE, SPOTLIGHT_QUANTITY
]
