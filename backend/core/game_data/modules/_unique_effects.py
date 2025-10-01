"""
This file defines the static data for all Unique Module Effects.

Each constant is an instance of the UniqueEffectInfo dataclass, providing
structured, type-safe information about the effect's name, template,
values per rarity, and applicable module type. These objects are then
composed into the main ModuleDefinition objects.
"""

from ._enums import ModuleType, Rarity
from .module_dataclass import UniqueEffectInfo

ANTI_CUBE_PORTAL = UniqueEffectInfo(
    name="Anti-Cube Portal",
    module_type=ModuleType.ARMOR,
    effect_template="Enemies take {X} damage for 7s after they are hit by a shockwave.",
    unit="x",
    values={
        Rarity.EPIC: 10,
        Rarity.LEGENDARY: 15,
        Rarity.MYTHIC: 20,
        Rarity.ANCESTRAL: 25
    }
)

ASTRAL_DELIVERANCE = UniqueEffectInfo(
    name="Astral Deliverance",
    module_type=ModuleType.CANNON,
    effect_template="Bounce Shot's range is increased by 3% of the Tower's total range. Each bounce increases the projectile's damage by {X}.",
    unit="%",
    values={
        Rarity.EPIC: 20,
        Rarity.LEGENDARY: 40,
        Rarity.MYTHIC: 60,
        Rarity.ANCESTRAL: 80
    }
)

BEING_ANNIHILATOR = UniqueEffectInfo(
    name="Being Annihilator",
    module_type=ModuleType.CANNON,
    effect_template="When you super crit, your next {X} shots are guaranteed super crit.",
    unit="",
    values={
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 4,
        Rarity.MYTHIC: 5,
        Rarity.ANCESTRAL: 6
    }
)

BLACK_HOLE_DIGESTOR = UniqueEffectInfo(
    name="Black Hole Digestor",
    module_type=ModuleType.GENERATOR,
    effect_template="Temporarily get {X} extra Coins / Kill Bonus for each free upgrade you got on the current wave. Free Upgrades can not increase Tower Range.",
    unit="%",
    values={
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 5,
        Rarity.MYTHIC: 7,
        Rarity.ANCESTRAL: 10
    }
)

DEATH_PENALTY = UniqueEffectInfo(
    name="Death Penalty",
    module_type=ModuleType.CANNON,
    effect_template="Chance of {X} to mark an enemy for death when it spawns, causing the first hit to destroy it.",
    unit="%",
    values={
        Rarity.EPIC: 5,
        Rarity.LEGENDARY: 8,
        Rarity.MYTHIC: 11,
        Rarity.ANCESTRAL: 15
    }
)

DIMENSION_CORE = UniqueEffectInfo(
    name="Dimension Core",
    module_type=ModuleType.CORE,
    effect_template="Chain Lightning have 60% chance of hitting the initial target. Shock chance and multiplier is doubled. If a shock is applied again to the same enemy the shock multiplier will add up to a max stack of {X}.",
    unit="",
    values={
        Rarity.EPIC: 5,
        Rarity.LEGENDARY: 10,
        Rarity.MYTHIC: 15,
        Rarity.ANCESTRAL: 20
    }
)

GALAXY_COMPRESSOR = UniqueEffectInfo(
    name="Galaxy Compressor",
    module_type=ModuleType.GENERATOR,
    effect_template="Collecting a recovery package reduces the cooldown of all Ultimate Weapons except Poison Swamp by {X}.",
    unit="s",
    values={
        Rarity.EPIC: 10,
        Rarity.LEGENDARY: 13,
        Rarity.MYTHIC: 17,
        Rarity.ANCESTRAL: 20
    }
)

HARMONY_CONDUCTOR = UniqueEffectInfo(
    name="Harmony Conductor",
    module_type=ModuleType.CORE,
    effect_template="{X} chance of poisoned enemies to miss attack. Boss chance is halved.",
    unit="%",
    values={
        Rarity.EPIC: 15,
        Rarity.LEGENDARY: 20,
        Rarity.MYTHIC: 25,
        Rarity.ANCESTRAL: 30
    }
)

HAVOC_BRINGER = UniqueEffectInfo(
    name="Havoc Bringer",
    module_type=ModuleType.CANNON,
    effect_template="{X} chance for Rend Armor to instantly go to max.",
    unit="%",
    values={
        Rarity.EPIC: 10,
        Rarity.LEGENDARY: 13,
        Rarity.MYTHIC: 15,
        Rarity.ANCESTRAL: 20
    }
)

MAGNETIC_HOOK = UniqueEffectInfo(
    name="Magnetic Hook",
    module_type=ModuleType.CORE,
    effect_template="{X} Inner Land Mines are fired at Bosses as they enter Tower range. 25% of Elites have Inner Land Mines fired at them as they enter Tower range.",
    unit="",
    values={
        Rarity.EPIC: 1,
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 3,
        Rarity.ANCESTRAL: 4
    }
)

MULTIVERSE_NEXUS = UniqueEffectInfo(
    name="Multiverse Nexus",
    module_type=ModuleType.CORE,
    effect_template="Death Wave, Golden Tower and Black Hole will always activate at the same time, but the cooldown will be the average of those {X}.",
    unit="",
    values={
        Rarity.EPIC: 20,
        Rarity.LEGENDARY: 10,
        Rarity.MYTHIC: 1,
        Rarity.ANCESTRAL: -10
    }
)

NEGATIVE_MASS_PROJECTOR = UniqueEffectInfo(
    name="Negative Mass Projector",
    module_type=ModuleType.ARMOR,
    effect_template="Enemies take {X} damage for 7s after they are hit by a shockwave.",
    unit="x",
    values={
        Rarity.EPIC: 1,
        Rarity.LEGENDARY: 1.5,
        Rarity.MYTHIC: 2,
        Rarity.ANCESTRAL: 2.5
    }
)

OM_CHIP = UniqueEffectInfo(
    name="Om Chip",
    module_type=ModuleType.CORE,
    effect_template="Spotlight will rotate to focus a boss. This effect can only happen again after {X} bosses.",
    unit="",
    values={
        Rarity.EPIC: 3,
        Rarity.LEGENDARY: 2,
        Rarity.MYTHIC: 1,
        Rarity.ANCESTRAL: 0
    }
)

PROJECT_FUNDING = UniqueEffectInfo(
    name="Project Funding",
    module_type=ModuleType.GENERATOR,
    effect_template="Tower damage is multiplied by {X} of the number of digits in your current cash.",
    unit="%",
    values={
        Rarity.EPIC: 12.5,
        Rarity.LEGENDARY: 25,
        Rarity.MYTHIC: 50,
        Rarity.ANCESTRAL: 100
    }
)

PULSAR_HARVESTER = UniqueEffectInfo(
    name="Pulsar Harvester",
    module_type=ModuleType.GENERATOR,
    effect_template="Each time a projectile hits an enemy, there is a {X} chance that it will reduce the enemy's Health and Attack Level by 1.",
    unit="%",
    values={
        Rarity.EPIC: 1,
        Rarity.LEGENDARY: 1.5,
        Rarity.MYTHIC: 2,
        Rarity.ANCESTRAL: 2.5
    }
)

SHARP_FORTITUDE = UniqueEffectInfo(
    name="Sharp Fortitude",
    module_type=ModuleType.ARMOR,
    effect_template="Increase the Wall's health and regen by {X}. Enemies take +1% increased damage from wall thorns per subsequent hit.",
    unit="%",
    values={
        Rarity.EPIC: 1.25,
        Rarity.LEGENDARY: 1.5,
        Rarity.MYTHIC: 2,
        Rarity.ANCESTRAL: 2.5
    }
)

SHRINK_RAY = UniqueEffectInfo(
    name="Shrink Ray",
    module_type=ModuleType.CANNON,
    effect_template="Attacks have a 1% chance to apply a non-stacking effect that decreases the enemy's mass by {X}.",
    unit="%",
    values={
        Rarity.EPIC: 10,
        Rarity.LEGENDARY: 20,
        Rarity.MYTHIC: 30,
        Rarity.ANCESTRAL: 40
    }
)

SINGULARITY_HARNESS = UniqueEffectInfo(
    name="Singularity Harness",
    module_type=ModuleType.GENERATOR,
    effect_template="Increases the range of each bot by {X}. Enemies hit by the Flame bot receive double damage.",
    unit="m",
    values={
        Rarity.EPIC: 5,
        Rarity.LEGENDARY: 8,
        Rarity.MYTHIC: 11,
        Rarity.ANCESTRAL: 15
    }
)

SPACE_DISPLACER = UniqueEffectInfo(
    name="Space Displacer",
    module_type=ModuleType.ARMOR,
    effect_template="Landmines have a {X} chance of spawning as an Inner Land Mine (20 max) instead of a normal mine. These mines autonomously move and organize around the tower.",
    unit="%",
    values={
        Rarity.EPIC: 10,
        Rarity.LEGENDARY: 15,
        Rarity.MYTHIC: 25,
        Rarity.ANCESTRAL: 30
    }
)

WORMHOLE_REDIRECTOR = UniqueEffectInfo(
    name="Wormhole Redirector",
    module_type=ModuleType.ARMOR,
    effect_template="Health Regen can heal up to {X} of Package Max Recovery.",
    unit="%",
    values={
        Rarity.EPIC: 25,
        Rarity.LEGENDARY: 50,
        Rarity.MYTHIC: 75,
        Rarity.ANCESTRAL: 100
    }
)