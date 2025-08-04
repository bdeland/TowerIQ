"""
This file serves as the central registry for all Natural Epic module definitions.

Each definition represents a specific natural epic module type (like "Death Penalty" 
or "Astral Deliverance") that can be pulled when an Epic rarity is rolled.
These are the "blueprints" that get instantiated into actual ModuleInstance objects.
"""

from ._enums import ModuleType, Rarity, MaxLevel
from .module_dataclass import ModuleDefinition

# Import the defined substats and unique effects using a clear namespace
from . import _substats as substats
from . import _unique_effects as u_effects

# No need for max level mapping - it's calculated automatically from rarity!

# --------------------------------------------------------------------------
# CANNON MODULE DEFINITIONS
# --------------------------------------------------------------------------

DEATH_PENALTY = ModuleDefinition(
    name="Death Penalty",
    module_type=ModuleType.CANNON,
    rarity=Rarity.EPIC,
    is_natural_epic=True,
    unique_effect=u_effects.DEATH_PENALTY,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
)

ASTRAL_DELIVERANCE = ModuleDefinition(
    name="Astral Deliverance",
    module_type=ModuleType.CANNON,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.ASTRAL_DELIVERANCE,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
)

BEING_ANNIHILATOR = ModuleDefinition(
    name="Being Annihilator",
    module_type=ModuleType.CANNON,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.BEING_ANNIHILATOR,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
)

HAVOC_BRINGER = ModuleDefinition(
    name="Havoc Bringer",
    module_type=ModuleType.CANNON,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.HAVOC_BRINGER,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
)

# --------------------------------------------------------------------------
# ARMOR MODULE DEFINITIONS
# --------------------------------------------------------------------------

ANTI_CUBE_PORTAL = ModuleDefinition(
    name="Anti-Cube Portal",
    module_type=ModuleType.ARMOR,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.ANTI_CUBE_PORTAL,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
)

WORMHOLE_REDIRECTOR = ModuleDefinition(
    name="Wormhole Redirector",
    module_type=ModuleType.ARMOR,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.WORMHOLE_REDIRECTOR,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
)

NEGATIVE_MASS_PROJECTOR = ModuleDefinition(
    name="Negative Mass Projector",
    module_type=ModuleType.ARMOR,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.NEGATIVE_MASS_PROJECTOR,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
)

SPACE_DISPLACER = ModuleDefinition(
    name="Space Displacer",
    module_type=ModuleType.ARMOR,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.SPACE_DISPLACER,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
)

# --------------------------------------------------------------------------
# CORE MODULE DEFINITIONS
# --------------------------------------------------------------------------

DIMENSION_CORE = ModuleDefinition(
    name="Dimension Core",
    module_type=ModuleType.CORE,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.DIMENSION_CORE,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
)

MULTIVERSE_NEXUS = ModuleDefinition(
    name="Multiverse Nexus",
    module_type=ModuleType.CORE,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.MULTIVERSE_NEXUS,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
)

HARMONY_CONDUCTOR = ModuleDefinition(
    name="Harmony Conductor",
    module_type=ModuleType.CORE,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.HARMONY_CONDUCTOR,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
)

MAGNETIC_HOOK = ModuleDefinition(
    name="Magnetic Hook",
    module_type=ModuleType.CORE,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.MAGNETIC_HOOK,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
)

# --------------------------------------------------------------------------
# GENERATOR MODULE DEFINITIONS
# --------------------------------------------------------------------------

GALAXY_COMPRESSOR = ModuleDefinition(
    name="Galaxy Compressor",
    module_type=ModuleType.GENERATOR,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.GALAXY_COMPRESSOR,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
)

PROJECT_FUNDING = ModuleDefinition(
    name="Project Funding",
    module_type=ModuleType.GENERATOR,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.PROJECT_FUNDING,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
)

SHARP_FORTITUDE = ModuleDefinition(
    name="Sharp Fortitude",
    module_type=ModuleType.GENERATOR,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.SHARP_FORTITUDE,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
)

SHRINK_RAY = ModuleDefinition(
    name="Shrink Ray",
    module_type=ModuleType.GENERATOR,
    rarity=Rarity.EPIC,

    is_natural_epic=True,
    unique_effect=u_effects.SHRINK_RAY,
    possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
)

# ==========================================================================
# MASTER LIST OF ALL MODULE DEFINITIONS
# ==========================================================================

ALL_MODULES = [
    # Cannon Modules (4)
    DEATH_PENALTY,
    ASTRAL_DELIVERANCE,
    BEING_ANNIHILATOR,
    HAVOC_BRINGER,
    
    # Armor Modules (4)
    ANTI_CUBE_PORTAL,
    WORMHOLE_REDIRECTOR,
    NEGATIVE_MASS_PROJECTOR,
    SPACE_DISPLACER,
    
    # Core Modules (4)
    DIMENSION_CORE,
    MULTIVERSE_NEXUS,
    HARMONY_CONDUCTOR,
    MAGNETIC_HOOK,
    
    # Generator Modules (4)
    GALAXY_COMPRESSOR,
    PROJECT_FUNDING,
    SHARP_FORTITUDE,
    SHRINK_RAY,
]

# Organized by module type for easy lookup during simulation
MODULES_BY_TYPE = {
    ModuleType.CANNON: [DEATH_PENALTY, ASTRAL_DELIVERANCE, BEING_ANNIHILATOR, HAVOC_BRINGER],
    ModuleType.ARMOR: [ANTI_CUBE_PORTAL, WORMHOLE_REDIRECTOR, NEGATIVE_MASS_PROJECTOR, SPACE_DISPLACER],
    ModuleType.CORE: [DIMENSION_CORE, MULTIVERSE_NEXUS, HARMONY_CONDUCTOR, MAGNETIC_HOOK],
    ModuleType.GENERATOR: [GALAXY_COMPRESSOR, PROJECT_FUNDING, SHARP_FORTITUDE, SHRINK_RAY],
}