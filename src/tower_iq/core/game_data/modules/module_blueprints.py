"""
Comprehensive Module Blueprint System

This file combines all module aspects into a unified blueprint system:
- Module definitions (name, type, rarity, max rarity)
- Sprite information (frame, icon)
- Unique effects (for natural epics)
- Substats and progression rules
- Pull mechanics and rarity constraints

This replaces the need for separate _definitions.py, _module_catalog.py, and _sprites.py files.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum

from ._enums import ModuleType, Rarity, RARITY_TO_MAX_LEVEL
from .module_dataclass import UniqueEffectInfo, SubstatInfo
from . import _substats as substats
from . import _unique_effects as u_effects

@dataclass
class ModuleBlueprint:
    """
    Complete blueprint for a module type.
    
    This contains all the information needed to:
    - Generate module instances
    - Display modules in the UI
    - Handle pull mechanics
    - Manage progression and substats
    """
    # Core identification
    name: str
    module_type: ModuleType
    
    # Rarity information
    natural_rarity: Rarity  # The rarity this module is naturally pulled at
    
    # Sprite information
    icon_name: str         # Icon asset name
    
    # Unique effect (for natural epics)
    unique_effect: Optional[UniqueEffectInfo] = None
    
    # Substats and progression
    possible_substats: List[SubstatInfo] = field(default_factory=list)
    
    @property
    def is_natural_epic(self) -> bool:
        """Whether this is a natural epic module with unique effects."""
        return self.natural_rarity == Rarity.EPIC and self.unique_effect is not None
    
    @property
    def max_rarity(self) -> Rarity:
        """
        Get the maximum rarity this module can achieve through progression.
        
        Rules:
        - Common modules can only ever be Common
        - Natural Rare modules can progress up to Legendary+
        - Natural Epic modules can progress up to Ancestral5
        """
        if self.natural_rarity == Rarity.COMMON:
            return Rarity.COMMON
        elif self.natural_rarity == Rarity.RARE:
            return Rarity.LEGENDARY_PLUS
        elif self.natural_rarity == Rarity.EPIC:
            return Rarity.ANCESTRAL5
        else:
            # Fallback for any other natural rarities
            return self.natural_rarity
    
    @property
    def max_level(self) -> int:
        """Get the max level for this module's max rarity."""
        return RARITY_TO_MAX_LEVEL.get(self.max_rarity, 20)
    
    @property
    def frame_pattern(self) -> str:
        """Generate frame pattern based on module type and natural rarity."""
        return f"mf_{self.module_type.value}_{self.natural_rarity.display_name}"
    
    @property
    def substat_count_for_rarity(self) -> Dict[Rarity, int]:
        """Get substat count for each rarity level."""
        return {
            Rarity.COMMON: 1,
            Rarity.RARE: 2,
            Rarity.EPIC: 2,
            Rarity.LEGENDARY: 2,
            Rarity.MYTHIC: 2,
            Rarity.ANCESTRAL: 2,
        }
    
    def get_substat_count(self, rarity: Rarity) -> int:
        """Get number of substats for a specific rarity."""
        return self.substat_count_for_rarity.get(rarity, 2)
    
    def can_be_pulled_at(self, rarity: Rarity) -> bool:
        """
        Check if this module can be pulled at the given rarity.
        
        Logic:
        - Common modules can only be pulled at Common
        - Rare modules can be pulled at Rare (but not Common)
        - Epic modules can be pulled at Epic (but not Common/Rare)
        """
        if rarity == Rarity.COMMON:
            return self.natural_rarity == Rarity.COMMON
        elif rarity == Rarity.RARE:
            return self.natural_rarity == Rarity.RARE
        elif rarity == Rarity.EPIC:
            return self.natural_rarity == Rarity.EPIC
        return False

# =============================================================================
# COMPREHENSIVE MODULE BLUEPRINTS
# =============================================================================

# All module blueprints in a single list
ALL_MODULE_BLUEPRINTS = [
    # Common-only modules (can only be pulled at Common)
    ModuleBlueprint(
        name="Energy Cannon",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.COMMON,
        icon_name="cannon_common_1",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Matter Cannon",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.COMMON,
        icon_name="cannon_common_2",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Energy Barrier",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.COMMON,
        icon_name="armor_common_1",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Matter Barrier",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.COMMON,
        icon_name="armor_common_2",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Energy Chip",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.COMMON,
        icon_name="core_common_1",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Matter Chip",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.COMMON,
        icon_name="core_common_2",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Energy Converter",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.COMMON,
        icon_name="generator_common_2",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
    ModuleBlueprint(
        name="Matter Converter",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.COMMON,
        icon_name="generator_common_1",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
    
    # Rare modules (can be pulled at Rare, but not Common)
    ModuleBlueprint(
        name="Bounce Blitzer",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.RARE,
        icon_name="cannon_rare_1",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Omniboost Blitzer",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.RARE,
        icon_name="cannon_rare_4",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Rapidreach Blitzer",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.RARE,
        icon_name="cannon_rare_3",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Swiftstrike Blitzer",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.RARE,
        icon_name="cannon_rare_2",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Diamond Nanowall",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.RARE,
        icon_name="armor_rare_4",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Nano Intercept",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.RARE,
        icon_name="armor_rare_1",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Photon Counter",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.RARE,
        icon_name="armor_rare_2",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Solar Reflector",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.RARE,
        icon_name="armor_rare_3",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Chronosync",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.RARE,
        icon_name="core_rare_1",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Eon Mind",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.RARE,
        icon_name="core_rare_2",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Galactic Librarian",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.RARE,
        icon_name="core_rare_3",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Matrix Sim",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.RARE,
        icon_name="core_rare_4",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Antimatter Reactor",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.RARE,
        icon_name="generator_rare_4",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
    ModuleBlueprint(
        name="Orbital Sail",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.RARE,
        icon_name="generator_rare_2",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
    ModuleBlueprint(
        name="Solar Dyson Sphere",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.RARE,
        icon_name="generator_rare_3",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
    ModuleBlueprint(
        name="Stellar Lift",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.RARE,
        icon_name="generator_rare_1",
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
    
    # Natural Epic modules (with unique effects)
    ModuleBlueprint(
        name="Death Penalty",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.EPIC,
        icon_name="cannon_epic_2",
        unique_effect=u_effects.DEATH_PENALTY,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Astral Deliverance",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.EPIC,
        icon_name="cannon_epic_4",
        unique_effect=u_effects.ASTRAL_DELIVERANCE,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Being Annihilator",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.EPIC,
        icon_name="cannon_epic_3",
        unique_effect=u_effects.BEING_ANNIHILATOR,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Havoc Bringer",
        module_type=ModuleType.CANNON,
        natural_rarity=Rarity.EPIC,
        icon_name="cannon_epic_1",
        unique_effect=u_effects.HAVOC_BRINGER,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CANNON]
    ),
    ModuleBlueprint(
        name="Anti-Cube Portal",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.EPIC,
        icon_name="armor_epic_2",
        unique_effect=u_effects.ANTI_CUBE_PORTAL,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Wormhole Redirector",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.EPIC,
        icon_name="armor_epic_1",
        unique_effect=u_effects.WORMHOLE_REDIRECTOR,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Negative Mass Projector",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.EPIC,
        icon_name="armor_epic_4",
        unique_effect=u_effects.NEGATIVE_MASS_PROJECTOR,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Space Displacer",
        module_type=ModuleType.ARMOR,
        natural_rarity=Rarity.EPIC,
        icon_name="armor_epic_3",
        unique_effect=u_effects.SPACE_DISPLACER,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.ARMOR]
    ),
    ModuleBlueprint(
        name="Dimension Core",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.EPIC,
        icon_name="core_epic_2",
        unique_effect=u_effects.DIMENSION_CORE,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Multiverse Nexus",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.EPIC,
        icon_name="core_epic_1",
        unique_effect=u_effects.MULTIVERSE_NEXUS,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Harmony Conductor",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.EPIC,
        icon_name="core_epic_3",
        unique_effect=u_effects.HARMONY_CONDUCTOR,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Magnetic Hook",
        module_type=ModuleType.CORE,
        natural_rarity=Rarity.EPIC,
        icon_name="Magnetic Hook",  # Custom icon
        unique_effect=u_effects.MAGNETIC_HOOK,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.CORE]
    ),
    ModuleBlueprint(
        name="Galaxy Compressor",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.EPIC,
        icon_name="generator_epic_3",
        unique_effect=u_effects.GALAXY_COMPRESSOR,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
    ModuleBlueprint(
        name="Project Funding",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.EPIC,
        icon_name="Project Funding",  # Custom icon
        unique_effect=u_effects.PROJECT_FUNDING,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
    ModuleBlueprint(
        name="Sharp Fortitude",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.EPIC,
        icon_name="Sharp Fortitude",  # Custom icon
        unique_effect=u_effects.SHARP_FORTITUDE,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
    ModuleBlueprint(
        name="Shrink Ray",
        module_type=ModuleType.GENERATOR,
        natural_rarity=Rarity.EPIC,
        icon_name="Shrink Ray",  # Custom icon
        unique_effect=u_effects.SHRINK_RAY,
        possible_substats=[s for s in substats.ALL_SUBSTATS if s.applies_to == ModuleType.GENERATOR]
    ),
]

# =============================================================================
# MASTER COLLECTIONS (Generated from ALL_MODULE_BLUEPRINTS)
# =============================================================================

# Organized by module type
BLUEPRINTS_BY_TYPE = {
    ModuleType.CANNON: [bp for bp in ALL_MODULE_BLUEPRINTS if bp.module_type == ModuleType.CANNON],
    ModuleType.ARMOR: [bp for bp in ALL_MODULE_BLUEPRINTS if bp.module_type == ModuleType.ARMOR],
    ModuleType.CORE: [bp for bp in ALL_MODULE_BLUEPRINTS if bp.module_type == ModuleType.CORE],
    ModuleType.GENERATOR: [bp for bp in ALL_MODULE_BLUEPRINTS if bp.module_type == ModuleType.GENERATOR],
}

# Organized by pull rarity
BLUEPRINTS_BY_PULL_RARITY = {
    Rarity.COMMON: [bp for bp in ALL_MODULE_BLUEPRINTS if bp.can_be_pulled_at(Rarity.COMMON)],
    Rarity.RARE: [bp for bp in ALL_MODULE_BLUEPRINTS if bp.can_be_pulled_at(Rarity.RARE)],
    Rarity.EPIC: [bp for bp in ALL_MODULE_BLUEPRINTS if bp.can_be_pulled_at(Rarity.EPIC)],
}

# Name to blueprint lookup
BLUEPRINT_BY_NAME = {bp.name: bp for bp in ALL_MODULE_BLUEPRINTS}

# =============================================================================
# PUBLIC API FUNCTIONS
# =============================================================================

def get_max_rarity_for_natural_rarity(natural_rarity: Rarity) -> Rarity:
    """
    Get the maximum rarity a module can achieve based on its natural rarity.
    
    Rules:
    - Common modules can only ever be Common
    - Natural Rare modules can progress up to Legendary+
    - Natural Epic modules can progress up to Ancestral5
    
    Args:
        natural_rarity: The natural rarity of the module
        
    Returns:
        The maximum rarity the module can achieve through progression
    """
    if natural_rarity == Rarity.COMMON:
        return Rarity.COMMON
    elif natural_rarity == Rarity.RARE:
        return Rarity.LEGENDARY_PLUS
    elif natural_rarity == Rarity.EPIC:
        return Rarity.ANCESTRAL5
    else:
        # Fallback for any other natural rarities
        return natural_rarity

def get_blueprint_by_name(name: str) -> Optional[ModuleBlueprint]:
    """Get a module blueprint by name."""
    return BLUEPRINT_BY_NAME.get(name)

def get_blueprints_for_pull(rarity: Rarity, module_type: ModuleType) -> List[ModuleBlueprint]:
    """
    Get all blueprints that can be pulled at the given rarity and type.
    
    Args:
        rarity: The rarity being pulled
        module_type: The module type being pulled
        
    Returns:
        List of valid blueprints for this pull
    """
    valid_blueprints = []
    
    for blueprint in ALL_MODULE_BLUEPRINTS:
        if (blueprint.module_type == module_type and 
            blueprint.can_be_pulled_at(rarity)):
            valid_blueprints.append(blueprint)
    
    return valid_blueprints

def get_natural_epic_blueprints(module_type: ModuleType) -> List[ModuleBlueprint]:
    """Get all natural epic blueprints for a module type."""
    return [bp for bp in ALL_MODULE_BLUEPRINTS if bp.is_natural_epic and bp.module_type == module_type]

def get_frame_name(module_type: ModuleType, rarity: Rarity) -> str:
    """Generate frame name for a module type and rarity."""
    return f"mf_{module_type.value}_{rarity.display_name}"

def get_all_possible_frames() -> List[str]:
    """Get all possible frame names."""
    frames = []
    for module_type in ModuleType:
        for rarity in Rarity:
            frames.append(get_frame_name(module_type, rarity))
    return frames

def get_all_module_names() -> List[str]:
    """Get all module names."""
    return list(BLUEPRINT_BY_NAME.keys())

def get_blueprint_statistics() -> Dict[str, int]:
    """Get statistics about the blueprint collection."""
    stats = {
        "total_modules": len(ALL_MODULE_BLUEPRINTS),
        "common_modules": len([bp for bp in ALL_MODULE_BLUEPRINTS if bp.natural_rarity == Rarity.COMMON]),
        "rare_modules": len([bp for bp in ALL_MODULE_BLUEPRINTS if bp.natural_rarity == Rarity.RARE]),
        "natural_epics": len([bp for bp in ALL_MODULE_BLUEPRINTS if bp.is_natural_epic]),
    }
    
    for module_type in ModuleType:
        type_count = len(BLUEPRINTS_BY_TYPE[module_type])
        stats[f"{module_type.value}_modules"] = type_count
    
    return stats

# =============================================================================
# VALIDATION AND TESTING
# =============================================================================

def validate_blueprints():
    """Validate that all blueprints are properly configured."""
    print("Validating module blueprints...")
    
    # Check for duplicate names
    names = [bp.name for bp in ALL_MODULE_BLUEPRINTS]
    duplicates = [name for name in set(names) if names.count(name) > 1]
    if duplicates:
        print(f"ERROR: Duplicate module names: {duplicates}")
    else:
        print("✓ No duplicate module names")
    
    # Check that all blueprints have valid pull configurations
    for blueprint in ALL_MODULE_BLUEPRINTS:
        if not any([blueprint.can_be_pulled_at(Rarity.COMMON), 
                   blueprint.can_be_pulled_at(Rarity.RARE), 
                   blueprint.can_be_pulled_at(Rarity.EPIC)]):
            print(f"ERROR: {blueprint.name} has no valid pull rarity")
        else:
            print(f"✓ {blueprint.name} has valid pull configuration")
    
    # Check that natural epics have unique effects
    for blueprint in ALL_MODULE_BLUEPRINTS:
        if blueprint.is_natural_epic and blueprint.unique_effect is None:
            print(f"ERROR: {blueprint.name} is natural epic but has no unique effect")
        elif blueprint.is_natural_epic:
            print(f"✓ {blueprint.name} has unique effect: {blueprint.unique_effect.name if blueprint.unique_effect else 'None'}")

if __name__ == "__main__":
    validate_blueprints()
    
    stats = get_blueprint_statistics()
    print(f"\nBlueprint Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print(f"\nTotal modules: {len(get_all_module_names())}")
    print(f"Total possible frames: {len(get_all_possible_frames())}") 