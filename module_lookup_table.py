"""
TowerIQ Module Frame and Icon Lookup Table
Generated from analysis of 228 modules from stuff.txt

This module provides lookup functions and data structures for mapping
module types, rarities, and names to their corresponding frame and icon assets.
"""

from typing import Dict, List, Optional, Tuple
from enum import Enum

class ModuleType(Enum):
    """Module types found in the game"""
    ARMOR = "armor"
    CANNON = "cannon" 
    CORE = "core"
    GENERATOR = "generator"

class Rarity(Enum):
    """Module rarities found in the game"""
    COMMON = "common"
    RARE = "rare"
    RARE_PLUS = "rare_plus"
    EPIC = "epic"
    EPIC_PLUS = "epic_plus"
    LEGENDARY = "legendary"
    LEGENDARY_PLUS = "legendary_plus"
    MYTHIC = "mythic"
    MYTHIC_PLUS = "mythic_plus"

# Frame naming pattern: mf_[type]_[rarity]
FRAME_PATTERN = "mf_{type}_{rarity}"

# Standard icon naming pattern: [type]_[rarity]_[number]
ICON_PATTERN = "{type}_{rarity}_{number}"

# Custom icon names that don't follow the standard pattern
CUSTOM_ICONS = {
    "Shrink Ray": "Shrink Ray",
    "Sharp Fortitude": "Sharp Fortitude", 
    "Magnetic Hook": "Magnetic Hook",
    "Project Funding": "Project Funding"
}

# Module name to custom icon mapping
MODULE_TO_CUSTOM_ICON = {
    "Shrink Ray": "Shrink Ray",
    "Sharp Fortitude": "Sharp Fortitude",
    "Magnetic Hook": "Magnetic Hook", 
    "Project Funding": "Project Funding"
}

# Comprehensive module name to icon mapping extracted from stuff.txt
MODULE_TO_ICON = {
    "Anti-Cube Portal": "armor_epic_2",
    "Antimatter Reactor": "generator_rare_4",
    "Astral Deliverance": "cannon_epic_4",
    "Being Annihilator": "cannon_epic_3",
    "Black Hole Digestor": "generator_epic_1",
    "Bounce Blitzer": "cannon_rare_1",
    "Chronosync": "core_rare_1",
    "Death Penalty": "cannon_epic_2",
    "Diamond Nanowall": "armor_rare_4",
    "Dimension Core": "core_epic_2",
    "Energy Barrier": "armor_common_1",
    "Energy Cannon": "cannon_common_1",
    "Energy Chip": "core_common_1",
    "Energy Converter": "generator_common_2",
    "Eon Mind": "core_rare_2",
    "Galactic Librarian": "core_rare_3",
    "Galaxy Compressor": "generator_epic_3",
    "Harmony Conductor": "core_epic_3",
    "Havoc Bringer": "cannon_epic_1",
    "Magnetic Hook": "Magnetic Hook",
    "Matrix Sim": "core_rare_4",
    "Matter Barrier": "armor_common_2",
    "Matter Cannon": "cannon_common_2",
    "Matter Chip": "core_common_2",
    "Matter Converter": "generator_common_1",
    "Multiverse Nexus": "core_epic_1",
    "Nano Intercept": "armor_rare_1",
    "Negative Mass Projector": "armor_epic_4",
    "Om Chip": "core_epic_4",
    "Omniboost Blitzer": "cannon_rare_4",
    "Orbital Sail": "generator_rare_2",
    "Photon Counter": "armor_rare_2",
    "Project Funding": "Project Funding",
    "Pulsar Harvester": "generator_epic_2",
    "Rapidreach Blitzer": "cannon_rare_3",
    "Sharp Fortitude": "Sharp Fortitude",
    "Shrink Ray": "Shrink Ray",
    "Singularity Harness": "generator_epic_4",
    "Solar Dyson Sphere": "generator_rare_3",
    "Solar Reflector": "armor_rare_3",
    "Space Displacer": "armor_epic_3",
    "Stellar Lift": "generator_rare_1",
    "Swiftstrike Blitzer": "cannon_rare_2",
    "Wormhole Redirector": "armor_epic_1",
}

def get_frame_name(module_type: ModuleType, rarity: Rarity) -> str:
    """
    Generate frame name based on module type and rarity.
    
    Args:
        module_type: The type of module (armor, cannon, core, generator)
        rarity: The rarity of the module
        
    Returns:
        Frame asset name following the pattern mf_[type]_[rarity]
    """
    return FRAME_PATTERN.format(type=module_type.value, rarity=rarity.value)

def get_standard_icon_name(module_type: ModuleType, rarity: Rarity, number: int) -> str:
    """
    Generate standard icon name based on module type, rarity, and number.
    
    Args:
        module_type: The type of module (armor, cannon, core, generator)
        rarity: The rarity of the module (common, rare, epic only for standard icons)
        number: The icon number (1-4)
        
    Returns:
        Icon asset name following the pattern [type]_[rarity]_[number]
    """
    if rarity not in [Rarity.COMMON, Rarity.RARE, Rarity.EPIC]:
        raise ValueError(f"Standard icons only support common, rare, and epic rarities, got {rarity}")
    
    if not 1 <= number <= 4:
        raise ValueError(f"Icon number must be between 1 and 4, got {number}")
    
    return ICON_PATTERN.format(type=module_type.value, rarity=rarity.value, number=number)

def get_icon_name(module_name: str) -> Optional[str]:
    """
    Get icon name for a specific module.
    
    Args:
        module_name: The name of the module
        
    Returns:
        Icon asset name for the module, None if not found
    """
    return MODULE_TO_ICON.get(module_name)

def get_custom_icon_name(module_name: str) -> Optional[str]:
    """
    Get custom icon name for modules that don't follow the standard pattern.
    
    Args:
        module_name: The name of the module
        
    Returns:
        Custom icon name if the module has one, None otherwise
    """
    return MODULE_TO_CUSTOM_ICON.get(module_name)

def get_all_possible_frames() -> List[str]:
    """
    Generate all possible frame names based on the pattern.
    
    Returns:
        List of all possible frame asset names
    """
    frames = []
    for module_type in ModuleType:
        for rarity in Rarity:
            frames.append(get_frame_name(module_type, rarity))
    return frames

def get_all_possible_standard_icons() -> List[str]:
    """
    Generate all possible standard icon names based on the pattern.
    
    Returns:
        List of all possible standard icon asset names
    """
    icons = []
    for module_type in ModuleType:
        for rarity in [Rarity.COMMON, Rarity.RARE, Rarity.EPIC]:
            for number in range(1, 5):
                icons.append(get_standard_icon_name(module_type, rarity, number))
    return icons

def get_all_possible_icons() -> List[str]:
    """
    Get all possible icon names (standard + custom).
    
    Returns:
        List of all possible icon asset names
    """
    standard_icons = get_all_possible_standard_icons()
    custom_icons = list(CUSTOM_ICONS.values())
    return standard_icons + custom_icons

def get_all_module_names() -> List[str]:
    """
    Get all module names from the lookup table.
    
    Returns:
        List of all module names
    """
    return list(MODULE_TO_ICON.keys())

def get_icon_usage_breakdown() -> Dict[str, List[str]]:
    """
    Get a breakdown of which modules use each icon.
    
    Returns:
        Dictionary mapping icon names to lists of module names that use them
    """
    icon_usage = {}
    for module_name, icon in MODULE_TO_ICON.items():
        if icon not in icon_usage:
            icon_usage[icon] = []
        icon_usage[icon].append(module_name)
    return icon_usage

# Example usage and validation data from stuff.txt
EXAMPLE_MODULES = [
    # Frame: mf_armor_epic_plus, Icon: armor_rare_1
    {"name": "Nano Intercept", "type": ModuleType.ARMOR, "rarity": Rarity.EPIC_PLUS, "icon": "armor_rare_1"},
    
    # Frame: mf_core_legendary_plus, Icon: generator_epic_4  
    {"name": "Singularity Harness", "type": ModuleType.CORE, "rarity": Rarity.LEGENDARY_PLUS, "icon": "generator_epic_4"},
    
    # Frame: mf_cannon_epic_plus, Icon: Shrink Ray (custom)
    {"name": "Shrink Ray", "type": ModuleType.CANNON, "rarity": Rarity.EPIC_PLUS, "icon": "Shrink Ray"},
    
    # Frame: mf_armor_legendary_plus, Icon: Sharp Fortitude (custom)
    {"name": "Sharp Fortitude", "type": ModuleType.ARMOR, "rarity": Rarity.LEGENDARY_PLUS, "icon": "Sharp Fortitude"},
    
    # Frame: mf_generator_epic_plus, Icon: Magnetic Hook (custom)
    {"name": "Magnetic Hook", "type": ModuleType.GENERATOR, "rarity": Rarity.EPIC_PLUS, "icon": "Magnetic Hook"},
    
    # Frame: mf_core_epic, Icon: Project Funding (custom)
    {"name": "Project Funding", "type": ModuleType.CORE, "rarity": Rarity.EPIC, "icon": "Project Funding"},
]

def validate_patterns():
    """
    Validate that the patterns match the examples from stuff.txt
    """
    print("Validating frame and icon patterns...")
    
    for example in EXAMPLE_MODULES:
        expected_frame = f"mf_{example['type'].value}_{example['rarity'].value}"
        actual_icon = get_icon_name(example['name'])
        print(f"Module: {example['name']}")
        print(f"  Expected Frame: {expected_frame}")
        print(f"  Expected Icon: {example['icon']}")
        print(f"  Actual Icon: {actual_icon}")
        print(f"  Match: {actual_icon == example['icon']}")
        print()

def print_icon_usage_summary():
    """
    Print a summary of icon usage
    """
    icon_usage = get_icon_usage_breakdown()
    
    print("Icon usage summary:")
    for icon, modules in sorted(icon_usage.items()):
        print(f"  {icon}: {len(modules)} module(s)")
        if len(modules) > 1:
            print(f"    Used by: {', '.join(modules)}")

if __name__ == "__main__":
    validate_patterns()
    print_icon_usage_summary()
    
    print(f"\nTotal modules: {len(get_all_module_names())}")
    print(f"Total unique icons: {len(set(MODULE_TO_ICON.values()))}")
    print(f"Total possible frames: {len(get_all_possible_frames())}")
    print(f"Total possible standard icons: {len(get_all_possible_standard_icons())}")
    print(f"Total custom icons: {len(CUSTOM_ICONS)}") 