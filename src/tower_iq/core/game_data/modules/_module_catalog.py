"""
Complete module catalog containing all modules that can be pulled in the game.

Modules are organized by their MAXIMUM achievable rarity:
- COMMON_ONLY: Can only be pulled at Common rarity
- RARE_MAX: Can be pulled at Rare (and maybe Common), but never Epic naturally  
- EPIC_NATURAL: Natural epics with unique effects (handled by _definitions.py)

Based on actual game data from stuff.txt analysis.
"""

from ._enums import ModuleType, Rarity
from typing import Dict, List, Set

# ==========================================================================
# MODULES BY MAXIMUM RARITY AND TYPE
# ==========================================================================

# Modules that can ONLY be Common rarity
COMMON_ONLY_MODULES = {
    ModuleType.CANNON: [
        "Energy Cannon",
        "Matter Cannon",
    ],
    ModuleType.ARMOR: [
        "Energy Barrier",
        "Matter Barrier",
    ],
    ModuleType.CORE: [
        "Energy Chip",
        "Matter Chip",
    ],
    ModuleType.GENERATOR: [
        "Energy Converter",
        "Matter Converter",
    ],
}

# Modules that can be Rare (and possibly Common), but NOT Epic naturally
RARE_MAX_MODULES = {
    ModuleType.CANNON: [
        "Bounce Blitzer",  
        "Omniboost Blitzer",
        "Rapidreach Blitzer",
        "Swiftstrike Blitzer",
    ],
    ModuleType.ARMOR: [
        "Diamond Nanowall", 
        "Nano Intercept", 
        "Photon Counter",  
        "Solar Reflector",
    ],
    ModuleType.CORE: [
        "Chronosync",  
        "Eon Mind",   
        "Galactic Librarian",
        "Matrix Sim",   
    ],
    ModuleType.GENERATOR: [
        "Antimatter Reactor",
        "Orbital Sail",
        "Solar Dyson Sphere",
        "Stellar Lift",
    ],
}

# ==========================================================================
# PUBLIC API FUNCTIONS
# ==========================================================================

def get_modules_for_rarity_and_type(rarity: Rarity, module_type: ModuleType) -> List[str]:
    """
    Get list of module names that can be pulled at the given rarity and type.
    
    Args:
        rarity: The rarity being pulled (Common/Rare/Epic)
        module_type: The module type being pulled
        
    Returns:
        List of valid module names for this rarity/type combination
        
    Note: Epic rarity should use natural epic definitions, not this function
    """
    valid_modules = []
    
    if rarity == Rarity.COMMON:
        # Common pulls can get Common-only modules
        valid_modules.extend(COMMON_ONLY_MODULES.get(module_type, []))
        
    elif rarity == Rarity.RARE:
        # Rare pulls can get Rare-max modules (but not Common-only)
        valid_modules.extend(RARE_MAX_MODULES.get(module_type, []))
        
    # Epic rarity should use natural epic definitions from _definitions.py
    
    return valid_modules

def get_common_only_modules(module_type: ModuleType) -> List[str]:
    """Get modules that can only be pulled at Common rarity."""
    return COMMON_ONLY_MODULES.get(module_type, []).copy()

def get_rare_max_modules(module_type: ModuleType) -> List[str]:
    """Get modules that can be pulled at Rare (but not Common-only or natural Epic)."""
    return RARE_MAX_MODULES.get(module_type, []).copy()

def get_all_regular_modules_by_type() -> Dict[ModuleType, List[str]]:
    """Get all regular (non-epic) modules organized by type."""
    all_modules = {}
    
    for module_type in ModuleType:
        all_modules[module_type] = (
            COMMON_ONLY_MODULES.get(module_type, []) + 
            RARE_MAX_MODULES.get(module_type, [])
        )
    
    return all_modules

def get_total_module_count() -> int:
    """Get total count of regular (non-epic) modules."""
    total = 0
    for module_type in ModuleType:
        total += len(COMMON_ONLY_MODULES.get(module_type, []))
        total += len(RARE_MAX_MODULES.get(module_type, []))
    return total

# ==========================================================================
# STATISTICS (for debugging - call functions manually if needed)
# ==========================================================================

def print_catalog_statistics():
    """Print module catalog statistics for debugging."""
    print(f"Module Catalog Statistics:")
    
    for module_type in ModuleType:
        common_count = len(COMMON_ONLY_MODULES.get(module_type, []))
        rare_count = len(RARE_MAX_MODULES.get(module_type, []))
        total_count = common_count + rare_count
        
        print(f"  {module_type.value.title()}: {total_count} modules")
        print(f"    - Common-only: {common_count}")
        print(f"    - Rare-max: {rare_count}")
    
    print(f"  Total Regular: {get_total_module_count()} modules")
    print(f"  (Plus 16 Natural Epics with unique effects)")