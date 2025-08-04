"""
Modern Module Simulator using the new structured data system.

This demonstrates how to use the new GameDataManager and dataclasses
for module simulation instead of the legacy YAML-based approach.
"""

import random
import structlog
from typing import List, Set, Optional, Dict, Any
import numpy as np
from dataclasses import dataclass

from .game_data.modules._enums import Rarity, ModuleType, Substat
from .game_data.modules._probabilities import (
    MODULE_PULL_CHANCES, 
    SUBSTAT_PULL_CHANCES, 
    EPIC_PITY_PULL_COUNT,
    REROLL_COSTS
)
from .game_data.modules import _substats, _definitions, _module_catalog
from .game_data.modules.module_dataclass import RarityInfo, SubstatInfo, UniqueEffectInfo, ModuleDefinition

logger = structlog.get_logger()

@dataclass
class ModuleInstance:
    """
    A module instance using the new structured approach.
    This replaces the legacy Module class with proper types.
    """
    # Core identification
    guid: str
    name: str
    module_type: ModuleType
    rarity: Rarity
    level: int
    
    # Substats (now properly typed)
    substat_enum_ids: List[int]
    substat_rarities: List[Rarity]
    
    # Unique effect (for Epic+ modules)
    unique_effect: Optional[UniqueEffectInfo] = None
    
    # Progression
    coins_spent: int = 0
    shards_spent: int = 0
    
    # Status
    is_equipped: bool = False
    is_favorite: bool = False
    
    # UI
    frame_sprite: Optional[str] = None
    icon_sprite: Optional[str] = None
    
    def __post_init__(self):
        """Validate the module instance after creation."""
        if len(self.substat_enum_ids) != len(self.substat_rarities):
            raise ValueError("substat_enum_ids and substat_rarities must have same length")
    
    @property
    def substats(self) -> List[Dict[str, Any]]:
        """Get formatted substat data (for compatibility with legacy code)."""
        substats = []
        
        # Create lookup dict from ALL_SUBSTATS
        substat_lookup = {s.enum_id: s for s in _substats.ALL_SUBSTATS}
        
        for i, (enum_id, substat_rarity) in enumerate(zip(self.substat_enum_ids, self.substat_rarities)):
            substat_info = substat_lookup.get(enum_id)
            if not substat_info:
                logger.warning("Unknown substat", enum_id=enum_id)
                continue
                
            substat_data = {
                'index': i,
                'enum_id': enum_id,
                'name': substat_info.name.replace('_', ' '),
                'value': substat_info.values.get(substat_rarity),
                'unit': substat_info.unit,
                'rarity': substat_rarity.value,  # Convert enum to string
                'is_locked': False
            }
            substats.append(substat_data)
        
        return substats


class ModernModuleSimulator:
    """
    New module simulator using the structured data system.
    """
    
    def __init__(self):
        # Use the organized module definitions from _definitions module
        self.module_definitions_by_type = _definitions.MODULES_BY_TYPE
        
        # Build substats lookup by module type
        self.substats_by_type = {
            module_type: [s for s in _substats.ALL_SUBSTATS if s.applies_to == module_type]
            for module_type in ModuleType
        }
        
    def simulate_module_pull(self, current_pity: int = 0) -> ModuleInstance:
        """
        Simulate a module pull using the new data structures.
        
        Args:
            current_pity: Current pity counter for epic guarantee
            
        Returns:
            ModuleInstance with generated stats
        """
        # Step 1: Determine rarity (with pity system)
        rarity = self._roll_module_rarity(current_pity)
        
        # Step 2: Determine module type
        module_type = self._roll_module_type()
        
        # Step 3: Pick specific module name and unique effect
        module_definition = None
        unique_effect = None
        
        if rarity == Rarity.EPIC:
            # Epic modules get a natural epic definition with unique effect
            available_definitions = self.module_definitions_by_type.get(module_type, [])
            if available_definitions:
                module_definition = random.choice(available_definitions)
                module_name = module_definition.name
                unique_effect = module_definition.unique_effect
            else:
                module_name = f"Generic Epic {module_type.value.title()}"
        else:
            # Common/Rare modules use realistic names from catalog (no unique effects)
            # Respect rarity constraints - each module has a max rarity it can naturally achieve
            valid_modules = _module_catalog.get_modules_for_rarity_and_type(rarity, module_type)
            if valid_modules:
                module_name = random.choice(valid_modules)
            else:
                # Fallback to generic name if no valid modules for this rarity/type
                module_name = f"Generic {rarity.value} {module_type.value.title()}"
        
        # Step 4: Determine number of substats based on rarity
        num_substats = self._get_substat_count_for_rarity(rarity)
        
        # Step 5: Roll substats
        substat_enum_ids, substat_rarities = self._roll_substats(
            module_type, rarity, num_substats
        )
        
        # Step 6: Create module instance
        return ModuleInstance(
            guid=f"module_{random.randint(100000, 999999)}",
            name=module_name,
            module_type=module_type,
            rarity=rarity,
            level=1,
            substat_enum_ids=substat_enum_ids,
            substat_rarities=substat_rarities,
            unique_effect=unique_effect,
            coins_spent=0,
            shards_spent=0,
            is_equipped=False,
            is_favorite=False
        )
    
    def simulate_substat_reroll(self, module: ModuleInstance, substat_index: int) -> Rarity:
        """
        Simulate rerolling a specific substat's rarity.
        
        Args:
            module: The module to reroll a substat for
            substat_index: Which substat to reroll (0-based)
            
        Returns:
            New rarity for the substat
        """
        if substat_index >= len(module.substat_rarities):
            raise ValueError(f"Invalid substat index: {substat_index}")
        
        # Use the module's rarity as ceiling for reroll
        return self._roll_substat_rarity_with_ceiling(module.rarity)
    
    def _roll_module_rarity(self, current_pity: int) -> Rarity:
        """Roll module rarity with pity system."""
        if current_pity >= EPIC_PITY_PULL_COUNT:
            return Rarity.EPIC
        
        # Roll against pull chances
        roll = random.random()
        cumulative = 0.0
        
        for rarity, chance in MODULE_PULL_CHANCES.items():
            cumulative += chance
            if roll < cumulative:
                return rarity
        
        # Fallback to common if something goes wrong
        return Rarity.COMMON
    
    def _roll_module_type(self) -> ModuleType:
        """Roll a random module type."""
        return random.choice(list(ModuleType))
    
    def _get_substat_count_for_rarity(self, rarity: Rarity) -> int:
        """Get number of substats based on module rarity."""
        if rarity == Rarity.COMMON:
            return 1
        elif rarity in [Rarity.RARE, Rarity.EPIC]:
            return 2
        else:
            # Higher rarities (shouldn't happen in purchased modules)
            return 2
    
    def _roll_substats(self, module_type: ModuleType, module_rarity: Rarity, count: int) -> tuple[List[int], List[Rarity]]:
        """
        Roll substats for a module.
        
        Returns:
            Tuple of (substat_enum_ids, substat_rarities)
        """
        substat_enum_ids = []
        substat_rarities = []
        excluded_substats = set()
        
        # Get available substats for this module type
        available_substats = self.substats_by_type.get(module_type, [])
        
        for i in range(count):
            # Roll substat rarity (with module rarity as ceiling)
            substat_rarity = self._roll_substat_rarity_with_ceiling(module_rarity)
            
            # Roll specific substat
            substat_info = self._roll_specific_substat(
                available_substats, substat_rarity, excluded_substats
            )
            
            if substat_info:
                substat_enum_ids.append(substat_info.enum_id)
                substat_rarities.append(substat_rarity)
                excluded_substats.add(substat_info.enum_id)
            else:
                logger.warning("Failed to roll substat", 
                             module_type=module_type, 
                             rarity=substat_rarity, 
                             excluded=excluded_substats)
        
        return substat_enum_ids, substat_rarities
    
    def _roll_substat_rarity_with_ceiling(self, ceiling_rarity: Rarity) -> Rarity:
        """
        Roll substat rarity with module rarity as ceiling.
        """
        # Get valid rarities (up to ceiling)
        all_rarities = list(SUBSTAT_PULL_CHANCES.keys())
        ceiling_index = all_rarities.index(ceiling_rarity)
        valid_rarities = all_rarities[:ceiling_index + 1]
        
        # Get weights for valid rarities
        valid_weights = [SUBSTAT_PULL_CHANCES[r] for r in valid_rarities]
        total_weight = sum(valid_weights)
        normalized_weights = [w / total_weight for w in valid_weights]
        
        # Weighted random choice using indices, then map back to enum
        indices = np.arange(len(valid_rarities))
        chosen_index = np.random.choice(indices, p=normalized_weights)
        return valid_rarities[chosen_index]
    
    def _roll_specific_substat(self, available_substats: List[SubstatInfo], 
                              target_rarity: Rarity, 
                              excluded_ids: Set[int]) -> Optional[SubstatInfo]:
        """
        Roll a specific substat from available options.
        """
        # Filter substats that:
        # 1. Have values for the target rarity
        # 2. Are not already excluded
        candidates = []
        for substat in available_substats:
            if (substat.enum_id not in excluded_ids and 
                target_rarity in substat.values):
                candidates.append(substat)
        
        if not candidates:
            return None
        
        # Uniform random choice for now
        # TODO: Could implement weighted selection here
        return random.choice(candidates)


# =============================================================================
# DEMO AND TESTING FUNCTIONS
# =============================================================================

def demo_new_system():
    """Demonstrate the new module simulation system."""
    print("=== Modern Module Simulator Demo ===\n")
    
    simulator = ModernModuleSimulator()
    
    # Simulate a few module pulls
    for i in range(5):
        print(f"Pull #{i+1}:")
        module = simulator.simulate_module_pull()
        
        print(f"  Module: {module.name}")
        print(f"  Type: {module.module_type.value}")
        print(f"  Rarity: {module.rarity.value}")
        print(f"  Substats:")
        
        for substat in module.substats:
            print(f"    - {substat['name']} ({substat['rarity']}): "
                  f"{substat['value']}{substat['unit']}")
        
        # Show unique effect if Epic
        if module.unique_effect:
            print(f"  Unique Effect: {module.unique_effect.name}")
            print(f"    Effect: {module.unique_effect.effect_template}")
        
        print()
    
    print("=== Substat Reroll Demo ===")
    
    # Demo rerolling
    module = simulator.simulate_module_pull()
    print(f"Original module: {module.name} ({module.rarity.value})")
    print("Original substats:")
    for i, substat in enumerate(module.substats):
        print(f"  {i}: {substat['name']} ({substat['rarity']})")
    
    # Reroll first substat
    if module.substats:
        new_rarity = simulator.simulate_substat_reroll(module, 0)
        print(f"\nRerolled substat 0 to: {new_rarity.value}")


def compare_systems():
    """Compare legacy vs new system output."""
    print("=== System Comparison ===\n")
    
    # Legacy system (if it works)
    try:
        from .module_simulator import simulate_module_pull as legacy_pull
        legacy_module = legacy_pull(0)
        print("Legacy System Output:")
        print(f"  Type: {legacy_module.module_type}")
        print(f"  Rarity: {legacy_module.rarity}")
        print(f"  Substats: {len(legacy_module.substats)}")
        print()
    except Exception as e:
        print(f"Legacy system error: {e}\n")
    
    # New system
    simulator = ModernModuleSimulator()
    modern_module = simulator.simulate_module_pull()
    print("Modern System Output:")
    print(f"  Type: {modern_module.module_type.value}")
    print(f"  Rarity: {modern_module.rarity.value}")
    print(f"  Substats: {len(modern_module.substats)}")
    print()


if __name__ == "__main__":
    demo_new_system()
    print("\n" + "="*50 + "\n")
    compare_systems()