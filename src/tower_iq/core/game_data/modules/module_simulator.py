"""
Module Simulator

This module provides functions to simulate the creation of modules and their substats
using the existing game logic and constraints. It generates valid modules that match
the limitations and requirements for module pulls.
"""

import random
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from ._enums import ModuleType, Rarity, Substat, MaxLevel, RARITY_HIERARCHY, SUBSTAT_RARITY_TIERS
from ._probabilities import MODULE_PULL_CHANCES, SUBSTAT_PULL_CHANCES
from ._substats import ALL_SUBSTATS
from .module_blueprints import (
    ALL_MODULE_BLUEPRINTS, 
    get_blueprints_for_pull,
    BLUEPRINTS_BY_TYPE
)
from .module_dataclass import SubstatInfo, UniqueEffectInfo, ModuleDefinition


@dataclass
class GeneratedSubstat:
    """Represents a generated substat with its value and rarity."""
    substat_info: SubstatInfo
    rarity: Rarity
    value: float
    
    @property
    def name(self) -> str:
        return self.substat_info.name
    
    @property
    def unit(self) -> str:
        return self.substat_info.unit
    
    @property
    def enum_id(self) -> int:
        return self.substat_info.enum_id


@dataclass
class GeneratedModule:
    """Represents a complete generated module with all properties."""
    name: str
    module_type: ModuleType
    rarity: Rarity
    is_natural_epic: bool
    unique_effect: Optional[UniqueEffectInfo]
    substats: List[GeneratedSubstat]
    icon_name: str
    frame_pattern: str
    max_level: int
    
    @property
    def substat_count(self) -> int:
        return len(self.substats)
    
    @property
    def has_unique_effect(self) -> bool:
        return self.unique_effect is not None
    
    def get_substat_by_name(self, name: str) -> Optional[GeneratedSubstat]:
        """Get a substat by its name."""
        for substat in self.substats:
            if substat.name == name:
                return substat
        return None
    
    def get_substat_by_enum(self, enum_id: int) -> Optional[GeneratedSubstat]:
        """Get a substat by its enum ID."""
        for substat in self.substats:
            if substat.enum_id == enum_id:
                return substat
        return None


class ModuleSimulator:
    """
    Simulator for generating valid modules with appropriate substats.
    
    This class handles the logic for:
    - Selecting module blueprints based on pull probabilities
    - Generating appropriate substats for the module type and rarity
    - Ensuring all constraints and limitations are respected
    """
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize the module simulator.
        
        Args:
            seed: Optional random seed for reproducible results
        """
        if seed is not None:
            random.seed(seed)
    
    def simulate_module_pull(self) -> GeneratedModule:
        """
        Simulate a complete module pull with appropriate rarity and substats.
        
        Returns:
            A complete GeneratedModule with all properties set
        """
        # Select random module type
        module_type = random.choice(list(ModuleType))
        
        # Select rarity based on probabilities
        rarity = self._select_rarity_by_probability()
        
        # Get valid blueprints for this pull
        valid_blueprints = get_blueprints_for_pull(rarity, module_type)
        
        if not valid_blueprints:
            raise ValueError(f"No valid blueprints found for {module_type.value} at {rarity.value}")
        
        # Select a random blueprint
        blueprint = random.choice(valid_blueprints)
        
        # Generate substats for this module
        substats = self._generate_substats_for_module(blueprint, rarity)
        
        # Get the correct max level for this rarity
        # Map from Rarity enum to MaxLevel enum
        rarity_to_maxlevel = {
            Rarity.COMMON: MaxLevel.COMMON,
            Rarity.RARE: MaxLevel.RARE,
            Rarity.RARE_PLUS: MaxLevel.RARE_PLUS,
            Rarity.EPIC: MaxLevel.EPIC,
            Rarity.EPIC_PLUS: MaxLevel.EPIC_PLUS,
            Rarity.LEGENDARY: MaxLevel.LEGENDARY,
            Rarity.LEGENDARY_PLUS: MaxLevel.LEGENDARY_PLUS,
            Rarity.MYTHIC: MaxLevel.MYTHIC,
            Rarity.MYTHIC_PLUS: MaxLevel.MYTHIC_PLUS,
            Rarity.ANCESTRAL: MaxLevel.ANCESTRAL,
            Rarity.ANCESTRAL1: MaxLevel.ANCESTRAL1,
            Rarity.ANCESTRAL2: MaxLevel.ANCESTRAL2,
            Rarity.ANCESTRAL3: MaxLevel.ANCESTRAL3,
            Rarity.ANCESTRAL4: MaxLevel.ANCESTRAL4,
            Rarity.ANCESTRAL5: MaxLevel.ANCESTRAL5,
        }
        max_level = rarity_to_maxlevel[rarity].value
        
        # Create the generated module
        return GeneratedModule(
            name=blueprint.name,
            module_type=blueprint.module_type,
            rarity=rarity,
            is_natural_epic=blueprint.is_natural_epic,
            unique_effect=blueprint.unique_effect,
            substats=substats,
            icon_name=blueprint.icon_name,
            frame_pattern=blueprint.frame_pattern,
            max_level=max_level
        )
    
    def simulate_multiple_pulls(self, count: int) -> List[GeneratedModule]:
        """
        Simulate multiple module pulls.
        
        Args:
            count: Number of modules to generate
            
        Returns:
            List of generated modules
        """
        modules = []
        for _ in range(count):
            module = self.simulate_module_pull()
            modules.append(module)
        return modules
    
    def _select_rarity_by_probability(self) -> Rarity:
        """
        Select a rarity based on the pull probabilities.
        
        Returns:
            Selected rarity
        """
        # Create a list of rarities and their probabilities
        rarities = list(MODULE_PULL_CHANCES.keys())
        probabilities = list(MODULE_PULL_CHANCES.values())
        
        # Select based on probability
        return random.choices(rarities, weights=probabilities)[0]
    
    def _generate_substats_for_module(self, 
                                    blueprint, 
                                    rarity: Rarity) -> List[GeneratedSubstat]:
        """
        Generate appropriate substats for a module.
        
        Args:
            blueprint: The module blueprint
            rarity: The rarity of the module
            
        Returns:
            List of generated substats
        """
        # Get the number of substats for this rarity
        substat_count = blueprint.get_substat_count(rarity)
        
        # Get all possible substats for this module type
        all_possible_substats = [s for s in blueprint.possible_substats if s.applies_to == blueprint.module_type]
        
        if not all_possible_substats:
            raise ValueError(f"No valid substats found for {blueprint.module_type.value}")
        
        # Filter out substats that are higher than the module's rarity
        # A substat is valid if it has at least one value at or below the module's rarity
        # Use the simplified 5-tier system for comparison
        module_tier = SUBSTAT_RARITY_TIERS.get(rarity, 1)
        valid_substats = []
        for substat in all_possible_substats:
            # Check if this substat has any values at or below the module's tier
            available_rarities = []
            for r in substat.values.keys():
                rarity_tier = SUBSTAT_RARITY_TIERS.get(r, 1)
                if rarity_tier <= module_tier:
                    available_rarities.append(r)
            if available_rarities:
                valid_substats.append(substat)
        
        if not valid_substats:
            raise ValueError(f"No substats available for {blueprint.module_type.value} at {rarity.value} rarity")
        
        # Generate substat instances
        generated_substats = []
        remaining_substats = valid_substats.copy()
        
        for _ in range(substat_count):
            if not remaining_substats:
                break
                
            # Step 1: Roll for substat rarity (constrained to module rarity or lower)
            substat_rarity = self._select_substat_rarity(rarity)
            
            # Step 2: Filter substats to only those that have a value for the selected rarity
            available_substats = [s for s in remaining_substats if substat_rarity in s.values]
            
            # If no substats available at this rarity, try the next lower rarity
            if not available_substats:
                # Find the next lower rarity that has available substats
                # Use the simplified 5-tier system for comparison
                module_tier = SUBSTAT_RARITY_TIERS.get(rarity, 1)
                available_rarities = [r for r in SUBSTAT_PULL_CHANCES.keys() 
                                    if SUBSTAT_RARITY_TIERS.get(r, 1) <= module_tier]
                # Sort by tier in descending order
                available_rarities.sort(key=lambda r: SUBSTAT_RARITY_TIERS.get(r, 1), reverse=True)
                
                for test_rarity in available_rarities:
                    if test_rarity == substat_rarity:
                        continue
                    available_substats = [s for s in remaining_substats if test_rarity in s.values]
                    if available_substats:
                        substat_rarity = test_rarity
                        break
            
            # If still no substats available, use the module's rarity as fallback
            if not available_substats:
                available_substats = [s for s in remaining_substats if rarity in s.values]
                if available_substats:
                    substat_rarity = rarity
                else:
                    # Last resort: use any available substat with its highest available rarity
                    for substat in remaining_substats:
                        available_rarities = []
                        for r in substat.values.keys():
                            rarity_tier = SUBSTAT_RARITY_TIERS.get(r, 1)
                            if rarity_tier <= module_tier:
                                available_rarities.append(r)
                        if available_rarities:
                            # Find the highest tier rarity
                            substat_rarity = max(available_rarities, 
                                               key=lambda r: SUBSTAT_RARITY_TIERS.get(r, 1))
                            available_substats = [substat]
                            break
            
            # Step 3: Choose a random substat from the available ones
            if available_substats:
                selected_substat = random.choice(available_substats)
                value = selected_substat.values[substat_rarity]
                
                generated_substat = GeneratedSubstat(
                    substat_info=selected_substat,
                    rarity=substat_rarity,
                    value=value
                )
                generated_substats.append(generated_substat)
                
                # Remove the selected substat from the remaining list
                remaining_substats.remove(selected_substat)
        
        return generated_substats
    
    def _select_substat_rarity(self, module_rarity: Rarity) -> Rarity:
        """
        Select a substat rarity based on the substat pull probabilities,
        but constrained to the module's rarity level or lower.
        
        Uses the simplified 5-tier system: Common, Rare, Epic, Legendary, Ancestral.
        Rarity+ variants are treated the same as their base rarity for substat purposes.
        
        Args:
            module_rarity: The rarity of the module
            
        Returns:
            Selected substat rarity (will be <= module_rarity)
        """
        # Get the module's tier in the simplified 5-tier system
        module_tier = SUBSTAT_RARITY_TIERS.get(module_rarity, 1)
        
        # Filter rarities to only those at or below the module's tier
        available_rarities = []
        available_probabilities = []
        
        for rarity, probability in SUBSTAT_PULL_CHANCES.items():
            rarity_tier = SUBSTAT_RARITY_TIERS.get(rarity, 1)
            if rarity_tier <= module_tier:
                available_rarities.append(rarity)
                available_probabilities.append(probability)
        
        # If no rarities available, fall back to the module's rarity
        if not available_rarities:
            return module_rarity
        
        # Normalize probabilities to sum to 1
        total_probability = sum(available_probabilities)
        if total_probability > 0:
            normalized_probabilities = [p / total_probability for p in available_probabilities]
        else:
            # If all probabilities are 0, use equal weights
            normalized_probabilities = [1.0 / len(available_rarities)] * len(available_rarities)
        
        # Select based on normalized probability from available rarities
        return random.choices(available_rarities, weights=normalized_probabilities)[0]
    
    def simulate_epic_pity_pull(self) -> GeneratedModule:
        """
        Simulate an epic pity pull (guaranteed epic after 150 pulls).
        
        Returns:
            A generated epic module
        """
        # For epic pity pulls, we need to force epic rarity
        # Since we removed forced_rarity, we'll implement this differently
        # by filtering blueprints to only epic ones
        epic_blueprints = []
        for blueprint in ALL_MODULE_BLUEPRINTS:
            if blueprint.natural_rarity == Rarity.EPIC:
                epic_blueprints.append(blueprint)
        
        if not epic_blueprints:
            raise ValueError("No epic blueprints found")
        
        # Select a random epic blueprint
        blueprint = random.choice(epic_blueprints)
        
        # Generate substats for this module
        substats = self._generate_substats_for_module(blueprint, Rarity.EPIC)
        
        # Get the correct max level for epic rarity
        max_level = MaxLevel.EPIC.value
        
        # Create the generated module
        return GeneratedModule(
            name=blueprint.name,
            module_type=blueprint.module_type,
            rarity=Rarity.EPIC,
            is_natural_epic=blueprint.is_natural_epic,
            unique_effect=blueprint.unique_effect,
            substats=substats,
            icon_name=blueprint.icon_name,
            frame_pattern=blueprint.frame_pattern,
            max_level=max_level
        )
    
    def get_pull_statistics(self, pull_count: int = 10000) -> Dict[str, float]:
        """
        Simulate multiple pulls and return statistics.
        
        Args:
            pull_count: Number of pulls to simulate
            
        Returns:
            Dictionary with pull statistics
        """
        rarity_counts = {rarity: 0 for rarity in MODULE_PULL_CHANCES.keys()}
        type_counts = {module_type: 0 for module_type in ModuleType}
        
        for _ in range(pull_count):
            module = self.simulate_module_pull()
            rarity_counts[module.rarity] += 1
            type_counts[module.module_type] += 1
        
        # Calculate percentages
        stats = {}
        for rarity, count in rarity_counts.items():
            stats[f"{rarity.value}_percentage"] = (count / pull_count) * 100
        
        for module_type, count in type_counts.items():
            stats[f"{module_type.value}_percentage"] = (count / pull_count) * 100
        
        stats["total_pulls"] = pull_count
        
        return stats


# Convenience functions for easy use
def simulate_single_pull(seed: Optional[int] = None) -> GeneratedModule:
    """
    Convenience function to simulate a single module pull.
    
    Args:
        seed: Optional random seed
        
    Returns:
        Generated module
    """
    simulator = ModuleSimulator(seed)
    return simulator.simulate_module_pull()


def simulate_multiple_pulls(count: int, seed: Optional[int] = None) -> List[GeneratedModule]:
    """
    Convenience function to simulate multiple module pulls.
    
    Args:
        count: Number of modules to generate
        seed: Optional random seed
        
    Returns:
        List of generated modules
    """
    simulator = ModuleSimulator(seed)
    return simulator.simulate_multiple_pulls(count)


def get_pull_statistics(pull_count: int = 10000, seed: Optional[int] = None) -> Dict[str, float]:
    """
    Convenience function to get pull statistics.
    
    Args:
        pull_count: Number of pulls to simulate
        seed: Optional random seed
        
    Returns:
        Dictionary with pull statistics
    """
    simulator = ModuleSimulator(seed)
    return simulator.get_pull_statistics(pull_count)


# Example usage and testing
if __name__ == "__main__":
    # Test the simulator
    print("Testing Module Simulator...")
    
    # Create simulator
    simulator = ModuleSimulator(seed=42)
    
    # Simulate some pulls
    print("\n=== Single Pull Examples ===")
    for i in range(5):
        module = simulator.simulate_module_pull()
        print(f"Pull {i+1}: {module.name} ({module.rarity.value}) - {module.substat_count} substats")
        for substat in module.substats:
            print(f"  - {substat.name}: {substat.value}{substat.unit} ({substat.rarity.value})")
    
    print("\n=== Epic Pull Example ===")
    epic_module = simulator.simulate_epic_pity_pull()
    print(f"Epic: {epic_module.name} - {epic_module.substat_count} substats")
    if epic_module.has_unique_effect and epic_module.unique_effect:
        print(f"Unique Effect: {epic_module.unique_effect.name}")
    
    print("\n=== Pull Statistics ===")
    stats = simulator.get_pull_statistics(1000)
    for key, value in stats.items():
        if "percentage" in key:
            print(f"{key}: {value:.2f}%")
        else:
            print(f"{key}: {value}") 