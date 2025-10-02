"""
Module Simulator

This module provides functions to simulate the creation of modules and their substats
using the existing game logic and constraints. It generates valid modules that match
the limitations and requirements for module pulls.
"""

import random
import numpy as np
from typing import List, Dict, Optional
from dataclasses import dataclass

from ._enums import ModuleType, Rarity, RARITY_TO_MAX_LEVEL
from ._probabilities import MODULE_PULL_CHANCES
from .module_blueprints import (
    ALL_MODULE_BLUEPRINTS,
    get_blueprints_for_pull
)
from .module_dataclass import SubstatInfo, UniqueEffectInfo
from .game_data_manager import GameDataManager

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
    level: int = 1  # Current level of the module (starts at 1 for generated modules)
    is_equipped: bool = False  # Whether the module is currently equipped
    is_favorite: bool = False  # Whether the module is favorited

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

    def __init__(self, data_manager: GameDataManager, seed: Optional[int] = None, enable_profiling: bool = False):
        """
        Initialize the module simulator.

        Args:
            data_manager: The GameDataManager instance for optimized lookups
            seed: Optional random seed for reproducible results
            enable_profiling: Whether to enable detailed profiling
        """
        # Store the data manager
        self.data_manager = data_manager

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
            raise ValueError(f"No valid blueprints found for {module_type.value} at {rarity.display_name}")

        # Select a random blueprint
        blueprint = random.choice(valid_blueprints)

        # Generate substats for this module
        substats = self._generate_substats_for_module(blueprint, rarity)

        # Get the correct max level for this rarity
        # Map from Rarity enum to MaxLevel enum
        max_level = RARITY_TO_MAX_LEVEL[rarity]

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
            max_level=max_level,
            level=1,  # Generated modules start at level 1
            is_equipped=False,  # Generated modules start as unequipped
            is_favorite=False  # Generated modules start as unfavorited
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
        Generate appropriate substats for a module using an optimized selection method.

        Args:
            blueprint: The module blueprint
            rarity: The rarity of the module

        Returns:
            List of generated substats
        """
        substat_count = blueprint.get_substat_count(rarity)

        # --- OPTIMIZATION 1: Use the pre-computed map for an instant lookup ---
        # This gets all possible SubstatInfo objects for the module's type.
        possible_substats_for_type = self.data_manager.valid_substats_map[blueprint.module_type]

        # Create a flat, de-duplicated list of all possible substat info objects
        # that are valid for this module's rarity
        unique_possible_substats = []
        seen_substats = set()

        # First, try to get substats that are valid for this specific rarity
        if rarity in possible_substats_for_type:
            for sub_info in possible_substats_for_type[rarity]:
                if sub_info.enum_id not in seen_substats:
                    unique_possible_substats.append(sub_info)
                    seen_substats.add(sub_info.enum_id)

        # If we don't have enough substats for this rarity, add substats from lower rarities
        if len(unique_possible_substats) < substat_count:
            for r in possible_substats_for_type.keys():
                if r < rarity:  # Only consider lower rarities
                    for sub_info in possible_substats_for_type[r]:
                        if sub_info.enum_id not in seen_substats:
                            unique_possible_substats.append(sub_info)
                            seen_substats.add(sub_info.enum_id)
                            if len(unique_possible_substats) >= substat_count:
                                break
                    if len(unique_possible_substats) >= substat_count:
                        break

        if not unique_possible_substats:
            return [] # No possible substats for this module type

        # --- OPTIMIZATION 2: Use random.sample for efficient unique selection ---
        # This replaces the slow loop with list.remove().
        if len(unique_possible_substats) <= substat_count:
            # If we don't have enough unique substats, just take all of them
            chosen_substats = unique_possible_substats
        else:
            # Select N unique substats efficiently
            chosen_substats = random.sample(unique_possible_substats, k=substat_count)

        # --- Generate the final substat objects ---
        generated_substats = []
        for substat_info in chosen_substats:
            # For each chosen substat, now determine its specific rarity
            substat_rarity = self._select_substat_rarity(rarity)

            # CRITICAL VALIDATION: The rolled rarity might not be valid for this specific substat.
            # Example: We chose "Multishot Targets" but rolled a "Common" rarity.
            # We must find a valid rarity to use as a fallback.
            if substat_rarity not in substat_info.values:
                # Find the highest possible rarity this substat supports that is AT or BELOW the module's rarity
                valid_rarities = list(substat_info.values if r <= rarity)
                if not valid_rarities:
                    # If no valid rarities, try to find the lowest possible rarity for this substat
                    valid_rarities = list(substat_info.values.keys())
                    if not valid_rarities:
                        continue  # This substat has no values at all, skip it

                    # Use the lowest available rarity as a fallback
                    substat_rarity = min(valid_rarities)
                else:
                    # Use the best possible rarity as a fallback
                    substat_rarity = max(valid_rarities)

            # Get the value for the final, valid rarity
            value = substat_info.values[substat_rarity]

            generated_substats.append(GeneratedSubstat(
                substat_info=substat_info,
                rarity=substat_rarity,
                value=value
            ))

        return generated_substats

    def _select_substat_rarity(self, module_rarity: Rarity) -> Rarity:
        """
        Select a substat rarity based on the substat pull probabilities,
        but constrained to the module's rarity level or lower.

        Now using optimized NumPy operations for speed.

        Args:
            module_rarity: The rarity of the module

        Returns:
            Selected substat rarity (will be <= module_rarity)
        """
        max_rarity_idx = module_rarity.value - 1  # Get IntEnum value (e.g., EPIC = 4)

        weights = self.data_manager.substat_rarity_weights[:max_rarity_idx + 1]
        normalized_weights = weights / weights.sum()

        chosen_idx = np.random.choice(max_rarity_idx + 1, p=normalized_weights)
        return self.data_manager.rarity_enums[chosen_idx]

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
        max_level = RARITY_TO_MAX_LEVEL[Rarity.EPIC]

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
            max_level=max_level,
            level=1,  # Generated modules start at level 1
            is_equipped=False,  # Generated modules start as unequipped
            is_favorite=False  # Generated modules start as unfavorited
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
            stats[f"{rarity.display_name}_percentage"] = (count / pull_count) * 100

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
    data_manager = GameDataManager()
    simulator = ModuleSimulator(data_manager, seed)
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
    data_manager = GameDataManager()
    simulator = ModuleSimulator(data_manager, seed)
    return simulator.simulate_multiple_pulls(count)
