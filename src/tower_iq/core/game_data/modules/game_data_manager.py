"""
Game Data Manager for Optimized Simulations

This module provides a GameDataManager class that loads all static game data
from the Python modules ONCE and creates optimized data structures for
high-performance simulations.
"""

import numpy as np
from collections import defaultdict
from typing import List

from ._enums import Rarity, ModuleType
from ._probabilities import SUBSTAT_PULL_CHANCES
from ._substats import ALL_SUBSTATS
from .module_blueprints import ALL_MODULE_BLUEPRINTS


class GameDataManager:
    """
    Loads all static game data from the Python modules ONCE and creates
    optimized data structures for high-performance simulations.
    """

    def __init__(self):
        # --- Pre-computed Probability Arrays ---
        self.rarity_enums = list(Rarity)
        self.substat_rarity_weights = np.array(
            [SUBSTAT_PULL_CHANCES.get(r, 0.0) for r in self.rarity_enums],
            dtype=np.float64
        )
        self.substat_rarity_weights /= self.substat_rarity_weights.sum()

        # --- THE MOST IMPORTANT OPTIMIZATION ---
        # Pre-compute a map of all valid substats for a given module type and rarity tier.
        # Structure: Dict[ModuleType, Dict[Rarity, List[SubstatInfo]]]
        self.valid_substats_map = defaultdict(lambda: defaultdict(list))
        for substat in ALL_SUBSTATS:
            for rarity_enum in substat.values:
                self.valid_substats_map[substat.applies_to][rarity_enum].append(substat)

        # --- Blueprint Lookups ---
        self.blueprints_by_type_and_rarity = defaultdict(lambda: defaultdict(list))
        for bp in ALL_MODULE_BLUEPRINTS:
            self.blueprints_by_type_and_rarity[bp.module_type][bp.natural_rarity].append(bp)

    def get_valid_substats_for_type_and_rarity(self, module_type: ModuleType, rarity: Rarity) -> List:
        """
        Get all valid substats for a given module type and rarity.

        This is the optimized lookup that replaces the expensive filtering
        in the original _generate_substats_for_module function.
        """
        return self.valid_substats_map[module_type][rarity]

    def get_blueprints_for_pull(self, rarity: Rarity, module_type: ModuleType) -> List:
        """
        Get all blueprints that can be pulled at the given rarity and type.

        This is an optimized version of the original function.
        """
        return self.blueprints_by_type_and_rarity[module_type][rarity]
