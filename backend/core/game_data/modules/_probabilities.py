"""
This file defines global game mechanics and system-wide constants,
such as drop chances and other probability tables.
"""

from ._enums import Rarity

MODULE_PULL_CHANCES: dict[Rarity, float] = {
    Rarity.COMMON: 0.685,
    Rarity.RARE:   0.290,
    Rarity.EPIC:   0.025,
}


SUBSTAT_PULL_CHANCES: dict[Rarity, float] = {
    Rarity.COMMON:    0.462,
    Rarity.RARE:      0.400,
    Rarity.EPIC:      0.100,
    Rarity.LEGENDARY: 0.025,
    Rarity.MYTHIC:    0.010,
    Rarity.ANCESTRAL: 0.003,
}

REROLL_COSTS: dict[int, int] = {
    1: 10, 
    2: 40, 
    3: 160, 
    4: 500, 
    5: 1000, 
    6: 1600, 
    7: 2250, 
    8: 3000,
}

EPIC_PITY_PULL_COUNT: int = 150