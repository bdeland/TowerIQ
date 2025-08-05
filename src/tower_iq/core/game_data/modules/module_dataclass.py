
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from ._enums import Rarity, ModuleType, MaxLevel # Assuming your enums are in core/enums.py

@dataclass(frozen=True)
class RarityInfo:
    """Defines all properties associated with a rarity."""
    name: Rarity
    display_name: str
    light_color: str
    dark_color: str
    max_level: int

@dataclass(frozen=True)
class SubstatInfo:
    """Defines a single substat, its values, and constraints."""
    enum_id: int
    name: str
    applies_to: ModuleType
    unit: str
    values: Dict[Rarity, float]

@dataclass(frozen=True)
class UniqueEffectInfo:
    """Defines a unique effect for a natural epic module."""
    name: str
    module_type: ModuleType
    effect_template: str
    unit: str
    values: Dict[Rarity, float]

@dataclass(frozen=True)
class ModuleDefinition:
    """Defines the static properties of a single module."""
    name: str
    module_type: ModuleType
    rarity: Rarity
    is_natural_epic: bool
    unique_effect: Optional[UniqueEffectInfo] = None
    possible_substats: List[SubstatInfo] = field(default_factory=list)
    
    @property
    def max_level(self) -> MaxLevel:
        """Get the max level for this module's rarity."""
        return getattr(MaxLevel, self.rarity.value)