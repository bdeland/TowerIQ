from typing import Dict, List, Optional
from . import _rarities, _substats, _definitions
from ._enums import Rarity, ModuleType
from .module_dataclass import RarityInfo, SubstatInfo, ModuleDefinition

class GameDataManager:
    def __init__(self):
        # --- Build high-performance lookup tables from the data definition files ---
        
        self.rarities: Dict[Rarity, RarityInfo] = {
            r.name: r for r in _rarities.ALL_RARITIES
        }
        
        self.substats: Dict[int, SubstatInfo] = {
            s.enum_id: s for s in _substats.ALL_SUBSTATS
        }
        
        self.modules: Dict[str, ModuleDefinition] = {
            m.name: m for m in _definitions.ALL_MODULES
        }
        
        # You can also pre-compute other useful lookups here
        self.substats_by_type: Dict[ModuleType, List[SubstatInfo]] = {
            mtype: [s for s in _substats.ALL_SUBSTATS if s.applies_to == mtype]
            for mtype in ModuleType
        }

    def get_substat(self, enum_id: int) -> Optional[SubstatInfo]:
        return self.substats.get(enum_id)

    def get_rarity_info(self, rarity: Rarity) -> Optional[RarityInfo]:
        return self.rarities.get(rarity)
    
    # ... other helpful getter methods