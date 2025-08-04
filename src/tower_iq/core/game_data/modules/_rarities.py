from ._enums import Rarity
from .module_dataclass import RarityInfo

COMMON = RarityInfo(
    name=Rarity.COMMON, 
    display_name="Common", 
    light_color="#e4e4e5", 
    dark_color="#ffffff", 
    max_level=20)

RARE = RarityInfo(
    name=Rarity.RARE, 
    display_name="Rare", 
    light_color="#9ff4fe", 
    dark_color="#47dbff", 
    max_level=30, 
    unlocks_at=[41, 101])

RARE_PLUS = RarityInfo(
    name=Rarity.RARE_PLUS, 
    display_name="Rare+", 
    light_color="#9ff4fe", 
    dark_color="#47dbff", 
    max_level=40, 
    unlocks_at=[41, 101])

EPIC = RarityInfo(
    name=Rarity.EPIC, 
    display_name="Epic", 
    light_color="#ff9afa", 
    dark_color="#ff4ccf", 
    max_level=60, 
    unlocks_at=[41, 101, 141, 161])

EPIC_PLUS = RarityInfo(
    name=Rarity.EPIC_PLUS, 
    display_name="Epic+", 
    light_color="#ff9afa", 
    dark_color="#ff4ccf", 
    max_level=80, 
    unlocks_at=[41, 101, 141, 161])

LEGENDARY = RarityInfo(
    name=Rarity.LEGENDARY, 
    display_name="Legendary", 
    light_color="#fbb97f", 
    dark_color="#ff9c3d", 
    max_level=100, 
    unlocks_at=[41, 101, 141, 161])

LEGENDARY_PLUS = RarityInfo(
    name=Rarity.LEGENDARY_PLUS, 
    display_name="Legendary+", 
    light_color="#fbb97f", 
    dark_color="#ff9c3d",  
    max_level=120, 
    unlocks_at=[41, 101, 141, 161])

MYTHIC = RarityInfo(
    name=Rarity.MYTHIC, 
    display_name="Mythic", 
    light_color="#ff7586", 
    dark_color="#ff4040", 
    max_level=140, 
    unlocks_at=[41, 101, 141, 161])

MYTHIC_PLUS = RarityInfo(
    name=Rarity.MYTHIC_PLUS, 
    display_name="Mythic+", 
    light_color="#ff7586", 
    dark_color="#ff4040", 
    max_level=160, 
    unlocks_at=[41, 101, 141, 161])

ANCESTRAL = RarityInfo(
    name=Rarity.ANCESTRAL, 
    display_name="Ancestral", 
    light_color="#99d1ac", 
    dark_color="#79f369", 
    max_level=200, 
    unlocks_at=[41, 101, 141, 161])
ANCESTRAL1 = RarityInfo(
    name=Rarity.ANCESTRAL1, 
    display_name="Ancestral1", 
    light_color="#99d1ac", 
    dark_color="#79f369", 
    max_level=220, 
    unlocks_at=[41, 101, 141, 161])

ANCESTRAL2 = RarityInfo(
    name=Rarity.ANCESTRAL2, 
    display_name="Ancestral2", 
    light_color="#99d1ac", 
    dark_color="#79f369", 
    max_level=240, 
    unlocks_at=[41, 101, 141, 161])

ANCESTRAL3 = RarityInfo(
    name=Rarity.ANCESTRAL3, 
    display_name="Ancestral3", 
    light_color="#99d1ac", 
    dark_color="#79f369", 
    max_level=260, 
    unlocks_at=[41, 101, 141, 161])

ANCESTRAL4 = RarityInfo(
    name=Rarity.ANCESTRAL4, 
    display_name="Ancestral4", 
    light_color="#99d1ac", 
    dark_color="#79f369", 
    max_level=280, 
    unlocks_at=[41, 101, 141, 161])

ANCESTRAL5 = RarityInfo(
    name=Rarity.ANCESTRAL5, 
    display_name="Ancestral5", 
    light_color="#99d1ac", 
    dark_color="#79f369", 
    max_level=300, 
    unlocks_at=[41, 101, 141, 161])

ALL_RARITIES = [
    COMMON, 
    RARE, 
    RARE_PLUS, 
    EPIC, 
    EPIC_PLUS, 
    LEGENDARY, 
    LEGENDARY_PLUS, 
    MYTHIC, 
    MYTHIC_PLUS, 
    ANCESTRAL, 
    ANCESTRAL1, 
    ANCESTRAL2, 
    ANCESTRAL3, 
    ANCESTRAL4, 
    ANCESTRAL5]