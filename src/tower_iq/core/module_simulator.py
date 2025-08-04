import structlog
import yaml
import random
import colorama
from typing import Dict, List, Set, Optional, Tuple, Any
import datetime
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

lookup_file = "resources/lookups/module_lookups.yaml"
module_lookups = yaml.load(open(lookup_file), Loader=yaml.FullLoader)

class Module:
    def __init__(self, 
                 name: str, 
                 module_type: str, 
                 rarity: str, 
                 level: int, 
                 substat_enum_ids: Optional[List[int]] = None, 
                 substat_rarities: Optional[List[str]] = None,
                 coins_spent: int = 0, 
                 shards_spent: int = 0,
                 is_equipped: bool = False, 
                 is_favorite: bool = False, 
                 frame: Optional[str] = None, 
                 icon: Optional[str] = None,
                 guid: Optional[str] = None
                 ):
        """
        Initialize a Module instance.
        
        Args:
            name: Display name of the module
            module_type: Type of module (Cannon, Armor, Generator, Core)
            rarity: Rarity level (Common, Rare, Epic, Legendary, Mythic, Ancestral, etc.)
            level: Current level of the module
            substat_enum_ids: List of substat enum IDs for this module
            substat_rarities: List of rarity levels for each substat (must match length of substat_enum_ids)
            coins_spent: Total coins spent on this module
            shards_spent: Total shards spent on this module
            is_equipped: Whether the module is currently equipped
            is_favorite: Whether the module is marked as favorite
            frame: Frame sprite name
            icon: Icon sprite name
            guid: Unique identifier for the module
        """
        self.guid = guid
        self.name = name
        self.module_type = module_type
        self.rarity = rarity
        self.level = level
        self.substat_enum_ids = substat_enum_ids or []
        self.substat_rarities = substat_rarities or []
        self.coins_spent = coins_spent
        self.shards_spent = shards_spent
        self.is_equipped = is_equipped
        self.is_favorite = is_favorite
        self.frame = frame
        self.icon = icon
        
        # Validate substat data
        self._validate_substat_data()
        
        # Initialize substats
        self.substats = self._initialize_substats()
        
        # Validation
        self._validate_module()
    
    def _get_frame_sprite(self) -> str:
        """Get the frame sprite based on rarity."""
        rarity_mapping = {
            'Common': 'mf_armor_common',
            'Rare': 'mf_armor_rare',
            'RarePlus': 'mf_armor_rare_plus',
            'Epic': 'mf_armor_epic',
            'EpicPlus': 'mf_armor_epic_plus',
            'Legendary': 'mf_armor_legendary',
            'LegendaryPlus': 'mf_armor_legendary_plus',
            'Mythic': 'mf_armor_mythic',
            'MythicPlus': 'mf_armor_mythic_plus',
            'Ancestral': 'mf_armor_ancestral'
        }
        
        base_frame = rarity_mapping.get(self.rarity, 'mf_armor_common')
        # Replace armor with the correct module type
        return base_frame.replace('armor', self.module_type.lower())
    
    def _get_icon_sprite(self) -> str:
        """Get the icon sprite based on module type and rarity."""
        # This would need to be implemented based on the actual icon mapping
        # For now, using a placeholder
        return f"{self.module_type.lower()}_epic_1"
    
    def _validate_substat_data(self):
        """Validate that substat_enum_ids and substat_rarities have matching lengths."""
        if len(self.substat_enum_ids) != len(self.substat_rarities):
            raise ValueError(
                f"substat_enum_ids ({len(self.substat_enum_ids)}) and "
                f"substat_rarities ({len(self.substat_rarities)}) must have the same length"
            )
    
    def _initialize_substats(self) -> List[Dict[str, Any]]:
        """Initialize substats based on enum IDs and their individual rarities."""
        substats = []
        for i, (enum_id, substat_rarity) in enumerate(zip(self.substat_enum_ids, self.substat_rarities)):
            substat_data = {
                'index': i,
                'enum_id': enum_id,
                'name': self._get_substat_name(enum_id),
                'value': self._get_substat_value_with_rarity(enum_id, substat_rarity),
                'unit': self._get_substat_unit(enum_id),
                'rarity': substat_rarity,  # Use the individual substat rarity
                'is_locked': False  # Default to unlocked
            }
            substats.append(substat_data)
        return substats
    
    def _get_substat_name(self, enum_id: int) -> str:
        """Get substat name from enum ID."""
        try:
            return module_lookups['substat_values'][enum_id]['name'].replace('_', ' ')
        except KeyError:
            return f"Unknown_{enum_id}"
    
    def _get_substat_value(self, enum_id: int) -> Optional[float]:
        """Get substat value for the module's rarity (legacy method)."""
        try:
            return module_lookups['substat_values'][enum_id]['values'][self.rarity]
        except KeyError:
            return None
    
    def _get_substat_value_with_rarity(self, enum_id: int, substat_rarity: str) -> Optional[float]:
        """Get substat value for a specific substat rarity."""
        try:
            return module_lookups['substat_values'][enum_id]['values'][substat_rarity]
        except KeyError:
            return None
    
    def _get_substat_unit(self, enum_id: int) -> str:
        """Get substat unit from enum ID."""
        try:
            return module_lookups['substat_values'][enum_id]['unit']
        except KeyError:
            return ""
    
    def _get_substat_rarity(self, enum_id: int) -> str:
        """Get substat rarity - for now using module rarity."""
        return self.rarity
    
    def _get_base_rarity(self, rarity: str) -> str:
        """Convert full rarity name to base rarity for lookup."""
        rarity_map = {
            'common': 'Common',
            'rare': 'Rare',
            'rareplus': 'Rare',
            'epic': 'Epic',
            'epicplus': 'Epic',
            'legendary': 'Legendary',
            'legendaryplus': 'Legendary',
            'mythic': 'Mythic',
            'mythicplus': 'Mythic',
            'ancestral': 'Ancestral'
        }
        return rarity_map.get(rarity.lower(), 'Common')
    
    def _validate_module(self):
        """Validate the module data."""
        if not self.guid:
            raise ValueError("Module GUID cannot be empty")
        
        if not self.name:
            raise ValueError("Module name cannot be empty")
        
        if self.level < 1:
            raise ValueError("Module level must be at least 1")
        
        # Validate rarity exists using base rarity
        base_rarity = self._get_base_rarity(self.rarity)
        if base_rarity not in module_lookups.get('rarity_colors', {}):
            logger.warning(f"Unknown base rarity: {base_rarity} (from {self.rarity})")
    
    def get_formatted_name(self) -> str:
        """Get the formatted name with level and rarity."""
        return f'"{self.name}" (Level {self.level}, {self.rarity})'
    
    def get_status_flags(self) -> List[str]:
        """Get list of status flags (Equipped, Favorite, etc.)."""
        flags = []
        if self.is_equipped:
            flags.append("Equipped")
        if self.is_favorite:
            flags.append("Favorite")
        return flags
    
    def get_formatted_status(self) -> str:
        """Get formatted status string."""
        flags = self.get_status_flags()
        if flags:
            return f" - [{', '.join(flags)}]"
        return ""
    
    def get_stats_summary(self) -> str:
        """Get formatted stats summary."""
        return f"Coins Spent: {self.coins_spent:,}, Shards Spent: {self.shards_spent:,}"
    
    def get_sprites_summary(self) -> str:
        """Get formatted sprites summary."""
        return f"Frame: '{self.frame}', Icon: '{self.icon}'"
    
    def get_substat_summary(self, index: int) -> str:
        """Get formatted substat summary."""
        if index >= len(self.substats):
            return ""
        
        substat = self.substats[index]
        locked_status = " | Locked: true" if substat['is_locked'] else ""
        return f"Substat {index} -> {substat['name']} ({substat['rarity']}){locked_status}"
    
    def to_string(self) -> str:
        """Convert module to string representation."""
        lines = [
            f"{self.get_formatted_name()}{self.get_formatted_status()}",
            f"    GUID -> \"{self.guid}\"",
            f"    Stats -> {self.get_stats_summary()}",
            f"    Sprites -> {self.get_sprites_summary()}"
        ]
        
        for i, substat in enumerate(self.substats):
            lines.append(f"    {self.get_substat_summary(i)}")
        
        return "\n".join(lines)
    
    def __str__(self) -> str:
        return self.to_string()
    
    def __repr__(self) -> str:
        return f"Module(name='{self.name}', type='{self.module_type}', rarity='{self.rarity}', level={self.level})"


def simulate_substat_rarity(module_rarity: str) -> str:
    """
    Simulates the rarity of a single substat for purchased modules only,
    respecting the module's rarity as a ceiling.

    Args:
        module_rarity: The rarity of the parent module (e.g., "Epic").
                     Only "Common", "Rare", or "Epic" are allowed for purchased modules.

    Returns:
        The simulated rarity string for the substat (e.g., "Rare").
        
    Raises:
        ValueError: If module_rarity is not a valid purchased module rarity.
    """
    # Validate that this is a purchased module rarity
    valid_purchased_rarities = ["Common", "Rare", "Epic"]
    if module_rarity not in valid_purchased_rarities:
        raise ValueError(
            f"Invalid module rarity '{module_rarity}'. "
            f"Purchased modules can only be {', '.join(valid_purchased_rarities)}. "
            f"Received: {module_rarity}"
        )
    
    RARITY_ORDER = module_lookups['rarity_order']
    BASE_SUBSTAT_WEIGHTS = module_lookups['subeffect_drop_chance']
    # Step 1: Filter the probabilities
    module_rarity_index = RARITY_ORDER.index(module_rarity)
    
    valid_rarities = []
    valid_weights = []
    
    for i, rarity in enumerate(RARITY_ORDER):
        if i <= module_rarity_index:
            valid_rarities.append(rarity)
            valid_weights.append(BASE_SUBSTAT_WEIGHTS[rarity])

    # Step 2 & 3: Normalize the weights
    # NumPy automatically handles normalization if the probabilities don't sum to 1
    normalized_weights = np.array(valid_weights, dtype=np.float64) / sum(valid_weights)

    # Step 4: Perform the weighted random choice
    chosen_rarity = np.random.choice(valid_rarities, p=normalized_weights)
    
    return chosen_rarity


# Test code to run simulate_substat_rarity 100 times on each module rarity level
def test_substat_rarity_distribution():
    """Test the distribution of substat rarities for each module rarity level."""
    from collections import Counter
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    
    # Define purchased module rarity levels only (Common, Rare, Epic)
    module_rarities = ["Common", "Rare", "Epic"]
    
    # Dictionary to store results for each module rarity
    results = {}
    
    print("Testing substat rarity distribution for each module rarity level...")
    print("=" * 80)
    print(f"Using rarity order: {module_lookups['rarity_order']}")
    print(f"Using drop chances: {module_lookups['subeffect_drop_chance']}")
    print("=" * 80)
    
    # Create a figure with subplots for each module rarity (3 purchased rarities)
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    fig.suptitle('Substat Rarity Distribution for Purchased Modules', fontsize=16, fontweight='bold')
    
    for idx, module_rarity in enumerate(module_rarities):
        print(f"\nTesting module rarity: {module_rarity}")
        print("-" * 40)
        
        # Run simulation 100 times for this module rarity
        substat_rarities = []
        for i in range(100000):
            substat_rarity = simulate_substat_rarity(module_rarity)
            substat_rarities.append(substat_rarity)
        
        # Count occurrences of each substat rarity
        rarity_counts = Counter(substat_rarities)
        
        # Store results
        results[module_rarity] = dict(rarity_counts)
        
        # Print results for this module rarity
        total_sims = 100000
        print(f"Results for {module_rarity} modules ({total_sims:,} simulations):")
        for substat_rarity, count in sorted(rarity_counts.items()):
            percentage = (count / total_sims) * 100
            print(f"  {substat_rarity}: {count:,} ({percentage:.1f}%)")
        
        # Create histogram for this module rarity
        create_histogram(axes[idx], rarity_counts, module_rarity)
    
    # Adjust layout and display
    plt.tight_layout()
    plt.show()
    
    print("\n" + "=" * 80)
    print("SUMMARY OF ALL RESULTS:")
    print("=" * 80)
    
    # Print summary table
    all_substat_rarities = set()
    for counts in results.values():
        all_substat_rarities.update(counts.keys())
    
    # Header
    header = f"{'Module Rarity':<12}"
    for substat_rarity in sorted(all_substat_rarities):
        header += f"{substat_rarity:<10}"
    print(header)
    print("-" * len(header))
    
    # Data rows
    for module_rarity in module_rarities:
        row = f"{module_rarity:<12}"
        for substat_rarity in sorted(all_substat_rarities):
            count = results[module_rarity].get(substat_rarity, 0)
            row += f"{count:<10}"
        print(row)
    
    # Print expected vs actual comparison (accounting for ceiling effect)
    print("\n" + "=" * 80)
    print("EXPECTED vs ACTUAL COMPARISON (with ceiling effect):")
    print("=" * 80)
    expected_chances = module_lookups['subeffect_drop_chance']
    print(f"{'Module':<12}{'Substat':<12}{'Expected %':<12}{'Actual %':<12}{'Difference':<12}")
    print("-" * 60)
    
    for module_rarity in module_rarities:
        if module_rarity in results:
            # Calculate actual percentages for this module rarity
            total_sims = 100000
            actual_percentages = {}
            for substat_rarity, count in results[module_rarity].items():
                actual_percentages[substat_rarity] = (count / total_sims) * 100
            
            # Get the module's rarity index to determine ceiling
            module_rarity_index = module_lookups['rarity_order'].index(module_rarity)
            
            # Compare with expected (accounting for ceiling)
            for substat_rarity in sorted(all_substat_rarities):
                substat_rarity_index = module_lookups['rarity_order'].index(substat_rarity)
                
                # Check if this substat rarity is within the module's ceiling
                if substat_rarity_index <= module_rarity_index:
                    # Calculate expected percentage with ceiling effect
                    # Get all valid rarities for this module
                    valid_rarities = []
                    valid_weights = []
                    for i, rarity in enumerate(module_lookups['rarity_order']):
                        if i <= module_rarity_index:
                            valid_rarities.append(rarity)
                            valid_weights.append(expected_chances[rarity])
                    
                    # Normalize weights for this module's ceiling
                    total_weight = sum(valid_weights)
                    if total_weight > 0:
                        normalized_weight = expected_chances[substat_rarity] / total_weight
                        expected_pct = normalized_weight * 100
                    else:
                        expected_pct = 0.0
                else:
                    # This substat rarity is above the module's ceiling
                    expected_pct = 0.0
                
                actual_pct = actual_percentages.get(substat_rarity, 0)
                diff = actual_pct - expected_pct
                print(f"{module_rarity:<12}{substat_rarity:<12}{expected_pct:<12.1f}{actual_pct:<12.1f}{diff:<12.1f}")
    
    # Print summary of ceiling effect
    print("\n" + "=" * 80)
    print("CEILING EFFECT SUMMARY:")
    print("=" * 80)
    print("Each module rarity can only roll substats at or below its own rarity level:")
    for module_rarity in module_rarities:
        module_rarity_index = module_lookups['rarity_order'].index(module_rarity)
        valid_substats = [rarity for i, rarity in enumerate(module_lookups['rarity_order']) if i <= module_rarity_index]
        print(f"{module_rarity:<12} -> Can roll: {', '.join(valid_substats)}")
    
    return results


def test_substat_pulling():
    """Test the new substat pulling functionality."""
    print("Testing substat pulling functionality...")
    print("=" * 80)
    
    # Test a few module pulls to see the new substat system in action
    for i in range(5):
        print(f"\nModule Pull #{i+1}:")
        print("-" * 30)
        
        try:
            module = simulate_module_pull(0)
            print(f"Module: {module.module_type} {module.rarity}")
            print(f"Substats:")
            for j, (enum_id, rarity) in enumerate(zip(module.substat_enum_ids, module.substat_rarities)):
                substat_name = module_lookups['substat_values'][enum_id]['name']
                print(f"  {j+1}. {substat_name} ({rarity})")
        except Exception as e:
            print(f"Error: {e}")
    
    print("\n" + "=" * 80)
    print("Substat pulling test completed!")
    print("=" * 80)


def create_histogram(ax, counts, module_rarity):
    """Create a matplotlib histogram for the given counts."""
    if not counts:
        ax.text(0.5, 0.5, 'No data to display', ha='center', va='center', transform=ax.transAxes)
        return
    
    # Get all possible rarities in order
    all_rarities = module_lookups['rarity_order']
    
    # Prepare data for plotting
    rarities = []
    values = []
    colors = []
    
    # Define colors for each rarity
    rarity_colors = {
        'Common': '#8B8B8B',      # Gray
        'Rare': '#4A90E2',        # Blue
        'Epic': '#9B59B6',        # Purple
        'Legendary': '#F39C12',   # Orange
        'Mythic': '#E74C3C',      # Red
        'Ancestral': '#FFD700'    # Gold
    }
    
    for rarity in all_rarities:
        count = counts.get(rarity, 0)
        rarities.append(rarity)
        values.append(count)
        colors.append(rarity_colors.get(rarity, '#CCCCCC'))
    
    # Create bar plot
    bars = ax.bar(rarities, values, color=colors, alpha=0.8, edgecolor='black', linewidth=0.5)
    
    # Customize the plot
    ax.set_title(f'{module_rarity} Modules', fontweight='bold', fontsize=12)
    ax.set_xlabel('Substat Rarity')
    ax.set_ylabel('Count (out of 100)')
    
    # Rotate x-axis labels for better readability
    ax.tick_params(axis='x', rotation=45)
    
    # Set y-axis limit to accommodate labels
    ax.set_ylim(0, max(values) * 1.15 if values else 10)
    
    # Add grid for better readability
    ax.grid(axis='y', alpha=0.3)
    
    # Add percentage annotations only
    total = sum(values)
    for i, (rarity, value) in enumerate(zip(rarities, values)):
        if value > 0:
            percentage = (value / total) * 100
            ax.text(i, value + 1, f'{percentage:.1f}%', 
                   ha='center', va='bottom', fontsize=10, fontweight='bold')

# Run the test
if __name__ == "__main__":
    test_results = test_substat_rarity_distribution()


def simulate_module_pull(current_pity: int) -> Module:
    """Simulate a module pull and return a Module instance."""
    level = 1
    def roll_rarity(current_pity: int) -> str:
        if current_pity == 150:
            rarity = "Epic"
            current_pity = 0
        else:
            rarity_roll = random.random()
            if rarity_roll < 0.025:
                rarity = "Epic"
                current_pity = 0
            elif rarity_roll < 0.315:
                rarity = "Rare"
                current_pity += 1
            else:
                rarity = "Common"
                current_pity += 1
        return rarity
    def roll_module_type():
        type_roll = random.randint(1, 4)
        if type_roll == 1:
            module_type = "Cannon"
        elif type_roll == 2:
            module_type = "Armor"
        elif type_roll == 3:
            module_type = "Generator"
        elif type_roll == 4:
            module_type = "Core"
        else:   
            raise ValueError(f"Invalid module type: {type_roll}")
        return module_type
    def roll_substat_rarity(module_rarity: str) -> str:
        # Validate that this is a purchased module rarity
        valid_purchased_rarities = ["Common", "Rare", "Epic"]
        if module_rarity not in valid_purchased_rarities:
            raise ValueError(
                f"Invalid module rarity '{module_rarity}'. "
                f"Purchased modules can only be {', '.join(valid_purchased_rarities)}. "
                f"Received: {module_rarity}"
            )
        
        RARITY_ORDER = module_lookups['rarity_order']
        BASE_SUBSTAT_WEIGHTS = module_lookups['subeffect_drop_chance']
        # Step 1: Filter the probabilities
        module_rarity_index = RARITY_ORDER.index(module_rarity)
        valid_rarities = []
        valid_weights = []
        for i, rarity in enumerate(RARITY_ORDER):
            if i <= module_rarity_index:
                valid_rarities.append(rarity)
                valid_weights.append(BASE_SUBSTAT_WEIGHTS[rarity])

        # Step 2: Normalize the weights
        normalized_weights = np.array(valid_weights, dtype=np.float64) / sum(valid_weights)

        # Step 3: Perform the weighted random choice
        chosen_rarity = np.random.choice(valid_rarities, p=normalized_weights)
        
        return chosen_rarity
    def roll_substat(module_type: str, substat_rarity: str, excluded_substats: Optional[Set[int]] = None) -> int:
        """
        Simulate pulling a specific substat based on module type, substat rarity, and excluded substats.
        
        Args:
            module_type: The type of module (Cannon, Armor, Generator, Core)
            substat_rarity: The rarity of the substat to roll
            excluded_substats: Set of substat enum IDs that have already been chosen (for Rare/Epic modules)
            
        Returns:
            The enum ID of the chosen substat
        """
        if excluded_substats is None:
            excluded_substats = set()
        
        # Get all substats from module_lookups
        substat_values = module_lookups['substat_values']
        
        # Step 1: Filter substats by module type
        type_filtered_substats = []
        for enum_id, substat_data in substat_values.items():
            if substat_data['type'] == module_type:
                type_filtered_substats.append((enum_id, substat_data))
        
        # Step 2: Filter substats that have a value for the specified rarity
        rarity_filtered_substats = []
        for enum_id, substat_data in type_filtered_substats:
            if substat_rarity in substat_data['values']:
                rarity_filtered_substats.append((enum_id, substat_data))
        
        # Step 3: Filter out already chosen substats
        available_substats = []
        for enum_id, substat_data in rarity_filtered_substats:
            if enum_id not in excluded_substats:
                available_substats.append((enum_id, substat_data))
        
        # Check if we have any available substats
        if not available_substats:
            raise ValueError(
                f"No available substats for {module_type} module with {substat_rarity} rarity. "
                f"Excluded substats: {excluded_substats}"
            )
        
        # Step 4: Randomly choose from available substats
        # For now, using uniform distribution - could be weighted in the future
        chosen_enum_id, _ = random.choice(available_substats)
        
        return chosen_enum_id
    
    # Simulate the module pull
    rarity = roll_rarity(current_pity)
    module_type = roll_module_type()
    
    # Determine number of substats based on module rarity
    if rarity == "Common":
        num_substats = 1
    elif rarity == "Rare":
        num_substats = 2
    elif rarity == "Epic":
        num_substats = 2
    else:
        # This shouldn't happen for purchased modules, but handle it gracefully
        num_substats = 1
    
    # Roll substats
    substat_enum_ids = []
    substat_rarities = []
    excluded_substats = set()
    
    for i in range(num_substats):
        # Roll substat rarity for this slot
        substat_rarity = roll_substat_rarity(rarity)
        
        # Roll specific substat
        substat_enum_id = roll_substat(module_type, substat_rarity, excluded_substats)
        
        # Add to results
        substat_enum_ids.append(substat_enum_id)
        substat_rarities.append(substat_rarity)
        
        # Add to excluded set for subsequent rolls
        excluded_substats.add(substat_enum_id)
    
    # Create and return the module
    return Module(
        guid=f"module_{random.randint(1000, 9999)}",
        name=f"{module_type} Module",
        module_type=module_type,
        rarity=rarity,
        level=level,
        substat_enum_ids=substat_enum_ids,
        substat_rarities=substat_rarities,
        coins_spent=0,
        shards_spent=0,
        is_equipped=False,
    )

# Initialize logger
logger = structlog.get_logger()

def build_module_lookup(lookup_file: str):
    try:
        with open(lookup_file, "r") as f:
            module_lookups = yaml.safe_load(f)
        logger.info("Module lookup data loaded successfully", file=lookup_file)
        return module_lookups
    except FileNotFoundError:
        logger.error("Module lookup file not found", file=lookup_file)
        raise
    except yaml.YAMLError as e:
        logger.error("Failed to parse YAML file", file=lookup_file, error=str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error loading module lookup", file=lookup_file, error=str(e))
        raise

module_lookups = build_module_lookup(lookup_file)

def get_substat_value(enum_id, rarity):
    try:
        return module_lookups['substat_values'][enum_id]['values'][rarity]
    except KeyError:
        logger.error("Substat value not found", enum_id=enum_id, rarity=rarity)
        return None

def get_substat_name(enum_id):
    try:
        return module_lookups['substat_values'][enum_id]['name'].replace('_', ' ')
    except KeyError:
        logger.error("Substat name not found", enum_id=enum_id)
        return None

def get_substat_unit(enum_id):
    try:
        return module_lookups['substat_values'][enum_id]['unit']
    except KeyError:
        logger.error("Substat unit not found", enum_id=enum_id)
        return None
    
def get_substat_value_sign(enum_id, rarity):
    try:
        if module_lookups['substat_values'][enum_id]['values'][rarity] > 0:
            return "+"
        else:
            return ""
    except KeyError:
        logger.error("Substat value sign not found", enum_id=enum_id, rarity=rarity)
        return None

def get_substat_value_formatted(enum_id, rarity):
    substat_value_sign = get_substat_value_sign(enum_id, rarity)
    substat_value = get_substat_value(enum_id, rarity)
    substat_unit = get_substat_unit(enum_id)
    return f"{substat_value_sign}{substat_value}{substat_unit}"

def get_substat_light_color(rarity):
    try:
        return module_lookups['rarity_colors'][rarity]['light_color']
    except KeyError:
        return None

def get_substat_dark_color(rarity):
    try:
        return module_lookups['rarity_colors'][rarity]['dark_color']
    except KeyError:
        return None

def hex_to_rgb(hex_str):
    hex_str = hex_str.strip("#")
    return tuple(int(hex_str[i:i+2], 16) for i in (0, 2, 4))

def print_colored(text, hex_color, background=False):
    r, g, b = hex_to_rgb(hex_color)
    prefix = "48" if background else "38"
    return (f"\033[{prefix};2;{r};{g};{b}m{text}\033[0m")

def validate(enum_id, rarity, module_type: Optional[str] = None, module_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Comprehensive validation function for module combinations.
    
    Args:
        enum_id: The substat enum ID to validate
        rarity: The rarity level to validate
        module_type: Optional module type (Cannon, Armor, Generator, Core) for compatibility check
        module_id: Optional module ID for additional validation
        
    Returns:
        Dict containing validation results with detailed information
    """
    validation_result = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'details': {
            'enum_id': enum_id,
            'rarity': rarity,
            'module_type': module_type,
            'module_id': module_id,
            'substat_name': None,
            'substat_unit': None,
            'substat_value': None,
            'applies_to': None,
            'rarity_colors': None
        }
    }
    
    logger.info("Starting comprehensive validation", 
                enum_id=enum_id, rarity=rarity, module_type=module_type, module_id=module_id)
    
    # 1. Validate enum_id exists
    if enum_id not in module_lookups['substat_values']:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Invalid enum_id: {enum_id} does not exist")
        logger.error("Invalid enum_id", enum_id=enum_id)
        return validation_result
    
    substat_data = module_lookups['substat_values'][enum_id]
    validation_result['details']['substat_name'] = substat_data.get('name', 'Unknown')
    
    # 2. Validate rarity exists in rarity_colors
    if rarity not in module_lookups['rarity_colors']:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Invalid rarity: {rarity} does not exist")
        logger.error("Invalid rarity", rarity=rarity)
        return validation_result
    
    validation_result['details']['rarity_colors'] = module_lookups['rarity_colors'][rarity]
    
    # 3. Validate substat has required fields
    required_fields = ['name', 'unit', 'applies_to', 'values']
    for field in required_fields:
        if field not in substat_data:
            validation_result['valid'] = False
            validation_result['errors'].append(f"Missing required field '{field}' for enum_id {enum_id}")
            logger.error("Missing required field", field=field, enum_id=enum_id)
    
    if not validation_result['valid']:
        return validation_result
    
    # 4. Validate substat value exists for this rarity
    if rarity not in substat_data['values']:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Substat {substat_data['name']} (ID: {enum_id}) does not have a value for rarity {rarity}")
        logger.error("Substat value not found for rarity", 
                    enum_id=enum_id, substat_name=substat_data['name'], rarity=rarity)
        return validation_result
    
    # 5. Validate substat value is not null/empty
    substat_value = substat_data['values'][rarity]
    if substat_value is None:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Substat {substat_data['name']} (ID: {enum_id}) has null value for rarity {rarity}")
        logger.error("Null substat value", enum_id=enum_id, substat_name=substat_data['name'], rarity=rarity)
        return validation_result
    
    validation_result['details']['substat_value'] = substat_value
    validation_result['details']['substat_unit'] = substat_data['unit']
    validation_result['details']['applies_to'] = substat_data['applies_to']
    
    # 6. Validate module type compatibility (if provided)
    if module_type is not None:
        if module_type != substat_data['applies_to']:
            validation_result['warnings'].append(
                f"Module type '{module_type}' may not be compatible with substat '{substat_data['name']}' "
                f"which applies to '{substat_data['applies_to']}'"
            )
            logger.warning("Potential module type incompatibility", 
                          module_type=module_type, applies_to=substat_data['applies_to'], 
                          substat_name=substat_data['name'])
    
    # 7. Validate module_id (if provided)
    if module_id is not None:
        # Check if module_id exists in module definitions
        if 'modules' in module_lookups and str(module_id) in module_lookups['modules']:
            module_data = module_lookups['modules'][str(module_id)]
            module_type_from_id = module_data.get('type', 'Unknown')
            
            if module_type_from_id != substat_data['applies_to']:
                validation_result['warnings'].append(
                    f"Module ID {module_id} is type '{module_type_from_id}' but substat '{substat_data['name']}' "
                    f"applies to '{substat_data['applies_to']}'"
                )
                logger.warning("Module ID type mismatch", 
                              module_id=module_id, module_type=module_type_from_id, 
                              applies_to=substat_data['applies_to'])
        else:
            validation_result['warnings'].append(f"Module ID {module_id} not found in module definitions")
            logger.warning("Module ID not found", module_id=module_id)
    
    # 8. Validate rarity color definitions
    rarity_colors = module_lookups['rarity_colors'][rarity]
    if 'light_color' not in rarity_colors or 'dark_color' not in rarity_colors:
        validation_result['warnings'].append(f"Missing color definitions for rarity {rarity}")
        logger.warning("Missing color definitions", rarity=rarity)
    
    # 9. Check for zero values (might be intentional but worth noting)
    if isinstance(substat_value, (int, float)) and substat_value == 0:
        validation_result['warnings'].append(f"Substat {substat_data['name']} has zero value for rarity {rarity}")
        logger.debug("Zero substat value", enum_id=enum_id, substat_name=substat_data['name'], rarity=rarity)
    
    logger.info("Validation completed", 
                valid=validation_result['valid'], 
                error_count=len(validation_result['errors']),
                warning_count=len(validation_result['warnings']))
    
    return validation_result

def validate_module_combination(module_id: int, rarity: str, substat_enum_id: int) -> Dict[str, Any]:
    """
    Validate a complete module combination including module ID, rarity, and substat.
    
    Args:
        module_id: The module ID to validate
        rarity: The rarity level
        substat_enum_id: The substat enum ID
        
    Returns:
        Dict containing comprehensive validation results
    """
    validation_result = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'details': {
            'module_id': module_id,
            'rarity': rarity,
            'substat_enum_id': substat_enum_id,
            'module_name': None,
            'module_type': None,
            'substat_name': None,
            'compatibility': 'unknown'
        }
    }
    
    logger.info("Starting module combination validation", 
                module_id=module_id, rarity=rarity, substat_enum_id=substat_enum_id)
    
    # 1. Validate module exists
    if 'modules' not in module_lookups or str(module_id) not in module_lookups['modules']:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Module ID {module_id} does not exist")
        logger.error("Module ID not found", module_id=module_id)
        return validation_result
    
    module_data = module_lookups['modules'][str(module_id)]
    validation_result['details']['module_name'] = module_data.get('name', 'Unknown')
    validation_result['details']['module_type'] = module_data.get('type', 'Unknown')
    
    # 2. Validate substat
    substat_validation = validate(substat_enum_id, rarity, module_data.get('type'))
    if not substat_validation['valid']:
        validation_result['valid'] = False
        validation_result['errors'].extend(substat_validation['errors'])
    
    validation_result['warnings'].extend(substat_validation['warnings'])
    validation_result['details']['substat_name'] = substat_validation['details']['substat_name']
    
    # 3. Check compatibility
    if substat_validation['details']['applies_to'] == module_data.get('type'):
        validation_result['details']['compatibility'] = 'compatible'
    elif substat_validation['details']['applies_to'] != module_data.get('type'):
        validation_result['details']['compatibility'] = 'incompatible'
        validation_result['warnings'].append(
            f"Module '{module_data.get('name')}' (type: {module_data.get('type')}) "
            f"may not be compatible with substat '{substat_validation['details']['substat_name']}' "
            f"(applies to: {substat_validation['details']['applies_to']})"
        )
    
    logger.info("Module combination validation completed", 
                valid=validation_result['valid'],
                compatibility=validation_result['details']['compatibility'])
    
    return validation_result

def print_validation_result(validation_result: Dict[str, Any], show_details: bool = True):
    """
    Print validation results in a formatted way.
    
    Args:
        validation_result: The validation result dictionary
        show_details: Whether to show detailed information
    """
    if validation_result['valid']:
        print(f"✅ VALID: {validation_result['details']['substat_name']} (ID: {validation_result['details']['enum_id']}) at {validation_result['details']['rarity']} rarity")
    else:
        print(f"❌ INVALID: {validation_result['details']['substat_name']} (ID: {validation_result['details']['enum_id']}) at {validation_result['details']['rarity']} rarity")
    
    if validation_result['errors']:
        print("  Errors:")
        for error in validation_result['errors']:
            print(f"    ❌ {error}")
    
    if validation_result['warnings']:
        print("  Warnings:")
        for warning in validation_result['warnings']:
            print(f"    ⚠️  {warning}")
    
    if show_details and validation_result['details']['substat_value'] is not None:
        print(f"  Value: {validation_result['details']['substat_value']}{validation_result['details']['substat_unit']}")
        if validation_result['details']['applies_to']:
            print(f"  Applies to: {validation_result['details']['applies_to']}")

def print_colored_substat_full(enum_id, rarity):
    substat_name = get_substat_name(enum_id)
    substat_value_formatted = get_substat_value_formatted(enum_id, rarity)
    substat_light_color = get_substat_light_color(rarity)
    substat_dark_color = get_substat_dark_color(rarity)
    print(print_colored(substat_value_formatted, substat_dark_color) + " " + print_colored(substat_name, substat_light_color))

def test_module_class():
    """Test function to demonstrate the Module class usage."""
    try:
        # Create a test module based on the data from the attached files
        test_module = Module(
            guid="59211dfd-747b-448a-8e3a-640dc3514984",
            name="Wormhole Redirector",
            module_type="Armor",
            rarity="LegendaryPlus",
            level=90,
            substat_enum_ids=[19, 20, 21],  # Example substat IDs
            coins_spent=4796440000,
            shards_spent=15588,
            is_equipped=True,
            is_favorite=True
        )
        
        print("Test Module Created Successfully:")
        print(test_module)
        print("\n" + "="*50)
        
        # Test individual methods
        print(f"Formatted Name: {test_module.get_formatted_name()}")
        print(f"Status Flags: {test_module.get_status_flags()}")
        print(f"Stats Summary: {test_module.get_stats_summary()}")
        print(f"Sprites Summary: {test_module.get_sprites_summary()}")
        
        return True
        
    except Exception as e:
        logger.error("Test failed", error=str(e))
        return False

if __name__ == "__main__":
    test_substat_rarity_distribution()
    test_substat_pulling()
    test_module_class()
