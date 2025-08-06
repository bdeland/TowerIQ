"""
Module Simulator

This module provides functions to simulate the creation of modules and their substats
using the existing game logic and constraints. It generates valid modules that match
the limitations and requirements for module pulls.
"""

import random
import time
import cProfile
import pstats
import io
import numpy as np
from functools import wraps
from typing import List, Dict, Optional, Tuple, Callable, Any
from dataclasses import dataclass

# Try to import pyinstrument for flame graphs
try:
    from pyinstrument import Profiler
    PYINSTRUMENT_AVAILABLE = True
except ImportError:
    PYINSTRUMENT_AVAILABLE = False
    Profiler = None

from ._enums import ModuleType, Rarity, Substat, RARITY_TO_MAX_LEVEL
from ._probabilities import MODULE_PULL_CHANCES, SUBSTAT_PULL_CHANCES
from ._substats import ALL_SUBSTATS
from .module_blueprints import (
    ALL_MODULE_BLUEPRINTS, 
    get_blueprints_for_pull,
    BLUEPRINTS_BY_TYPE
)
from .module_dataclass import SubstatInfo, UniqueEffectInfo, ModuleDefinition
from .game_data_manager import GameDataManager


def timing_decorator(func: Callable) -> Callable:
    """Decorator to measure execution time of functions."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        wrapper.execution_times = getattr(wrapper, 'execution_times', [])
        wrapper.execution_times.append(execution_time)
        return result
    return wrapper


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
        
        self.enable_profiling = enable_profiling
        self.profiler = None
        self.pyinstrument_profiler = None
        self.profiling_stats = {}
        
        if enable_profiling:
            self.profiler = cProfile.Profile()
            if PYINSTRUMENT_AVAILABLE and Profiler is not None:
                self.pyinstrument_profiler = Profiler()
    
    def start_profiling(self):
        """Start profiling if enabled."""
        if self.enable_profiling and self.profiler:
            self.profiler.enable()
        if self.enable_profiling and self.pyinstrument_profiler:
            self.pyinstrument_profiler.start()
    
    def stop_profiling(self) -> Dict[str, Any]:
        """Stop profiling and return statistics if enabled."""
        if not self.enable_profiling or not self.profiler:
            return {}
        
        self.profiler.disable()
        
        # Get profiling statistics
        s = io.StringIO()
        ps = pstats.Stats(self.profiler, stream=s).sort_stats('cumulative')
        ps.print_stats(20)  # Top 20 functions by cumulative time
        
        stats_output = s.getvalue()
        
        # Return the raw profiling output
        stats = {
            'raw_output': stats_output,
            'profiler_stats': ps
        }
        
        return stats
    
    def stop_pyinstrument_profiling(self) -> Dict[str, Any]:
        """Stop pyinstrument profiling and return HTML flame graph if enabled."""
        if not self.enable_profiling or not self.pyinstrument_profiler:
            return {}
        
        self.pyinstrument_profiler.stop()
        
        # Generate HTML flame graph
        html_output = self.pyinstrument_profiler.output_html()
        
        # Get text output as well
        text_output = self.pyinstrument_profiler.output_text()
        
        stats = {
            'html_output': html_output,
            'text_output': text_output,
            'pyinstrument_profiler': self.pyinstrument_profiler
        }
        
        return stats
    
    def profile_with_pyinstrument(self, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """
        Profile a function using pyinstrument and return HTML flame graph.
        
        Args:
            func: Function to profile
            *args: Arguments to pass to the function
            **kwargs: Keyword arguments to pass to the function
            
        Returns:
            Dictionary with profiling results including HTML flame graph
        """
        if not PYINSTRUMENT_AVAILABLE or Profiler is None:
            return {'error': 'pyinstrument not available'}
        
        profiler = Profiler()
        profiler.start()
        
        try:
            result = func(*args, **kwargs)
        finally:
            profiler.stop()
        
        # Generate HTML flame graph
        html_output = profiler.output_html()
        text_output = profiler.output_text()
        
        return {
            'result': result,
            'html_output': html_output,
            'text_output': text_output,
            'profiler': profiler
        }
    
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
    
    @timing_decorator
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
        unique_possible_substats = []
        seen_substats = set()
        for rarity_list in possible_substats_for_type.values():
            for sub_info in rarity_list:
                # Use enum_id for deduplication since SubstatInfo objects aren't hashable
                if sub_info.enum_id not in seen_substats:
                    unique_possible_substats.append(sub_info)
                    seen_substats.add(sub_info.enum_id)

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
                valid_rarities = [r for r in substat_info.values if r <= rarity]
                if not valid_rarities:
                    continue # This substat cannot exist on this module, skip it. Should be rare.
                
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


def get_pull_statistics(pull_count: int = 10000, seed: Optional[int] = None) -> Dict[str, float]:
    """
    Convenience function to get pull statistics.
    
    Args:
        pull_count: Number of pulls to simulate
        seed: Optional random seed
        
    Returns:
        Dictionary with pull statistics
    """
    data_manager = GameDataManager()
    simulator = ModuleSimulator(data_manager, seed)
    return simulator.get_pull_statistics(pull_count)


def profile_module_simulation(count: int = 100, seed: Optional[int] = None, 
                            save_html: bool = True, html_filename: str = "module_simulation_profile.html") -> Dict[str, Any]:
    """
    Profile module simulation with both cProfile and pyinstrument.
    
    Args:
        count: Number of modules to simulate
        seed: Optional random seed
        save_html: Whether to save the HTML flame graph to a file
        html_filename: Filename for the HTML output
        
    Returns:
        Dictionary with profiling results
    """
    data_manager = GameDataManager()
    simulator = ModuleSimulator(data_manager, seed=seed, enable_profiling=True)
    
    # Start profiling
    simulator.start_profiling()
    
    # Run the simulation
    modules = simulator.simulate_multiple_pulls(count)
    
    # Stop profiling and get results
    cprofile_stats = simulator.stop_profiling()
    pyinstrument_stats = simulator.stop_pyinstrument_profiling()
    
    # Get timing statistics from decorators
    timing_stats = {}
    for method_name in ['simulate_module_pull', 'simulate_multiple_pulls', 
                       '_select_rarity_by_probability', '_generate_substats_for_module', 
                       '_select_substat_rarity']:
        method = getattr(simulator, method_name, None)
        if method is not None and hasattr(method, 'execution_times'):
            times = method.execution_times
            if times:
                timing_stats[method_name] = {
                    'total_time': sum(times),
                    'avg_time': sum(times) / len(times),
                    'min_time': min(times),
                    'max_time': max(times),
                    'call_count': len(times)
                }
    
    # Save HTML flame graph if requested
    if save_html and 'html_output' in pyinstrument_stats:
        try:
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(pyinstrument_stats['html_output'])
            pyinstrument_stats['html_file_saved'] = html_filename
        except Exception as e:
            pyinstrument_stats['html_save_error'] = str(e)
    
    return {
        'modules_generated': len(modules),
        'cprofile_stats': cprofile_stats,
        'pyinstrument_stats': pyinstrument_stats,
        'timing_stats': timing_stats,
        'modules': modules
    }


def quick_profile_pull(count: int = 100, seed: Optional[int] = None) -> Dict[str, Any]:
    """
    Quick profiling of module pulls using pyinstrument only.
    
    Args:
        count: Number of modules to simulate
        seed: Optional random seed
        
    Returns:
        Dictionary with profiling results
    """
    data_manager = GameDataManager()
    simulator = ModuleSimulator(data_manager, seed=seed)
    
    def run_simulation():
        return simulator.simulate_multiple_pulls(count)
    
    return simulator.profile_with_pyinstrument(run_simulation)


# Example usage and testing
if __name__ == "__main__":
    # Test the simulator
    print("Testing Module Simulator...")
    
    # Create simulator
    data_manager = GameDataManager()
    simulator = ModuleSimulator(data_manager, seed=42)
    
    # Simulate some pulls
    print("\n=== Single Pull Examples ===")
    for i in range(5):
        module = simulator.simulate_module_pull()
        print(f"Pull {i+1}: {module.name} ({module.rarity.display_name}) - {module.substat_count} substats")
        for substat in module.substats:
            print(f"  - {substat.name}: {substat.value}{substat.unit} ({substat.rarity.display_name})")
    
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
    
    print("\n=== Profiling Example ===")
    print("Profiling 100 module pulls...")
    
    # Profile with pyinstrument
    if PYINSTRUMENT_AVAILABLE:
        print("Using pyinstrument for flame graph...")
        profile_result = quick_profile_pull(100, seed=42)
        
        if 'html_output' in profile_result:
            print("HTML flame graph generated!")
            print("Text output preview:")
            print(profile_result['text_output'][:500] + "...")
            
            # Save HTML file
            with open("module_pull_flamegraph.html", "w", encoding="utf-8") as f:
                f.write(profile_result['html_output'])
            print("HTML flame graph saved to: module_pull_flamegraph.html")
        else:
            print("Error generating flame graph:", profile_result.get('error', 'Unknown error'))
    else:
        print("pyinstrument not available. Install with: pip install pyinstrument")
    
    # Profile with timing decorators
    print("\n=== Timing Analysis ===")
    timing_result = profile_module_simulation(100, seed=42, save_html=False)
    
    print("Method timing statistics:")
    for method_name, stats in timing_result['timing_stats'].items():
        print(f"  {method_name}:")
        print(f"    Total time: {stats['total_time']:.6f}s")
        print(f"    Average time: {stats['avg_time']:.6f}s")
        print(f"    Calls: {stats['call_count']}")
        print(f"    Min/Max: {stats['min_time']:.6f}s / {stats['max_time']:.6f}s") 