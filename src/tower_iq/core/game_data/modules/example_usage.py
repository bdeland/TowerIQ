"""
Example Usage of Module Simulator

This script demonstrates how to use the module simulator for various scenarios.
"""

from .module_simulator import (
    ModuleSimulator, 
    simulate_single_pull, 
    simulate_multiple_pulls,
    get_pull_statistics
)
from ._enums import ModuleType, Rarity


def example_basic_usage():
    """Demonstrate basic usage of the module simulator."""
    print("=== Basic Usage Example ===")
    
    # Create a simulator with a fixed seed for reproducible results
    simulator = ModuleSimulator(seed=123)
    
    # Simulate a random module pull
    module = simulator.simulate_module_pull()
    print(f"Random pull: {module.name} ({module.rarity.value})")
    print(f"Type: {module.module_type.value}")
    print(f"Substats: {module.substat_count}")
    for substat in module.substats:
        print(f"  - {substat.name}: {substat.value}{substat.unit} ({substat.rarity.value})")
    
    if module.has_unique_effect and module.unique_effect:
        print(f"Unique Effect: {module.unique_effect.name}")


def example_specific_pulls():
    """Demonstrate pulling specific module types and rarities."""
    print("\n=== Specific Pulls Example ===")
    
    simulator = ModuleSimulator(seed=456)
    
    # Pull random modules (no forced type or rarity)
    module1 = simulator.simulate_module_pull()
    print(f"Random pull 1: {module1.name} ({module1.rarity.value}) - {module1.module_type.value}")
    
    module2 = simulator.simulate_module_pull()
    print(f"Random pull 2: {module2.name} ({module2.rarity.value}) - {module2.module_type.value}")
    
    module3 = simulator.simulate_module_pull()
    print(f"Random pull 3: {module3.name} ({module3.rarity.value}) - {module3.module_type.value}")


def example_multiple_pulls():
    """Demonstrate simulating multiple pulls."""
    print("\n=== Multiple Pulls Example ===")
    
    simulator = ModuleSimulator(seed=789)
    
    # Simulate 10 random pulls
    modules = simulator.simulate_multiple_pulls(10)
    
    print(f"Generated {len(modules)} modules:")
    for i, module in enumerate(modules, 1):
        print(f"{i:2d}. {module.name} ({module.rarity.value}) - {module.substat_count} substats")


def example_convenience_functions():
    """Demonstrate using the convenience functions."""
    print("\n=== Convenience Functions Example ===")
    
    # Single pull using convenience function
    module = simulate_single_pull(seed=111)
    print(f"Convenience pull: {module.name} ({module.rarity.value})")
    
    # Multiple pulls using convenience function
    modules = simulate_multiple_pulls(5, seed=222)
    print(f"5 random modules:")
    for i, module in enumerate(modules, 1):
        print(f"{i}. {module.name} ({module.rarity.value}) - {module.module_type.value}")


def example_statistics():
    """Demonstrate getting pull statistics."""
    print("\n=== Statistics Example ===")
    
    # Get statistics from 1000 pulls
    stats = get_pull_statistics(1000, seed=333)
    
    print("Pull Statistics (1000 pulls):")
    for key, value in stats.items():
        if "percentage" in key:
            print(f"  {key}: {value:.2f}%")
        else:
            print(f"  {key}: {value}")


def example_epic_pity_pull():
    """Demonstrate epic pity pull simulation."""
    print("\n=== Epic Pity Pull Example ===")
    
    simulator = ModuleSimulator(seed=444)
    
    # Simulate epic pity pull
    epic_module = simulator.simulate_epic_pity_pull()
    print(f"Epic pity pull: {epic_module.name}")
    print(f"Type: {epic_module.module_type.value}")
    print(f"Substats: {epic_module.substat_count}")
    
    if epic_module.has_unique_effect and epic_module.unique_effect:
        print(f"Unique Effect: {epic_module.unique_effect.name}")
        print(f"Effect Template: {epic_module.unique_effect.effect_template}")


def example_substat_analysis():
    """Demonstrate analyzing substats across multiple pulls."""
    print("\n=== Substat Analysis Example ===")
    
    simulator = ModuleSimulator(seed=555)
    
    # Generate 50 modules and analyze substats
    modules = simulator.simulate_multiple_pulls(50)
    
    # Count substat occurrences
    substat_counts = {}
    for module in modules:
        for substat in module.substats:
            name = substat.name
            substat_counts[name] = substat_counts.get(name, 0) + 1
    
    print("Most common substats (out of 50 modules):")
    sorted_substats = sorted(substat_counts.items(), key=lambda x: x[1], reverse=True)
    for name, count in sorted_substats[:10]:
        print(f"  {name}: {count} times")


if __name__ == "__main__":
    print("Module Simulator Examples")
    print("=" * 50)
    
    example_basic_usage()
    example_specific_pulls()
    example_multiple_pulls()
    example_convenience_functions()
    example_statistics()
    example_epic_pity_pull()
    example_substat_analysis()
    
    print("\n" + "=" * 50)
    print("All examples completed successfully!") 