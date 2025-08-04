#!/usr/bin/env python3
"""
Demo script for the modern module simulator.
Run this to see the new system in action with proper module definitions!
"""

import sys
sys.path.append('src')

from tower_iq.core.modern_module_simulator import ModernModuleSimulator, demo_new_system

def demo_epic_modules():
    """Demo Epic modules specifically to show unique effects."""
    print("=== Epic Module Demo ===")
    
    simulator = ModernModuleSimulator()
    
    # Try to pull some Epic modules (we'll force the pity system)
    print("Forcing Epic pulls to show unique effects:\n")
    
    epic_count = 0
    attempts = 0
    
    while epic_count < 5 and attempts < 200:  # Safety limit
        # Force Epic by using pity system
        module = simulator.simulate_module_pull(current_pity=150)
        attempts += 1
        
        if module.rarity.value == "Epic":
            epic_count += 1
            print(f"Epic Pull #{epic_count}:")
            print(f"  Module: {module.name}")
            print(f"  Type: {module.module_type.value}")
            print(f"  Rarity: {module.rarity.value}")
            
            if module.unique_effect:
                print(f"  🌟 Unique Effect: {module.unique_effect.name}")
                # Show effect at Epic rarity
                epic_value = module.unique_effect.values.get(module.rarity)
                effect_text = module.unique_effect.effect_template.replace("{X}", str(epic_value))
                print(f"     {effect_text}")
            
            print(f"  Substats:")
            for substat in module.substats:
                print(f"    - {substat['name']} ({substat['rarity']}): "
                      f"{substat['value']}{substat['unit']}")
            print()
    
    print(f"Found {epic_count} Epic modules in {attempts} attempts")

def demo_all_epic_modules():
    """Show all available Epic module definitions."""
    print("\n=== All Available Epic Modules ===")
    
    simulator = ModernModuleSimulator()
    
    for module_type, definitions in simulator.module_definitions_by_type.items():
        print(f"\n{module_type.value.title()} Modules ({len(definitions)}):")
        for definition in definitions:
            print(f"  - {definition.name}")
            if definition.unique_effect:
                epic_value = definition.unique_effect.values.get(definition.rarity, "?")
                effect_preview = definition.unique_effect.effect_template.replace("{X}", str(epic_value))
                print(f"    Effect: {effect_preview}")

if __name__ == "__main__":
    print("🎮 Modern Module Simulator Demo")
    print("=" * 50)
    
    # Run the standard demo
    demo_new_system()
    
    print("\n" + "=" * 50)
    
    # Show Epic modules specifically
    demo_epic_modules()
    
    print("=" * 50)
    
    # Show all available modules
    demo_all_epic_modules()
    
    print("\n🎉 Demo complete! The modern system is working with proper ModuleDefinitions.")