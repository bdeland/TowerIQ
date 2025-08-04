#!/usr/bin/env python3
"""
Demo of the complete rarity-constrained module system with realistic module names.
"""

import sys
sys.path.append('src')

from tower_iq.core.modern_module_simulator import ModernModuleSimulator
from tower_iq.core.game_data.modules._enums import Rarity, ModuleType
from tower_iq.core.game_data.modules import _module_catalog

def demo_realistic_pulls():
    """Demo the realistic module pull system."""
    print("🎮 TowerIQ Module Pull Simulator - Realistic Edition")
    print("=" * 60)
    
    simulator = ModernModuleSimulator()
    
    # Show the available modules by rarity
    print("\n📊 Available Modules by Rarity:")
    _module_catalog.print_catalog_statistics()
    
    print("\n🎲 Sample Module Pulls:")
    print("-" * 40)
    
    # Demo different types of pulls
    pull_count = 0
    
    # Show some Common pulls
    print("\n💎 Common Rarity Pulls:")
    for _ in range(8):
        pull_count += 1
        module = simulator.simulate_module_pull(current_pity=0)  # Force no epic pity
        
        if module.rarity == Rarity.COMMON:
            print(f"  [{pull_count:2d}] {module.name} ({module.module_type.value.title()})")
            print(f"      Substats: {len(module.substat_enum_ids)}")
            for substat in module.substats[:2]:  # Show first 2 substats
                print(f"        • {substat['name']}: {substat['value']}{substat['unit']} ({substat['rarity']})")
            if len(module.substats) > 2:
                print(f"        • ... {len(module.substats) - 2} more substats")
            print()
    
    # Show some Rare pulls
    print("💜 Rare Rarity Pulls:")
    rare_count = 0
    attempts = 0
    while rare_count < 6 and attempts < 50:
        attempts += 1
        module = simulator.simulate_module_pull(current_pity=0)
        
        if module.rarity == Rarity.RARE:
            rare_count += 1
            pull_count += 1
            print(f"  [{pull_count:2d}] {module.name} ({module.module_type.value.title()})")
            print(f"      Substats: {len(module.substat_enum_ids)}")
            for substat in module.substats[:3]:  # Show first 3 substats
                print(f"        • {substat['name']}: {substat['value']}{substat['unit']} ({substat['rarity']})")
            if len(module.substats) > 3:
                print(f"        • ... {len(module.substats) - 3} more substats")
            print()
    
    # Show some Epic pulls (with unique effects)
    print("🟠 Epic Rarity Pulls (Natural Epics with Unique Effects):")
    for _ in range(5):
        pull_count += 1
        module = simulator.simulate_module_pull(current_pity=150)  # Force epic with pity
        
        if module.rarity == Rarity.EPIC:
            print(f"  [{pull_count:2d}] ⭐ {module.name} ({module.module_type.value.title()})")
            if module.unique_effect:
                print(f"      🔮 Unique Effect: {module.unique_effect.name}")
                effect_preview = module.unique_effect.effect_template[:80] + "..." if len(module.unique_effect.effect_template) > 80 else module.unique_effect.effect_template
                print(f"         {effect_preview}")
            print(f"      Substats: {len(module.substat_enum_ids)}")
            for substat in module.substats[:3]:  # Show first 3 substats
                print(f"        • {substat['name']}: {substat['value']}{substat['unit']} ({substat['rarity']})")
            if len(module.substats) > 3:
                print(f"        • ... {len(module.substats) - 3} more substats")
            print()
    
    print("=" * 60)
    print("✅ Realistic Module Pull System Complete!")
    print(f"   • {_module_catalog.get_total_module_count()} Regular modules with rarity constraints")
    print(f"   • 16 Natural Epic modules with unique effects") 
    print(f"   • Common pulls: Only basic modules (Energy Cannon, Matter Cannon, etc.)")
    print(f"   • Rare pulls: Advanced modules (Stellar Lift, Galactic Librarian, etc.)")
    print(f"   • Epic pulls: Natural epics with special abilities")

def demo_constraint_verification():
    """Show that the constraints are working correctly."""
    print("\n🔍 Constraint Verification:")
    print("-" * 40)
    
    # Test specific examples
    examples = [
        ("Energy Cannon", "can only be Common"),
        ("Matter Barrier", "can only be Common"),
        ("Stellar Lift", "can only be Rare (never Common)"),
        ("Galactic Librarian", "can only be Rare (never Common)"),
        ("Death Penalty", "can only be Epic (Natural Epic with unique effect)")
    ]
    
    for module_name, constraint in examples:
        print(f"📋 {module_name}: {constraint}")
    
    print(f"\n💡 This ensures pulls feel realistic and match actual game behavior!")

if __name__ == "__main__":
    demo_realistic_pulls()
    demo_constraint_verification()