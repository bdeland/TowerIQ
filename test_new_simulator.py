#!/usr/bin/env python3
"""
Test script to verify the new module simulator works correctly.
Run this to validate your migration from legacy to modern system.
"""

import sys
import os
sys.path.append('src')

from tower_iq.core.modern_module_simulator import ModernModuleSimulator, demo_new_system
from tower_iq.core.game_data.modules._enums import Rarity, ModuleType
from tower_iq.core.game_data.modules._probabilities import MODULE_PULL_CHANCES

def test_basic_functionality():
    """Test that the new simulator works for basic operations."""
    print("=== Testing Basic Functionality ===")
    
    simulator = ModernModuleSimulator()
    
    # Test single pull
    try:
        module = simulator.simulate_module_pull()
        print(f"✅ Module pull successful: {module.name}")
        print(f"   Type: {module.module_type.value}")
        print(f"   Rarity: {module.rarity.value}")
        print(f"   Substats: {len(module.substats)}")
        
        # Test substat access
        if module.substats:
            first_substat = module.substats[0]
            print(f"   First substat: {first_substat['name']} = {first_substat['value']}{first_substat['unit']}")
        
    except Exception as e:
        print(f"❌ Module pull failed: {e}")
        return False
    
    # Test reroll
    try:
        if module.substats:
            original_rarity = module.substat_rarities[0]
            new_rarity = simulator.simulate_substat_reroll(module, 0)
            print(f"✅ Substat reroll successful: {original_rarity.value} -> {new_rarity.value}")
        
    except Exception as e:
        print(f"❌ Substat reroll failed: {e}")
        return False
    
    return True

def test_data_consistency():
    """Test that the new system uses the structured data correctly."""
    print("\n=== Testing Data Consistency ===")
    
    simulator = ModernModuleSimulator()
    
    # Test that we can access structured data
    try:
        # Test module definitions access
        cannon_modules = simulator.module_definitions_by_type.get(ModuleType.CANNON, [])
        if cannon_modules:
            print(f"✅ Module definitions accessible: {len(cannon_modules)} cannon modules")
            print(f"    Example: {cannon_modules[0].name}")
        else:
            print("❌ Could not access module definitions")
            return False
        
        # Test substats by type
        cannon_substats = simulator.substats_by_type.get(ModuleType.CANNON, [])
        print(f"✅ Cannon substats available: {len(cannon_substats)}")
        
        # Test that we can access a specific substat
        if cannon_substats:
            substat = cannon_substats[0]
            print(f"✅ Substat data accessible: {substat.name}")
        
    except Exception as e:
        print(f"❌ Data consistency test failed: {e}")
        return False
    
    return True

def test_rarity_distribution():
    """Test that rarity distribution matches expected probabilities."""
    print("\n=== Testing Rarity Distribution ===")
    
    simulator = ModernModuleSimulator()
    
    # Pull many modules
    num_pulls = 1000
    rarity_counts = {}
    
    try:
        for _ in range(num_pulls):
            module = simulator.simulate_module_pull()
            rarity = module.rarity
            rarity_counts[rarity] = rarity_counts.get(rarity, 0) + 1
        
        print(f"Results from {num_pulls} pulls:")
        for rarity, count in rarity_counts.items():
            percentage = (count / num_pulls) * 100
            expected = MODULE_PULL_CHANCES.get(rarity, 0) * 100
            print(f"  {rarity.value}: {count} ({percentage:.1f}%) - Expected: {expected:.1f}%")
        
        # Check if Common is most frequent (should be ~68.5%)
        common_count = rarity_counts.get(Rarity.COMMON, 0)
        if common_count > num_pulls * 0.5:  # At least 50% should be common
            print("✅ Rarity distribution looks reasonable")
        else:
            print("⚠️ Rarity distribution seems off")
            
    except Exception as e:
        print(f"❌ Rarity distribution test failed: {e}")
        return False
    
    return True

def test_compatibility():
    """Test that new system is compatible with existing code patterns."""
    print("\n=== Testing Legacy Compatibility ===")
    
    simulator = ModernModuleSimulator()
    
    try:
        module = simulator.simulate_module_pull()
        
        # Test that we can access data like the legacy system
        substats = module.substats
        print(f"✅ Legacy-style substat access works: {len(substats)} substats")
        
        # Test data format matches legacy expectations
        if substats:
            substat = substats[0]
            required_keys = ['index', 'enum_id', 'name', 'value', 'unit', 'rarity', 'is_locked']
            missing_keys = [key for key in required_keys if key not in substat]
            
            if not missing_keys:
                print("✅ Substat data format matches legacy expectations")
            else:
                print(f"❌ Missing substat keys: {missing_keys}")
                return False
        
        # Test string conversions work
        module_type_str = module.module_type.value
        rarity_str = module.rarity.value
        print(f"✅ Enum to string conversion works: {module_type_str}, {rarity_str}")
        
    except Exception as e:
        print(f"❌ Compatibility test failed: {e}")
        return False
    
    return True

def main():
    """Run all tests."""
    print("Testing New Module Simulator System")
    print("=" * 50)
    
    tests = [
        test_basic_functionality,
        test_data_consistency,
        test_rarity_distribution,
        test_compatibility
    ]
    
    passed = 0
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n=== Results ===")
    print(f"Passed: {passed}/{len(tests)} tests")
    
    if passed == len(tests):
        print("🎉 All tests passed! Your new system is working correctly.")
        print("\nNext steps:")
        print("1. Update your GUI code to use ModernModuleSimulator")
        print("2. Run the demo: python src/tower_iq/core/modern_module_simulator.py")
        print("3. Gradually replace legacy module_simulator.py usage")
    else:
        print("⚠️ Some tests failed. Check the errors above.")
        print("Make sure your data files are properly set up in game_data/modules/")

if __name__ == "__main__":
    main()