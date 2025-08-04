#!/usr/bin/env python3
"""
Test script to verify the rarity-constrained module system works correctly.
"""

import sys
sys.path.append('src')

from tower_iq.core.modern_module_simulator import ModernModuleSimulator
from tower_iq.core.game_data.modules._enums import Rarity, ModuleType
from tower_iq.core.game_data.modules import _module_catalog

def test_catalog_api():
    """Test that the module catalog API works correctly."""
    print("=== Testing Module Catalog API ===")
    
    # Test catalog statistics
    _module_catalog.print_catalog_statistics()
    print()
    
    # Test rarity-specific functions
    for module_type in ModuleType:
        print(f"{module_type.value.title()} Modules:")
        
        common_modules = _module_catalog.get_modules_for_rarity_and_type(Rarity.COMMON, module_type)
        rare_modules = _module_catalog.get_modules_for_rarity_and_type(Rarity.RARE, module_type)
        
        print(f"  Common-pullable: {common_modules}")
        print(f"  Rare-pullable: {rare_modules}")
        print()
    
    return True

def test_rarity_constraints():
    """Test that module pulls respect rarity constraints."""
    print("=== Testing Rarity Constraints ===")
    
    simulator = ModernModuleSimulator()
    
    # Test results tracking
    common_pulls = {"valid": 0, "invalid": 0, "modules": set()}
    rare_pulls = {"valid": 0, "invalid": 0, "modules": set()}
    epic_pulls = {"valid": 0, "invalid": 0, "modules": set()}
    
    # Simulate many pulls
    num_tests = 1000
    print(f"Simulating {num_tests} pulls for each rarity...")
    
    # Test Common pulls
    for _ in range(num_tests):
        # Force Common rarity (pity = 0)
        module = simulator.simulate_module_pull(current_pity=0)
        if module.rarity == Rarity.COMMON:
            common_pulls["modules"].add(module.name)
            
            # Check if this module should be pullable at Common
            valid_common_modules = _module_catalog.get_modules_for_rarity_and_type(
                Rarity.COMMON, module.module_type
            )
            
            if module.name in valid_common_modules or module.name.startswith("Generic"):
                common_pulls["valid"] += 1
            else:
                common_pulls["invalid"] += 1
                print(f"❌ INVALID Common pull: {module.name} ({module.module_type.value})")
    
    # Test Rare pulls (force by manipulating probabilities temporarily)
    for _ in range(num_tests):
        # This is a bit tricky - we need to force Rare pulls
        # For now, let's pull normally and filter
        module = simulator.simulate_module_pull(current_pity=0)
        if module.rarity == Rarity.RARE:
            rare_pulls["modules"].add(module.name)
            
            # Check if this module should be pullable at Rare
            valid_rare_modules = _module_catalog.get_modules_for_rarity_and_type(
                Rarity.RARE, module.module_type
            )
            
            if module.name in valid_rare_modules or module.name.startswith("Generic"):
                rare_pulls["valid"] += 1
            else:
                rare_pulls["invalid"] += 1
                print(f"❌ INVALID Rare pull: {module.name} ({module.module_type.value})")
    
    # Test Epic pulls (force by using pity)
    for _ in range(100):  # Fewer epic tests since they're guaranteed
        # Force Epic with pity system
        module = simulator.simulate_module_pull(current_pity=150)
        if module.rarity == Rarity.EPIC:
            epic_pulls["modules"].add(module.name)
            
            # Epic modules should have unique effects (natural epics)
            if module.unique_effect is not None:
                epic_pulls["valid"] += 1
            else:
                epic_pulls["invalid"] += 1
                print(f"❌ INVALID Epic pull: {module.name} (no unique effect)")
    
    # Print results
    print(f"\n=== Results ===")
    print(f"Common Pulls: {common_pulls['valid']} valid, {common_pulls['invalid']} invalid")
    print(f"  Unique modules pulled: {len(common_pulls['modules'])}")
    print(f"  Sample modules: {list(common_pulls['modules'])[:5]}")
    
    print(f"\nRare Pulls: {rare_pulls['valid']} valid, {rare_pulls['invalid']} invalid")
    print(f"  Unique modules pulled: {len(rare_pulls['modules'])}")
    print(f"  Sample modules: {list(rare_pulls['modules'])[:5]}")
    
    print(f"\nEpic Pulls: {epic_pulls['valid']} valid, {epic_pulls['invalid']} invalid")
    print(f"  Unique modules pulled: {len(epic_pulls['modules'])}")
    print(f"  Sample modules: {list(epic_pulls['modules'])[:5]}")
    
    # Validate constraints
    success = True
    if common_pulls["invalid"] > 0:
        print(f"❌ FAILED: {common_pulls['invalid']} invalid Common pulls")
        success = False
    
    if rare_pulls["invalid"] > 0:
        print(f"❌ FAILED: {rare_pulls['invalid']} invalid Rare pulls")
        success = False
        
    if epic_pulls["invalid"] > 0:
        print(f"❌ FAILED: {epic_pulls['invalid']} invalid Epic pulls")
        success = False
    
    if success:
        print("✅ All rarity constraints respected!")
    
    return success

def test_specific_constraints():
    """Test specific known constraints from game data."""
    print("\n=== Testing Specific Known Constraints ===")
    
    # Test that Energy Cannon can only be Common
    common_cannons = _module_catalog.get_modules_for_rarity_and_type(Rarity.COMMON, ModuleType.CANNON)
    rare_cannons = _module_catalog.get_modules_for_rarity_and_type(Rarity.RARE, ModuleType.CANNON)
    
    print(f"Energy Cannon in Common cannons: {'Energy Cannon' in common_cannons}")
    print(f"Energy Cannon in Rare cannons: {'Energy Cannon' in rare_cannons}")
    
    # Test that Stellar Lift can only be Rare (not Common)
    common_generators = _module_catalog.get_modules_for_rarity_and_type(Rarity.COMMON, ModuleType.GENERATOR)
    rare_generators = _module_catalog.get_modules_for_rarity_and_type(Rarity.RARE, ModuleType.GENERATOR)
    
    print(f"Stellar Lift in Common generators: {'Stellar Lift' in common_generators}")
    print(f"Stellar Lift in Rare generators: {'Stellar Lift' in rare_generators}")
    
    # Verify constraints
    constraints_correct = (
        'Energy Cannon' in common_cannons and
        'Energy Cannon' not in rare_cannons and
        'Stellar Lift' not in common_generators and
        'Stellar Lift' in rare_generators
    )
    
    if constraints_correct:
        print("✅ Specific constraints verified!")
        return True
    else:
        print("❌ Specific constraints failed!")
        return False

def main():
    """Run all rarity constraint tests."""
    print("Testing Rarity-Constrained Module System\n")
    
    # Run all tests
    test1_pass = test_catalog_api()
    test2_pass = test_rarity_constraints() 
    test3_pass = test_specific_constraints()
    
    # Overall result
    if test1_pass and test2_pass and test3_pass:
        print("\n🎉 ALL TESTS PASSED! Rarity constraints working correctly.")
        return True
    else:
        print("\n❌ SOME TESTS FAILED! Check output above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)