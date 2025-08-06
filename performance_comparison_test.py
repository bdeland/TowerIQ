#!/usr/bin/env python3
"""
Performance Comparison Test

This script demonstrates the performance improvements from the optimizations
implemented in the module simulation system.
"""

import sys
import os
import time

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from tower_iq.core.game_data.modules.game_data_manager import GameDataManager
from tower_iq.core.game_data.modules.module_simulator import ModuleSimulator


def test_performance_comparison():
    """Test performance improvements with different simulation sizes."""
    print("Performance Comparison Test")
    print("=" * 50)
    
    # Initialize the GameDataManager once
    print("Initializing GameDataManager...")
    start_time = time.perf_counter()
    data_manager = GameDataManager()
    init_time = time.perf_counter() - start_time
    print(f"✓ GameDataManager initialized in {init_time:.6f}s")
    
    # Test different simulation sizes
    test_sizes = [100, 1000, 10000, 100000]
    
    for size in test_sizes:
        print(f"\n--- Testing {size:,} module simulations ---")
        
        # Create simulator with data manager
        simulator = ModuleSimulator(data_manager, seed=42)
        
        # Time the simulation
        start_time = time.perf_counter()
        modules = simulator.simulate_multiple_pulls(size)
        end_time = time.perf_counter()
        
        simulation_time = end_time - start_time
        modules_per_second = size / simulation_time
        
        print(f"✓ Generated {len(modules):,} modules in {simulation_time:.3f}s")
        print(f"✓ Performance: {modules_per_second:,.0f} modules/second")
        
        # Show some sample modules
        if size <= 1000:
            print("Sample modules:")
            for i, module in enumerate(modules[:3]):
                print(f"  {i+1}. {module.name} ({module.rarity.display_name}) - {module.substat_count} substats")
    
    print(f"\n" + "=" * 50)
    print("Performance Test Completed!")
    print("\nKey Improvements:")
    print("1. GameDataManager pre-computes all lookup tables")
    print("2. IntEnum provides fast rarity comparisons")
    print("3. NumPy optimizes probability calculations")
    print("4. Pre-filtered substat pools eliminate expensive filtering")


if __name__ == "__main__":
    test_performance_comparison() 