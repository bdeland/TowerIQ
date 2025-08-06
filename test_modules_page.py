#!/usr/bin/env python3
"""
Test script for module simulator profiling.

This script demonstrates the profiling capabilities of the module simulator,
including timing analysis and HTML flame graph generation.
"""

import sys
import os
import time

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from tower_iq.core.game_data.modules.module_simulator import (
    ModuleSimulator, 
    profile_module_simulation, 
    quick_profile_pull,
    PYINSTRUMENT_AVAILABLE
)
from tower_iq.core.game_data.modules.game_data_manager import GameDataManager


def test_basic_simulation(data_manager: GameDataManager):
    """Test basic module simulation without profiling."""
    print("=== Basic Module Simulation Test ===")
    
    simulator = ModuleSimulator(data_manager, seed=42)
    
    # Simulate a few modules
    modules = simulator.simulate_multiple_pulls(10)
    
    print(f"Generated {len(modules)} modules:")
    for i, module in enumerate(modules[:3]):  # Show first 3
        print(f"  {i+1}. {module.name} ({module.rarity.display_name}) - {module.substat_count} substats")
    
    if len(modules) > 3:
        print(f"  ... and {len(modules) - 3} more modules")


def test_timing_profiling():
    """Test timing-based profiling with decorators."""
    print("\n=== Timing Profiling Test ===")
    
    # Profile 100 module pulls
    print("Profiling 100 module pulls with timing decorators...")
    start_time = time.perf_counter()
    
    result = profile_module_simulation(100, seed=42, save_html=False)
    
    end_time = time.perf_counter()
    total_time = end_time - start_time
    
    print(f"Total profiling time: {total_time:.3f}s")
    print(f"Modules generated: {result['modules_generated']}")
    
    # Show timing statistics
    print("\nMethod timing breakdown:")
    for method_name, stats in result['timing_stats'].items():
        print(f"  {method_name}:")
        print(f"    Total: {stats['total_time']:.6f}s ({stats['total_time']/total_time*100:.1f}%)")
        print(f"    Average: {stats['avg_time']:.6f}s per call")
        print(f"    Calls: {stats['call_count']}")
        print(f"    Min/Max: {stats['min_time']:.6f}s / {stats['max_time']:.6f}s")


def test_pyinstrument_profiling():
    """Test pyinstrument profiling with HTML flame graphs."""
    print("\n=== PyInstrument Profiling Test ===")
    
    if not PYINSTRUMENT_AVAILABLE:
        print("pyinstrument not available. Install with: pip install pyinstrument")
        return
    
    print("Profiling with pyinstrument (HTML flame graph)...")
    
    # Quick profile with pyinstrument
    result = quick_profile_pull(100, seed=42)
    
    if 'html_output' in result:
        print("✓ HTML flame graph generated successfully!")
        
        # Save the HTML file
        html_filename = "module_simulation_flamegraph.html"
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(result['html_output'])
        
        print(f"✓ HTML flame graph saved to: {html_filename}")
        print("  Open this file in your browser to view the interactive flame graph")
        
        # Show text preview
        print("\nText output preview:")
        text_lines = result['text_output'].split('\n')[:10]
        for line in text_lines:
            print(f"  {line}")
        if len(result['text_output'].split('\n')) > 10:
            print("  ...")
    else:
        print("✗ Error generating flame graph:", result.get('error', 'Unknown error'))


def test_comprehensive_profiling():
    """Test comprehensive profiling with both methods."""
    print("\n=== Comprehensive Profiling Test ===")
    
    print("Running comprehensive profiling (1000 modules)...")
    start_time = time.perf_counter()
    
    # Use the comprehensive profiling function
    result = profile_module_simulation(
        count=100000, 
        seed=42, 
        save_html=True, 
        html_filename="comprehensive_module_profile.html"
    )
    
    end_time = time.perf_counter()
    total_time = end_time - start_time
    
    print(f"✓ Comprehensive profiling completed in {total_time:.3f}s")
    print(f"✓ Generated {result['modules_generated']} modules")
    
    # Show timing breakdown
    print("\nDetailed timing breakdown:")
    total_method_time = sum(stats['total_time'] for stats in result['timing_stats'].values())
    
    for method_name, stats in result['timing_stats'].items():
        percentage = (stats['total_time'] / total_method_time * 100) if total_method_time > 0 else 0
        print(f"  {method_name}: {stats['total_time']:.6f}s ({percentage:.1f}%)")
    
    # Show HTML file info
    if 'pyinstrument_stats' in result and 'html_file_saved' in result['pyinstrument_stats']:
        print(f"\n✓ HTML flame graph saved to: {result['pyinstrument_stats']['html_file_saved']}")


def main():
    """Main test function."""
    print("Module Simulator Profiling Test")
    print("=" * 40)
    
    # Initialize GameDataManager for optimized simulations
    print("Initializing GameDataManager for optimized simulations...")
    start_time = time.perf_counter()
    data_manager = GameDataManager()  # Create the manager ONCE
    end_time = time.perf_counter()
    print(f"DataManager initialized in {end_time - start_time:.3f}s")
    
    # Test basic functionality
    test_basic_simulation(data_manager)
    
    # Test timing profiling
    test_timing_profiling()
    
    # Test pyinstrument profiling
    test_pyinstrument_profiling()
    
    # Test comprehensive profiling
    test_comprehensive_profiling()
    
    print("\n" + "=" * 40)
    print("Profiling tests completed!")
    print("\nTo view the HTML flame graphs:")
    print("1. Open the generated .html files in your web browser")
    print("2. The flame graphs show function call hierarchies and timing")
    print("3. Hover over bars to see detailed timing information")
    print("4. Click on bars to zoom into specific function calls")


if __name__ == "__main__":
    main() 