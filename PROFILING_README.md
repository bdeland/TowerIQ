# Module Simulator Profiling

This document explains how to use the profiling features added to the module simulator to analyze performance when simulating large numbers of modules.

## Features

The module simulator now includes comprehensive profiling capabilities:

1. **Timing Decorators**: Automatic timing of key methods with detailed statistics
2. **cProfile Integration**: Standard Python profiling with detailed function call analysis
3. **PyInstrument Integration**: Beautiful HTML flame graphs for visual performance analysis
4. **Convenience Functions**: Easy-to-use functions for quick profiling

## Installation

Install the required profiling dependencies:

```bash
pip install -r requirements_profiling.txt
```

Or install pyinstrument directly:

```bash
pip install pyinstrument
```

## Quick Start

### Basic Profiling

```python
from tower_iq.core.game_data.modules.module_simulator import profile_module_simulation

# Profile 100 module pulls with timing analysis
result = profile_module_simulation(100, seed=42)

# View timing statistics
for method_name, stats in result['timing_stats'].items():
    print(f"{method_name}: {stats['total_time']:.6f}s")
```

### HTML Flame Graph

```python
from tower_iq.core.game_data.modules.module_simulator import quick_profile_pull

# Generate HTML flame graph
result = quick_profile_pull(100, seed=42)

# Save HTML file
with open("flamegraph.html", "w") as f:
    f.write(result['html_output'])
```

## Available Functions

### `profile_module_simulation(count, seed=None, save_html=True, html_filename="module_simulation_profile.html")`

Comprehensive profiling function that combines:
- Timing decorators for method-level analysis
- cProfile for detailed function call profiling
- PyInstrument for HTML flame graphs

**Returns**: Dictionary with timing stats, profiling data, and generated modules

### `quick_profile_pull(count, seed=None)`

Quick profiling using only PyInstrument for HTML flame graphs.

**Returns**: Dictionary with HTML output and text output

### `ModuleSimulator(enable_profiling=True)`

Create a simulator with profiling enabled:

```python
simulator = ModuleSimulator(seed=42, enable_profiling=True)
simulator.start_profiling()
modules = simulator.simulate_multiple_pulls(100)
stats = simulator.stop_profiling()
pyinstrument_stats = simulator.stop_pyinstrument_profiling()
```

## Performance Analysis

### Timing Breakdown

The profiling provides detailed timing for key methods:

- `simulate_module_pull`: Complete module generation
- `simulate_multiple_pulls`: Batch module generation
- `_select_rarity_by_probability`: Rarity selection logic
- `_generate_substats_for_module`: Substat generation (usually the most time-consuming)
- `_select_substat_rarity`: Substat rarity selection

### Typical Performance

Based on profiling results:
- **100 modules**: ~0.08 seconds
- **1000 modules**: ~0.2 seconds
- **10,000 modules**: ~2 seconds

The most time-consuming operations are:
1. Substat generation (~25% of total time)
2. Module pull simulation (~35% of total time)
3. Rarity selection (~1-2% of total time)

## HTML Flame Graphs

The PyInstrument integration generates interactive HTML flame graphs that show:

- Function call hierarchies
- Time spent in each function
- Call counts
- Interactive zoom and hover features

To view the flame graphs:
1. Open the generated `.html` files in a web browser
2. Hover over bars to see detailed timing
3. Click on bars to zoom into specific function calls
4. Use the search feature to find specific functions

## Example Usage

Run the test script to see all features in action:

```bash
python test_modules_page.py
```

This will:
1. Test basic module simulation
2. Run timing profiling on 100 modules
3. Generate HTML flame graphs
4. Run comprehensive profiling on 1000 modules
5. Save HTML files for visual analysis

## Troubleshooting

### PyInstrument Not Available

If you see "pyinstrument not available", install it:

```bash
pip install pyinstrument
```

### Import Errors

Make sure you're running from the project root directory and the `src` folder is in your Python path.

### Performance Issues

If profiling itself is slow:
- Reduce the number of modules being profiled
- Use `quick_profile_pull()` for faster PyInstrument-only profiling
- Disable HTML generation with `save_html=False`

## Memory Usage

The profiling features add minimal memory overhead:
- Timing decorators: ~1KB per method call
- cProfile: ~10-50KB depending on call depth
- PyInstrument: ~100-500KB for HTML generation

For large simulations (10,000+ modules), consider profiling smaller batches to avoid memory issues. 