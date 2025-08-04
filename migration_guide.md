# Module Simulator Migration Guide

## Overview

You currently have two data structure approaches for your module simulator:

1. **Legacy System**: Working but less organized
2. **New Structured System**: Better architecture but incomplete

This guide explains how to migrate to the new system and integrate everything properly.

## Current State Analysis

### ✅ What's Working (Legacy)
- `module_simulator.py` with `Module` class
- `simulate_module_pull()` function
- Data loaded from `module_lookups.yaml`
- Substat rarity distribution testing

### 🚧 What's New (Structured)
- Proper dataclasses in `dataclasses/module_dataclass.py`
- Organized game data in `core/game_data/modules/`
- Type-safe enums (`Rarity`, `ModuleType`, `Substat`)
- `GameDataManager` for efficient lookups
- Separated concerns (rarities, substats, probabilities)

## Migration Steps

### Step 1: Use the New Simulator

I've created `modern_module_simulator.py` that bridges both systems. It uses:
- Your new structured data (enums, dataclasses)
- Proper type safety
- The same simulation logic as your legacy code

### Step 2: Test the New System

```python
from src.tower_iq.core.modern_module_simulator import ModernModuleSimulator

# Create simulator
simulator = ModernModuleSimulator()

# Pull a module (same as before, but type-safe)
module = simulator.simulate_module_pull(current_pity=0)

# Access data (compatible with legacy format)
print(f"Module: {module.name}")
print(f"Type: {module.module_type.value}")  # Enum -> string
print(f"Rarity: {module.rarity.value}")     # Enum -> string

# Substats work the same way
for substat in module.substats:
    print(f"  {substat['name']}: {substat['value']}{substat['unit']}")
```

### Step 3: Add Reroll Functionality

The new system includes proper reroll support:

```python
# Reroll a specific substat
new_rarity = simulator.simulate_substat_reroll(module, substat_index=0)

# Calculate reroll costs
from src.tower_iq.core.game_data.modules._probabilities import REROLL_COSTS
cost = REROLL_COSTS[1]  # First reroll costs 10
```

### Step 4: Gradually Replace Legacy Code

1. Keep `module_simulator.py` for now (backup)
2. Update your GUI code to use `ModernModuleSimulator`
3. Update test files to use new system
4. Eventually remove legacy code

## Key Improvements

### Type Safety
```python
# Old way (strings, error-prone)
module_type = "Cannon"  # Could typo as "Canon"
rarity = "Epic"         # Could typo as "Epik"

# New way (enums, compile-time safe)
module_type = ModuleType.CANNON  # IDE autocomplete
rarity = Rarity.EPIC             # Impossible to typo
```

### Better Data Organization
```python
# Old way (YAML lookup)
substat_value = module_lookups['substat_values'][enum_id]['values'][rarity]

# New way (typed objects)
substat_info = game_data.get_substat(enum_id)
substat_value = substat_info.values[rarity]
```

### Extensibility
```python
# Easy to add new features
class ModuleInstance:
    enhancement_level: int = 0      # New field
    set_bonus: Optional[str] = None # Another new field
```

## Testing Your Migration

### Run the Demo
```bash
cd src/tower_iq/core
python modern_module_simulator.py
```

### Compare Systems
The demo includes a comparison function that shows both systems working side by side.

### Validate Data Consistency
```python
# Ensure new system produces same results as legacy
legacy_pulls = [simulate_module_pull(0) for _ in range(1000)]
modern_pulls = [simulator.simulate_module_pull(0) for _ in range(1000)]

# Compare distributions
legacy_rarities = [p.rarity for p in legacy_pulls]
modern_rarities = [p.rarity.value for p in modern_pulls]
```

## Recommended Next Steps

1. **Test the new simulator** with your existing GUI
2. **Update your test files** to use `ModernModuleSimulator`
3. **Extend the system** with features like:
   - Module enhancement/upgrade simulation
   - Set bonus calculations
   - Inventory management
4. **Remove legacy code** once everything is migrated

## Getting Help

If you run into issues:
1. Check the console output for enum/type errors
2. Compare legacy vs modern output using the comparison function
3. The new system is designed to be compatible with your existing GUI code

The new system gives you much better organization and type safety while keeping the same simulation logic you've already tested.