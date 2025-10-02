"""
Enhanced Fast Module Simulator for The Tower (CPU-only)

Refactored to remove GPU dependencies and support multiple target epic modules.
Runs a high-performance NumPy simulation that models pulls with pity and uniform
distribution across epic modules.
"""

import numpy as np
import time
import argparse
from typing import Callable, Optional, List, Dict

# List of all 16 natural epic modules
EPIC_MODULES = [
    "Death Penalty", "Astral Deliverance", "Being Annihilator", "Havoc Bringer",  # Cannon
    "Anti-Cube Portal", "Wormhole Redirector", "Negative Mass Projector", "Space Displacer",  # Armor
    "Dimension Core", "Multiverse Nexus", "Harmony Conductor", "Magnetic Hook",  # Core
    "Galaxy Compressor", "Project Funding", "Sharp Fortitude", "Shrink Ray"  # Generator
]

def print_progress(current, total, start_time, prefix="Progress"):
    """Print a progress bar with completion percentage and ETA."""
    if total == 0:
        return

    percentage = (current / total) * 100
    elapsed_time = time.perf_counter() - start_time

    if current > 0:
        estimated_total_time = elapsed_time * total / current
        remaining_time = estimated_total_time - elapsed_time
        eta_str = f"ETA: {remaining_time:.1f}s"
    else:
        eta_str = "ETA: --"

    # Create progress bar
    bar_length = 30
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)

    # Print progress
    print(f"\r{prefix}: |{bar}| {percentage:.1f}% ({current:,}/{total:,}) {eta_str}", end='', flush=True)

    if current == total:
        print()  # New line when complete

def run_simulation_numpy(
    num_sims: int,
    targets: List[Dict],
    total_epics: int = 16,
    pity_limit: int = 150,
    show_progress: bool = True,
    progress_callback: Optional[Callable[[int], None]] = None,
    partial_results_callback: Optional[Callable[[np.ndarray], None]] = None,
) -> np.ndarray:
    """
    Run a vectorized NumPy simulation for module pulls supporting multiple targets.

    Args:
        num_sims: Number of independent simulations to run.
        targets: List of target specs, e.g. [{"name": "Magnetic Hook", "copies": 2}, ...].
        total_epics: Total number of epic modules in the pool.
        pity_limit: Pulls since last epic to guarantee an epic.
        show_progress: Unused for printing; kept for API compatibility.
        progress_callback: Optional callback receiving percent completion (0-100).

    Returns:
        A NumPy array of length num_sims with total gems spent per simulation.
    """
    # Build the target copies requirement vector across all epic indices
    target_copies_array = np.zeros(total_epics, dtype=np.int16)
    for target in targets or []:
        try:
            module_name = str(target.get("name", target.get("module", ""))).strip()
            copies_required = int(target.get("copies", target.get("count", 1)))
        except Exception:
            continue
        if copies_required <= 0:
            continue
        if module_name in EPIC_MODULES:
            idx = EPIC_MODULES.index(module_name)
            # If the same module appears multiple times, use the maximum copies requested
            target_copies_array[idx] = max(target_copies_array[idx], copies_required)

    # --- State Arrays ---
    gems_spent = np.zeros(num_sims, dtype=np.int32)
    pity_counter = np.zeros(num_sims, dtype=np.int16)
    # Track counts for all epic modules for each simulation
    copies_obtained = np.zeros((num_sims, total_epics), dtype=np.int16)
    sims_finished = np.zeros(num_sims, dtype=np.bool_)

    # --- Constants ---
    EPIC_CHANCE = 0.025  # 2.5% base chance for an epic

    # Progress tracking (for callback only)
    start_time = time.perf_counter()
    last_emit_time = start_time
    emit_interval = 0.3  # seconds

    while not np.all(sims_finished):
        active_mask = ~sims_finished
        num_active = int(active_mask.sum())
        if num_active == 0:
            break

        # Simulate one pull for each active simulation
        gems_spent[active_mask] += 20

        # Natural epic chance
        pull_rolls = np.random.rand(num_active)
        is_natural_epic = pull_rolls < EPIC_CHANCE

        # Pity check
        pity_hits = pity_counter[active_mask] >= pity_limit
        is_epic_pull = np.logical_or(is_natural_epic, pity_hits)

        # For each epic, choose which epic module was pulled and update counts
        if np.any(is_epic_pull):
            active_indices = np.where(active_mask)[0]
            sims_with_epics_indices = active_indices[is_epic_pull]
            epic_module_indices = np.random.randint(0, total_epics, size=sims_with_epics_indices.shape[0])
            np.add.at(copies_obtained, (sims_with_epics_indices, epic_module_indices), 1)

            # Reset pity counters for those simulations that pulled an epic
            pity_counter[sims_with_epics_indices] = 0

        # Increment pity for active simulations
        pity_counter[active_mask] += 1

        # Check completion for active simulations: all targeted counts satisfied
        if np.any(active_mask):
            active_indices = np.where(active_mask)[0]
            active_rows = copies_obtained[active_mask]
            # Broadcast comparison against the target vector
            completed_mask_active = np.all(active_rows >= target_copies_array, axis=1)
            if np.any(completed_mask_active):
                completed_sim_indices = active_indices[completed_mask_active]
                sims_finished[completed_sim_indices] = True

        # Progress and partial results callbacks (throttled)
        now = time.perf_counter()
        if (now - last_emit_time) >= emit_interval:
            if progress_callback is not None:
                completed_sims = int(np.sum(sims_finished))
                progress_percent = int((completed_sims / num_sims) * 100) if num_sims > 0 else 100
                progress_callback(progress_percent)
            if partial_results_callback is not None:
                # Emit finished gems_spent only to avoid partial/incomplete data
                try:
                    partial = gems_spent[sims_finished]
                    partial_results_callback(partial.copy())
                except Exception:
                    # Swallow any callback errors
                    pass
            last_emit_time = now

    return gems_spent

# GPU-based implementations removed (CPU-only simulator)

def run_simulation_fixed_pulls_numpy(num_sims: int, num_pulls: int, total_epics: int = 16, pity_limit: int = 150, show_progress: bool = True) -> dict:
    """Fully vectorized simulation of a fixed number of pulls using NumPy."""
    # --- Constants ---
    EPIC_CHANCE = 0.025

    # --- Generate ALL random numbers for ALL pulls at once ---
    # Shape: (num_simulations, num_pulls)
    pull_rolls = np.random.rand(num_sims, num_pulls)

    # --- Simulate Pity ---
    # Create a boolean array for natural epics
    is_natural_epic = pull_rolls < EPIC_CHANCE

    # Calculate pulls since last epic for every single pull
    # This is a clever vectorized way to handle pity
    cum_epics = np.cumsum(is_natural_epic, axis=1)
    # Create a trigger that resets the count after each epic
    reset_mask = np.diff(np.c_[np.zeros(num_sims), cum_epics], axis=1) > 0
    # A running count of pulls since the last epic
    pity_tracker = np.arange(num_pulls) - np.maximum.accumulate(reset_mask * np.arange(num_pulls), axis=1) + 1

    pity_hits = pity_tracker >= pity_limit
    is_epic_pull = np.logical_or(is_natural_epic, pity_hits)

    # --- Track Results ---
    epics_obtained = is_epic_pull.sum(axis=1).astype(np.int16)

    # --- Module Distribution ---
    num_epics_total = int(is_epic_pull.sum())
    # Generate one random number for every epic that was pulled
    epic_module_rolls = np.random.randint(0, total_epics, size=num_epics_total, dtype=np.int16)

    # Find the coordinates of every epic pull in the main array
    sim_indices, pull_indices = np.where(is_epic_pull)

    # Create the final module counts array and populate it
    module_counts = np.zeros((num_sims, total_epics), dtype=np.int16)
    # Use advanced indexing to add 1 to the module count for each epic
    np.add.at(module_counts, (sim_indices, epic_module_rolls), 1)

    return {
        'gems_spent': np.full(num_sims, num_pulls * 20, dtype=np.int32),
        'epics_obtained': epics_obtained,
        'module_counts': module_counts,
        'total_pulls': num_pulls
    }

# GPU fixed-pulls implementation removed (CPU-only simulator)

def calculate_probability_with_budget(
    budget_gems: int,
    target_module: str,
    target_copies: int = 1,
    num_sims: int = 100_000,
) -> float:
    """
    Calculate probability of success within a gem budget for a single target (CPU-only).
    """
    targets = [{"name": target_module, "copies": target_copies}]
    results = run_simulation_numpy(num_sims=num_sims, targets=targets, show_progress=False)
    successful_sims = int(np.sum(results <= budget_gems))
    return float(successful_sims / num_sims)

# Removed uncompiled/JIT variants; CPU-only implementation above is used directly

def calculate_gems_for_confidence(
    target_module: str,
    target_copies: int = 1,
    confidence: float = 0.95,
    num_sims: int = 100_000,
) -> int:
    """Gems needed to obtain target copies at the given confidence (CPU-only)."""
    targets = [{"name": target_module, "copies": target_copies}]
    results = run_simulation_numpy(num_sims=num_sims, targets=targets, show_progress=False)
    return int(float(np.percentile(results, confidence * 100)))

def main():
    parser = argparse.ArgumentParser(description="Enhanced module pull simulator for specific epic modules.")
    parser.add_argument("-n", "--simulations", type=int, required=True, help="Number of simulations to run.")
    parser.add_argument("-m", "--module", type=str, choices=EPIC_MODULES, help="Target epic module name (for targeting mode).")
    parser.add_argument("-c", "--copies", type=int, default=1, help="Number of copies needed (default: 1, for targeting mode).")
    parser.add_argument("--pulls", type=int, help="Number of pulls to simulate (for fixed pulls mode).")
    parser.add_argument("--no-progress", action="store_true", help="Disable progress tracking.")
    parser.add_argument("--budget", type=int, help="Calculate probability of success with this gem budget.")
    parser.add_argument("--confidence", type=float, default=0.95, help="Confidence level for gem calculation (default: 0.95).")

    args = parser.parse_args()

    # Determine simulation mode
    if args.pulls is not None:
        # Fixed pulls mode
        mode = "fixed_pulls"
        if args.module is not None:
            print("⚠️  Warning: Module targeting ignored in fixed pulls mode.")
    elif args.module is not None:
        # Targeting mode
        mode = "targeting"
        if args.module not in EPIC_MODULES:
            print(f"❌ Error: '{args.module}' is not a valid epic module.")
            print(f"Available modules: {', '.join(EPIC_MODULES)}")
            return
    else:
        print("❌ Error: Must specify either --module (for targeting) or --pulls (for fixed pulls).")
        return

    # CPU-only device string
    device = "CPU (NumPy)"

    # Progress setting
    show_progress = not args.no_progress

    # Special modes
    if args.budget and mode == "targeting":
        print(f"🎯 Calculating probability of obtaining {args.copies}x '{args.module}' with {args.budget:,} gems...")
        probability = calculate_probability_with_budget(
            args.budget, args.module, args.copies, args.simulations
        )
        print(f"📊 Probability of success: {probability:.2%}")
        return

    # Main simulation
    if mode == "targeting":
        print(f"🚀 Running {args.simulations:,} simulations on {device}...")
        print(f"🎯 Target: {args.copies}x '{args.module}'")

        start_time = time.perf_counter()

        targets = [{"name": args.module, "copies": args.copies}]
        results_array = run_simulation_numpy(
            num_sims=args.simulations,
            targets=targets,
            show_progress=show_progress,
        )

        end_time = time.perf_counter()
        total_time = end_time - start_time

        # Analyze Results
        sims_per_second = args.simulations / total_time
        mean_gems = np.mean(results_array)
        percentile_50 = np.percentile(results_array, 50)
        percentile_95 = np.percentile(results_array, args.confidence * 100)
        percentile_99 = np.percentile(results_array, 99)

        print(f"\n✅ Completed in {total_time:.4f} seconds ({sims_per_second:,.0f} sims/sec)")

        print(f"\n--- Simulation Results for {args.copies}x '{args.module}' ---")
        print(f"  Average Gems Required: {mean_gems:,.0f}")
        print(f"  Median (50%): {percentile_50:,.0f} gems")
        print(f"  {args.confidence:.0%} Confidence: {percentile_95:,.0f} gems")
        print(f"  99% Confidence: {percentile_99:,.0f} gems")

        # Additional insights
        prob_single_pull = 1 / 16
        print("\n--- Theoretical Analysis ---")
        print(f"  Single Epic Probability: {prob_single_pull:.3%}")
        print(f"  Expected Epics for {args.copies}x: {args.copies / prob_single_pull:.1f}")

    elif mode == "fixed_pulls":
        print(f"🚀 Running {args.simulations:,} simulations on {device}...")
        print(f"🎯 Simulating {args.pulls:,} pulls per simulation ({args.pulls * 20:,} gems)")

        start_time = time.perf_counter()

        results = run_simulation_fixed_pulls_numpy(args.simulations, args.pulls, show_progress=show_progress)

        end_time = time.perf_counter()
        total_time = end_time - start_time

        # Analyze Results
        sims_per_second = args.simulations / total_time
        epics_obtained = results['epics_obtained']
        module_counts = results['module_counts']

        print(f"\n✅ Completed in {total_time:.4f} seconds ({sims_per_second:,.0f} sims/sec)")

        print(f"\n--- Simulation Results for {args.pulls:,} pulls ---")
        print(f"  Average Epics Obtained: {np.mean(epics_obtained):.2f}")
        print(f"  Median Epics: {np.percentile(epics_obtained, 50):.1f}")
        print(f"  95% Range: {np.percentile(epics_obtained, 2.5):.1f} - {np.percentile(epics_obtained, 97.5):.1f} epics")

        # Module distribution
        print("\n--- Module Distribution (Average per simulation) ---")
        for i, module_name in enumerate(EPIC_MODULES):
            avg_count = np.mean(module_counts[:, i])
            if avg_count > 0.01:  # Only show modules with meaningful counts
                print(f"  {module_name}: {avg_count:.3f}")

        # Theoretical comparison
        expected_epics = args.pulls * 0.025  # 2.5% base rate
        print("\n--- Theoretical Analysis ---")
        print(f"  Expected Epics (no pity): {expected_epics:.2f}")
        print(f"  Actual Average: {np.mean(epics_obtained):.2f}")
        print(f"  Pity System Impact: +{np.mean(epics_obtained) - expected_epics:.2f} epics")

if __name__ == "__main__":
    main()
