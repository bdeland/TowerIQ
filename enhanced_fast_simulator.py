# Enhanced Fast Module Simulator for The Tower
# High-performance, device-agnostic module pull simulator with specific module targeting
# Supports CPU (NumPy + Numba) and GPU (CuPy) execution

import numpy as np
import time
import argparse
import sys

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

def run_simulation_numpy(num_sims: int, target_module: str, target_copies: int = 1, 
                        total_epics: int = 16, pity_limit: int = 150, show_progress: bool = True) -> np.ndarray:
    """
    Performs a vectorized simulation using NumPy for specific module targeting.

    Args:
        num_sims: The number of simulations to run.
        target_module: Name of the specific epic module to target.
        target_copies: Number of copies of the target module needed.
        total_epics: Total number of natural epic modules in the pool.
        pity_limit: The number of pulls to guarantee an epic.
        show_progress: Whether to show progress updates.

    Returns:
        An array containing the gems spent for each simulation.
    """
    # --- State Arrays ---
    gems_spent = np.zeros(num_sims, dtype=np.int32)
    pity_counter = np.zeros(num_sims, dtype=np.int16)
    copies_obtained = np.zeros(num_sims, dtype=np.int16)  # Track copies of target module
    sims_finished = np.zeros(num_sims, dtype=np.bool_)
    
    # --- Constants ---
    EPIC_CHANCE = 0.025  # 2.5% base chance for epic
    PROB_OF_TARGET_IF_EPIC = 1 / total_epics  # Equal chance among all epic modules (6.25%)

    # Progress tracking
    start_time = time.perf_counter()
    last_progress_time = start_time
    progress_interval = 0.5  # Update progress every 0.5 seconds
    
    iteration = 0
    while not np.all(sims_finished):
        active_mask = ~sims_finished
        num_active = int(active_mask.sum())

        # --- Simulate individual pulls for all active simulations ---
        gems_spent[active_mask] += 20  # Each pull costs 20 gems
        
        # Generate random numbers for each active simulation
        pull_rolls = np.random.rand(num_active)
        is_natural_epic = pull_rolls < EPIC_CHANCE
        
        # --- Pity Check ---
        pity_hits = pity_counter[active_mask] >= pity_limit
        
        is_epic_pull = np.logical_or(is_natural_epic, pity_hits)

        # --- Check for Target Module Success ---
        sims_with_epics_mask = is_epic_pull
        if np.any(sims_with_epics_mask):
            # For each epic pulled, roll to see if it's the target module
            epic_target_rolls = np.random.rand(num_active)
            target_hits = epic_target_rolls < PROB_OF_TARGET_IF_EPIC
            
            # Update copies obtained for active simulations
            active_indices = np.where(active_mask)[0]
            sims_with_epics_indices = active_indices[sims_with_epics_mask]
            
            # Check which epics are target modules
            target_hits = epic_target_rolls[sims_with_epics_mask] < PROB_OF_TARGET_IF_EPIC
            target_hits_indices = sims_with_epics_indices[target_hits]
            
            # Add target modules obtained
            copies_obtained[target_hits_indices] += 1
            
            # Check if any simulations have reached their target
            completed_mask = copies_obtained[target_hits_indices] >= target_copies
            completed_sim_indices = target_hits_indices[completed_mask]
            sims_finished[completed_sim_indices] = True
        
        # --- Update Pity Counters ---
        pity_counter[active_mask] += 1
        # Reset pity for those that pulled an epic
        pity_counter[active_mask][sims_with_epics_mask] = 0
        
        # Progress tracking
        iteration += 1
        if show_progress and (time.perf_counter() - last_progress_time) >= progress_interval:
            completed_sims = int(np.sum(sims_finished))
            print_progress(completed_sims, num_sims, start_time, "Simulations")
            last_progress_time = time.perf_counter()
            
    return gems_spent

def run_simulation_cupy(num_sims: int, target_module: str, target_copies: int = 1,
                       total_epics: int = 16, pity_limit: int = 150, show_progress: bool = True):
    """
    Performs a vectorized simulation using CuPy for specific module targeting.
    """
    import cupy as cp
    
    # --- State Arrays ---
    gems_spent = cp.zeros(num_sims, dtype=cp.int32)
    pity_counter = cp.zeros(num_sims, dtype=cp.int16)
    copies_obtained = cp.zeros(num_sims, dtype=cp.int16)
    sims_finished = cp.zeros(num_sims, dtype=cp.bool_)
    
    # --- Constants ---
    EPIC_CHANCE = 0.025
    PROB_OF_TARGET_IF_EPIC = 1 / total_epics

    # Progress tracking
    start_time = time.perf_counter()
    last_progress_time = start_time
    progress_interval = 0.5  # Update progress every 0.5 seconds
    
    iteration = 0
    while not cp.all(sims_finished):
        active_mask = ~sims_finished
        num_active = int(active_mask.sum())

        # --- Simulate individual pulls for all active simulations ---
        gems_spent[active_mask] += 20  # Each pull costs 20 gems
        
        # Generate random numbers for each active simulation
        pull_rolls = cp.random.rand(num_active)
        is_natural_epic = pull_rolls < EPIC_CHANCE
        
        # --- Pity Check ---
        pity_hits = pity_counter[active_mask] >= pity_limit
        
        is_epic_pull = cp.logical_or(is_natural_epic, pity_hits)

        # --- Check for Target Module Success ---
        sims_with_epics_mask = is_epic_pull
        if cp.any(sims_with_epics_mask):
            # For each epic pulled, roll to see if it's the target module
            epic_target_rolls = cp.random.rand(num_active)
            target_hits = epic_target_rolls < PROB_OF_TARGET_IF_EPIC
            
            # Update copies obtained for active simulations
            active_indices = cp.where(active_mask)[0]
            sims_with_epics_indices = active_indices[sims_with_epics_mask]
            
            # Check which epics are target modules
            target_hits = epic_target_rolls[sims_with_epics_mask] < PROB_OF_TARGET_IF_EPIC
            target_hits_indices = sims_with_epics_indices[target_hits]
            
            # Add target modules obtained
            copies_obtained[target_hits_indices] += 1
            
            # Check if any simulations have reached their target
            completed_mask = copies_obtained[target_hits_indices] >= target_copies
            completed_sim_indices = target_hits_indices[completed_mask]
            sims_finished[completed_sim_indices] = True
        
        # --- Update Pity Counters ---
        pity_counter[active_mask] += 1
        # Reset pity for those that pulled an epic
        pity_counter[active_mask][sims_with_epics_mask] = 0
        
        # Progress tracking (disabled for GPU to maintain performance)
        # GPU-CPU synchronization kills performance, so we skip progress updates
        iteration += 1
            
    return gems_spent

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

def run_simulation_fixed_pulls_cupy(num_sims: int, num_pulls: int, total_epics: int = 16, pity_limit: int = 150, show_progress: bool = True) -> dict:
    """Fully vectorized simulation of a fixed number of pulls using CuPy."""
    import cupy as cp
    
    # --- Constants ---
    EPIC_CHANCE = 0.025
    
    # --- Generate ALL random numbers for ALL pulls at once on the GPU ---
    pull_rolls = cp.random.rand(num_sims, num_pulls)
    
    # --- Simulate Pity ---
    is_natural_epic = pull_rolls < EPIC_CHANCE
    cum_epics = cp.cumsum(is_natural_epic, axis=1)
    reset_mask = cp.diff(cp.c_[cp.zeros(num_sims), cum_epics], axis=1) > 0
    
    # CuPy doesn't support maximum.accumulate, so we implement it manually
    # Create the array to accumulate
    reset_times = reset_mask * cp.arange(num_pulls)
    # Manual implementation of maximum.accumulate
    max_accumulate = cp.zeros_like(reset_times)
    for i in range(num_pulls):
        if i == 0:
            max_accumulate[:, i] = reset_times[:, i]
        else:
            max_accumulate[:, i] = cp.maximum(max_accumulate[:, i-1], reset_times[:, i])
    
    pity_tracker = cp.arange(num_pulls) - max_accumulate + 1
    
    pity_hits = pity_tracker >= pity_limit
    is_epic_pull = cp.logical_or(is_natural_epic, pity_hits)
    
    # --- Track Results ---
    epics_obtained = is_epic_pull.sum(axis=1).astype(cp.int16)
    
    # --- Module Distribution (Optimized GPU Implementation) ---
    num_epics_total = int(is_epic_pull.sum())
    epic_module_rolls = cp.random.randint(0, total_epics, size=num_epics_total, dtype='int16')
    
    sim_indices, pull_indices = cp.where(is_epic_pull)
    
    # Create module counts array on GPU
    module_counts = cp.zeros((num_sims, total_epics), dtype=cp.int16)
    
    # Use scatter_add for atomic operations on GPU (more efficient than CPU transfer)
    # This is a more GPU-friendly approach
    if num_epics_total > 0:
        # Create a linear index for the 2D array
        linear_indices = sim_indices * total_epics + epic_module_rolls
        # Use bincount to count occurrences
        counts = cp.bincount(linear_indices, minlength=num_sims * total_epics)
        # Reshape back to 2D
        module_counts = counts.reshape(num_sims, total_epics).astype(cp.int16)
    
    return {
        'gems_spent': cp.full(num_sims, num_pulls * 20, dtype=cp.int32),
        'epics_obtained': epics_obtained,
        'module_counts': module_counts,
        'total_pulls': num_pulls
    }

def calculate_probability_with_budget(budget_gems: int, target_module: str, target_copies: int = 1,
                                    num_sims: int = 100000, use_gpu: bool = False) -> float:
    """
    Calculate the probability of obtaining target copies within a gem budget.
    
    Args:
        budget_gems: Available gem budget
        target_module: Name of the target epic module
        target_copies: Number of copies needed
        num_sims: Number of simulations to run
        use_gpu: Whether to use GPU acceleration
        
    Returns:
        Probability of success (0.0 to 1.0)
    """
    if use_gpu:
        try:
            import cupy as cp
            if cp.cuda.is_available():
                results = run_simulation_cupy(num_sims, target_module, target_copies)
                cp.cuda.Stream.null.synchronize()
                results = results.get()
            else:
                # Use uncompiled numpy version for GPU fallback
                results = run_simulation_numpy_uncompiled(num_sims, target_module, target_copies)
        except ImportError:
            # Use uncompiled numpy version for import error
            results = run_simulation_numpy_uncompiled(num_sims, target_module, target_copies)
    else:
        # Apply numba compilation for CPU
        from numba import njit
        compiled_func = njit(run_simulation_numpy)
        results = compiled_func(num_sims, target_module, target_copies)
    
    successful_sims = np.sum(results <= budget_gems)
    return float(successful_sims / num_sims)

# Create uncompiled version for non-JIT usage
def run_simulation_numpy_uncompiled(num_sims: int, target_module: str, target_copies: int = 1, 
                                  total_epics: int = 16, pity_limit: int = 150) -> np.ndarray:
    """Uncompiled version of the numpy simulation for fallback usage."""
    return run_simulation_numpy(num_sims, target_module, target_copies, total_epics, pity_limit)

def calculate_gems_for_confidence(target_module: str, target_copies: int = 1, confidence: float = 0.95,
                                num_sims: int = 100000, use_gpu: bool = False) -> int:
    """
    Calculate gems needed to obtain target copies with specified confidence.
    
    Args:
        target_module: Name of the target epic module
        target_copies: Number of copies needed  
        confidence: Desired confidence level (0.0 to 1.0)
        num_sims: Number of simulations to run
        use_gpu: Whether to use GPU acceleration
        
    Returns:
        Gems needed for specified confidence level
    """
    if use_gpu:
        try:
            import cupy as cp
            if cp.cuda.is_available():
                results = run_simulation_cupy(num_sims, target_module, target_copies)
                cp.cuda.Stream.null.synchronize()
                results = results.get()
            else:
                results = run_simulation_numpy(num_sims, target_module, target_copies)
        except ImportError:
            results = run_simulation_numpy(num_sims, target_module, target_copies)
    else:
        # Apply numba compilation for CPU
        from numba import njit
        compiled_func = njit(run_simulation_numpy)
        results = compiled_func(num_sims, target_module, target_copies)
    
    return int(float(np.percentile(results, confidence * 100)))

def main():
    parser = argparse.ArgumentParser(description="Enhanced module pull simulator for specific epic modules.")
    parser.add_argument("-n", "--simulations", type=int, required=True, help="Number of simulations to run.")
    parser.add_argument("-m", "--module", type=str, choices=EPIC_MODULES, help="Target epic module name (for targeting mode).")
    parser.add_argument("-c", "--copies", type=int, default=1, help="Number of copies needed (default: 1, for targeting mode).")
    parser.add_argument("--pulls", type=int, help="Number of pulls to simulate (for fixed pulls mode).")
    parser.add_argument("--gpu", action="store_true", help="Run on GPU using CuPy.")
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

    # Backend Selection
    use_gpu = False
    device = "CPU"

    if args.gpu:
        try:
            import cupy as cp
            if cp.cuda.is_available():
                use_gpu = True
                device = "GPU (CuPy)"
            else:
                print("⚠️  Warning: GPU not available. Falling back to CPU.")
        except ImportError:
            print("⚠️  Warning: CuPy not installed. Falling back to CPU.")
    
    if not use_gpu:
        device = "CPU (NumPy + Numba)"
        # Numba compilation will be applied when needed

    # Progress setting
    show_progress = not args.no_progress

    # Special modes
    if args.budget and mode == "targeting":
        print(f"🎯 Calculating probability of obtaining {args.copies}x '{args.module}' with {args.budget:,} gems...")
        probability = calculate_probability_with_budget(
            args.budget, args.module, args.copies, args.simulations, use_gpu
        )
        print(f"📊 Probability of success: {probability:.2%}")
        return

    # Main simulation
    if mode == "targeting":
        print(f"🚀 Running {args.simulations:,} simulations on {device}...")
        print(f"🎯 Target: {args.copies}x '{args.module}'")
        
        start_time = time.perf_counter()
        
        if use_gpu:
            results_array = run_simulation_cupy(args.simulations, args.module, args.copies, show_progress=show_progress)
            import cupy as cp
            cp.cuda.Stream.null.synchronize()
            results_array = results_array.get()
        else:
            # Use the original function directly with progress setting
            results_array = run_simulation_numpy(
                args.simulations, args.module, args.copies, show_progress=show_progress
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
        print(f"\n--- Theoretical Analysis ---")
        print(f"  Single Epic Probability: {prob_single_pull:.3%}")
        print(f"  Expected Epics for {args.copies}x: {args.copies / prob_single_pull:.1f}")
    
    elif mode == "fixed_pulls":
        print(f"🚀 Running {args.simulations:,} simulations on {device}...")
        print(f"🎯 Simulating {args.pulls:,} pulls per simulation ({args.pulls * 20:,} gems)")
        
        start_time = time.perf_counter()
        
        if use_gpu:
            results = run_simulation_fixed_pulls_cupy(args.simulations, args.pulls, show_progress=show_progress)
            import cupy as cp
            cp.cuda.Stream.null.synchronize()
            # Convert CuPy arrays to NumPy
            results = {k: v.get() if hasattr(v, 'get') else v for k, v in results.items()}
        else:
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
        print(f"\n--- Module Distribution (Average per simulation) ---")
        for i, module_name in enumerate(EPIC_MODULES):
            avg_count = np.mean(module_counts[:, i])
            if avg_count > 0.01:  # Only show modules with meaningful counts
                print(f"  {module_name}: {avg_count:.3f}")
        
        # Theoretical comparison
        expected_epics = args.pulls * 0.025  # 2.5% base rate
        print(f"\n--- Theoretical Analysis ---")
        print(f"  Expected Epics (no pity): {expected_epics:.2f}")
        print(f"  Actual Average: {np.mean(epics_obtained):.2f}")
        print(f"  Pity System Impact: +{np.mean(epics_obtained) - expected_epics:.2f} epics")

if __name__ == "__main__":
    main()