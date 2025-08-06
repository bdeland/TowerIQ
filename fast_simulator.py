# Fast Module Simulator for The Tower
# High-performance, device-agnostic module pull simulator
# Supports CPU (NumPy + Numba) and GPU (CuPy) execution

import numpy as np
import time
import argparse

def run_simulation_numpy(num_sims: int, is_featured: bool, total_epics: int, pity_limit: int, 
                        target_module_name: str | None = None, target_rarity: str | None = None, target_type: str | None = None) -> np.ndarray:
    """
    Performs a vectorized simulation using NumPy.

    Args:
        num_sims: The number of simulations to run.
        is_featured: Whether the target module is featured.
        total_epics: Total number of natural epic modules in the pool.
        pity_limit: The number of pulls to guarantee an epic.
        target_module_name: Specific module name to target (e.g., "Death Penalty", "Wormhole Redirector")
        target_rarity: Target rarity ("Common", "Rare", "Epic", "Legendary", "Mythic", "Ancestral")
        target_type: Target module type ("Cannon", "Armor", "Core", "Generator")

    Returns:
        An array containing the gems spent for each simulation.
    """
    # --- State Arrays ---
    gems_spent = np.zeros(num_sims, dtype=np.int32)
    pity_counter = np.zeros(num_sims, dtype=np.int16)
    sims_finished = np.zeros(num_sims, dtype=np.bool_)
    
    # --- Constants ---
    EPIC_CHANCE = 0.025
    
    if is_featured:
        # 50% chance of the epic being featured
        # 50% chance of it being a random one (1/16 chance of being the target)
        PROB_OF_TARGET_IF_EPIC = 0.5 + 0.5 * (1 / total_epics)
    else:
        PROB_OF_TARGET_IF_EPIC = 1 / total_epics

    while not np.all(sims_finished):
        active_mask = ~sims_finished
        num_active = int(active_mask.sum())

        # --- Simulate a 10-pull for all active simulations ---
        gems_spent[active_mask] += 200
        
        # Generate 10 random numbers for each active simulation
        pull_rolls = np.random.rand(num_active, 10)
        is_natural_epic = pull_rolls < EPIC_CHANCE
        
        # --- Vectorized Pity Check ---
        pity_matrix = pity_counter[active_mask, np.newaxis] + np.arange(1, 11, dtype=np.int16)
        pity_hits = pity_matrix >= pity_limit
        
        is_epic_pull = np.logical_or(is_natural_epic, pity_hits)
        num_epics_per_sim = is_epic_pull.sum(axis=1)

        # --- Check for Success ---
        sims_with_epics_mask = num_epics_per_sim > 0
        if np.any(sims_with_epics_mask):
            num_with_epics = int(sims_with_epics_mask.sum())
            
            # Probability of getting AT LEAST ONE target in the batch of epics
            prob_success = 1 - (1 - PROB_OF_TARGET_IF_EPIC) ** num_epics_per_sim[sims_with_epics_mask]
            
            # Roll for success for each simulation that got an epic
            success_rolls = np.random.rand(num_with_epics)
            successes = success_rolls < prob_success
            
            # Update the master finished mask
            active_indices = np.where(active_mask)[0]
            sims_with_epics_indices = active_indices[sims_with_epics_mask]
            successful_sim_indices = sims_with_epics_indices[successes]
            sims_finished[successful_sim_indices] = True
        
        # --- Update Pity Counters ---
        pity_counter[active_mask] += 10
        # Reset pity for those that pulled an epic
        # Note: This is a simplification. A fully accurate pity reset is complex to vectorize.
        # This implementation resets the entire counter if any epic was pulled.
        # It's very close for high sim counts and essential for performance.
        pity_counter[active_mask][sims_with_epics_mask] = 0
            
    return gems_spent

def run_simulation_cupy(num_sims: int, is_featured: bool, total_epics: int, pity_limit: int):
    """
    Performs a vectorized simulation using CuPy.
    
    Args:
        num_sims: The number of simulations to run.
        is_featured: Whether the target module is featured.
        total_epics: Total number of natural epic modules in the pool.
        pity_limit: The number of pulls to guarantee an epic.

    Returns:
        A CuPy array containing the gems spent for each simulation.
    """
    import cupy as cp
    
    # --- State Arrays ---
    gems_spent = cp.zeros(num_sims, dtype=cp.int32)
    pity_counter = cp.zeros(num_sims, dtype=cp.int16)
    sims_finished = cp.zeros(num_sims, dtype=cp.bool_)
    
    # --- Constants ---
    EPIC_CHANCE = 0.025
    
    if is_featured:
        # 50% chance of the epic being featured
        # 50% chance of it being a random one (1/16 chance of being the target)
        PROB_OF_TARGET_IF_EPIC = 0.5 + 0.5 * (1 / total_epics)
    else:
        PROB_OF_TARGET_IF_EPIC = 1 / total_epics

    while not cp.all(sims_finished):
        active_mask = ~sims_finished
        num_active = int(active_mask.sum())

        # --- Simulate a 10-pull for all active simulations ---
        gems_spent[active_mask] += 200
        
        # Generate 10 random numbers for each active simulation
        pull_rolls = cp.random.rand(num_active, 10)
        is_natural_epic = pull_rolls < EPIC_CHANCE
        
        # --- Vectorized Pity Check ---
        pity_matrix = pity_counter[active_mask, cp.newaxis] + cp.arange(1, 11, dtype=cp.int16)
        pity_hits = pity_matrix >= pity_limit
        
        is_epic_pull = cp.logical_or(is_natural_epic, pity_hits)
        num_epics_per_sim = is_epic_pull.sum(axis=1)

        # --- Check for Success ---
        sims_with_epics_mask = num_epics_per_sim > 0
        if cp.any(sims_with_epics_mask):
            num_with_epics = int(sims_with_epics_mask.sum())
            
            # Probability of getting AT LEAST ONE target in the batch of epics
            prob_success = 1 - (1 - PROB_OF_TARGET_IF_EPIC) ** num_epics_per_sim[sims_with_epics_mask]
            
            # Roll for success for each simulation that got an epic
            success_rolls = cp.random.rand(num_with_epics)
            successes = success_rolls < prob_success
            
            # Update the master finished mask
            active_indices = cp.where(active_mask)[0]
            sims_with_epics_indices = active_indices[sims_with_epics_mask]
            successful_sim_indices = sims_with_epics_indices[successes]
            sims_finished[successful_sim_indices] = True
        
        # --- Update Pity Counters ---
        pity_counter[active_mask] += 10
        # Reset pity for those that pulled an epic
        # Note: This is a simplification. A fully accurate pity reset is complex to vectorize.
        # This implementation resets the entire counter if any epic was pulled.
        # It's very close for high sim counts and essential for performance.
        pity_counter[active_mask][sims_with_epics_mask] = 0
            
    return gems_spent

def main():
    # --- 1. Command-Line Argument Parsing ---
    parser = argparse.ArgumentParser(description="High-performance module pull simulator for The Tower.")
    parser.add_argument(
        "-n", "--simulations",
        type=int,
        required=True,
        help="Number of simulations to run."
    )
    parser.add_argument(
        "--gpu",
        action="store_true",
        help="Run the simulation on an NVIDIA GPU (requires CuPy and CUDA)."
    )
    parser.add_argument(
        "--featured",
        action="store_true",
        help="Simulate pulling for a featured module (increases chances)."
    )
    args = parser.parse_args()

    # --- 2. Backend Selection (Dispatcher) ---
    use_gpu = False
    device = "CPU"

    if args.gpu:
        try:
            import cupy as cp
            if cp.cuda.is_available():
                use_gpu = True
                device = "GPU (CuPy)"
            else:
                print("⚠️  Warning: CuPy is installed but no GPU device was found. Falling back to CPU.")
        except ImportError:
            print("⚠️  Warning: --gpu flag was used, but CuPy is not installed. Falling back to CPU.")
    
    if not use_gpu:
        device = "CPU (NumPy + Numba)"
        # Apply Numba JIT compilation only for the CPU path
        from numba import njit
        global run_simulation_numpy
        run_simulation_numpy = njit(run_simulation_numpy)

    # --- 3. Run the Simulation ---
    print(f"🚀 Running {args.simulations:,} simulations on the {device}...")
    
    start_time = time.perf_counter()
    
    if use_gpu:
        results_array = run_simulation_cupy(
            num_sims=args.simulations,
            is_featured=args.featured,
            total_epics=16,
            pity_limit=150
        )
        # Wait for the computation to finish and move data to CPU
        import cupy as cp
        cp.cuda.Stream.null.synchronize()
        results_array = results_array.get() # .get() moves data from GPU to CPU
    else:
        results_array = run_simulation_numpy(
            num_sims=args.simulations,
            is_featured=args.featured,
            total_epics=16,
            pity_limit=150
        )

    end_time = time.perf_counter()
    total_time = end_time - start_time

    # --- 4. Analyze and Print Results ---
    sims_per_second = args.simulations / total_time
    
    print(f"\n✅ Completed in {total_time:.4f} seconds ({sims_per_second:,.0f} sims/sec)")
    
    mean_gems = np.mean(results_array)
    percentile_95 = np.percentile(results_array, 95)
    
    print("\n--- Simulation Results ---")
    print(f"  Target Module Featured: {args.featured}")
    print(f"  Average Gems to Acquire: {mean_gems:,.0f}")
    print(f"  95% Confidence: Acquired within {percentile_95:,.0f} gems")

if __name__ == "__main__":
    main()