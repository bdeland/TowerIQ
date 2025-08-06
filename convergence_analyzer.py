# Convergence Analyzer for Module Pull Simulator
# This script analyzes how many simulations are needed for accurate results

import argparse
import time
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# We will import the high-performance simulation function directly
from enhanced_fast_simulator import run_simulation_numpy

# --- Plotting Functions ---

def create_convergence_report(history: dict, final_mean: float, threshold: float, args, show_monte_carlo: bool = False):
    """Creates a comprehensive convergence report with all plots on one page."""
    
    # Create figure with subplots - adjust layout based on whether to show Monte Carlo plot
    if show_monte_carlo:
        fig = plt.figure(figsize=(20, 12))
        # Create 2x3 subplot layout for Monte Carlo plot
        gs = fig.add_gridspec(2, 3, hspace=0.3, wspace=0.3, top=0.75, bottom=0.1, left=0.05, right=0.98)
    else:
        fig = plt.figure(figsize=(16, 12))
        # Create 2x2 subplot layout
        gs = fig.add_gridspec(2, 2, hspace=0.3, wspace=0.3, top=0.75, bottom=0.1, left=0.1, right=0.95)
    
    # Initialize summary text (will be updated with Monte Carlo results if needed)
    summary_text = f"""CONVERGENCE ANALYSIS SUMMARY

Test Parameters:
• Target Module: {args.copies}x '{args.module}'
• Max Simulations: {args.max_simulations:,}
• Batch Size: {args.batch_size:,}
• Convergence Threshold: {threshold:.3%}
• Execution Mode: CPU (NumPy)

Results:
• Convergence Point: {history['sim_counts'][-1]:,} simulations
• Final Mean: {final_mean:,.1f} gems
• Standard Deviation: {history['std_devs'][-1]:,.1f} gems
• Final Confidence Interval: ±{history['ci_highs'][-1] - history['ci_lows'][-1]:,.1f} gems

This analysis shows how many simulations are needed to get accurate results for the module pull simulator.
The convergence point indicates when the running average stabilizes within the specified threshold."""
    
    # Plot 1: Mean Convergence
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.plot(history['sim_counts'], history['means'], marker='o', linestyle='-', markersize=4, label="Running Average")
    ax1.axhline(y=final_mean, color='r', linestyle='--', label=f"Final Mean ({final_mean:,.0f})")
    ax1.set_title("Mean Convergence", fontsize=14, fontweight='bold')
    ax1.set_xlabel("Number of Simulations")
    ax1.set_ylabel("Average Gems Required")
    ax1.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax1.legend()
    ax1.set_xscale('log')
    # Format axes to use regular numbers
    ax1.xaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    ax1.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    
    # Plot 2: Confidence Interval
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.plot(history['sim_counts'], history['means'], 'r-', label="Mean")
    ax2.fill_between(history['sim_counts'], history['ci_lows'], history['ci_highs'], 
                     color='blue', alpha=0.2, label="95% Confidence Interval")
    ax2.set_title("Confidence Interval Convergence", fontsize=14, fontweight='bold')
    ax2.set_xlabel("Number of Simulations")
    ax2.set_ylabel("Gem Cost")
    ax2.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax2.legend()
    ax2.set_xscale('log')
    # Format axes to use regular numbers
    ax2.xaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    ax2.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    
    # Plot 3: Convergence Rate
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.plot(history['sim_counts'][1:], history['percent_changes'][1:], 
             marker='o', linestyle='-', markersize=4, label="Percent Change")
    ax3.axhline(y=threshold, color='r', linestyle='--', label=f"Threshold ({threshold:.3%})")
    ax3.set_title("Convergence Rate", fontsize=14, fontweight='bold')
    ax3.set_xlabel("Number of Simulations")
    ax3.set_ylabel("Percent Change Between Batches")
    ax3.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax3.legend()
    ax3.set_yscale('log')
    ax3.set_xscale('log')
    # For log scales, we need to format manually
    ax3.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{x:.1f}'))
    ax3.xaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    
    # Plot 4: Convergence Accuracy
    ax4 = fig.add_subplot(gs[1, 1])
    
    # Calculate convergence accuracy at each point
    convergence_accuracies = []
    for i, (count, mean, std_dev) in enumerate(zip(history['sim_counts'], history['means'], history['std_devs'])):
        # Calculate margin of error as percentage of mean
        margin_of_error = 1.96 * (std_dev / np.sqrt(count))  # 95% confidence
        accuracy_percentage = (margin_of_error / mean) * 100 if mean > 0 else 100
        convergence_accuracies.append(accuracy_percentage)
    
    ax4.plot(history['sim_counts'], convergence_accuracies, marker='o', linestyle='-', 
             markersize=4, color='green', label="Convergence Accuracy")
    ax4.set_title("Convergence Accuracy", fontsize=14, fontweight='bold')
    ax4.set_xlabel("Number of Simulations")
    ax4.set_ylabel("Margin of Error (% of Mean)")
    ax4.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax4.legend()
    ax4.set_yscale('log')
    ax4.set_xscale('log')
    # For log scales, we need to format manually
    ax4.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{x:.1f}'))
    ax4.xaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    
    # Add horizontal lines for common accuracy levels
    for accuracy in [50, 25, 10, 5, 2, 1, 0.5]:
        ax4.axhline(y=accuracy, color='gray', linestyle=':', alpha=0.5, linewidth=1)
        ax4.text(history['sim_counts'][-1], accuracy, f' {accuracy}%', 
                verticalalignment='bottom', fontsize=8, alpha=0.7)
    
    # Plot 5: Monte Carlo Fan Plot (if requested)
    if show_monte_carlo:
        ax5 = fig.add_subplot(gs[:, 2])  # Span both rows
        
        # Generate Monte Carlo paths
        num_paths = 1000  # More paths for better percentile estimation
        max_sims = history['sim_counts'][-1]
        batch_size = args.batch_size
        
        # Create time points for x-axis
        time_points = np.arange(batch_size, max_sims + 1, batch_size)
        
        # Generate random paths based on final statistics
        final_std = history['std_devs'][-1]
        paths = []
        
        for path in range(num_paths):
            # Start with a random initial value around the final mean
            current_mean = final_mean + np.random.normal(0, final_std / 2)
            path_values = [current_mean]
            
            for i in range(1, len(time_points)):
                # Add random walk component that decreases over time
                noise_scale = final_std / np.sqrt(time_points[i]) * 0.5
                step = np.random.normal(0, noise_scale)
                current_mean += step
                path_values.append(current_mean)
            
            paths.append(path_values)
        
        # Convert to numpy array and calculate percentiles
        paths = np.array(paths)
        
        # Calculate percentiles at each time point
        percentiles_90 = np.percentile(paths, 90, axis=0)
        percentiles_75 = np.percentile(paths, 75, axis=0)
        percentiles_50 = np.percentile(paths, 50, axis=0)  # median
        percentiles_25 = np.percentile(paths, 25, axis=0)
        percentiles_10 = np.percentile(paths, 10, axis=0)
        
        # Plot percentile bands with specified colors
        # 90th to 75th and 25th to 10th percentiles in #f7ca77
        ax5.fill_between(time_points, percentiles_90, percentiles_75, 
                        color='#f7ca77', alpha=0.6, label="90th-75th & 25th-10th Percentiles")
        ax5.fill_between(time_points, percentiles_25, percentiles_10, 
                        color='#f7ca77', alpha=0.6)
        
        # 75th to 50th and 50th to 25th percentiles in #00ff66
        ax5.fill_between(time_points, percentiles_75, percentiles_50, 
                        color='#00ff66', alpha=0.6, label="75th-50th & 50th-25th Percentiles")
        ax5.fill_between(time_points, percentiles_50, percentiles_25, 
                        color='#00ff66', alpha=0.6)
        
        # Plot median line
        ax5.plot(time_points, percentiles_50, 'k-', linewidth=2, label="Median")
        
        # Plot the actual convergence path
        ax5.plot(history['sim_counts'], history['means'], 'r-', linewidth=3, label="Actual Path")
        
        # Add confidence bands
        ax5.fill_between(history['sim_counts'], history['ci_lows'], history['ci_highs'], 
                        color='red', alpha=0.2, label="95% Confidence Interval")
        
        ax5.set_title("Monte Carlo Fan Plot", fontsize=14, fontweight='bold')
        ax5.set_xlabel("Number of Simulations")
        ax5.set_ylabel("Average Gems Required")
        ax5.grid(True, which='both', linestyle='--', linewidth=0.5)
        ax5.legend()
        ax5.set_xscale('log')
        ax5.xaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
        ax5.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
        
        # Add Monte Carlo summary to the main summary text
        final_median = percentiles_50[-1]
        final_10th = percentiles_10[-1]
        final_90th = percentiles_90[-1]
        final_25th = percentiles_25[-1]
        final_75th = percentiles_75[-1]
        
        monte_carlo_summary = f"""

Monte Carlo Analysis:
• In {max_sims:,} simulations, {final_median:,.0f} is the median gems
• 10th to 90th percentile: {final_10th:,.0f} to {final_90th:,.0f} gems to target
• 25th to 75th percentile: {final_25th:,.0f} to {final_75th:,.0f} gems to target"""
        
        # Update the summary text to include Monte Carlo results
        summary_text += monte_carlo_summary
    
    # Add summary as text box (after all plots are created)
    plt.figtext(0.02, 0.95, summary_text, fontsize=10, fontfamily='monospace',
                bbox=dict(boxstyle="round,pad=0.5", facecolor="lightgray", alpha=0.8),
                verticalalignment='top')
    
    return fig


# --- Main Analysis Function ---

def analyze_convergence(
    max_sims: int, 
    batch_size: int, 
    threshold: float,
    confidence: float,
    target_module: str,
    target_copies: int
):
    """
    Runs simulations in batches to find the point of convergence.
    """
    all_results = np.array([], dtype=np.int32)
    history = {
        'sim_counts': [], 'means': [], 'std_devs': [],
        'ci_lows': [], 'ci_highs': [], 'percent_changes': []
    }
    z_score = 1.96 # For 95% confidence

    total_batches = max_sims // batch_size
    print(f"Analyzing convergence up to {max_sims:,} simulations in batches of {batch_size:,}...")

    for i in range(1, total_batches + 1):
        # Run one batch of simulations
        batch_results = run_simulation_numpy(batch_size, target_module, target_copies, show_progress=False)
        
        all_results = np.concatenate((all_results, batch_results))
        
        # --- Calculate and store metrics for this point in time ---
        current_sim_count = len(all_results)
        mean = np.mean(all_results)
        std_dev = np.std(all_results)
        
        # Calculate confidence interval width
        margin_of_error = z_score * (std_dev / np.sqrt(current_sim_count))
        
        # Calculate percentage change from the previous batch
        if len(history['means']) > 0:
            prev_mean = history['means'][-1]
            percent_change = abs((mean - prev_mean) / prev_mean) if prev_mean != 0 else 0
        else:
            percent_change = 1.0 # 100% change for the first batch

        # Store history
        history['sim_counts'].append(current_sim_count)
        history['means'].append(mean)
        history['std_devs'].append(std_dev)
        history['ci_lows'].append(mean - margin_of_error)
        history['ci_highs'].append(mean + margin_of_error)
        history['percent_changes'].append(percent_change)

        print(f"  Total Sims: {current_sim_count:<8,} | Running Avg: {mean:,.1f} | Change: {percent_change:.4%}")

        # --- Check for convergence ---
        if i > 1 and percent_change < threshold:
            print(f"\n✅ Convergence reached at {current_sim_count:,} simulations!")
            print(f"   The running average changed by less than the {threshold:.3%} threshold.")
            break
            
    if i == total_batches:
        print("\n⚠️  Warning: Max simulations reached without meeting the convergence threshold.")

    return history, all_results

# --- CLI and Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Convergence analyzer for the module pull simulator.")
    parser.add_argument("-n", "--max-simulations", type=int, default=100000, help="Maximum number of simulations to test.")
    parser.add_argument("-b", "--batch-size", type=int, default=1000, help="Number of simulations to run per batch.")
    parser.add_argument("-m", "--module", type=str, default="Death Penalty", help="Target epic module for the analysis.")
    parser.add_argument("-c", "--copies", type=int, default=1, help="Number of copies of the target module.")
    parser.add_argument("--threshold", type=float, default=0.001, help="Convergence threshold as a decimal (e.g., 0.001 for 0.1 percent).")
    parser.add_argument("--monte-carlo", action="store_true", help="Show Monte Carlo fan plot of possible convergence paths.")
    args = parser.parse_args()

    # --- Run Analysis ---
    start_time = time.perf_counter()
    history, final_results = analyze_convergence(
        max_sims=args.max_simulations,
        batch_size=args.batch_size,
        threshold=args.threshold,
        confidence=0.95, # Hardcoded 95% confidence for analysis
        target_module=args.module,
        target_copies=args.copies
    )
    end_time = time.perf_counter()

    # --- Print Summary ---
    final_sim_count = history['sim_counts'][-1]
    final_mean = history['means'][-1]
    final_std_dev = history['std_devs'][-1]
    
    print("\n" + "="*50)
    print("CONVERGENCE ANALYSIS COMPLETE")
    print("="*50)
    print(f"Total analysis time: {end_time - start_time:.2f} seconds")
    print(f"Target Module: {args.copies}x '{args.module}'")
    print(f"Convergence Point: {final_sim_count:,} simulations")
    
    print("\n--- Final Statistics ---")
    print(f"  Converged Mean: {final_mean:,.1f} gems")
    print(f"  Standard Deviation: {final_std_dev:,.1f} gems")
    
    # --- Recommendation ---
    # Find the smallest sim count that gives a reasonably tight CI
    recommended_n = 10000 # A sensible default
    for i, count in enumerate(history['sim_counts']):
        ci_width = history['ci_highs'][i] - history['ci_lows'][i]
        # Recommend the first count where the CI is less than 5% of the mean
        if ci_width < (history['means'][i] * 0.05):
            recommended_n = count
            break

    print("\n--- Recommendation ---")
    print(f"A good default number of simulations for this scenario is ~{recommended_n:,}.")
    print("This provides a good balance between speed and accuracy, with a tight confidence interval.")
    
    # --- Generate Plots ---
    print("\nGenerating comprehensive convergence report...")
    fig = create_convergence_report(history, final_mean, args.threshold, args, show_monte_carlo=args.monte_carlo)
    print("Displaying report. Close the plot window to exit.")
    plt.show()

if __name__ == "__main__":
    main()
