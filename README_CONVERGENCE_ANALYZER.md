# Convergence Analyzer for Module Pull Simulator

This script analyzes how many simulations are needed to get accurate results for the module pull simulator. It runs simulations in batches and tracks when the results become stable.

## Installation

First, install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python convergence_analyzer.py
```

This will run the default analysis:
- Target module: "Death Penalty" (1 copy)
- Max simulations: 100,000
- Batch size: 1,000
- Convergence threshold: 0.1% (0.001)

### Advanced Usage

```bash
python convergence_analyzer.py -n 50000 -b 500 -m "Astral Deliverance" -c 2 --threshold 0.0005 --monte-carlo
```

### Command Line Arguments

- `-n, --max-simulations`: Maximum number of simulations to test (default: 100000)
- `-b, --batch-size`: Number of simulations to run per batch (default: 1000)
- `-m, --module`: Target epic module name (default: "Death Penalty")
- `-c, --copies`: Number of copies of the target module needed (default: 1)
- `--threshold`: Convergence threshold as decimal (default: 0.001 for 0.1%)
- `--monte-carlo`: Show Monte Carlo fan plot of possible convergence paths

## What the Script Does

1. **Runs simulations in batches** - Starts with small batches and gradually increases
2. **Tracks convergence** - Monitors how much the average result changes between batches
3. **Calculates confidence intervals** - Shows the statistical uncertainty at each step
4. **Stops automatically** - When the result changes by less than the threshold
5. **Generates visualizations** - Four plots showing different aspects of convergence
6. **Optional Monte Carlo plot** - Shows possible convergence paths with fan plot

## Output

The script provides:

1. **Real-time progress** - Shows running averages and convergence status
2. **Final statistics** - Converged mean, standard deviation, and confidence interval
3. **Recommendation** - Suggests a good default number of simulations for future runs
4. **Four standard plots**:
   - Mean convergence over time
   - Confidence interval narrowing
   - Rate of convergence (percent change between batches)
   - Convergence accuracy (margin of error as % of mean)
5. **Optional Monte Carlo fan plot** - Shows percentile bands and 1,000 possible convergence paths

## Example Output

```
Analyzing convergence up to 100,000 simulations in batches of 1,000...
  Total Sims: 1,000     | Running Avg: 3,245.6 | Change: 100.0000%
  Total Sims: 2,000     | Running Avg: 3,198.3 | Change: 1.4780%
  Total Sims: 3,000     | Running Avg: 3,201.7 | Change: 0.1062%
  Total Sims: 4,000     | Running Avg: 3,203.1 | Change: 0.0437%
  Total Sims: 5,000     | Running Avg: 3,202.8 | Change: 0.0094%

✅ Convergence reached at 5,000 simulations!
   The running average changed by less than the 0.100% threshold.

==================================================
CONVERGENCE ANALYSIS COMPLETE
==================================================
Total analysis time: 2.34 seconds
Target Module: 1x 'Death Penalty'
Convergence Point: 5,000 simulations

--- Final Statistics ---
  Converged Mean: 3,202.8 gems
  Standard Deviation: 1,847.3 gems

--- Recommendation ---
A good default number of simulations for this scenario is ~5,000.
This provides a good balance between speed and accuracy, with a tight confidence interval.
```

## Monte Carlo Fan Plot

When you use the `--monte-carlo` flag, the script generates an additional plot showing:

- **1,000 simulated convergence paths** - Based on the final statistics from your actual run
- **Percentile bands** - 10th, 25th, 50th (median), 75th, and 90th percentiles
- **Color-coded regions**:
  - **Orange (#f7ca77)**: 90th-75th and 25th-10th percentile ranges
  - **Green (#00ff66)**: 75th-50th and 50th-25th percentile ranges
- **Median line** - Black line showing the 50th percentile
- **Actual convergence path** - Your real data in red
- **Confidence intervals** - The statistical uncertainty bands

The summary includes:
- Median gems required at convergence
- 10th to 90th percentile range
- 25th to 75th percentile range

This helps visualize:
- How much variation is possible in convergence paths
- Whether your actual path is typical or unusual
- The uncertainty reduction as more simulations are added
- Probability ranges for different gem costs

## Tips

- **For quick testing**: Use smaller batch sizes (100-500) and lower thresholds (0.01-0.05)
- **For production runs**: Use larger batch sizes (1000-5000) and tighter thresholds (0.001-0.005)
- **Different modules**: Some modules may require more simulations to converge due to their rarity
- **Monte Carlo plot**: Use `--monte-carlo` for a more comprehensive view of convergence uncertainty

## Understanding the Plots

1. **Mean Convergence**: Shows how the running average stabilizes over time
2. **Confidence Interval**: Shows the statistical uncertainty narrowing as more simulations are run
3. **Convergence Rate**: Shows the rate of change between batches - when this drops below the threshold line, convergence is reached
4. **Convergence Accuracy**: Shows the margin of error as a percentage of the mean at different simulation counts
5. **Monte Carlo Fan Plot**: Shows possible convergence paths and uncertainty visualization
