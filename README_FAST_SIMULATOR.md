# Fast Module Simulator for The Tower

A blazing-fast, device-agnostic module pull simulator that can execute millions of module pull simulations in seconds. This script can run on either CPU (using NumPy + Numba) or NVIDIA GPU (using CuPy) based on command-line flags.

## ✨ Features

- **High Performance**: 17,000+ simulations per second on CPU
- **Device Agnostic**: Same code runs on CPU or GPU
- **Vectorized Operations**: Optimized for massive parallel computation
- **Real Game Logic**: Accurate simulation of The Tower's module pull mechanics
- **Statistical Analysis**: Provides mean, 95% confidence intervals

## 📊 Performance Results

From testing on a modern CPU:
- **100,000 simulations** completed in ~5.7 seconds (**17,478 sims/sec**)
- **1,000,000 simulations** would complete in ~57 seconds
- **GPU mode** can achieve even higher performance with compatible hardware

## 🔧 Installation

### Prerequisites

- Python 3.7+
- For GPU support: NVIDIA GPU with CUDA 11.x

### Install Dependencies

```bash
pip install -r requirements.txt
```

**For CPU-only usage:**
```bash
pip install numpy numba
```

**For GPU support (optional):**
```bash
pip install cupy-cuda11x
```

*Note: The exact CuPy version depends on your CUDA toolkit. See the [CuPy installation guide](https://docs.cupy.dev/en/stable/install.html) for details.*

## 🚀 Usage

### Basic Usage

```bash
# Run 1,000 simulations on CPU
python fast_simulator.py -n 1000

# Run 100,000 simulations for featured module
python fast_simulator.py -n 100000 --featured

# Run on GPU (if available)
python fast_simulator.py -n 1000000 --gpu
```

### Command Line Options

- `-n, --simulations`: Number of simulations to run (required)
- `--gpu`: Run on NVIDIA GPU using CuPy (optional)
- `--featured`: Simulate pulling for a featured module (optional)

### Example Output

```
🚀 Running 100,000 simulations on the CPU (NumPy + Numba)...

✅ Completed in 5.7215 seconds (17,478 sims/sec)

--- Simulation Results ---
  Target Module Featured: False
  Average Gems to Acquire: 3,009
  95% Confidence: Acquired within 4,000 gems
```

## 📈 Understanding Results

### Non-Featured Modules
- **Average**: ~3,009 gems (typical expectation)
- **95% Confidence**: ~4,000 gems (worst-case scenario for most players)

### Featured Modules  
- **Average**: ~1,390 gems (much better odds!)
- **95% Confidence**: ~3,200 gems (significantly reduced worst-case)

### Simulation Parameters
- **Epic Chance**: 2.5% per pull (matches game)
- **Pity Limit**: 150 pulls guaranteed epic
- **Total Epics**: 16 natural epic modules in pool
- **Pull Cost**: 200 gems per 10-pull

## 🔧 How It Works

### Core Architecture

The simulator uses a **backend-agnostic design** with separate optimized functions:

1. **`run_simulation_numpy()`** - CPU implementation with Numba JIT compilation
2. **`run_simulation_cupy()`** - GPU implementation using CuPy arrays

### Vectorized Algorithm

Instead of simulating one pull at a time, the simulator:

1. **Batch Processing**: Simulates 10-pulls for all active simulations simultaneously
2. **Vectorized Pity**: Calculates pity mechanics across all simulations in parallel  
3. **Parallel Success Checks**: Determines target module acquisition probability for all epics at once
4. **State Management**: Tracks completion status and updates counters efficiently

### Performance Optimizations

- **NumPy/CuPy Arrays**: All operations use optimized array libraries
- **Numba JIT**: CPU code is compiled to machine code for maximum speed
- **GPU Memory**: CuPy keeps all data on GPU until final results transfer
- **Vectorized Logic**: No Python loops for simulation logic

## 💡 Use Cases

### Game Analysis
- **Expected Costs**: Calculate realistic gem requirements for target modules
- **Strategy Planning**: Compare featured vs non-featured pull strategies
- **Budget Planning**: Understand 95% confidence intervals for worst-case scenarios

### Statistical Research
- **Distribution Analysis**: Study gem cost distributions across many scenarios
- **Pity System Verification**: Validate pity mechanics implementation
- **Pull Strategy Optimization**: Test different approaches to module acquisition

## 🏗️ Technical Details

### Dependencies
- **NumPy**: Core array operations and CPU backend
- **Numba**: Just-in-time compilation for CPU performance  
- **CuPy**: GPU array operations (optional)
- **argparse**: Command-line interface

### Limitations
- **Pity Reset Simplification**: Uses approximate pity reset for vectorization performance
- **Memory Usage**: Large simulations require proportional RAM/VRAM
- **CUDA Requirement**: GPU mode requires NVIDIA hardware and CUDA toolkit

## 🛠️ Development

### Code Structure
```
fast_simulator.py
├── run_simulation_numpy()    # CPU backend
├── run_simulation_cupy()     # GPU backend  
└── main()                    # CLI and orchestration
```

### Adding Features
- **New Backends**: Add new `run_simulation_*()` functions
- **Different Games**: Modify constants and probability logic
- **Analysis Tools**: Extend output formatting and statistics

## 📜 License

This simulator is designed for educational and analysis purposes for The Tower mobile game.

---

**Ready to simulate millions of module pulls in seconds? 🚀**