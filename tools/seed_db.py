import sys
import json
import math
import random
import uuid
import multiprocessing as mp
import sqlite3
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

# Ensure we can import the project src package when running from repo root
PROJECT_ROOT = Path(__file__).parent.resolve()
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

import structlog  # noqa: E402

from tower_iq.core.config import ConfigurationManager  # noqa: E402
from tower_iq.core.logging_config import setup_logging  # noqa: E402
from tower_iq.services.database_service import DatabaseService  # noqa: E402

# Import database schema configuration
try:
    # Try importing from project root config directory
    import importlib.util
    
    CONFIG_PATH = PROJECT_ROOT / "config" / "database_schema.py"
    
    if CONFIG_PATH.exists():
        spec = importlib.util.spec_from_file_location("database_schema", CONFIG_PATH)
        if spec is not None and spec.loader is not None:
            database_schema = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(database_schema)
        else:
            raise ImportError("Failed to create module spec")
        
        METRIC_METADATA = database_schema.METRIC_METADATA
        EVENT_METADATA = database_schema.EVENT_METADATA
        get_tables_to_wipe = database_schema.get_tables_to_wipe
        SCHEMA_VERSION = database_schema.SCHEMA_VERSION
    else:
        raise ImportError("database_schema.py not found")
        
except (ImportError, AttributeError):
    # Fallback if schema config is not available
    METRIC_METADATA = {}
    EVENT_METADATA = {}
    SCHEMA_VERSION = "1.0"
    
    def get_tables_to_wipe():
        return ['events', 'metrics', 'runs', 'game_versions', 'metric_names', 'event_names', 'db_metrics', 'db_metric_names', 'db_monitored_objects']


# ============================================================================
# METADATA DEFINITIONS - Now imported from config/database_schema.py
# ============================================================================
# METRIC_METADATA and EVENT_METADATA are imported from database_schema

# ============================================================================
# CONFIGURATION VARIABLES - Edit these to customize the seeding behavior
# ============================================================================

# Default command line arguments (can be overridden with --runs, --tiers, etc.)
DEFAULT_RUNS = 100
DEFAULT_TIERS = "5-10"  # Tier range, e.g. "5-8" or single tier like "7"
DEFAULT_MIN_WAVE = 800
DEFAULT_MAX_WAVE = 1500
DEFAULT_SEED = 422452487245672
DEFAULT_WORKERS = None  # None = use CPU count
DEFAULT_START_DATE = "90d"  # Start date: "30d" (30 days ago), "2024-01-01", or "2024-01-01 14:30"
DEFAULT_END_DATE = "now"  # End date: "now", "2024-12-31", or "2024-12-31 18:00"
DEFAULT_TIME_DISTRIBUTION = "evening_heavy"  # Time distribution: "uniform", "afternoon_heavy", "evening_heavy", or custom weights

# Game simulation parameters
GAME_VERSION = "27.0.4"
SECONDS_PER_WAVE = 30.0  # Game time per wave
STAGGER_MINUTES = 10  # Minutes between run start times

# Note: Database now stores raw integer values without scaling factors
# All values are stored as raw integers for optimal performance

# Survival probability parameters
SURVIVAL_PROB_MIN_WAVE = 0.95  # 95% survival at min_wave
SURVIVAL_PROB_MAX_WAVE = 0.50  # 50% survival at max_wave

# Coin generation parameters
BASE_COINS_MIN = 1297
BASE_COINS_MAX = 387567
WAVE_SCALE_FACTOR = 0.15  # Each wave gives 15% more base coins
COIN_MULTIPLIERS = [0.1, 0.3, 0.8, 1.2, 2.0, 4.0, 8.0]
BONUS_WAVE_CHANCE = 0.15  # 15% chance of bonus wave
BONUS_MULTIPLIER_MIN = 15.0
BONUS_MULTIPLIER_MAX = 90.0
PENALTY_WAVE_CHANCE = 0.15  # 15% chance of penalty wave
PENALTY_MULTIPLIER_MIN = 0.01
PENALTY_MULTIPLIER_MAX = 0.9

# Cell generation parameters
CELLS_MIN = 10
CELLS_MAX = 5000
CELLS_TOTAL_MULTIPLIER = 2.0
CELLS_RANDOM_MAX = 100

# Cash generation parameters
CASH_DELTAS = [0.0, 0.1, 0.2, 0.0, 0.0]  # Possible cash deltas per wave
CASH_RANDOM_MAX = 5

# Stone generation parameters
STONES_MIN = 0.0
STONES_MAX = 2.0

# Gem generation parameters
GEM_BLOCK_TAP_CHANCE = 0.4  # 40% chance per wave
GEM_BLOCK_TAPS_MIN = 1
GEM_BLOCK_TAPS_MAX = 3
GEM_BLOCK_VALUE = 2
AD_GEM_CLAIM_CHANCE = 0.25  # 25% chance per wave
AD_GEM_VALUE = 5
GUARDIAN_GEM_VALUES = [0, 0, 1, 2]  # Possible guardian gem values
GEMS_TOTAL_MULTIPLIER = 5.0
GEMS_RANDOM_MAX = 10000

# Speed change parameters
SPEED_CHANGE_CHANCE = 0.15  # 15% chance per wave
SPEED_OPTIONS = [0.75, 1.0, 1.25, 1.5, 2.0]

# Pause/resume parameters
PAUSE_CHANCE = 0.01  # 10% chance per wave
PAUSE_DURATION_MS = 1000  # 1 second pause

# Progress reporting
PROGRESS_LOG_INTERVAL = 5  # Log every 5th run
PROGRESS_BAR_WIDTH = 50

# Database metrics collection
METRICS_COLLECTION_ENABLED = True  # Enable daily metrics collection during seeding
METRICS_COLLECTION_INTERVAL_HOURS = 24  # Collect metrics every 24 hours (daily)

# Time distribution presets (weights for each hour 0-23)
TIME_DISTRIBUTIONS = {
    "uniform": [1.0] * 24,  # Equal probability for all hours
    "afternoon_heavy": [
        0.2, 0.1, 0.1, 0.1, 0.1, 0.2,  # 0-5: Very light
        0.3, 0.5, 0.8, 1.0, 1.2, 1.5,  # 6-11: Morning ramp-up
        2.0, 2.5, 3.0, 3.5, 4.0, 3.5,  # 12-17: Heavy afternoon
        3.0, 2.5, 2.0, 1.5, 1.0, 0.5   # 18-23: Evening wind-down
    ],
    "evening_heavy": [
        0.1, 0.1, 0.1, 0.1, 0.1, 0.1,  # 0-5: Very light
        0.2, 0.4, 0.6, 0.8, 1.0, 1.2,  # 6-11: Morning build-up
        1.5, 1.8, 2.0, 2.2, 2.5, 3.0,  # 12-17: Afternoon
        3.5, 4.0, 4.5, 3.5, 2.5, 1.0   # 18-23: Heavy evening peak
    ],
    "morning_heavy": [
        0.1, 0.1, 0.1, 0.1, 0.1, 0.2,  # 0-5: Very light
        1.0, 2.0, 3.5, 4.0, 3.5, 3.0,  # 6-11: Heavy morning
        2.5, 2.0, 1.8, 1.5, 1.2, 1.0,  # 12-17: Afternoon decline
        0.8, 0.6, 0.4, 0.3, 0.2, 0.1   # 18-23: Light evening
    ]
}


def parse_date_string(date_str: str) -> datetime:
    """
    Parse various date string formats:
    - "30d" -> 30 days ago from now
    - "7d" -> 7 days ago from now  
    - "now" -> current datetime
    - "2024-01-01" -> specific date at midnight
    - "2024-01-01 14:30" -> specific date and time
    - "2024-01-01 14:30:45" -> specific date, time, and seconds
    """
    date_str = date_str.strip().lower()
    
    if date_str == "now":
        return datetime.now()
    elif date_str.endswith("d") and date_str[:-1].isdigit():
        # Handle relative days (e.g., "30d")
        days_ago = int(date_str[:-1])
        return datetime.now() - timedelta(days=days_ago)
    else:
        # Handle specific date/time formats
        formats = [
            "%Y-%m-%d %H:%M:%S",  # 2024-01-01 14:30:45
            "%Y-%m-%d %H:%M",     # 2024-01-01 14:30
            "%Y-%m-%d",           # 2024-01-01 (midnight)
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        raise ValueError(f"Unable to parse date string: {date_str}")


def parse_time_distribution(distribution_str: str) -> list:
    """
    Parse time distribution string:
    - "uniform" -> predefined uniform distribution
    - "afternoon_heavy" -> predefined afternoon-heavy distribution
    - "evening_heavy" -> predefined evening-heavy distribution
    - "morning_heavy" -> predefined morning-heavy distribution
    - "1,1,1,2,3,4,..." -> custom 24-hour weights (comma-separated)
    """
    distribution_str = distribution_str.strip().lower()
    
    if distribution_str in TIME_DISTRIBUTIONS:
        return TIME_DISTRIBUTIONS[distribution_str]
    elif "," in distribution_str:
        # Parse custom weights
        try:
            weights = [float(x.strip()) for x in distribution_str.split(",")]
            if len(weights) != 24:
                raise ValueError(f"Custom time distribution must have exactly 24 values (one for each hour), got {len(weights)}")
            return weights
        except ValueError as e:
            raise ValueError(f"Invalid custom time distribution format: {e}")
    else:
        raise ValueError(f"Unknown time distribution: {distribution_str}")


def generate_distributed_timestamp(start_date: datetime, end_date: datetime, time_weights: list, rng: random.Random) -> datetime:
    """
    Generate a random timestamp within the date range using the specified time-of-day distribution.
    
    Args:
        start_date: Start of date range
        end_date: End of date range  
        time_weights: List of 24 weights for hours 0-23
        rng: Random number generator instance
    
    Returns:
        Random datetime within the range following the time distribution
    """
    # Calculate total days in range
    date_range = end_date - start_date
    total_days = date_range.total_seconds() / (24 * 3600)
    
    # Pick a random day within the range
    random_day_offset = rng.uniform(0, total_days)
    base_date = start_date + timedelta(days=random_day_offset)
    
    # Normalize weights to create probability distribution
    total_weight = sum(time_weights)
    probabilities = [w / total_weight for w in time_weights]
    
    # Use weighted random choice to pick an hour
    hour = rng.choices(range(24), weights=probabilities)[0]
    
    # Add random minutes and seconds within that hour
    minute = rng.randint(0, 59)
    second = rng.randint(0, 59)
    
    # Combine date and time
    result = base_date.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(hours=hour, minutes=minute, seconds=second)
    
    # Ensure result is within bounds (edge case handling)
    if result < start_date:
        result = start_date
    elif result > end_date:
        result = end_date
        
    return result


def wipe_tables(db: DatabaseService) -> None:
    conn = db.sqlite_conn
    assert conn is not None
    
    # Only delete from tables that exist - use schema config
    tables_to_wipe = get_tables_to_wipe()
    for table in tables_to_wipe:
        try:
            conn.execute(f"DELETE FROM {table}")
        except sqlite3.OperationalError:
            # Table doesn't exist, skip it
            pass
    
    conn.commit()
    # Invalidate service-level caches
    db._metric_name_cache.clear()
    db._event_name_cache.clear()
    db._game_version_cache.clear()




def cleanup_sqlite_auxiliary_files(db_path: str, logger) -> None:
    """
    Clean up SQLite auxiliary files (SHM and WAL) that may be left behind.
    These files are created when SQLite uses WAL mode and can accumulate over time.
    """
    db_path_obj = Path(db_path)
    base_name = db_path_obj.stem
    db_dir = db_path_obj.parent
    
    # List of auxiliary files to clean up
    auxiliary_files = [
        db_dir / f"{base_name}-shm",  # Shared memory file
        db_dir / f"{base_name}-wal",  # Write-ahead log file
        db_dir / f"{base_name}.sqlite-shm",  # Alternative naming
        db_dir / f"{base_name}.sqlite-wal",  # Alternative naming
    ]
    
    cleaned_files = []
    for aux_file in auxiliary_files:
        if aux_file.exists():
            try:
                aux_file.unlink()
                cleaned_files.append(str(aux_file))
                logger.info("Cleaned up SQLite auxiliary file", file=str(aux_file))
            except OSError as e:
                logger.warning("Failed to clean up SQLite auxiliary file", 
                             file=str(aux_file), error=str(e))
    
    if cleaned_files:
        logger.info("SQLite auxiliary file cleanup completed", 
                   cleaned_files=cleaned_files)
    else:
        logger.debug("No SQLite auxiliary files found to clean up")


def calculate_survival_probability(wave: int, min_wave: int, max_wave: int) -> float:
    """
    Calculate the probability of surviving to the next wave.
    
    Uses a gentler decay formula where:
    - At min_wave, survival probability is high (configurable)
    - As wave approaches max_wave, survival probability decreases more gradually
    - At max_wave, survival probability is moderate (configurable)
    
    Formula: P(survive) = SURVIVAL_PROB_MIN_WAVE * exp(-k * (wave - min_wave))
    where k is chosen so that P(max_wave) ≈ SURVIVAL_PROB_MAX_WAVE
    """
    if wave < min_wave:
        return 1.0  # Always survive before min_wave
    
    # Calculate decay constant k for gentler decay
    # SURVIVAL_PROB_MAX_WAVE = SURVIVAL_PROB_MIN_WAVE * exp(-k * (max_wave - min_wave))
    # k = -ln(SURVIVAL_PROB_MAX_WAVE/SURVIVAL_PROB_MIN_WAVE) / (max_wave - min_wave)
    k = -math.log(SURVIVAL_PROB_MAX_WAVE / SURVIVAL_PROB_MIN_WAVE) / (max_wave - min_wave)
    
    # Calculate survival probability
    survival_prob = SURVIVAL_PROB_MIN_WAVE * math.exp(-k * (wave - min_wave))
    return max(SURVIVAL_PROB_MAX_WAVE, min(0.99, survival_prob))  # Clamp between max_wave_prob and 99%


def generate_run_data_worker(args_tuple):
    """
    Worker function for multiprocessing. Generates run data in memory without
    database operations to avoid SQLite locking issues.
    """
    run_index = -1  # Default value in case unpacking fails
    try:
        (tier, min_wave, max_wave, start_date, end_date, time_weights, run_index, base_seed) = args_tuple
        
        # Use a unique seed for each run to ensure different random sequences
        unique_seed = base_seed + run_index
        random.seed(unique_seed)
        
        # Generate run data in memory
        run_data = generate_run_data(tier, min_wave, max_wave, start_date, end_date, time_weights, run_index, unique_seed)
        return {"success": True, "run_index": run_index, "tier": tier, "data": run_data}
    except Exception as e:
        return {"success": False, "run_index": run_index, "error": str(e)}


def generate_run_data(tier: int, min_wave: int, max_wave: int, start_date: datetime, end_date: datetime, time_weights: list, run_index: int, seed: int) -> dict:
    """
    Generate run data in memory without database operations.
    Returns a dictionary containing all the data needed to insert into the database.
    """
    run_id = str(uuid.uuid4())
    game_version = GAME_VERSION

    # Create a random instance for this specific run to ensure reproducibility
    rng = random.Random(seed)
    
    # Generate a distributed timestamp within the date range using time-of-day weights
    start_dt = generate_distributed_timestamp(start_date, end_date, time_weights, rng)
    start_time_ms = int(start_dt.timestamp() * 1000)

    # Initialize simulated accumulators
    coins_total = 0.0
    cells_total = 0.0
    cash_total = 0.0
    stones_total = 0.0
    gem_blocks_count = 0
    ad_gems_count = 0
    guardian_gems_value = 0

    last_speed = 1.0
    final_wave = 0

    events = []
    metrics = []

    # Simulate wave progression with survival probability
    for wave in range(1, max_wave + 1):
        # Check if we survive this wave
        survival_prob = calculate_survival_probability(wave, min_wave, max_wave)
        if wave > min_wave and rng.random() > survival_prob:
            # Game over - we died on this wave
            final_wave = wave - 1
            break
        
        final_wave = wave
        # Game time per wave
        game_ts_sec = float(wave * SECONDS_PER_WAVE)
        real_ts_ms = start_time_ms + int(game_ts_sec * 1000)
        
        # Game timestamp in milliseconds (no scaling needed)
        game_ts_ms = int(game_ts_sec * 1000)

        # Per-wave deltas with some variability
        base_coins = rng.uniform(BASE_COINS_MIN, BASE_COINS_MAX)

        # Wave scaling (later waves give more coins)
        wave_scale = 1.0 + (wave * WAVE_SCALE_FACTOR)

        # Random multiplier for dramatic variation
        multiplier = rng.choice(COIN_MULTIPLIERS)

        # Occasional bonus waves
        if rng.random() < BONUS_WAVE_CHANCE:
            multiplier *= rng.uniform(BONUS_MULTIPLIER_MIN, BONUS_MULTIPLIER_MAX)

        # Occasional penalty waves  
        if rng.random() < PENALTY_WAVE_CHANCE:
            multiplier *= rng.uniform(PENALTY_MULTIPLIER_MIN, PENALTY_MULTIPLIER_MAX)

        wave_coins = base_coins * wave_scale * multiplier
        coins_total += wave_coins

        wave_cells = rng.uniform(CELLS_MIN, CELLS_MAX)
        cells_total += wave_cells

        cash_delta = rng.choice(CASH_DELTAS)
        cash_total += cash_delta

        stones_delta = rng.uniform(STONES_MIN, STONES_MAX)
        stones_total += stones_delta

        # Gem sources
        # Randomly decide block taps and ad claims near some checkpoints
        if rng.random() < GEM_BLOCK_TAP_CHANCE:
            block_taps = rng.randint(GEM_BLOCK_TAPS_MIN, GEM_BLOCK_TAPS_MAX)
            gem_blocks_count += block_taps
            events.append({
                "run_id": run_id,
                "timestamp": real_ts_ms,
                "event_name": "gemBlockTapped",
                "data": {"gemValue": GEM_BLOCK_VALUE}
            })
        if rng.random() < AD_GEM_CLAIM_CHANCE:
            ad_claims = 1
            ad_gems_count += ad_claims
            events.append({
                "run_id": run_id,
                "timestamp": real_ts_ms,
                "event_name": "adGemClaimed",
                "data": {"gemValue": AD_GEM_VALUE}
            })

        # Guardian gems sometimes contribute a few
        guardian_gems_value += rng.choice(GUARDIAN_GEM_VALUES)

        # Occasional speed change event
        if rng.random() < SPEED_CHANGE_CHANCE:
            new_speed = round(rng.choice(SPEED_OPTIONS), 2)
            if new_speed != last_speed:
                last_speed = new_speed
                events.append({
                    "run_id": run_id,
                    "timestamp": real_ts_ms,
                    "event_name": "gameSpeedChanged",
                    "data": {"value": new_speed}
                })

        # Build metrics bundle aligned with hook names
        # Store raw integer values without scaling
        metrics_data = {
            "round_coins": int(coins_total),
            "wave_coins": int(wave_coins),
            "coins": int(coins_total * GEMS_TOTAL_MULTIPLIER + rng.uniform(0, GEMS_RANDOM_MAX)),
            "gems": int((gem_blocks_count * GEM_BLOCK_VALUE) + (ad_gems_count * AD_GEM_VALUE) + guardian_gems_value),
            "round_cells": int(cells_total),
            "wave_cells": int(wave_cells),
            "cells": int(cells_total * CELLS_TOTAL_MULTIPLIER + rng.uniform(0, CELLS_RANDOM_MAX)),
            "round_cash": int(cash_total),
            "cash": int(cash_total + rng.uniform(0, CASH_RANDOM_MAX)),
            "stones": int(stones_total),
            "round_gems_from_blocks_count": int(gem_blocks_count),
            "round_gems_from_blocks_value": int(gem_blocks_count * GEM_BLOCK_VALUE),
            "round_gems_from_ads_count": int(ad_gems_count),
            "round_gems_from_ads_value": int(ad_gems_count * AD_GEM_VALUE),
            "round_gems_from_guardian": int(guardian_gems_value),
        }

        metrics.append({
            "run_id": run_id,
            "real_timestamp": real_ts_ms,
            "game_duration": game_ts_ms,  # Duration in milliseconds
            "current_wave": wave,
            "metrics": metrics_data,
        })

        # Pause/resume occasionally
        if rng.random() < PAUSE_CHANCE:
            events.append({
                "run_id": run_id,
                "timestamp": real_ts_ms,
                "event_name": "gamePaused",
                "data": {}
            })
            events.append({
                "run_id": run_id,
                "timestamp": real_ts_ms + PAUSE_DURATION_MS,
                "event_name": "gameResumed",
                "data": {}
            })

    # Finalize run
    duration_gametime = final_wave * SECONDS_PER_WAVE
    end_time_ms = start_time_ms + int(duration_gametime * 1000)
    coins_earned = coins_total
    
    # Calculate actual real-time duration in milliseconds
    # Note: duration_realtime should be in milliseconds for database storage
    duration_realtime = int(duration_gametime * 1000)
    
    events.append({
        "run_id": run_id,
        "timestamp": end_time_ms,
        "event_name": "gameOver",
        "data": {"coinsEarned": coins_earned}
    })

    # Add start event
    events.insert(0, {
        "run_id": run_id,
        "timestamp": start_time_ms,
        "event_name": "startNewRound",
        "data": {"tier": tier}
    })

    return {
        "run_id": run_id,
        "start_time": start_time_ms,
        "end_time": end_time_ms,
        "game_version": game_version,
        "tier": tier,
        "final_wave": final_wave,
        "round_coins": int(coins_earned),  # Raw integer value
        "duration_realtime": duration_realtime,
        "duration_gametime": int(duration_gametime * 1000),  # Convert to milliseconds
        "round_cells": int(cells_total),  # Raw integer value
        "round_gems": int((gem_blocks_count * GEM_BLOCK_VALUE) + (ad_gems_count * AD_GEM_VALUE) + guardian_gems_value),  # Raw integer value
        "round_cash": int(cash_total),  # Raw integer value
        "events": events,
        "metrics": metrics
    }


# Removed generate_run function - no longer needed with bulk operations


def write_run_data_to_db(db: DatabaseService, run_data: dict) -> None:
    """
    Write pre-generated run data to the database using bulk operations.
    This is much faster than individual inserts.
    """
    # Temporarily replace the debug method with a no-op to suppress debug messages
    original_debug = db.logger.debug
    db.logger.debug = lambda *args, **kwargs: None
    
    try:
        # Use the new bulk method for maximum efficiency
        db.bulk_write_run_data(run_data)
    finally:
        # Restore original debug method
        db.logger.debug = original_debug


def get_metrics_collection_timestamps(run_data_list: list, start_date: datetime, end_date: datetime, metrics_enabled: bool = True) -> list:
    """
    Generate timestamps for metrics collection based on the date range and run data.
    Collects metrics at daily intervals within the data generation period.
    
    Args:
        run_data_list: List of generated run data
        start_date: Start date of the data generation period
        end_date: End date of the data generation period
    
    Returns:
        List of datetime objects representing when to collect metrics
    """
    if not metrics_enabled or not run_data_list:
        return []
    
    # Create a list of timestamps at daily intervals
    collection_timestamps = []
    current_time = start_date
    
    while current_time <= end_date:
        collection_timestamps.append(current_time)
        current_time += timedelta(hours=METRICS_COLLECTION_INTERVAL_HOURS)
    
    # Always include the end date as the final collection point
    if collection_timestamps[-1] != end_date:
        collection_timestamps.append(end_date)
    
    return collection_timestamps


def bulk_write_all_runs_to_db(db: DatabaseService, run_data_list: list, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None, logger=None, metrics_enabled: bool = True) -> None:
    """
    Write all run data to the database using the most efficient bulk operations.
    This groups operations by type and uses transactions for maximum performance.
    Also collects database metrics at daily intervals during the seeding process.
    """
    if not run_data_list:
        return
    
    # Temporarily replace the debug method with a no-op to suppress debug messages
    original_debug = db.logger.debug
    db.logger.debug = lambda *args, **kwargs: None
    
    try:
        # Start a single large transaction for maximum performance
        if not db.sqlite_conn:
            raise Exception("Database connection not available")
        db.sqlite_conn.execute("BEGIN TRANSACTION")
        
        # Sort runs by start time for chronological insertion and metrics collection
        sorted_runs = sorted(run_data_list, key=lambda x: x['start_time'])
        
        # Get metrics collection timestamps if enabled
        metrics_timestamps = []
        if metrics_enabled and start_date and end_date and logger:
            metrics_timestamps = get_metrics_collection_timestamps(sorted_runs, start_date, end_date, metrics_enabled)
            print(f"📈 Database metrics will be collected at {len(metrics_timestamps)} time points")
        
        # Group data by type for bulk operations
        runs_start_data = []
        events_data = []
        metrics_data = []
        runs_end_data = []
        
        # Process runs in chronological order and collect metrics at intervals
        metrics_index = 0
        next_metrics_time = metrics_timestamps[0] if metrics_timestamps else None
        
        for i, run_data in enumerate(sorted_runs):
            # Check if we should collect metrics before inserting this run
            if (next_metrics_time and 
                datetime.fromtimestamp(run_data['start_time'] / 1000) >= next_metrics_time):
                
                # Collect metrics at this timestamp
                try:
                    db.collect_and_store_db_metrics()
                    print(f"📈 Database metrics collected at {next_metrics_time.strftime('%Y-%m-%d %H:%M')}")
                except Exception as e:
                    if logger:
                        logger.warning("Failed to collect database metrics", error=str(e))
                    else:
                        print(f"⚠️  Failed to collect database metrics: {e}")
                
                # Move to next metrics collection time
                metrics_index += 1
                if metrics_index < len(metrics_timestamps):
                    next_metrics_time = metrics_timestamps[metrics_index]
                else:
                    next_metrics_time = None
            
            # Collect run start data
            runs_start_data.append({
                'run_id': run_data['run_id'],
                'start_time': run_data['start_time'],
                'game_version': run_data['game_version'],
                'tier': run_data['tier']
            })
            
            # Collect events data
            if run_data.get('events'):
                events_data.extend(run_data['events'])
            
            # Collect metrics data
            if run_data.get('metrics'):
                metrics_data.extend(run_data['metrics'])
            
            # Collect run end data
            runs_end_data.append({
                'run_id': run_data['run_id'],
                'end_time': run_data['end_time'],
                'final_wave': run_data['final_wave'],
                'round_coins': run_data['round_coins'],
                'duration_realtime': run_data['duration_realtime'],
                'duration_gametime': run_data['duration_gametime'],
                'round_cells': run_data['round_cells'],
                'round_gems': run_data['round_gems'],
                'round_cash': run_data['round_cash']
            })
        
        # Execute bulk operations in order (all within the same transaction)
        print("📊 Bulk inserting run starts...")
        db.bulk_insert_runs(runs_start_data)
        
        print("📊 Bulk inserting events...")
        db.bulk_insert_events(events_data)
        
        print("📊 Bulk inserting metrics...")
        db.bulk_insert_metrics(metrics_data)
        
        print("📊 Bulk updating run ends...")
        db.bulk_update_runs_end(runs_end_data)
        
        # Collect any remaining metrics timestamps (after all runs)
        while metrics_index < len(metrics_timestamps):
            try:
                db.collect_and_store_db_metrics()
                print(f"📈 Database metrics collected at {metrics_timestamps[metrics_index].strftime('%Y-%m-%d %H:%M')}")
            except Exception as e:
                if logger:
                    logger.warning("Failed to collect database metrics", error=str(e))
                else:
                    print(f"⚠️  Failed to collect database metrics: {e}")
            metrics_index += 1
        
        # Commit the entire transaction
        if db.sqlite_conn:
            db.sqlite_conn.commit()
        print("✅ All data committed to database!")
        
        if metrics_timestamps:
            print(f"📈 Database metrics collected at {len(metrics_timestamps)} time points during seeding")
        
    except Exception as e:
        # Rollback on error
        if db.sqlite_conn:
            db.sqlite_conn.rollback()
        print(f"❌ Transaction rolled back due to error: {e}")
        raise
    finally:
        # Restore original debug method
        db.logger.debug = original_debug


def pre_populate_lookup_tables(db: DatabaseService, logger):
    logger.info("Pre-populating metadata for lookup tables...")
    for name, meta in METRIC_METADATA.items():
        db.pre_populate_metric_metadata(name, meta)
    for name, meta in EVENT_METADATA.items():
        db.pre_populate_event_metadata(name, meta)
    logger.info("Metadata pre-population complete.")


def main():
    import argparse
    import time

    parser = argparse.ArgumentParser(description="Seed TowerIQ SQLite DB with synthetic runs/metrics/events")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS, help="Number of runs to generate")
    parser.add_argument("--tiers", type=str, default=DEFAULT_TIERS, help="Tier range, e.g. 5-8")
    parser.add_argument("--min-wave", type=int, default=DEFAULT_MIN_WAVE, help="Minimum wave where survival becomes probabilistic")
    parser.add_argument("--max-wave", type=int, default=DEFAULT_MAX_WAVE, help="Maximum possible wave (very low survival probability)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed for reproducibility")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Number of worker processes (default: CPU count)")
    parser.add_argument("--start-date", type=str, default=DEFAULT_START_DATE, help="Start date: '30d' (30 days ago), '2024-01-01', or '2024-01-01 14:30'")
    parser.add_argument("--end-date", type=str, default=DEFAULT_END_DATE, help="End date: 'now', '2024-12-31', or '2024-12-31 18:00'")
    parser.add_argument("--time-distribution", type=str, default=DEFAULT_TIME_DISTRIBUTION, help="Time distribution: 'uniform', 'afternoon_heavy', 'evening_heavy', 'morning_heavy', or custom weights")
    parser.add_argument("--collect-metrics", action='store_true', default=METRICS_COLLECTION_ENABLED, help="Enable database metrics collection during seeding (default: enabled)")
    parser.add_argument("--no-collect-metrics", dest='collect_metrics', action='store_false', help="Disable database metrics collection during seeding")
    args = parser.parse_args()

    random.seed(args.seed)

    # Parse tier range
    if "-" in args.tiers:
        tmin, tmax = args.tiers.split("-", 1)
        tier_values = list(range(int(tmin), int(tmax) + 1))
    else:
        tier_values = [int(args.tiers)]
    
    # Parse date range
    try:
        start_date = parse_date_string(args.start_date)
        end_date = parse_date_string(args.end_date)
        
        if start_date >= end_date:
            raise ValueError("Start date must be before end date")
            
    except ValueError as e:
        print(f"❌ Date parsing error: {e}")
        return 1
    
    # Parse time distribution
    try:
        time_weights = parse_time_distribution(args.time_distribution)
    except ValueError as e:
        print(f"❌ Time distribution parsing error: {e}")
        return 1

    config = ConfigurationManager('config/main_config.yaml')
    # Preliminary logger; db-aware logging configured after db connection
    logger = structlog.get_logger().bind(source="SeedDB")

    db_path = config.get('database.sqlite_path', 'data/toweriq.sqlite')
    
    # Clean up any existing SQLite auxiliary files before starting
    cleanup_sqlite_auxiliary_files(db_path, logger)

    db = DatabaseService(config=config, logger=logger, db_path=db_path)
    # Minimal logging wiring
    setup_logging(config, db_service=db)
    db.connect()
    
    # Temporarily reduce database logging verbosity during seeding
    import logging
    
    # Get the root logger and set it to INFO level to suppress DEBUG messages
    root_logger = logging.getLogger()
    original_root_level = root_logger.level
    root_logger.setLevel(logging.INFO)
    
    # Also try to get the specific structlog logger
    structlog_logger = logging.getLogger('structlog')
    original_structlog_level = structlog_logger.level
    structlog_logger.setLevel(logging.INFO)

    wipe_tables(db)
    pre_populate_lookup_tables(db, logger)

    # Determine number of workers
    num_workers = args.workers or mp.cpu_count()
    logger.info("Starting multiprocessing", 
                runs=args.runs, 
                workers=num_workers,
                start_date=start_date.strftime("%Y-%m-%d %H:%M:%S"),
                end_date=end_date.strftime("%Y-%m-%d %H:%M:%S"),
                time_distribution=args.time_distribution)
    
    # Prepare arguments for each worker
    worker_args = []
    for i in range(args.runs):
        tier = random.choice(tier_values)
        worker_args.append((tier, args.min_wave, args.max_wave, start_date, end_date, time_weights, i, args.seed))
    
    start_time = time.time()
    
    # Use ProcessPoolExecutor for better error handling and progress tracking
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        # Submit all jobs
        future_to_run = {executor.submit(generate_run_data_worker, args): args[6] for args in worker_args}
        
        completed_runs = 0
        failed_runs = 0
        run_data_list = []
        
        # Process completed jobs as they finish
        for future in as_completed(future_to_run):
            run_index = future_to_run[future]
            try:
                result = future.result()
                if result["success"]:
                    completed_runs += 1
                    run_data_list.append(result["data"])
                    # Only log every N runs to reduce verbosity
                    if completed_runs % PROGRESS_LOG_INTERVAL == 0 or completed_runs == 1:
                        logger.info("Runs generated", completed=completed_runs, total=args.runs)
                else:
                    failed_runs += 1
                    logger.error("Run failed", run_index=run_index, error=result["error"])
            except Exception as e:
                failed_runs += 1
                logger.error("Run exception", run_index=run_index, error=str(e))
    
    # Write all generated data to database using bulk operations for maximum performance
    print(f"\n💾 Writing {len(run_data_list)} runs to database using bulk operations...")
    
    try:
        bulk_write_all_runs_to_db(db, run_data_list, start_date, end_date, logger, args.collect_metrics)
        print("✅ Bulk write completed successfully!")
    except Exception as e:
        logger.error("Failed to bulk write runs to database", error=str(e))
        # Fallback to individual writes if bulk fails
        print("⚠️  Bulk write failed, falling back to individual writes...")
        bar_width = PROGRESS_BAR_WIDTH
        total_runs = len(run_data_list)
        
        for i, run_data in enumerate(run_data_list):
            try:
                write_run_data_to_db(db, run_data)
                
                # Update progress bar
                progress = (i + 1) / total_runs
                filled_width = int(bar_width * progress)
                bar = "█" * filled_width + "░" * (bar_width - filled_width)
                print(f"\r📊 [{bar}] {progress*100:.1f}% ({i+1}/{total_runs})", end="", flush=True)
                
            except Exception as e:
                logger.error("Failed to write run to database", run_index=i, error=str(e))
                failed_runs += 1
                completed_runs -= 1
        
        print()  # New line after progress bar
    
    end_time = time.time()
    duration = end_time - start_time
    
    stats = db.get_database_statistics()
    logger.info("Seeding complete", 
                completed_runs=completed_runs, 
                failed_runs=failed_runs,
                duration_seconds=round(duration, 2),
                table_rows=json.dumps(stats.get('table_rows', {})))
    
    # Properly close database connection
    try:
        db.close()
        logger.info("Database connection closed")
    except Exception as e:
        logger.warning("Error closing database connection", error=str(e))
    
    # Restore original logging levels
    if 'original_root_level' in locals():
        root_logger.setLevel(original_root_level)
    if 'original_structlog_level' in locals():
        structlog_logger.setLevel(original_structlog_level)
    logger.info("Restored original logging levels")
    
    # Clean up any SQLite auxiliary files that may have been created
    cleanup_sqlite_auxiliary_files(db_path, logger)
    
    # Print comprehensive summary
    print("\n" + "="*80)
    print("🎯 TOWERIQ DATABASE SEEDING SUMMARY")
    print("="*80)
    print(f"📊 Total Runs Generated: {completed_runs}")
    print(f"❌ Failed Runs: {failed_runs}")
    print(f"⏱️  Total Duration: {duration:.2f} seconds ({duration/60:.1f} minutes)")
    print(f"🏃 Runs per Second: {completed_runs/duration:.2f}")
    print(f"⚙️  Workers Used: {num_workers}")
    print(f"🎲 Random Seed: {args.seed}")
    print(f"🌊 Wave Range: {args.min_wave}-{args.max_wave}")
    print(f"🏆 Tier Range: {args.tiers}")
    print(f"📅 Date Range: {start_date.strftime('%Y-%m-%d %H:%M')} to {end_date.strftime('%Y-%m-%d %H:%M')}")
    print(f"⏰ Time Distribution: {args.time_distribution}")
    print(f"📈 Database Metrics Collection: {'Enabled' if args.collect_metrics else 'Disabled'}")
    
    if stats.get('table_rows'):
        print("\n📋 Database Statistics:")
        for table, count in stats['table_rows'].items():
            print(f"   • {table}: {count:,} rows")
    
    # Show metrics collection info if enabled
    if args.collect_metrics and db.sqlite_conn:
        try:
            # Count db_metrics entries to show how many metrics were collected
            metrics_count = db.sqlite_conn.execute("SELECT COUNT(*) FROM db_metrics").fetchone()[0]
            unique_timestamps = db.sqlite_conn.execute("SELECT COUNT(DISTINCT timestamp) FROM db_metrics").fetchone()[0]
            print("\n📈 Database Metrics Collected:")
            print(f"   • Total Metrics: {metrics_count:,}")
            print(f"   • Collection Points: {unique_timestamps:,}")
            
            # Show date range of metrics
            if metrics_count > 0:
                first_metric = db.sqlite_conn.execute("SELECT MIN(timestamp) FROM db_metrics").fetchone()[0]
                last_metric = db.sqlite_conn.execute("SELECT MAX(timestamp) FROM db_metrics").fetchone()[0]
                first_date = datetime.fromtimestamp(first_metric).strftime('%Y-%m-%d %H:%M')
                last_date = datetime.fromtimestamp(last_metric).strftime('%Y-%m-%d %H:%M')
                print(f"   • Metrics Range: {first_date} to {last_date}")
        except Exception as e:
            logger.warning("Failed to get metrics statistics", error=str(e))
    
    print(f"\n💾 Database Path: {db_path}")
    print(f"🗂️  Generated Files: {len(run_data_list)} run data packages")
    
    # Calculate some derived stats from the generated data
    if run_data_list:
        total_events = sum(len(run['events']) for run in run_data_list)
        total_metrics = sum(len(run['metrics']) for run in run_data_list)
        avg_wave = sum(run['final_wave'] for run in run_data_list) / len(run_data_list)
        max_wave = max(run['final_wave'] for run in run_data_list)
        min_wave = min(run['final_wave'] for run in run_data_list)
        
        print("\n🎮 Game Data Generated:")
        print(f"   • Total Events: {total_events:,}")
        print(f"   • Total Metrics: {total_metrics:,}")
        print(f"   • Average Final Wave: {avg_wave:.1f}")
        print(f"   • Highest Wave Reached: {max_wave}")
        print(f"   • Lowest Final Wave: {min_wave}")
        
        # Tier breakdown
        tier_counts = {}
        for run in run_data_list:
            tier = run['tier']
            tier_counts[tier] = tier_counts.get(tier, 0) + 1
        
        print("\n🏆 Tier Distribution:")
        for tier in sorted(tier_counts.keys()):
            count = tier_counts[tier]
            percentage = (count / len(run_data_list)) * 100
            print(f"   • Tier {tier}: {count} runs ({percentage:.1f}%)")
    
    print("="*80)
    print("✅ Seeding process completed successfully!")
    print("="*80 + "\n")


if __name__ == "__main__":
    # Required for multiprocessing on Windows
    mp.freeze_support()
    main()


