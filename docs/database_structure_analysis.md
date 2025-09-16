# TowerIQ Database Structure Analysis

## Overview
This document provides a comprehensive analysis of the TowerIQ database structure for external analysis.

## Database Statistics
- **Database File Size**: 746.2 MB (782,417,920 bytes)
- **Total Runs**: 300
- **Total Metrics**: 3,670,935
- **Total Events**: 193,561
- **Total Logs**: 0
- **Total Settings**: 9
- **Total Dashboards**: 0
- **Total MOCK_DATA**: 1,000 (test data)

## Table Structure

### 1. `runs` Table
**Purpose**: Stores game run sessions and their summary statistics
**Primary Key**: `run_id` (TEXT)

| Column | Type | Description |
|--------|------|-------------|
| run_id | TEXT | Unique identifier for each run |
| start_time | INTEGER | Start timestamp |
| end_time | INTEGER | End timestamp (nullable) |
| duration_realtime | INTEGER | Real-time duration |
| duration_gametime | REAL | In-game time duration |
| final_wave | INTEGER | Last wave reached |
| coins_earned | REAL | Total coins earned |
| CPH | REAL | Coins per hour |
| round_cells | REAL | Round cells value |
| round_gems | REAL | Round gems value |
| round_cash | REAL | Round cash value |
| game_version | TEXT | Game version |
| tier | INTEGER | Game tier |

### 2. `metrics` Table
**Purpose**: Stores detailed metrics collected during runs
**Primary Key**: `id` (INTEGER AUTOINCREMENT)
**Foreign Key**: `run_id` → `runs.run_id`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| run_id | TEXT | References runs.run_id |
| real_timestamp | INTEGER | Real-world timestamp |
| game_timestamp | REAL | In-game timestamp |
| current_wave | INTEGER | Wave number when metric was recorded |
| metric_name | TEXT | Name of the metric |
| metric_value | REAL | Value of the metric |

**Indexes**:
- `idx_metrics_run_name_time` on (run_id, metric_name, real_timestamp)
- `idx_metrics_run_id` on (run_id)

### 3. `events` Table
**Purpose**: Stores game events that occur during runs
**Primary Key**: `id` (INTEGER AUTOINCREMENT)
**Foreign Key**: `run_id` → `runs.run_id`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| run_id | TEXT | References runs.run_id |
| timestamp | INTEGER | Event timestamp |
| event_name | TEXT | Name of the event |
| data | TEXT | Additional event data (JSON) |

### 4. `logs` Table
**Purpose**: Application logging data
**Primary Key**: None (no primary key defined)

| Column | Type | Description |
|--------|------|-------------|
| timestamp | INTEGER | Log timestamp |
| level | TEXT | Log level (DEBUG, INFO, WARN, ERROR) |
| source | TEXT | Source component |
| event | TEXT | Event description |
| data | TEXT | Additional log data |

### 5. `settings` Table
**Purpose**: Application configuration settings
**Primary Key**: `id` (INTEGER AUTOINCREMENT)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| key | TEXT | Setting key (unique) |
| value | TEXT | Setting value |
| value_type | TEXT | Data type (default: 'string') |
| description | TEXT | Setting description |
| category | TEXT | Setting category (default: 'general') |
| is_sensitive | BOOLEAN | Whether setting contains sensitive data |
| created_at | TEXT | Creation timestamp |
| updated_at | TEXT | Last update timestamp |
| created_by | TEXT | Creator (default: 'system') |
| version | INTEGER | Setting version (default: 1) |

**Indexes**:
- `idx_settings_key` on (key)
- `idx_settings_category` on (category)

### 6. `dashboards` Table
**Purpose**: Dashboard configurations
**Primary Key**: `id` (TEXT)

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | Dashboard ID |
| uid | TEXT | Unique identifier |
| title | TEXT | Dashboard title |
| description | TEXT | Dashboard description |
| config | TEXT | Dashboard configuration (JSON) |
| tags | TEXT | Dashboard tags |
| created_at | TEXT | Creation timestamp |
| updated_at | TEXT | Last update timestamp |
| created_by | TEXT | Creator (default: 'system') |
| is_default | BOOLEAN | Whether this is the default dashboard |
| schema_version | INTEGER | Schema version (default: 1) |

**Indexes**:
- `idx_dashboards_uid` on (uid)
- `idx_dashboards_title` on (title)
- `idx_dashboards_created_at` on (created_at)

### 7. `MOCK_DATA` Table
**Purpose**: Test/development data
**Primary Key**: None

| Column | Type | Description |
|--------|------|-------------|
| time | DATE | Timestamp |
| value1 | DECIMAL(7,3) | Numeric value 1 |
| value2 | DECIMAL(6,2) | Numeric value 2 |
| value3 | VARCHAR(50) | String value |

## Data Relationships

```
runs (1) ←→ (many) metrics
runs (1) ←→ (many) events
```

## Key Observations

1. **High Volume Data**: The metrics table contains over 600K records, indicating detailed data collection during gameplay.

2. **Time-based Data**: Most tables use INTEGER timestamps, suggesting Unix timestamp format.

3. **Flexible Configuration**: The settings table supports various data types and categories for flexible configuration management.

4. **Dashboard System**: The dashboards table is set up for a dashboard management system but currently contains no data.

5. **Event Tracking**: The events table captures game events with flexible JSON data storage.

## Files Generated for Analysis

1. `database_schema.sql` - Complete SQL schema
2. `database_full_dump.sql` - Complete database dump with data
3. `database_structure_analysis.md` - This analysis document

## Data Summary with Examples

### Current Database Statistics (Updated)
- **Total Runs**: 300
- **Total Metrics**: 3,670,935
- **Total Events**: 193,561
- **Total Logs**: 0
- **Total Settings**: 9
- **Total Dashboards**: 0
- **Total MOCK_DATA**: 1,000 (test data)

### Sample Data Examples

#### 1. `runs` Table (300 rows)
**Sample Records:**
```json
{
  "run_id": "b3bf970c-b840-466b-87ca-aa9c8d21ff0e",
  "start_time": 1755170235000,
  "end_time": 1755195225000,
  "duration_realtime": 24,
  "duration_gametime": 24990.0,
  "final_wave": 833,
  "coins_earned": 163769743246.21985,
  "CPH": 24565461486932.977,
  "round_cells": 2088997.1844397758,
  "round_gems": 3077.0,
  "round_cash": 47.50000000000023,
  "game_version": "27.0.4",
  "tier": 10
}
```

#### 2. `metrics` Table (3,670,935 rows)
**Metric Types Found:**
- `cash`, `cells`, `coins`, `gems`
- `round_cash`, `round_cells`, `round_coins`, `round_gems_from_ads_count`
- `round_gems_from_ads_value`, `round_gems_from_blocks_count`

**Sample Records:**
```json
{
  "id": 5369266,
  "run_id": "b3bf970c-b840-466b-87ca-aa9c8d21ff0e",
  "real_timestamp": 1755170265000,
  "game_timestamp": 30.0,
  "current_wave": 1,
  "metric_name": "round_coins",
  "metric_value": 28401798.583818313
}
```

#### 3. `events` Table (193,561 rows)
**Event Types Found:**
- `startNewRound`, `gemBlockTapped`, `adGemClaimed`
- `gameSpeedChanged`, `gamePaused`, `gameResumed`, `gameOver`

**Sample Records:**
```json
{
  "id": 322344,
  "run_id": "b3bf970c-b840-466b-87ca-aa9c8d21ff0e",
  "timestamp": 1755170235000,
  "event_name": "startNewRound",
  "data": "{\"tier\": 10}"
}
```

#### 4. `settings` Table (9 rows)
**Sample Records:**
```json
{
  "id": 1,
  "key": "db_version",
  "value": "3",
  "value_type": "string",
  "description": null,
  "category": "general",
  "is_sensitive": 0,
  "created_at": "2025-07-23 11:50:35",
  "updated_at": "2025-07-23 11:50:35",
  "created_by": "system",
  "version": 1
}
```

#### 5. `MOCK_DATA` Table (1,000 rows - Test Data)
**Sample Records:**
```json
{
  "time": 1754991307000,
  "value1": 867.103,
  "value2": 50.5,
  "value3": "1"
}
```

#### 6. `dashboards` Table (0 rows)
**Structure Ready:** Table exists but contains no data yet.

#### 7. `logs` Table (0 rows)
**Structure Ready:** Table exists but contains no data yet.

## Recommendations for Analysis

1. Focus on the `metrics` table for performance analysis - it contains the most data
2. Examine the relationship between `runs` and `metrics` for run-based analysis
3. Check the `events` table for game event patterns
4. Review `settings` table for configuration analysis
5. The `MOCK_DATA` table appears to be for testing and can likely be ignored
