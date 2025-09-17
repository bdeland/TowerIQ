# TowerIQ Database Structure Analysis

## Overview
This document provides a comprehensive analysis of the TowerIQ database structure for external analysis.

## Database Statistics
- **Database File Size**: 85.3 MB (89,497,600 bytes)
- **Schema Version**: 24 (Database V5 with db_metrics table)
- **Total Runs**: 100
- **Total Metrics**: 1,222,005
- **Total Events**: 64,417
- **Total Logs**: 0
- **Total Settings**: 0
- **Total Dashboards**: 0
- **Total DB Metrics**: 2,275 (database health monitoring data)
- **Total Event Names**: 7 (lookup table)
- **Total Metric Names**: 15 (lookup table)

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

### 7. `db_metrics` Table
**Purpose**: Database health monitoring and performance metrics
**Primary Key**: `id` (INTEGER AUTOINCREMENT)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| timestamp | INTEGER | Unix timestamp when metric was collected |
| metric_name | TEXT | Name of the metric (e.g., 'table_size_bytes', 'record_count') |
| metric_value | REAL | Numeric value of the metric |
| table_name | TEXT | Table name for table-specific metrics (nullable) |
| index_name | TEXT | Index name for index-specific metrics (nullable) |

**Indexes**:
- `idx_db_metrics_timestamp` on (timestamp)
- `idx_db_metrics_metric_name` on (metric_name)

### 8. `event_names` Table
**Purpose**: Lookup table for event name normalization
**Primary Key**: `id` (INTEGER AUTOINCREMENT)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| name | TEXT | Event name (unique) |

### 9. `metric_names` Table
**Purpose**: Lookup table for metric name normalization
**Primary Key**: `id` (INTEGER AUTOINCREMENT)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| name | TEXT | Metric name (unique) |


## Data Relationships

```
runs (1) ←→ (many) metrics
runs (1) ←→ (many) events
```

## Key Observations

1. **High Volume Data**: The metrics table contains over 1.2M records, indicating detailed data collection during gameplay.

2. **Database Health Monitoring**: New `db_metrics` table (V5 schema) provides comprehensive database performance and health monitoring with 2,275+ metrics collected.

3. **Normalized Lookup Tables**: `event_names` and `metric_names` tables provide data normalization for better storage efficiency and consistency.

4. **Time-based Data**: Most tables use INTEGER timestamps in Unix timestamp format for efficient storage and querying.

5. **Flexible Configuration**: The settings table supports various data types and categories for flexible configuration management.

6. **Dashboard System**: The dashboards table is set up for a dashboard management system but currently contains no data.

7. **Event Tracking**: The events table captures game events with flexible JSON data storage.

8. **Schema Evolution**: Database has evolved to V5 with significant improvements in monitoring and data normalization.

## Files Generated for Analysis

1. `database_schema.sql` - Complete SQL schema
2. `database_full_dump.sql` - Complete database dump with data
3. `database_structure_analysis.md` - This analysis document

## Data Summary with Examples

### Current Database Statistics (Updated)
- **Total Runs**: 100
- **Total Metrics**: 1,222,005
- **Total Events**: 64,417
- **Total Logs**: 0
- **Total Settings**: 0
- **Total Dashboards**: 0
- **Total DB Metrics**: 2,275
- **Total Event Names**: 7
- **Total Metric Names**: 15

### Sample Data Examples

#### 1. `runs` Table (100 rows)
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

#### 2. `metrics` Table (1,222,005 rows)
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

#### 3. `events` Table (64,417 rows)
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

#### 4. `settings` Table (0 rows)
**Structure Ready:** Table exists but contains no data currently.

#### 5. `db_metrics` Table (2,275 rows)
**Purpose:** Database health monitoring metrics collected automatically
**Sample Metric Types:**
- `table_size_bytes` - Size of each table in bytes
- `record_count` - Number of records per table
- `database_size` - Total database size
- `total_pages` - Database page count
- `free_pages` - Free page count

#### 6. `event_names` Table (7 rows)
**Purpose:** Lookup table for event name normalization
**Sample Event Names:**
- `startNewRound`, `gemBlockTapped`, `adGemClaimed`
- `gameSpeedChanged`, `gamePaused`, `gameResumed`, `gameOver`

#### 7. `metric_names` Table (15 rows)
**Purpose:** Lookup table for metric name normalization
**Sample Metric Names:**
- `cash`, `cells`, `coins`, `gems`
- `round_cash`, `round_cells`, `round_coins`
- `round_gems_from_ads_count`, `round_gems_from_blocks_count`

#### 8. `dashboards` Table (0 rows)
**Structure Ready:** Table exists but contains no data yet.

#### 9. `logs` Table (0 rows)
**Structure Ready:** Table exists but contains no data yet.


## Recommendations for Analysis

1. **Game Performance Analysis**: Focus on the `metrics` table (1.2M+ records) for detailed gameplay performance analysis
2. **Database Health Monitoring**: Use the `db_metrics` table for database performance trends, table growth, and optimization insights
3. **Normalized Data Access**: Leverage `event_names` and `metric_names` lookup tables for efficient queries and consistent naming
4. **Run-Based Analysis**: Examine relationships between `runs`, `metrics`, and `events` tables for comprehensive game session analysis
5. **Event Pattern Analysis**: Check the `events` table for gameplay event patterns and user behavior insights
6. **Time-Series Analysis**: All tables use Unix timestamps - ideal for time-series analysis and Grafana dashboards
7. **Schema Evolution**: Database V5 provides enhanced monitoring capabilities - consider leveraging these for operational insights
8. **Data Volume Considerations**: With 1.2M+ metrics records, consider indexing strategies for optimal query performance
