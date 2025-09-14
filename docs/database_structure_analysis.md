# TowerIQ Database Structure Analysis

## Overview
This document provides a comprehensive analysis of the TowerIQ database structure for external analysis.

## Database Statistics
- **Total Runs**: 50
- **Total Metrics**: 611,835
- **Total Events**: 32,104
- **Total Logs**: 0
- **Total Settings**: 9
- **Total Dashboards**: 0

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

## Recommendations for Analysis

1. Focus on the `metrics` table for performance analysis - it contains the most data
2. Examine the relationship between `runs` and `metrics` for run-based analysis
3. Check the `events` table for game event patterns
4. Review `settings` table for configuration analysis
5. The `MOCK_DATA` table appears to be for testing and can likely be ignored
