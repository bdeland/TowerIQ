# TowerIQ Database Structure Analysis

## Overview
This document provides a comprehensive analysis of the TowerIQ database structure for external analysis.

## Database Statistics
- **Database File Size**: 180.0 KB (184,320 bytes)
- **Schema Version**: 1.0 (Database V1.0 with normalized schema and integer storage)
- **Total Tables**: 12
- **Total Records**: 1,013
- **Total Runs**: 5
- **Total Metrics**: 165
- **Total Events**: 16
- **Total Logs**: 0
- **Total Settings**: 1
- **Total Dashboards**: 0
- **Total DB Metrics**: 783 (database health monitoring data)
- **Total Event Names**: 7 (lookup table)
- **Total Metric Names**: 15 (lookup table)
- **Total DB Metric Names**: 7 (lookup table)
- **Total DB Monitored Objects**: 12 (lookup table)
- **Total Game Versions**: 1 (lookup table)

## Table Structure

### 1. `runs` Table
**Purpose**: Stores game run sessions and their summary statistics
**Primary Key**: `run_id` (BLOB)

| Column | Type | Description |
|--------|------|-------------|
| run_id | BLOB | Unique identifier for each run (UUID stored as binary) |
| start_time | INTEGER | Start timestamp (milliseconds since epoch) |
| end_time | INTEGER | End timestamp (nullable) |
| duration_realtime | INTEGER | Real-time duration (milliseconds) |
| duration_gametime | INTEGER | In-game time duration (scaled by 1000) |
| final_wave | INTEGER | Last wave reached |
| round_coins | INTEGER | Total coins earned in the run |
| CPH | INTEGER | Coins per hour (scaled by 1000) |
| round_cells | INTEGER | Round cells value (scaled by 1000) |
| round_gems | INTEGER | Round gems value (scaled by 1000) |
| round_cash | INTEGER | Round cash value (scaled by 1000) |
| tier | INTEGER | Game tier |
| game_version_id | INTEGER | Foreign key to game_versions table |

### 2. `metrics` Table
**Purpose**: Stores detailed metrics collected during runs
**Primary Key**: `id` (INTEGER AUTOINCREMENT)
**Foreign Key**: `run_id` → `runs.run_id`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| run_id | BLOB | References runs.run_id |
| real_timestamp | INTEGER | Real-world timestamp (milliseconds since epoch) |
| game_duration | INTEGER | In-game duration when metric was recorded (milliseconds) |
| current_wave | INTEGER | Wave number when metric was recorded |
| metric_name_id | INTEGER | Foreign key to metric_names table |
| metric_value | INTEGER | Metric value as raw integer |

**Indexes**:
- `idx_metrics_run_id_name_time` on (run_id, metric_name_id, real_timestamp)

### 3. `events` Table
**Purpose**: Stores game events that occur during runs
**Primary Key**: `id` (INTEGER AUTOINCREMENT)
**Foreign Key**: `run_id` → `runs.run_id`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| run_id | BLOB | References runs.run_id |
| timestamp | INTEGER | Event timestamp (milliseconds since epoch) |
| event_name_id | INTEGER | Foreign key to event_names table |
| data | TEXT | Additional event data (JSON) |

**Indexes**:
- `idx_events_run_id_time` on (run_id, timestamp)

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
| display_name | TEXT | Human-readable display name |
| description | TEXT | Description of the metric |
| unit | TEXT | Unit of measurement |

### 10. `game_versions` Table
**Purpose**: Lookup table for game version normalization
**Primary Key**: `id` (INTEGER AUTOINCREMENT)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| version_text | TEXT | Game version string (unique) |

### 11. `db_metric_names` Table
**Purpose**: Lookup table for database metric names
**Primary Key**: `id` (INTEGER AUTOINCREMENT)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| name | TEXT | Database metric name (unique) |
| description | TEXT | Description of the database metric |

### 12. `db_monitored_objects` Table
**Purpose**: Lookup table for database objects being monitored
**Primary Key**: `id` (INTEGER AUTOINCREMENT)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| name | TEXT | Object name (table or index) |
| type | TEXT | Object type ('TABLE' or 'INDEX') |

### 13. Enhanced `db_metrics` Table
**Purpose**: Database health monitoring and performance metrics
**Primary Key**: `id` (INTEGER AUTOINCREMENT)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-incrementing primary key |
| timestamp | INTEGER | Unix timestamp when metric was collected |
| metric_id | INTEGER | Foreign key to db_metric_names table |
| object_id | INTEGER | Foreign key to db_monitored_objects table (nullable) |
| value | INTEGER | Numeric value of the metric |

**Indexes**:
- `idx_db_metrics_time_metric` on (timestamp, metric_id)


## Data Relationships

```
runs (1) ←→ (many) metrics
runs (1) ←→ (many) events
runs (1) ←→ (1) game_versions
metrics (many) ←→ (1) metric_names
events (many) ←→ (1) event_names
db_metrics (many) ←→ (1) db_metric_names
db_metrics (many) ←→ (1) db_monitored_objects (nullable)
```

## Key Observations

1. **Moderate Data Volume**: The metrics table contains 165 records from 5 game runs, representing a typical development/testing dataset.

2. **Enhanced Database Health Monitoring**: The `db_metrics` table (V1.0 schema) provides comprehensive database performance and health monitoring with 783 metrics collected using normalized lookup tables.

3. **Full Data Normalization**: All string-based identifiers now use foreign keys to lookup tables (`metric_names`, `event_names`, `game_versions`, `db_metric_names`, `db_monitored_objects`) for optimal storage efficiency and data consistency.

4. **Integer-based Storage**: All numeric values use INTEGER storage for optimal performance and storage efficiency. No scaling factors are applied - values are stored as raw integers.

5. **UUID Binary Storage**: Run IDs are stored as BLOB (binary) format for UUIDs, providing efficient storage and indexing.

6. **Time-based Data**: All tables use INTEGER timestamps in Unix millisecond format for efficient storage and querying.

7. **Flexible Configuration**: The settings table supports various data types and categories for flexible configuration management.

8. **Dashboard System**: The dashboards table is set up for a dashboard management system but currently contains no data.

9. **Event Tracking**: The events table captures game events with flexible JSON data storage and normalized event names.

10. **Schema Evolution**: Database has evolved to V1.0 with complete rewrite featuring normalized lookup tables, BLOB UUID storage, and optimized integer-based data types.

11. **Comprehensive Metadata**: All lookup tables now include rich metadata (display names, descriptions, units) for better data understanding and presentation.

## Files Generated for Analysis

1. `database_schema.sql` - Complete SQL schema
2. `database_full_dump.sql` - Complete database dump with data
3. `database_structure_analysis.md` - This analysis document

## Data Summary with Examples

### Current Database Statistics (Updated)
- **Total Runs**: 5
- **Total Metrics**: 165
- **Total Events**: 16
- **Total Logs**: 0
- **Total Settings**: 1
- **Total Dashboards**: 0
- **Total DB Metrics**: 783
- **Total Event Names**: 7
- **Total Metric Names**: 15
- **Total DB Metric Names**: 7
- **Total DB Monitored Objects**: 12
- **Total Game Versions**: 1

### Sample Data Examples

#### 1. `runs` Table (5 rows)
**Sample Records:**
```json
{
  "run_id": "b3bf970c-b840-466b-87ca-aa9c8d21ff0e",
  "start_time": 1755170235000,
  "end_time": 1755195225000,
  "duration_realtime": 24990000,
  "duration_gametime": 24990000,
  "final_wave": 833,
  "coins_earned": 163769743246,
  "CPH": 24565461486932,
  "round_cells": 2088997184,
  "round_gems": 3077000,
  "round_cash": 47500,
  "tier": 10,
  "game_version_id": 1
}
```
**Note**: All numeric values are stored as raw integers without scaling factors. Duration values are in milliseconds.

#### 2. `metrics` Table (165 rows)
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
  "game_timestamp": 30000,
  "current_wave": 1,
  "metric_name_id": 3,
  "metric_value": 28401798583
}
```
**Note**: `metric_name_id` references the `metric_names` table, and `metric_value` is stored as raw integer.

#### 3. `events` Table (16 rows)
**Event Types Found:**
- `startNewRound`, `gemBlockTapped`, `adGemClaimed`
- `gameSpeedChanged`, `gamePaused`, `gameResumed`, `gameOver`

**Sample Records:**
```json
{
  "id": 322344,
  "run_id": "b3bf970c-b840-466b-87ca-aa9c8d21ff0e",
  "timestamp": 1755170235000,
  "event_name_id": 1,
  "data": "{\"tier\": 10}"
}
```
**Note**: `event_name_id` references the `event_names` table for normalized event names.

#### 4. `settings` Table (1 row)
**Structure Ready:** Table contains application configuration settings.

#### 5. Enhanced `db_metrics` Table (783 rows)
**Purpose:** Database health monitoring metrics collected automatically using normalized structure
**Sample Metric Types:**
- `table_size_bytes` - Size of each table in bytes
- `record_count` - Number of records per table
- `database_size` - Total database size
- `total_pages` - Database page count
- `free_pages` - Free page count

**Sample Records:**
```json
{
  "id": 1234,
  "timestamp": 1755170235000,
  "metric_id": 1,
  "object_id": 5,
  "value": 111943680
}
```
**Note**: Uses foreign keys to `db_metric_names` and `db_monitored_objects` for normalized storage.

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

#### 10. `game_versions` Table (1 row)
**Purpose:** Lookup table for game version normalization
**Sample Data:**
```json
{
  "id": 1,
  "version_text": "27.0.4"
}
```

#### 11. `db_metric_names` Table (7 rows)
**Purpose:** Lookup table for database metric names
**Sample Metric Names:**
- `table_size_bytes`, `record_count`, `database_size`
- `total_pages`, `free_pages`, `index_count`

#### 12. `db_monitored_objects` Table (12 rows)
**Purpose:** Lookup table for database objects being monitored
**Sample Objects:**
- Tables: `runs`, `metrics`, `events`, `settings`, etc.
- Indexes: `idx_metrics_run_id_name_time`, `idx_events_run_id_time`, etc.


## Recommendations for Analysis

1. **Game Performance Analysis**: Focus on the `metrics` table (1.2M+ records) for detailed gameplay performance analysis. Use JOIN operations with `metric_names` for human-readable metric names.

2. **Enhanced Database Health Monitoring**: Use the normalized `db_metrics` table with `db_metric_names` and `db_monitored_objects` for comprehensive database performance trends, table growth, and optimization insights.

3. **Normalized Data Access**: Leverage all lookup tables (`event_names`, `metric_names`, `game_versions`, `db_metric_names`, `db_monitored_objects`) for efficient queries and consistent naming.

4. **Run-Based Analysis**: Examine relationships between `runs`, `metrics`, and `events` tables for comprehensive game session analysis. Use foreign key relationships for optimal query performance.

5. **Event Pattern Analysis**: Check the `events` table with `event_names` lookup for gameplay event patterns and user behavior insights.

6. **Time-Series Analysis**: All tables use Unix millisecond timestamps - ideal for time-series analysis and Grafana dashboards.

7. **Schema Evolution**: Database V1.0 provides enhanced monitoring capabilities with full normalization - consider leveraging these for operational insights.

8. **Data Structure Optimization**: The normalized structure with lookup tables and proper indexing provides optimal query performance even as data volume scales.

9. **Data Type Handling**: All numeric values are stored as raw integers without scaling factors. Duration values are in milliseconds, currency values are raw integers.

10. **UUID Handling**: Run IDs are stored as BLOB format - use appropriate UUID handling when working with these identifiers.

11. **Metadata Utilization**: Take advantage of rich metadata in lookup tables (display names, descriptions, units) for better data presentation and understanding.

12. **Foreign Key Relationships**: Use the normalized structure to ensure data consistency and leverage SQLite's foreign key constraints for data integrity.
