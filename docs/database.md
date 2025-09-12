### TowerIQ Database Overview (SQLite)

- **File**: `data/toweriq.sqlite`
- **Engine**: SQLite
- **Primary purpose**: Persist app configuration, dashboards, lightweight logs/events, and mock time-series used for chart demos.
- **Tables**: `settings`, `dashboards`, `logs`, `MOCK_DATA`
- **Foreign keys**: none declared

This document describes the current schema, data conventions, helpful queries, and examples to give agents enough context for data visualization work.

## settings

- **Purpose**: Central key–value store for user/system settings with metadata and audit fields
- **Common fields**:
  - `id` INTEGER PRIMARY KEY
  - `key` TEXT NOT NULL
  - `value` TEXT NOT NULL
  - `value_type` TEXT NOT NULL DEFAULT `'string'` (e.g., `string`, `json`)
  - `description` TEXT
  - `category` TEXT DEFAULT `'general'`
  - `is_sensitive` BOOLEAN DEFAULT 0
  - `created_at` TEXT DEFAULT `datetime('now','localtime')`
  - `updated_at` TEXT DEFAULT `datetime('now','localtime')`
  - `created_by` TEXT DEFAULT `'system'`
  - `version` INTEGER DEFAULT 1
- **Indexes**:
  - `idx_settings_category` on `(category)`
  - `idx_settings_key` on `(key)`
  - Unique composite on `(key, category)`
- **Notes**:
  - JSON values are stored as TEXT; callers should parse/serialize
  - Booleans are stored as `0/1`
- **Example rows**:
```json
{"key": "db_version", "value": "3", "value_type": "string", "category": "general"}
{"key": "gui.theme", "value": "dark", "value_type": "string", "category": "gui"}
{"key": "logging.categories", "value": "{\"ui\": true, \"backend\": true, \"system\": false}", "value_type": "json", "category": "logging"}
```
- **Useful queries**:
```sql
-- Read a specific setting
SELECT value, value_type FROM settings WHERE key='gui.theme' AND category='gui';

-- List all GUI settings
SELECT key, value, value_type FROM settings WHERE category='gui' ORDER BY key;
```

## dashboards

- **Purpose**: Stores saved dashboards (Grafana-like) as JSON, with descriptive metadata
- **Common fields**:
  - `id` TEXT PRIMARY KEY            (internal identifier)
  - `uid` TEXT NOT NULL             (stable external identifier)
  - `title` TEXT NOT NULL
  - `description` TEXT
  - `config` TEXT NOT NULL          (JSON string)
  - `tags` TEXT                     (JSON array string)
  - `created_at` TEXT DEFAULT `datetime('now','localtime')`
  - `updated_at` TEXT DEFAULT `datetime('now','localtime')`
  - `created_by` TEXT DEFAULT `'system'`
  - `is_default` BOOLEAN DEFAULT 0
  - `schema_version` INTEGER DEFAULT 1
- **Indexes**:
  - `idx_dashboards_created_at` on `(created_at)`
  - `idx_dashboards_title` on `(title)`
  - `idx_dashboards_uid` on `(uid)`
  - Unique on `(uid)` in addition to the primary key
- **Notes**:
  - `config` contains dashboard JSON including time ranges (e.g., `{ "time": { "from": "now-6h", "to": "now" } }`)
  - `tags` is a JSON array string (e.g., `["system","health"]`)
- **Example rows (abridged)**:
```json
{
  "id": "system-overview",
  "uid": "system-overview-001",
  "title": "System Overview",
  "tags": "[\"system\",\"health\"]",
  "is_default": 1,
  "schema_version": 1
}
{
  "id": "performance-analytics",
  "uid": "performance-analytics-001",
  "title": "Performance Analytics",
  "tags": "[\"performance\",\"metrics\"]",
  "is_default": 0
}
```
- **Useful queries**:
```sql
-- Retrieve the default dashboard
SELECT id, title, config FROM dashboards WHERE is_default=1 LIMIT 1;

-- Search dashboards by title
SELECT id, uid, title FROM dashboards WHERE title LIKE '%Overview%' ORDER BY updated_at DESC;
```

## logs

- **Purpose**: Lightweight application logs/events (useful for simple telemetry and UI event streams)
- **Common fields**:
  - `timestamp` INTEGER  (epoch milliseconds)
  - `level` TEXT         (e.g., `INFO`, `WARN`, `ERROR`)
  - `source` TEXT        (component/source)
  - `event` TEXT         (event name)
  - `data` TEXT          (JSON payload string)
- **Notes**:
  - Table has no explicit primary key; order by `timestamp` for recency
  - `data` should be parsed as JSON in application code
- **Example rows (abridged)**:
```json
{"timestamp": 1757282216694, "level": "INFO", "source": "game", "event": "startNewRound", "data": "{\"round\": 42, \"tier\": 1}"}
{"timestamp": 1757282216684, "level": "INFO", "source": "game", "event": "gameSpeedChanged", "data": "{\"value\": 1.5}"}
```
- **Useful queries**:
```sql
-- Recent logs
SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100;

-- Errors only
SELECT timestamp, source, event, data FROM logs WHERE level='ERROR' ORDER BY timestamp DESC;
```

## MOCK_DATA

- **Purpose**: Synthetic time-series used for charts/demos
- **Common fields**:
  - `time` DATE             (often stored as epoch ms)
  - `value1` DECIMAL(7,3)
  - `value2` DECIMAL(6,2)
  - `value3` VARCHAR(50)
- **Example rows**:
```json
{"time": 1754991307000, "value1": 867.103, "value2": 50.50, "value3": "1"}
{"time": 1755704516000, "value1": 756.129, "value2": 50.07, "value3": "1"}
```
- **Useful queries**:
```sql
-- First 100 points ordered by time
SELECT time, value1, value2 FROM MOCK_DATA ORDER BY time LIMIT 100;
```

## Data conventions

- **Timestamps**: Stored as INTEGER epoch ms in `logs`; audit fields in other tables are stored as TEXT (`datetime('now','localtime')`).
- **Booleans**: Stored as integers `0/1`.
- **JSON**: Stored as TEXT. Parse/serialize in the application. Consider JSON path indexes if query performance becomes critical.
- **Versioning**: `settings.version` and `dashboards.schema_version` facilitate schema/content evolution.

## Handy snippets for agents

```sql
-- Current DB version
SELECT value FROM settings WHERE key='db_version' AND category='general';

-- All settings (non-sensitive) useful for UI
SELECT key, value, value_type, category FROM settings WHERE IFNULL(is_sensitive, 0) = 0 ORDER BY category, key;

-- Dashboard IDs and titles
SELECT id, uid, title, is_default FROM dashboards ORDER BY is_default DESC, updated_at DESC;

-- Aggregate logs by level (last 24h)
SELECT level, COUNT(*) AS cnt
FROM logs
WHERE timestamp >= (strftime('%s','now') * 1000) - (24*60*60*1000)
GROUP BY level
ORDER BY cnt DESC;
```

## Notes for visualization work

- `dashboards.config` is the primary source for panel/widget definitions and time ranges.
- `MOCK_DATA` provides easy-to-consume time-series for ECharts/Grafana-style panels.
- `logs` can back live event streams or simple counters (with grouping by `level`, `source`, or `event`).
- `settings` should drive user-visible toggles (e.g., theme) and backend feature flags.


