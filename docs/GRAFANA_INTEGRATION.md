# Grafana Integration for TowerIQ

## Overview

TowerIQ now supports exposing its SQLite database to Grafana for creating custom dashboards. This feature allows you to write SQL queries in Grafana and visualize your game analytics data on any device on your local network.

## Features Implemented

### Backend

1. **Grafana Router** (`src/tower_iq/api/routers/grafana.py`)
   - `POST /api/grafana/query` - Execute read-only SQL queries
   - `GET /api/grafana/schema` - Get database schema (tables and columns)
   - `GET /api/grafana/test` - Test endpoint connectivity
2. **Settings Endpoints** (`src/tower_iq/api/routers/database.py`)

   - `GET /api/settings/grafana` - Get Grafana settings
   - `PUT /api/settings/grafana` - Update Grafana settings
   - `POST /api/settings/grafana/validate` - Validate settings and test connection

3. **Security Features**

   - Read-only queries only (INSERT/UPDATE/DELETE/DROP blocked)
   - Configurable query timeout (default: 30 seconds)
   - Configurable max rows per query (default: 10,000)
   - SQL injection protection via query parsing
   - IP address validation for bind settings

4. **Configuration**
   - Settings stored in database (persistent)
   - Default settings in `config/main_config.yaml`
   - Conditional router registration (only loads if enabled)
   - Configurable bind address (localhost, local network, or custom IP)

### Frontend

1. **Grafana Settings UI** (`frontend/src/pages/DatabaseSettings.tsx`)
   - Enable/disable toggle
   - Network access options (localhost/network/custom IP)
   - Port configuration with validation
   - Connection URL display with copy-to-clipboard
   - Test connection button
   - Advanced settings (query timeout, max rows)
   - Real-time validation feedback
   - Setup instructions for Grafana

## Setup Instructions

### 1. Enable Grafana Integration in TowerIQ

1. Open TowerIQ
2. Navigate to **Settings → Database**
3. Scroll to the **Grafana Integration** section
4. Toggle "Enable Grafana Integration" to ON
5. Choose network access option:
   - **Localhost only (127.0.0.1)** - Most secure, Grafana must run on the same machine
   - **Local Network (0.0.0.0)** - Accessible from other devices on your network (recommended for your use case)
   - **Custom IP Address** - Specify exact IP to bind to
6. Configure port (default: 8000)
7. Click "Save Grafana Settings"
8. **Restart TowerIQ** to apply network settings

### 2. Test the Connection

1. In the Grafana Integration section, click **"Test Connection"**
2. You should see a success message
3. Click **"Copy"** next to the Connection URL to copy it for Grafana setup

### 3. Configure Grafana (on your desktop PC)

1. Install the **Infinity** plugin in Grafana:

   - Go to Configuration → Plugins
   - Search for "Infinity"
   - Click "Install"

2. Add a new Infinity data source:

   - Go to Configuration → Data Sources
   - Click "Add data source"
   - Search for "Infinity"
   - Configure:
     - **Name**: TowerIQ Database
     - **Type**: JSON
     - **URL**: `http://<your-laptop-ip>:8000/api/grafana/query`
     - **Method**: POST
   - Click "Save & Test"

3. Create a dashboard panel:
   - Create a new dashboard
   - Add a panel
   - Select "TowerIQ Database" as the data source
   - Configure the query:
     - **Type**: JSON
     - **Method**: POST
     - **Body**:
       ```json
       { "sql": "SELECT * FROM runs ORDER BY start_time DESC LIMIT 10" }
       ```
   - Use JSONPath to extract columns: `$.rows[*]`
   - Apply transformations as needed

### 4. Example SQL Queries

#### Latest Runs

```sql
SELECT
  start_time,
  final_wave,
  CPH,
  round_coins,
  duration_realtime
FROM runs
ORDER BY start_time DESC
LIMIT 20
```

#### CPH Over Time

```sql
SELECT
  datetime(start_time/1000, 'unixepoch') as date,
  CPH
FROM runs
WHERE CPH IS NOT NULL
ORDER BY start_time
```

#### Database Size Trend

```sql
SELECT
  datetime(timestamp, 'unixepoch') as date,
  value as size_bytes
FROM db_metrics
JOIN db_metric_names ON metric_id = db_metric_names.id
WHERE name = 'database_size'
ORDER BY timestamp
```

#### Metrics Timeline

```sql
SELECT
  m.real_timestamp,
  m.current_wave,
  mn.name as metric_name,
  m.metric_value
FROM metrics m
JOIN metric_names mn ON m.metric_name_id = mn.id
WHERE mn.name = 'round_coins'
ORDER BY m.real_timestamp DESC
LIMIT 1000
```

#### View All Available Tables

Visit: `http://<laptop-ip>:8000/api/grafana/schema` in your browser

## Security Considerations

### Network Exposure Warning

When using "Local Network (0.0.0.0)" mode, your database becomes accessible to **all devices on your network**. This is designed for trusted home networks.

**Best Practices:**

- Only enable on trusted networks
- Use Windows Firewall to restrict access if needed
- Keep TowerIQ updated
- Monitor Grafana queries if concerned about data access

### Read-Only Protection

The API enforces read-only access:

- Only SELECT queries allowed
- Write operations (INSERT, UPDATE, DELETE, DROP, etc.) are blocked
- SQL injection attempts are rejected
- Query timeout prevents long-running queries
- Row limits prevent excessive data transfer

## Troubleshooting

### "Grafana integration is disabled" Error

- Ensure you've enabled Grafana Integration in Settings
- Restart TowerIQ after enabling
- Check that the "Test Connection" succeeds

### "Connection refused" from Grafana

- Verify TowerIQ is running
- Check that you're using the correct IP address (use `ipconfig` on Windows to find your laptop's IP)
- Verify the port is correct (default: 8000)
- Ensure Windows Firewall allows the connection
- Try binding to 0.0.0.0 instead of a specific IP

### "Port already in use"

- Default port 8000 may be in use by another application
- Change the port in Grafana settings to something like 8001 or 9000
- Restart TowerIQ after changing the port

### Queries Timing Out

- Increase query timeout in Advanced Settings
- Optimize your SQL queries (add WHERE clauses, reduce rows)
- Add indexes to frequently queried columns (advanced)

### "Invalid SQL" Errors

- Ensure you're only using SELECT statements
- Check for SQL syntax errors
- Verify table and column names using `/api/grafana/schema`

## Configuration Reference

### Default Settings (config/main_config.yaml)

```yaml
grafana:
  enabled: false
  bind_address: "127.0.0.1"
  port: 8000
  allow_read_only: true
  query_timeout: 30
  max_rows: 10000
```

### Settings Stored in Database

Settings are persisted in the `settings` table:

- `grafana.enabled` - Enable/disable feature
- `grafana.bind_address` - IP address to bind to
- `grafana.port` - Port number (requires restart)
- `grafana.query_timeout` - Max query execution time (seconds)
- `grafana.max_rows` - Max rows returned per query

## API Reference

### Execute Query

```
POST /api/grafana/query
Content-Type: application/json

{
  "sql": "SELECT * FROM runs LIMIT 10"
}

Response:
{
  "columns": ["run_id", "start_time", "final_wave", ...],
  "rows": [[row1], [row2], ...],
  "row_count": 10,
  "execution_time_ms": 15.23
}
```

### Get Schema

```
GET /api/grafana/schema

Response:
{
  "tables": [
    {
      "name": "runs",
      "columns": [
        {"name": "run_id", "type": "BLOB", "nullable": false, "primary_key": true},
        {"name": "start_time", "type": "INTEGER", "nullable": false, "primary_key": false},
        ...
      ]
    },
    ...
  ]
}
```

### Test Connection

```
GET /api/grafana/test

Response:
{
  "status": "ok",
  "timestamp": "2025-10-04T12:34:56.789Z",
  "message": "Grafana integration is active and ready"
}
```

## Files Modified/Created

### New Files

- `src/tower_iq/api/routers/grafana.py` - Grafana API router

### Modified Files

- `src/tower_iq/api/routers/database.py` - Added Grafana settings endpoints
- `src/tower_iq/api/models.py` - Added Grafana models
- `src/tower_iq/api_server.py` - Conditional Grafana router registration
- `frontend/src/pages/DatabaseSettings.tsx` - Grafana settings UI
- `config/main_config.yaml` - Default Grafana settings

## Future Enhancements (Optional)

- [ ] Basic authentication for additional security
- [ ] Query history/logging
- [ ] Saved query templates
- [ ] Rate limiting per IP
- [ ] HTTPS support
- [ ] Prometheus metrics format endpoint
- [ ] Query caching
- [ ] Database connection pooling

## Support

For issues or questions:

1. Check that Grafana Integration is enabled and TowerIQ is restarted
2. Use the "Test Connection" button to diagnose issues
3. Check TowerIQ logs for detailed error messages
4. Verify network connectivity between devices
