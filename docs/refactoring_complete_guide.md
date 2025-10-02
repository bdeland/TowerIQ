# API Server Refactoring - Complete Implementation Guide

**Status**: 59% Complete (34/58 endpoints extracted)  
**Date**: October 1, 2025

---

## ✅ COMPLETED ROUTERS (34 endpoints)

### 1. Health Router (`backend/api/routers/health.py`) - 7 endpoints ✅
- `GET /` - Root health check
- `OPTIONS /api/{path:path}` - CORS preflight
- `GET /api/status` - Backend status
- `POST /api/heartbeat` - Heartbeat receiver
- `POST /api/shutdown` - Graceful shutdown
- `GET /api/settings/get/{key}` - Get setting
- `POST /api/settings/set` - Set setting

### 2. ADB Router (`backend/api/routers/adb.py`) - 4 endpoints ✅
- `POST /api/adb/start` - Start ADB server
- `POST /api/adb/kill` - Kill ADB server
- `POST /api/adb/restart` - Restart ADB server
- `GET /api/adb/status` - Get ADB status

### 3. Scripts Router (`backend/api/routers/scripts.py`) - 4 endpoints ✅
- `POST /api/compatible-scripts` - Find compatible scripts
- `GET /api/available-scripts` - List all scripts
- `GET /api/hook-scripts` - Get hook scripts
- `GET /api/script-status` - Get script status

### 4. Devices Router (`backend/api/routers/devices.py`) - 4 endpoints ✅
- `GET /api/devices` - List devices (cached)
- `POST /api/devices/refresh` - Refresh device list
- `GET /api/devices/{id}/processes` - List processes
- `POST /api/test/simulate-device-disconnection` - Test helper

### 5. Connection Router (`backend/api/routers/connection.py`) - 5 endpoints ✅
- `POST /api/connect` - Connect to device
- `POST /api/disconnect` - Disconnect from device
- `POST /api/activate-hook` - Activate hook script
- `POST /api/deactivate-hook` - Deactivate hook script
- `POST /api/test-mode` - Set test mode

### 6. Frida Router (`backend/api/routers/frida.py`) - 7 endpoints ✅
- `GET /api/health/frida` - Frida health check
- `GET /api/devices/{id}/frida-status` - Frida status
- `POST /api/devices/{id}/frida-provision` - Provision Frida
- `POST /api/devices/{id}/frida-start` - Start Frida server
- `POST /api/devices/{id}/frida-stop` - Stop Frida server
- `POST /api/devices/{id}/frida-install` - Install Frida server
- `POST /api/devices/{id}/frida-remove` - Remove Frida server

### 7. Queries Router (`backend/api/routers/queries.py`) - 3 endpoints ✅
- `POST /api/query/preview` - Preview query
- `POST /api/query` - Execute query (v1)
- `POST /api/v2/query` - Execute query (v2)

---

## 📋 REMAINING ROUTERS (24 endpoints)

### 8. Database Router (`backend/api/routers/database.py`) - 9 endpoints ⏳
**Location in api_server.py**: Lines 1627-1863

Endpoints to extract:
- `GET /api/settings/database/backup` (line 1627)
- `PUT /api/settings/database/backup` (line 1646)
- `POST /api/database/backup` (line 1665)
- `GET /api/database/restore-suggestion` (line 1677)
- `POST /api/database/restore` (line 1710)
- `GET /api/settings/database/path` (line 1726)
- `PUT /api/settings/database/path` (line 1738)
- `GET /api/v1/database/statistics` (line 1837)
- `POST /api/v1/database/collect-metrics` (line 1866)

**Dependencies needed**: `db_service`, `logger`, `config`, `asyncio`, `Path`, `shutil`

### 9. Dashboards V1 Router (`backend/api/routers/dashboards_v1.py`) - 8 endpoints ⏳
**Location in api_server.py**: Lines 1422-1625

Endpoints to extract:
- `GET /api/dashboards` (line 1422)
- `GET /api/dashboards/{dashboard_id}` (line 1437)
- `POST /api/dashboards` (line 1457)
- `PUT /api/dashboards/{dashboard_id}` (line 1496)
- `DELETE /api/dashboards/{dashboard_id}` (line 1537)
- `POST /api/dashboards/{dashboard_id}/set-default` (line 1562)
- `GET /api/dashboards/default` (line 1587)
- `POST /api/dashboards/ensure-table` (line 1607)

**Dependencies needed**: `db_service`, `logger`, `json`, `datetime`, `uuid`
**Models needed**: `DashboardCreateRequest`, `DashboardUpdateRequest`, `DashboardResponse`

### 10. Dashboards V2 Router (`backend/api/routers/dashboards_v2.py`) - 5 endpoints ⏳
**Location in api_server.py**: Lines 2033-2283

Endpoints to extract:
- `GET /api/v2/dashboards` (line 2033)
- `GET /api/v2/dashboards/{dashboard_id}` (line 2076)
- `POST /api/v2/dashboards` (line 2114)
- `PUT /api/v2/dashboards/{dashboard_id}` (line 2158)
- `DELETE /api/v2/dashboards/{dashboard_id}` (line 2211)

**Dependencies needed**: `db_service`, `logger`, `json`, `datetime`
**Models needed**: Import from `tower_iq.models.dashboard_config_models`

### 11. Data Sources Router (`backend/api/routers/data_sources.py`) - 2 endpoints ⏳
**Location in api_server.py**: Lines 2243-2341

Endpoints to extract:
- `GET /api/v2/data-sources` (line 2243)
- `POST /api/v2/data-sources` (line 2283)
- `POST /api/v2/variables/{variable_name}/options` (line 2343) - *actually 3 endpoints*

**Dependencies needed**: `db_service`, `logger`
**Models needed**: Import from `tower_iq.models.dashboard_config_models`

---

## 🎯 HOW TO COMPLETE THE REMAINING ROUTERS

### Step 1: Create Database Router

```python
# backend/api/routers/database.py
"""
Database Management Router

Handles:
- Database backup and restore
- Database path configuration
- Database statistics and health metrics
"""

import asyncio
import json
from pathlib import Path
from datetime import datetime
from fastapi import APIRouter, HTTPException

from ..models import (
    BackupSettings, BackupRunResponse, DatabasePathResponse,
    DatabasePathUpdate, RestoreRequest, RestoreSuggestion
)

router = APIRouter()

# Module-level dependencies
logger = None
db_service = None
config = None


def initialize(log, db_svc, cfg):
    """Initialize module-level dependencies."""
    global logger, db_service, config
    logger = log
    db_service = db_svc
    config = cfg


# Copy endpoints from api_server.py lines 1627-1863
# Replace global references with module-level variables
```

### Step 2: Create Dashboards V1 Router

```python
# backend/api/routers/dashboards_v1.py
"""
Dashboard Management Router (V1 Legacy API)

Handles legacy dashboard CRUD operations.
"""

import json
from datetime import datetime
from typing import List
from fastapi import APIRouter, HTTPException

from ..models import DashboardCreateRequest, DashboardUpdateRequest, DashboardResponse

router = APIRouter()

logger = None
db_service = None


def initialize(log, db_svc):
    """Initialize module-level dependencies."""
    global logger, db_service
    logger = log
    db_service = db_svc


# Copy endpoints from api_server.py lines 1422-1625
```

### Step 3: Create Dashboards V2 Router

```python
# backend/api/routers/dashboards_v2.py
"""
Dashboard Management Router (V2 New API)

Handles new hierarchical dashboard system.
"""

import json
from datetime import datetime
from typing import List
from fastapi import APIRouter, HTTPException

from tower_iq.models.dashboard_config_models import (
    DashboardConfig, DashboardMetadata, DashboardListResponse,
    CreateDashboardRequest, UpdateDashboardRequest
)

router = APIRouter()

logger = None
db_service = None


def initialize(log, db_svc):
    """Initialize module-level dependencies."""
    global logger, db_service
    logger = log
    db_service = db_svc


# Copy endpoints from api_server.py lines 2033-2283
```

### Step 4: Create Data Sources Router

```python
# backend/api/routers/data_sources.py
"""
Data Source Management Router

Handles data source configuration and variable options.
"""

from typing import List
from fastapi import APIRouter, HTTPException

from tower_iq.models.dashboard_config_models import (
    DataSourceConfig, DataSourceCreateRequest,
    VariableOptionsRequest, VariableOption
)
from ..models import QueryRequest

router = APIRouter()

logger = None
db_service = None


def initialize(log, db_svc):
    """Initialize module-level dependencies."""
    global logger, db_service
    logger = log
    db_service = db_svc


# Copy endpoints from api_server.py lines 2243-2370
```

---

## 🔧 INTEGRATION STEPS

Once all routers are created, update `backend/api_server.py`:

```python
# backend/api_server.py (AFTER routers are created)

# At top of file, after imports
from backend.api.routers import (
    health, adb, scripts, devices, connection, frida, queries,
    database, dashboards_v1, dashboards_v2, data_sources
)
from backend.api import dependencies

# In lifespan function, after services are initialized
async def lifespan(app: FastAPI):
    """Manage the lifespan of the FastAPI application."""
    # ... existing initialization code ...
    
    # Initialize dependencies
    dependencies.set_logger(logger)
    dependencies.set_controller(controller)
    dependencies.set_db_service(db_service)
    dependencies.set_query_service(query_service)
    
    # Initialize all routers
    health.initialize(logger, controller, config)
    adb.initialize(logger, controller)
    scripts.initialize(logger, controller)
    devices.initialize(logger, controller)
    connection.initialize(logger, controller)
    frida.initialize(logger, controller)
    queries.initialize(logger, db_service, query_service)
    database.initialize(logger, db_service, config)
    dashboards_v1.initialize(logger, db_service)
    dashboards_v2.initialize(logger, db_service)
    data_sources.initialize(logger, db_service)
    
    # Register all routers
    app.include_router(health.router)
    app.include_router(adb.router)
    app.include_router(scripts.router)
    app.include_router(devices.router)
    app.include_router(connection.router)
    app.include_router(frida.router)
    app.include_router(queries.router)
    app.include_router(database.router)
    app.include_router(dashboards_v1.router)
    app.include_router(dashboards_v2.router)
    app.include_router(data_sources.router)
    
    yield
    
    # ... existing cleanup code ...

# REMOVE all the old @app.get/@app.post endpoint definitions (lines 502-2393)
# Keep only: logging config, lifespan, app creation, CORS, main entry point
```

---

## 📊 FINAL STATISTICS (When Complete)

| File | Lines Before | Lines After | Reduction |
|------|-------------|-------------|-----------|
| `api_server.py` | 2,393 | ~200 | 91% |
| **New routers** | 0 | ~2,200 | - |
| **Average per router** | - | ~200 | - |

**Total files**: 1 → 16 files (15 new)  
**Largest file**: 2,393 lines → 350 lines max  
**Linting issues**: Eliminates "too-many-lines" errors

---

## ✅ TESTING CHECKLIST

After integration:

1. ☐ Start the backend: `python start.py`
2. ☐ Test health endpoint: `GET http://localhost:8000/`
3. ☐ Test each router group:
   - ☐ Health endpoints
   - ☐ ADB endpoints  
   - ☐ Device discovery
   - ☐ Connection flow
   - ☐ Frida operations
   - ☐ Query execution
   - ☐ Dashboard CRUD
4. ☐ Run linter: `python scripts/lint.py backend`
5. ☐ Verify no regressions
6. ☐ Update API documentation

---

## 🎉 COMPLETION ESTIMATE

- **Remaining work**: 4 routers, ~500 lines to extract
- **Time estimate**: 2-3 hours
- **Complexity**: Low (following established pattern)
- **Risk**: Low (all patterns proven)

You're 59% complete with the hardest parts done! The remaining routers follow the exact same pattern.

