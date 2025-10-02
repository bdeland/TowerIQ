# TowerIQ Refactoring Visual Guide

## Current vs Proposed Architecture

### 1. API Server: Before & After

#### BEFORE (2,392 lines in 1 file)
```
backend/api_server.py
├─ Configure logging (50 lines)
├─ Pydantic models (200 lines)
├─ Lifespan management (200 lines)
├─ App setup + middleware (50 lines)
├─ 58 endpoint handlers (1,892 lines)
└─ Main entry point (10 lines)
```

#### AFTER (modular structure)
```
backend/
├─ api_server.py (150 lines)
│   ├─ FastAPI app creation
│   ├─ Middleware setup
│   ├─ Router registration
│   └─ Lifespan management
│
└─ api/
    ├─ dependencies.py (100 lines)
    │   └─ Shared DI functions
    │
    ├─ models.py (200 lines)
    │   └─ All Pydantic models
    │
    └─ routers/
        ├─ health.py (50 lines)
        ├─ connection.py (200 lines)
        ├─ devices.py (250 lines)
        ├─ frida.py (300 lines)
        ├─ scripts.py (150 lines)
        ├─ adb.py (100 lines)
        ├─ dashboards_v1.py (200 lines)
        ├─ dashboards_v2.py (250 lines)
        ├─ database.py (200 lines)
        └─ queries.py (250 lines)
```

**Result**: 10 focused files averaging 200 lines each

---

### 2. Emulator Service: Before & After

#### BEFORE (1,081 lines in 1 file)
```
backend/services/emulator_service.py
├─ Constants (100 lines)
├─ Process class (20 lines)
├─ Device class (80 lines)
├─ CacheEntry class (10 lines)
└─ EmulatorService class (871 lines)
    ├─ __init__ (30 lines)
    ├─ Device discovery methods (300 lines)
    ├─ Process listing methods (250 lines)
    ├─ Device info methods (150 lines)
    ├─ Frida integration (80 lines)
    ├─ ADB management (50 lines)
    └─ Caching methods (20 lines)
```

#### AFTER (modular structure)
```
backend/services/
├─ emulator_service.py (200 lines)
│   └─ Thin orchestrator, delegates to sub-services
│
├─ device_discovery_service.py (300 lines)
│   ├─ discover_devices()
│   ├─ _get_device_list()
│   ├─ _get_complete_device_info()
│   └─ Device property fetching
│
├─ process_listing_service.py (250 lines)
│   ├─ get_processes()
│   ├─ get_all_processes_unfiltered()
│   ├─ find_target_process()
│   └─ Process filtering logic
│
├─ device_info_service.py (200 lines)
│   ├─ get_device_properties()
│   ├─ detect_device_type()
│   └─ Device capability queries
│
└─ models/
    ├─ device.py (150 lines)
    │   ├─ Process dataclass
    │   └─ Device dataclass
    │
    └─ cache.py (100 lines)
        ├─ CacheEntry dataclass
        └─ CacheManager class
```

**Result**: 5 focused files averaging 200 lines each

---

## Endpoint Grouping by Router

### Router Organization Chart

```
FastAPI App
├─ Health Router (6 endpoints)
│   ├─ GET /
│   ├─ GET /api/status
│   ├─ POST /api/heartbeat
│   ├─ POST /api/shutdown
│   ├─ GET /api/settings/get/{key}
│   └─ POST /api/settings/set
│
├─ Connection Router (5 endpoints)
│   ├─ POST /api/connect
│   ├─ POST /api/disconnect
│   ├─ POST /api/activate-hook
│   ├─ POST /api/deactivate-hook
│   └─ POST /api/test-mode
│
├─ Devices Router (4 endpoints)
│   ├─ GET /api/devices
│   ├─ POST /api/devices/refresh
│   ├─ GET /api/devices/{id}/processes
│   └─ POST /api/test/simulate-device-disconnection
│
├─ Frida Router (7 endpoints)
│   ├─ GET /api/health/frida
│   ├─ GET /api/devices/{id}/frida-status
│   ├─ POST /api/devices/{id}/frida-provision
│   ├─ POST /api/devices/{id}/frida-start
│   ├─ POST /api/devices/{id}/frida-stop
│   ├─ POST /api/devices/{id}/frida-install
│   └─ POST /api/devices/{id}/frida-remove
│
├─ Scripts Router (4 endpoints)
│   ├─ POST /api/compatible-scripts
│   ├─ GET /api/available-scripts
│   ├─ GET /api/hook-scripts
│   └─ GET /api/script-status
│
├─ ADB Router (4 endpoints)
│   ├─ POST /api/adb/start
│   ├─ POST /api/adb/kill
│   ├─ POST /api/adb/restart
│   └─ GET /api/adb/status
│
├─ Dashboards V1 Router (8 endpoints)
│   ├─ GET /api/dashboards
│   ├─ GET /api/dashboards/{id}
│   ├─ POST /api/dashboards
│   ├─ PUT /api/dashboards/{id}
│   ├─ DELETE /api/dashboards/{id}
│   ├─ POST /api/dashboards/{id}/set-default
│   ├─ GET /api/dashboards/default
│   └─ POST /api/dashboards/ensure-table
│
├─ Dashboards V2 Router (6 endpoints)
│   ├─ GET /api/v2/dashboards
│   ├─ GET /api/v2/dashboards/{id}
│   ├─ POST /api/v2/dashboards
│   ├─ PUT /api/v2/dashboards/{id}
│   ├─ DELETE /api/v2/dashboards/{id}
│   └─ POST /api/v2/variables/{name}/options
│
├─ Data Sources Router (2 endpoints)
│   ├─ GET /api/v2/data-sources
│   └─ POST /api/v2/data-sources
│
├─ Database Router (7 endpoints)
│   ├─ GET /api/settings/database/backup
│   ├─ PUT /api/settings/database/backup
│   ├─ POST /api/database/backup
│   ├─ GET /api/database/restore-suggestion
│   ├─ POST /api/database/restore
│   ├─ GET /api/v1/database/statistics
│   └─ POST /api/v1/database/collect-metrics
│
└─ Queries Router (3 endpoints)
    ├─ POST /api/query
    ├─ POST /api/query/preview
    └─ POST /api/v2/query
```

**Total**: 58 endpoints across 10 routers

---

## Dependency Flow

### Current (Monolithic)
```
api_server.py
    ↓ (imports everything)
    ├─→ MainController
    ├─→ DatabaseService
    ├─→ QueryService
    ├─→ ConfigurationManager
    ├─→ EmulatorService
    └─→ FridaService
```

### Proposed (Modular)
```
api_server.py
    ↓ (minimal imports)
    └─→ api/routers/* (registers all routers)

api/routers/connection.py
    ↓
    └─→ api/dependencies.py
            ↓
            ├─→ MainController
            ├─→ FridaService
            └─→ EmulatorService

api/routers/queries.py
    ↓
    └─→ api/dependencies.py
            ↓
            ├─→ DatabaseService
            └─→ QueryService

... (each router imports only what it needs via dependencies)
```

**Benefit**: Clear dependency boundaries, easier to mock for testing

---

## Implementation Sequence

### Step-by-Step Refactoring Order

```
Phase 1: Foundation
1. Create api/ directory structure
2. Extract api/models.py (Pydantic models)
3. Create api/dependencies.py (DI functions)

Phase 2: Simple Routers (Easy wins)
4. Extract api/routers/health.py
5. Extract api/routers/adb.py
6. Extract api/routers/scripts.py

Phase 3: Medium Routers
7. Extract api/routers/connection.py
8. Extract api/routers/devices.py
9. Extract api/routers/frida.py

Phase 4: Complex Routers
10. Extract api/routers/queries.py
11. Extract api/routers/database.py
12. Extract api/routers/dashboards_v1.py
13. Extract api/routers/dashboards_v2.py

Phase 5: Integration
14. Update api_server.py to use all routers
15. Remove old code
16. Test everything
```

---

## Code Size Reduction Visualization

### Before Refactoring
```
api_server.py                    [████████████████████████] 2,392 lines
emulator_service.py              [████████████] 1,081 lines
                                 ─────────────────────────
Total                            3,473 lines in 2 files
```

### After Refactoring
```
api_server.py                    [█] 150 lines
api/models.py                    [██] 200 lines
api/dependencies.py              [█] 100 lines
api/routers/*.py (10 files)      [██████████████] 1,950 lines
emulator_service.py              [██] 200 lines
device_discovery_service.py      [███] 300 lines
process_listing_service.py       [███] 250 lines
device_info_service.py           [██] 200 lines
services/models/*.py (2 files)   [███] 250 lines
                                 ─────────────────────────
Total                            3,600 lines in 17 files
```

**Lines per file**: 2,392 → ~212 average (91% reduction in file size)

---

## Testing Pyramid

### Before (Monolithic)
```
      /\
     /  \    E2E Tests
    /────\
   /      \  Integration Tests
  /────────\
 /          \ Unit Tests (Hard to isolate)
/____________\
```

### After (Modular)
```
      /\
     /  \    E2E Tests
    /────\
   /      \  Router Integration Tests
  /────────\
 /          \ Service Unit Tests (Easy to isolate)
/____________\ Model Unit Tests
```

**Improvement**: Better test isolation and faster test execution

---

## Migration Checklist

### Before Starting
- [ ] Backup current codebase
- [ ] Create feature branch
- [ ] Write integration tests for current behavior
- [ ] Document all API endpoints
- [ ] Get team buy-in

### During Refactoring
- [ ] Extract one router/service at a time
- [ ] Test after each extraction
- [ ] Keep main branch deployable
- [ ] Update documentation incrementally
- [ ] Run linter after each change

### After Completion
- [ ] Full test suite passes
- [ ] No linting errors
- [ ] API documentation updated
- [ ] Performance benchmarks meet targets
- [ ] Code review completed
- [ ] Merge to main branch

---

## Quick Reference: File Locations

### API Files
| Purpose | File | Lines |
|---------|------|-------|
| Main app | `backend/api_server.py` | 150 |
| Models | `backend/api/models.py` | 200 |
| Dependencies | `backend/api/dependencies.py` | 100 |
| Health | `backend/api/routers/health.py` | 50 |
| Connection | `backend/api/routers/connection.py` | 200 |
| Devices | `backend/api/routers/devices.py` | 250 |
| Frida | `backend/api/routers/frida.py` | 300 |
| Scripts | `backend/api/routers/scripts.py` | 150 |
| ADB | `backend/api/routers/adb.py` | 100 |
| Dashboards V1 | `backend/api/routers/dashboards_v1.py` | 200 |
| Dashboards V2 | `backend/api/routers/dashboards_v2.py` | 250 |
| Database | `backend/api/routers/database.py` | 200 |
| Queries | `backend/api/routers/queries.py` | 250 |

### Service Files
| Purpose | File | Lines |
|---------|------|-------|
| Main service | `backend/services/emulator_service.py` | 200 |
| Discovery | `backend/services/device_discovery_service.py` | 300 |
| Processes | `backend/services/process_listing_service.py` | 250 |
| Device Info | `backend/services/device_info_service.py` | 200 |
| Models | `backend/services/models/device.py` | 150 |
| Cache | `backend/services/models/cache.py` | 100 |

