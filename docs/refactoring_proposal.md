# TowerIQ Refactoring Proposal

## Executive Summary

Two files have grown beyond maintainable size and need refactoring:
1. **`backend/api_server.py`**: 2,392 lines → Target: 5-8 smaller modules
2. **`backend/services/emulator_service.py`**: 1,081 lines → Target: 3-4 focused services

## 1. API Server Refactoring (`backend/api_server.py`)

### Current Structure Analysis

**58 API endpoints** grouped into these functional areas:
- Health/Status (2 endpoints)
- Connection Management (3 endpoints)
- Hook Management (5 endpoints)
- Device Management (4 endpoints)
- Frida Server Management (6 endpoints)
- Script Management (3 endpoints)
- ADB Management (4 endpoints)
- Dashboard Management v1 (7 endpoints)
- Dashboard Management v2 (5 endpoints)
- Database/Backup Management (5 endpoints)
- Settings Management (2 endpoints)
- Query Execution (3 endpoints)
- Data Source Management (2 endpoints)
- Test/Debug (2 endpoints)

### Proposed Structure

Create a new directory: `backend/api/routers/` with FastAPI routers:

```
backend/
├── api_server.py (150 lines - main app, lifespan, middleware)
└── api/
    ├── __init__.py
    ├── dependencies.py (shared dependencies: logger, config, services)
    ├── models.py (Pydantic models for all endpoints)
    └── routers/
        ├── __init__.py
        ├── connection.py (~200 lines - connection & hook management)
        ├── devices.py (~250 lines - device discovery & management)
        ├── frida.py (~300 lines - Frida server lifecycle)
        ├── scripts.py (~150 lines - hook script management)
        ├── adb.py (~100 lines - ADB server management)
        ├── dashboards_v1.py (~200 lines - legacy dashboard API)
        ├── dashboards_v2.py (~250 lines - new dashboard system)
        ├── database.py (~200 lines - backup, restore, settings)
        ├── queries.py (~250 lines - query execution v1 & v2)
        └── health.py (~50 lines - health checks & status)
```

### File Breakdown

#### `backend/api_server.py` (Main App - ~150 lines)
```python
"""
TowerIQ API Server - Main FastAPI application
Minimal orchestration file that wires together all routers.
"""

# Contents:
- Logging configuration
- FastAPI app creation
- CORS middleware setup
- Lifespan context manager (startup/shutdown)
- Router registration
- Main entry point
```

#### `backend/api/dependencies.py` (~100 lines)
```python
"""
Shared dependencies for API routers.
"""

# Contents:
- get_logger() dependency
- get_config() dependency
- get_controller() dependency
- get_db_service() dependency
- get_query_service() dependency
- Error handling utilities
```

#### `backend/api/models.py` (~200 lines)
```python
"""
Pydantic models for API requests and responses.
Centralized location for all API models.
"""

# Contents:
- All Pydantic BaseModel classes currently in api_server.py
- Request models
- Response models
- Shared models used across routers
```

#### `backend/api/routers/connection.py` (~200 lines)
**Endpoints:**
- `POST /api/connect` - Connect to device
- `POST /api/disconnect` - Disconnect from device
- `POST /api/activate-hook` - Activate Frida hook
- `POST /api/deactivate-hook` - Deactivate hook
- `POST /api/test-mode` - Toggle test mode
- `GET /api/status` - Get session status

**Responsibilities:**
- Connection lifecycle management
- Hook activation/deactivation
- Test mode configuration
- Session state queries

#### `backend/api/routers/devices.py` (~250 lines)
**Endpoints:**
- `GET /api/devices` - List all devices
- `POST /api/devices/refresh` - Refresh device list
- `GET /api/devices/{device_id}/processes` - Get device processes
- `POST /api/test/simulate-device-disconnection` - Test helper

**Responsibilities:**
- Device discovery and listing
- Process enumeration
- Device connection testing

#### `backend/api/routers/frida.py` (~300 lines)
**Endpoints:**
- `GET /api/health/frida` - Frida health check
- `GET /api/devices/{device_id}/frida-status` - Get Frida server status
- `POST /api/devices/{device_id}/frida-provision` - Provision Frida server
- `POST /api/devices/{device_id}/frida-start` - Start Frida server
- `POST /api/devices/{device_id}/frida-stop` - Stop Frida server
- `POST /api/devices/{device_id}/frida-install` - Install Frida server
- `POST /api/devices/{device_id}/frida-remove` - Remove Frida server

**Responsibilities:**
- Frida server lifecycle management
- Version checking
- Installation and removal
- Server health monitoring

#### `backend/api/routers/scripts.py` (~150 lines)
**Endpoints:**
- `POST /api/compatible-scripts` - Find compatible scripts
- `GET /api/available-scripts` - List all scripts
- `GET /api/hook-scripts` - Get hook scripts (legacy)
- `GET /api/script-status` - Get current script status

**Responsibilities:**
- Hook script discovery
- Compatibility checking
- Script metadata retrieval

#### `backend/api/routers/adb.py` (~100 lines)
**Endpoints:**
- `POST /api/adb/start` - Start ADB server
- `POST /api/adb/kill` - Kill ADB server
- `POST /api/adb/restart` - Restart ADB server
- `GET /api/adb/status` - Get ADB status

**Responsibilities:**
- ADB server lifecycle management
- ADB status monitoring

#### `backend/api/routers/dashboards_v1.py` (~200 lines)
**Endpoints:**
- `GET /api/dashboards` - List dashboards
- `GET /api/dashboards/{dashboard_id}` - Get dashboard
- `POST /api/dashboards` - Create dashboard
- `PUT /api/dashboards/{dashboard_id}` - Update dashboard
- `DELETE /api/dashboards/{dashboard_id}` - Delete dashboard
- `POST /api/dashboards/{dashboard_id}/set-default` - Set default
- `GET /api/dashboards/default` - Get default dashboard
- `POST /api/dashboards/ensure-table` - Ensure table exists

**Responsibilities:**
- Legacy dashboard CRUD operations
- Default dashboard management

#### `backend/api/routers/dashboards_v2.py` (~250 lines)
**Endpoints:**
- `GET /api/v2/dashboards` - List dashboards (v2)
- `GET /api/v2/dashboards/{dashboard_id}` - Get dashboard (v2)
- `POST /api/v2/dashboards` - Create dashboard (v2)
- `PUT /api/v2/dashboards/{dashboard_id}` - Update dashboard (v2)
- `DELETE /api/v2/dashboards/{dashboard_id}` - Delete dashboard (v2)
- `GET /api/v2/data-sources` - List data sources
- `POST /api/v2/data-sources` - Create data source
- `POST /api/v2/variables/{variable_name}/options` - Get variable options

**Responsibilities:**
- New hierarchical dashboard system
- Data source management
- Variable resolution

#### `backend/api/routers/database.py` (~200 lines)
**Endpoints:**
- `GET /api/settings/database/backup` - Get backup settings
- `PUT /api/settings/database/backup` - Update backup settings
- `POST /api/database/backup` - Run backup
- `GET /api/database/restore-suggestion` - Get restore suggestion
- `POST /api/database/restore` - Restore database
- `GET /api/settings/database/path` - Get database path
- `PUT /api/settings/database/path` - Update database path
- `GET /api/v1/database/statistics` - Get database stats
- `POST /api/v1/database/collect-metrics` - Collect metrics

**Responsibilities:**
- Database backup and restore
- Database path management
- Database statistics and metrics

#### `backend/api/routers/queries.py` (~250 lines)
**Endpoints:**
- `POST /api/query` - Execute query (v1)
- `POST /api/query/preview` - Preview query
- `POST /api/v2/query` - Execute query (v2)

**Responsibilities:**
- SQL query execution
- Query validation and safety
- Result formatting
- Query preview

#### `backend/api/routers/health.py` (~50 lines)
**Endpoints:**
- `GET /` - Root health check
- `OPTIONS /api/{path:path}` - CORS preflight
- `POST /api/heartbeat` - Client heartbeat
- `POST /api/shutdown` - Graceful shutdown
- `GET /api/settings/get/{setting_key:path}` - Get setting
- `POST /api/settings/set` - Set setting

**Responsibilities:**
- Application health monitoring
- CORS handling
- Settings management

### Migration Strategy

**Phase 1: Preparation (Day 1)**
1. Create new directory structure
2. Move Pydantic models to `api/models.py`
3. Create `api/dependencies.py` with shared dependencies
4. Write tests for each router before extraction

**Phase 2: Router Extraction (Days 2-4)**
1. Extract one router at a time, starting with simplest (health, adb)
2. Test each router independently
3. Update imports in main app
4. Verify all endpoints still work

**Phase 3: Integration (Day 5)**
1. Update main `api_server.py` to use routers
2. Remove old code from main file
3. Update documentation
4. Run full integration tests

**Phase 4: Cleanup (Day 6)**
1. Remove unused imports
2. Update type hints
3. Run linting and fix issues
4. Update API documentation

---

## 2. Emulator Service Refactoring (`backend/services/emulator_service.py`)

### Current Structure Analysis

**1,081 lines** containing:
- 4 dataclasses: `Process`, `Device`, `CacheEntry`, `EmulatorService`
- 30+ methods in `EmulatorService`
- Multiple responsibilities mixed together

### Proposed Structure

Split into focused services:

```
backend/
└── services/
    ├── emulator_service.py (~200 lines - main orchestrator)
    ├── device_discovery_service.py (~300 lines - device discovery)
    ├── process_listing_service.py (~250 lines - process management)
    ├── device_info_service.py (~200 lines - device properties)
    └── models/
        ├── __init__.py
        ├── device.py (Device, Process dataclasses)
        └── cache.py (CacheEntry and caching utilities)
```

### File Breakdown

#### `backend/services/models/device.py` (~150 lines)
```python
"""
Data models for devices and processes.
"""

# Contents:
- Process dataclass (with __post_init__)
- Device dataclass (with __post_init__ and _detect_device_type)
- Device type detection logic
- Constants (_EMULATOR_INDICATORS)
```

#### `backend/services/models/cache.py` (~100 lines)
```python
"""
Caching utilities for device and process data.
"""

# Contents:
- CacheEntry dataclass
- CacheManager class (extracted from EmulatorService)
- Cache key generation helpers
- Cache expiration logic
```

#### `backend/services/device_discovery_service.py` (~300 lines)
```python
"""
Service for discovering Android devices via ADB.
"""

class DeviceDiscoveryService:
    # Methods:
    - discover_devices() - Main discovery entry point
    - _get_device_list() - Get raw device list from ADB
    - _ensure_adb_server_running() - Ensure ADB is ready
    - _get_complete_device_info() - Get full device details
    - _get_device_properties() - Fetch device properties
    - _get_device_status() - Check device status
    - _test_device_connection() - Test connectivity
    - _get_device_info_with_detector() - Use device-detector library
    - _clean_device_name() - Normalize device names
    - _is_discovery_cache_valid() - Cache validation
```

#### `backend/services/process_listing_service.py` (~250 lines)
```python
"""
Service for listing and filtering processes on Android devices.
"""

class ProcessListingService:
    # Methods:
    - get_processes() - Get filtered processes
    - get_all_processes_unfiltered() - Get all processes
    - find_target_process() - Find specific process
    - _get_all_processes() - Internal process listing
    - _get_all_processes_unfiltered() - Internal unfiltered listing
    - _get_process_details() - Get detailed process info
    - _get_package_property() - Query package properties
    - _is_valid_package_name() - Validate package names
    - _is_system_package() - Identify system packages
```

#### `backend/services/device_info_service.py` (~200 lines)
```python
"""
Service for querying device information and properties.
"""

class DeviceInfoService:
    # Methods:
    - get_device_properties() - Get multiple properties
    - get_device_property() - Get single property
    - get_device_model_info() - Get model information
    - get_android_version() - Get Android version
    - detect_device_type() - Detect emulator vs physical
    - get_device_capabilities() - Query capabilities
```

#### `backend/services/emulator_service.py` (~200 lines - Orchestrator)
```python
"""
Main EmulatorService - orchestrates sub-services.
"""

class EmulatorService:
    def __init__(self, config, logger):
        # Initialize sub-services
        self.device_discovery = DeviceDiscoveryService(config, logger)
        self.process_listing = ProcessListingService(config, logger)
        self.device_info = DeviceInfoService(config, logger)
        self.frida_manager = FridaServerManager(logger, adb)
        self.cache_manager = CacheManager(config)
        self.adb = AdbWrapper(logger)

    # Delegate methods (thin wrappers):
    async def discover_devices(self, ...):
        return await self.device_discovery.discover_devices(...)

    async def get_processes(self, ...):
        return await self.process_listing.get_processes(...)

    # ADB management methods:
    async def start_adb_server(self): ...
    async def kill_adb_server(self): ...
    async def restart_adb_server(self): ...
    async def is_adb_server_running(self): ...
    async def get_adb_status(self): ...

    # Frida integration (delegation):
    async def ensure_frida_server_is_running(self, ...): ...
```

### Benefits of This Refactoring

**For `emulator_service.py`:**
1. **Single Responsibility**: Each service has one clear purpose
2. **Easier Testing**: Can test device discovery independently from process listing
3. **Better Caching**: Centralized cache management
4. **Reduced Complexity**: Each file is ~200-300 lines instead of 1,081
5. **Reusability**: Services can be used independently

**For `api_server.py`:**
1. **Organization**: Related endpoints grouped logically
2. **Independent Deployment**: Could deploy only certain routers
3. **Team Collaboration**: Multiple developers can work on different routers
4. **API Versioning**: v1 and v2 APIs clearly separated
5. **Testing**: Each router can be tested in isolation
6. **Documentation**: Auto-generated API docs are better organized

### Migration Steps for Emulator Service

**Phase 1: Extract Models (Day 1)**
1. Create `services/models/` directory
2. Move `Process`, `Device` to `models/device.py`
3. Move `CacheEntry` to `models/cache.py`
4. Update imports, test

**Phase 2: Extract Discovery Service (Day 2)**
1. Create `device_discovery_service.py`
2. Move discovery methods from `EmulatorService`
3. Update `EmulatorService` to delegate to new service
4. Test device discovery functionality

**Phase 3: Extract Process Service (Day 3)**
1. Create `process_listing_service.py`
2. Move process methods from `EmulatorService`
3. Update delegation
4. Test process listing

**Phase 4: Extract Info Service (Day 4)**
1. Create `device_info_service.py`
2. Move device property methods
3. Create `CacheManager` class
4. Update delegation

**Phase 5: Finalize (Day 5)**
1. Update all imports across codebase
2. Run full test suite
3. Update documentation
4. Run linting

---

## Testing Strategy

### For API Routers
- **Unit Tests**: Test each router independently with mocked dependencies
- **Integration Tests**: Test routers with real services
- **Contract Tests**: Verify API contracts haven't changed

### For Emulator Services
- **Unit Tests**: Test each service with mocked ADB
- **Integration Tests**: Test with real ADB (emulator required)
- **Mock Tests**: Use `pytest-mock` for external dependencies

---

## Risk Mitigation

### Risks
1. **Breaking Changes**: Existing code may break during refactoring
2. **Test Coverage**: Need comprehensive tests before refactoring
3. **Time Investment**: 1-2 weeks of development time
4. **API Compatibility**: Must maintain backward compatibility

### Mitigation Strategies
1. **Feature Flags**: Use flags to toggle between old and new implementations
2. **Parallel Run**: Run both old and new code simultaneously, compare results
3. **Incremental Rollout**: Refactor one module at a time
4. **Comprehensive Tests**: Write tests before refactoring
5. **Code Reviews**: Review each phase before moving to next

---

## Timeline Estimate

### API Server Refactoring: 5-6 days
- Day 1: Preparation and model extraction
- Days 2-4: Router extraction (2-3 routers per day)
- Day 5: Integration and testing
- Day 6: Cleanup and documentation

### Emulator Service Refactoring: 4-5 days
- Day 1: Model extraction
- Days 2-4: Service extraction (one per day)
- Day 5: Integration and testing

### Total: **10-11 days** (2 work weeks with buffer)

---

## Success Criteria

1. ✅ All files under 500 lines
2. ✅ Zero linting errors related to file length
3. ✅ All existing tests pass
4. ✅ API contracts unchanged (backward compatible)
5. ✅ Performance unchanged or improved
6. ✅ Code coverage maintained or improved
7. ✅ Documentation updated

---

## Recommendation

**Start with API Server refactoring** because:
1. More straightforward (clearer boundaries between endpoints)
2. Higher impact (2,392 lines vs 1,081 lines)
3. Better team learning opportunity
4. Enables better API versioning strategy

Once API refactoring is proven successful, apply lessons learned to EmulatorService.

