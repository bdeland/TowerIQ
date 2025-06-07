# TowerIQ v1.0 - Development Task List (Part 1: The Foundation)

**📅 Implementation Status: ✅ COMPLETED (December 2024)**

This document outlines the foundational modules required to build the TowerIQ application. This includes the project structure, configuration management, the unified logging system, session state management, and the core services for interacting with the database and Docker infrastructure.

**🎯 All foundational components have been successfully implemented and tested with mandatory SQLCipher encryption.**

---

## **1. Project Structure & Initial Setup** ✅

**Goal:** Establish the complete directory structure for the project.
**Status:** ✅ **COMPLETED** - Full directory structure created and verified.

### **1.1. File Structure**

Create the following directory and file layout. Empty `__init__.py` files should be created in all Python source directories to define them as packages.

```
tower_iq/
├── .github/
├── .venv/
├── config/
│   ├── hook_contract.yaml
│   └── main_config.yaml
├── dist/
│   └── wsl_distro/
│       └── distro.tar.gz
├── resources/
│   ├── assets/
│   │   ├── icons/
│   │   │   ├── connected.svg
│   │   │   └── error.svg
│   │   └── app_icon.ico
│   └── docker/
│       ├── toweriq_backend/
│       │   ├── Dockerfile
│       │   └── supervisord.conf
│       └── docker-compose.yml
├── src/
│   ├── tower_iq/
│   │   ├── __init__.py
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── config.py
│   │   │   ├── logging_config.py
│   │   │   └── session.py
│   │   ├── gui/
│   │   │   ├── __init__.py
│   │   │   ├── assets.py
│   │   │   ├── components/
│   │   │   └── main_window.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── database_service.py
│   │   │   ├── docker_service.py
│   │   │   ├── emulator_service.py
│   │   │   └── frida_service.py
│   │   ├── main_controller.py
│   │   └── main_app_entry.py
│   └── __init__.py
├── .env.example
├── .gitignore
└── pyproject.toml
```

### **1.2. Core Dependencies (`pyproject.toml`)** ✅

**Status:** ✅ **COMPLETED** - All dependencies defined and working.
This file will define all project dependencies.

*   **Required Packages:**
    *   `python = "^3.11"`
    *   `pyqt6 = "^6.6"`
    *   `qasync = "^0.24"` (Crucial for bridging PyQt and asyncio)
    *   `structlog = "^23.2"`
    *   `colorama = "*"` (For colored console logs on Windows)
    *   `pyyaml = "^6.0"`
    *   `python-dotenv = "^1.0"`
    *   `docker = "^7.0"` (The `docker-py` library)
    *   `influxdb-client = {extras = ["async"], version = "^1.40"}`
    *   `sqlcipher-pysqlite3-wheels = "^0.5"` (For encrypted SQLite)
    *   `aiohttp = "^3.9"` (For async HTTP requests)
    *   `pycryptodome = "^3.20"` (For script signature validation & decryption)
    *   `frida = "^16.2"`
    *   `pyinstaller = "^6.3"` (For building the final executable)

---

## **2. Core Module: Configuration** ✅

**Goal:** Create a single, authoritative source for all application configuration.
**Status:** ✅ **COMPLETED** - ConfigurationManager fully implemented with YAML and .env support.

### **File: `src/tower_iq/core/config.py`**

*   **Purpose:** This module defines the `ConfigurationManager` class, which loads, validates, and provides access to all configuration settings from YAML and `.env` files.

#### **Class: `ConfigurationManager`**

*   **Purpose:** To be the single source of truth for all config values. An instance of this class is created once at startup and passed down to other components via dependency injection.

*   **Methods:**
    *   `__init__(self, yaml_path: str, env_path: str) -> None:`
        *   **Purpose:** Initializes the manager with paths to the config files.
        *   **Arguments:**
            *   `yaml_path`: Absolute path to `main_config.yaml`.
            *   `env_path`: Absolute path to the `.env` file.
        *   **State:** Initializes `self.settings` as an empty dictionary.

    *   `load_and_validate(self) -> None:`
        *   **Purpose:** The main method to perform the entire loading sequence. It reads the YAML, reads the `.env`, merges them, validates the result, and stores it in `self.settings`.
        *   **Logic:**
            1.  Calls private method `_load_yaml()`.
            2.  Calls private method `_load_dotenv()`.
            3.  Calls private method `_merge_configs()`.
            4.  Calls private method `_validate_config()`.

    *   `get(self, key: str, default: Any = None) -> Any:`
        *   **Purpose:** Provides simple dictionary-like access to the final, merged settings.
        *   **Example:** `config_manager.get("logging.level")`.

    *   `_load_yaml(self) -> dict:`
        *   **Purpose:** Loads the `main_config.yaml` file.
        *   **Returns:** A dictionary representing the YAML content.
        *   **Error Handling:** Raises `FileNotFoundError` or `yaml.YAMLError`.

    *   `_load_dotenv(self) -> dict:`
        *   **Purpose:** Loads the `.env` file.
        *   **Returns:** A dictionary of secrets from the `.env` file.

    *   `_merge_configs(self, yaml_config: dict, env_config: dict) -> None:`
        *   **Purpose:** Merges the two configurations. The `.env` config should take precedence for any overlapping keys (though this should be rare).

    *   `_validate_config(self) -> None:`
        *   **Purpose:** Validates the final merged configuration. Checks for the presence of essential keys.
        *   **Error Handling:** Raises `ValueError` if a required key is missing.

*   **Testing:**
    *   **Unit:** Test that YAML and `.env` files are loaded correctly. Verify that `.env` values correctly override YAML values. Test that validation raises errors on missing keys.
    *   ✅ **IMPLEMENTED:** Configuration loading and validation tested and working.

---

## **3. Core Module: Unified Logging System** ✅

**Goal:** Establish the `structlog`-based pipeline as the one and only logging system for the application.
**Status:** ✅ **COMPLETED** - Full structlog pipeline with JSON, console, and file outputs implemented.

### **File: `src/tower_iq/core/logging_config.py`**

*   **Purpose:** Provides the `setup_logging` function, which configures the entire pipeline based on the loaded configuration.

#### **Function: `setup_logging(config: ConfigurationManager) -> None`**

*   **Purpose:** The single entry point for initializing the logging system. Called once at application startup.
*   **Arguments:**
    *   `config`: The fully initialized `ConfigurationManager` instance.
*   **Logic:**
    1.  Extract logging settings from the `config` object (log levels, filters, file paths).
    2.  Define shared processors (`add_epoch_millis_timestamp`, `structlog.contextvars.merge_contextvars`, etc.).
    3.  Define custom processors (`SourceFilter`, `add_human_readable_timestamp`).
    4.  Call `structlog.configure()` to set up the global pipeline.
    5.  Get the root logger, clear any existing handlers.
    6.  Create and configure the mandatory `StdoutJsonHandler` and `FileFallbackHandler`.
    7.  If `console.enabled` is true in the config, create and configure the `ConsoleHandler`.
    8.  Add all active handlers to the root logger.

#### **Custom Processors (defined within `logging_config.py`)**

*   `add_epoch_millis_timestamp(logger, method_name, event_dict) -> dict:`
    *   **Purpose:** Adds a `timestamp_ms` key with the current epoch milliseconds to every log record.

*   `add_human_readable_timestamp(logger, method_name, event_dict) -> dict:`
    *   **Purpose:** Adds a `display_timestamp` key with a formatted local time string. Intended only for the console renderer.

*   **Class: `SourceFilter`**
    *   `__init__(self, enabled_sources: set[str]) -> None:`
        *   **Purpose:** Initializes the filter with a set of uppercase source names that are allowed to pass.
    *   `__call__(self, logger, method_name, event_dict) -> dict:`
        *   **Purpose:** The filter logic. If the log's `source` is not in `self.enabled_sources`, it raises `structlog.DropRecord`.

*   **Testing:**
    *   **Unit:** Verify that `setup_logging` correctly configures handlers based on the config.
    *   **Integration:** Test the `SourceFilter` by creating a logger, sending two messages from different sources, and asserting that only one appears on the (mocked) console handler. Verify `timestamp_ms` is present on all logs and `display_timestamp` is only on console logs.
    *   ✅ **IMPLEMENTED:** Logging system fully tested with multiple output formats working.

---

## **4. Core Module: Session Management** ✅

**Goal:** Create a centralized, thread-safe object to hold the application's volatile state.
**Status:** ✅ **COMPLETED** - Thread-safe SessionManager with all required state variables implemented.

### **File: `src/tower_iq/core/session.py`**

*   **Purpose:** This module defines the `SessionManager` class.

#### **Class: `SessionManager`**

*   **Purpose:** To be the single source of truth for dynamic application state like the current run ID, game version, and connection statuses.
*   **State Variables (private, e.g., `_current_runId`):**
    *   `current_runId: Optional[str] = None`
    *   `game_version: Optional[str] = None`
    *   `is_emulator_connected: bool = False`
    *   `is_frida_server_running: bool = False`
    *   `is_hook_active: bool = False`
    *   `current_monitoring_state: str = "NORMAL"` (values: "NORMAL", "HIGH_RESOLUTION")
*   **Internal Components:**
    *   `_lock = threading.Lock()`
*   **Methods:**
    *   The class will expose each state variable via Python properties (`@property`) for getters and setters.
    *   Every setter method **must** acquire `self._lock` before changing a value and release it in a `finally` block to ensure thread safety.
    *   `get_monitoring_state(self) -> str:`
    *   `set_monitoring_state(self, state: str) -> None:`
    *   `start_new_run(self) -> str:`
        *   **Purpose:** Generates a new UUID for a run, sets it as the `current_runId`, and returns it.
    *   `end_run(self) -> None:`
        *   **Purpose:** Resets `current_runId` to `None`.

*   **Testing:**
    *   **Unit/Integration:** Create two threads. Have one thread continuously set a value in the `SessionManager` while the other continuously reads it. Assert that no race conditions or corrupted data occur.
    *   ✅ **IMPLEMENTED:** Thread-safe SessionManager with properties and UUID generation tested and working.

---

## **5. Foundational Service: Docker Management** ✅

**Goal:** Create a service that reliably manages the application's Docker infrastructure.
**Status:** ✅ **COMPLETED** - Full Docker Compose orchestration with health monitoring implemented.

### **File: `src/tower_iq/services/docker_service.py`**

*   **Purpose:** Defines the `DockerService` class for interacting with the Docker Engine.

#### **Class: `DockerService`**

*   **Purpose:** To abstract all Docker and Docker Compose operations into a clean, async interface.
*   **Methods:**
    *   `__init__(self, config: ConfigurationManager, logger: Any) -> None:`
        *   **Purpose:** Initializes the service.
        *   **State:**
            *   `self.logger = logger.bind(source="DockerService")`
            *   `self.compose_file_path: str` (from config)
            *   `self.docker_client = docker.from_env()` (initializes the client)

    *   `async start_stack(self) -> bool:`
        *   **Purpose:** Starts the backend stack using `docker compose up -d`.
        *   **Logic:** Uses `asyncio.to_thread` or `run_in_executor` to run the blocking `docker-py` commands or a `subprocess` call to `docker compose`.
        *   **Returns:** `True` on success, `False` on failure.
        *   **Logs:** Logs the start attempt and the result.

    *   `async stop_stack(self) -> bool:`
        *   **Purpose:** Stops the backend stack using `docker compose down`.
        *   **Returns:** `True` on success, `False` on failure.

    *   `async is_healthy(self) -> bool:`
        *   **Purpose:** Performs a comprehensive health check.
        *   **Logic:**
            1.  Uses `self.docker_client` to find the `TowerIQ-Backend-Services` container and check if its status is "running".
            2.  Makes async HTTP requests (using `aiohttp`) to the health endpoints of the services running inside the container (e.g., `http://127.0.0.1:8086/health` for InfluxDB).
        *   **Returns:** `True` only if the container is running and all internal services are responsive.

*   **Testing:**
    *   **Integration:** Requires a running Docker daemon. Write tests that start, check, and stop a simple test container to verify the service's functionality. Mock the HTTP health check endpoints.
    *   ✅ **IMPLEMENTED:** Docker service with async operations, health checks, and container management tested and working.

---

## **6. Foundational Service: Database Management** ✅

**Goal:** Create a service that is the sole interface to both InfluxDB and the local SQLite database.
**Status:** ✅ **COMPLETED** - Full database abstraction with InfluxDB and encrypted SQLite support, migrations, and backups implemented.

### **File: `src/tower_iq/services/database_service.py`**

*   **Purpose:** Defines the `DatabaseService` class.

#### **Class: `DatabaseService`**

*   **Purpose:** To handle all database writes, reads, migrations, and backups.
*   **Methods:**
    *   `__init__(self, config: ConfigurationManager, logger: Any) -> None:`
        *   **Purpose:** Initializes the service with DB connection details from the config.
        *   **State:**
            *   `self.logger = logger.bind(source="DatabaseService")`
            *   `self.influx_client: Optional[InfluxDBClient] = None`
            *   `self.sqlite_conn: Optional[Connection] = None`
            *   `self.sqlite_db_path: str`
            *   `self.sqlite_encryption_key: str`

    *   `async connect(self) -> None:`
        *   **Purpose:** Establishes connections to both InfluxDB and the encrypted SQLite DB. Called once at startup.

    *   `async close(self) -> None:`
        *   **Purpose:** Gracefully closes both database connections.

    *   **InfluxDB Methods:**
        *   `async write_metric(self, measurement: str, fields: dict, tags: dict) -> None:`
        *   `async write_event(self, measurement: str, fields: dict, tags: dict) -> None:`
        *   **Logic:** These methods use the official `influxdb-client` async API to construct and write `Point` objects.
        *   **Error Handling:** Catches connection errors and logs them.

    *   **SQLite Methods:**
        *   `async run_migrations(self) -> None:`
            *   **Purpose:** Checks a `schema_version` table in the DB and applies any necessary `.sql` migration scripts.
        *   `async get_setting(self, key: str) -> Optional[str]:`
        *   `async set_setting(self, key: str, value: str) -> None:`
            *   **Logic:** Executes `INSERT OR REPLACE INTO settings...`
        *   `async backup_database(self, backup_path: str) -> None:`
            *   **Purpose:** Performs a safe online backup of the SQLite database file.

*   **Testing:**
    *   **Unit:** Mock the database clients. Verify that `write_metric` creates a correctly formatted InfluxDB `Point`. Verify that `set_setting` executes the correct SQL query.
    *   **Integration:** Requires running InfluxDB and a local file system. Write a value, read it back, and assert equality.
    *   ✅ **IMPLEMENTED:** Database service with dual InfluxDB/SQLite support, migrations, and backup functionality tested and working.

---

---

## **✅ IMPLEMENTATION SUMMARY**

This concludes **Part 1** of the development task list. **ALL FOUNDATIONAL COMPONENTS HAVE BEEN SUCCESSFULLY IMPLEMENTED AND TESTED.**

### **🎯 What Was Accomplished:**

1. ✅ **Complete Project Structure** - All directories, files, and packages created
2. ✅ **Core Configuration System** - YAML + .env loading with validation  
3. ✅ **Unified Logging System** - Structlog pipeline with JSON, console, and file outputs
4. ✅ **Session Management** - Thread-safe state management with UUID generation
5. ✅ **Docker Service** - Full container orchestration with health monitoring
6. ✅ **Database Service** - InfluxDB and encrypted SQLite integration with migrations
7. ✅ **Main Controller** - Application lifecycle and service orchestration
8. ✅ **Application Entry Point** - Complete initialization and dependency injection
9. ✅ **Docker Infrastructure** - Backend services with InfluxDB and health checks
10. ✅ **Testing Framework** - Foundation test script that validates all components

### **📊 Test Results:**
```
TowerIQ Foundation Test
==================================================
✅ Configuration Manager - PASSED
✅ Logging System - PASSED  
✅ Session Manager - PASSED
✅ Docker Service - PASSED
✅ Database Service - PASSED
==================================================
✅ All foundation tests passed!
```

### **🚀 Ready for Part 2:**
The foundation is now complete and ready for **Part 2** implementation, which will include:
- `EmulatorService` (ADB integration)
- `FridaService` (instrumentation framework)  
- GUI Framework (PyQt6 with qasync)
- `main_window.py` and GUI components

### **📝 Additional Files Created:**
- ✅ `README.md` - Comprehensive project documentation
- ✅ `test_foundation.py` - Foundation testing script
- ✅ `resources/docker/docker-compose.yml` - Backend services configuration
- ✅ `resources/docker/toweriq_backend/Dockerfile` - Backend container
- ✅ `resources/docker/toweriq_backend/supervisord.conf` - Process management

**🎉 The TowerIQ foundation is solid, tested, and ready for advanced features!**