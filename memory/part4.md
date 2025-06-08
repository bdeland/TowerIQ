## **TowerIQ Refactoring Plan: From Docker to Embedded**

**Objective:** To replace the Docker/WSL2/Grafana-based backend with a fully embedded stack using SQLite for storage and PyQtGraph for visualization. This will eliminate all external system dependencies and create a truly self-contained desktop application.

---

### **Part 1: Decommissioning the Old Infrastructure**

**Goal:** To completely remove all code and configuration related to the Docker-based stack. This is a "subtractive" phase to create a clean slate for the new components.

#### **Task 1.1: Delete Docker-Related Services and Utilities**

*   **Action:** Delete the following Python files entirely. Their functionality is no longer needed.
    *   `src/tower_iq/services/docker_service.py`
    *   `src/tower_iq/services/setup_service.py` (This will be replaced by a much simpler validator).
*   **Rationale:** We no longer manage Docker containers or a complex WSL2 environment.

#### **Task 1.2: Delete Docker and Infrastructure Configuration Files**

*   **Action:** Delete the following files and directories from the project root.
    *   `resources/docker/` (The entire directory, including `docker-compose.yml` and the custom image `Dockerfile`).
    *   `config/loki-config.yml`
    *   `config/promtail-config.yml`
    *   `dist/wsl_distro/` (The entire directory).
*   **Rationale:** These configuration files are specific to the decommissioned Docker stack.

#### **Task 1.3: Update Project Dependencies**

*   **File to Modify:** `pyproject.toml`
*   **Action:**
    *   **Remove** the following packages:
        *   `docker`
    *   **Add** the following new packages:
        *   `pyqtgraph = "^0.13"`
        *   `pandas = "^2.2"` (Often useful for data manipulation before plotting).
        *   `numpy = "^1.26"` (A dependency for both pandas and pyqtgraph).
*   **Rationale:** Swapping out the Docker library for the native plotting library.

---

### **Part 2: Implementing the New Embedded Backend**

**Goal:** To build the new `DatabaseService` and native UI components that replace InfluxDB, Loki, and Grafana.

#### **Task 2.1: Revamp the `DatabaseService` for SQLite**

*   **File to Modify:** `src/tower_iq/services/database_service.py`
*   **Action:** Rewrite the `DatabaseService` class almost entirely.
*   **New Class Definition:** `DatabaseService`
    *   **`__init__(self, config: ConfigurationManager, logger: Any)`:**
        *   Should now get the path to the single SQLite file from the config: `self.db_path = config.get("database.sqlite_path")`.
    *   **`connect(self) -> None:` (Was async, now synchronous):**
        *   Connect to the encrypted SQLite database using `sqlcipher-pysqlite3`.
        *   Enable Write-Ahead Logging for better concurrency: `self.sqlite_conn.execute("PRAGMA journal_mode=WAL;")`.
    *   **`run_migrations(self) -> None:` (Was async, now synchronous):**
        *   Execute `CREATE TABLE IF NOT EXISTS ...` statements for all required tables.
    *   **NEW: Define Table Schemas (within `run_migrations`):**
        *   **`runs` table:** `(run_id TEXT PRIMARY KEY, start_time INTEGER, end_time INTEGER, game_version TEXT, tier INTEGER)`
        *   **`metrics` table:** `(run_id TEXT, timestamp INTEGER, name TEXT, value REAL)` -> Add an index on `(run_id, name, timestamp)`.
        *   **`events` table:** `(run_id TEXT, timestamp INTEGER, name TEXT, data TEXT)` -> `data` column stores a JSON string.
        *   **`logs` table:** `(timestamp INTEGER, level TEXT, source TEXT, event TEXT, data TEXT)`
        *   **`settings` table:** `(key TEXT PRIMARY KEY, value TEXT)`
    *   **REWRITE `write_metric` (Was async, now synchronous):**
        *   `def write_metric(self, run_id: str, timestamp: int, name: str, value: float) -> None:`
        *   Executes an `INSERT INTO metrics ...` SQL statement.
    *   **REWRITE `write_event` (Was async, now synchronous):**
        *   `def write_event(self, run_id: str, timestamp: int, name: str, data: dict) -> None:`
        *   Serializes the `data` dictionary to a JSON string before inserting.
    *   **NEW: `write_log_entry(self, log_entry: dict) -> None:`**
        *   This is the new target for our logging handler.
        *   Takes a processed `structlog` dictionary and inserts it into the `logs` table.
    *   **NEW: `get_run_metrics(self, run_id: str, metric_name: str) -> pd.DataFrame:`**
        *   **Purpose:** Fetches all data for a specific metric in a run, ready for plotting.
        *   **Logic:** Executes `SELECT timestamp, value FROM metrics WHERE run_id = ? AND name = ?`.
        *   **Returns:** A pandas DataFrame, which is highly compatible with plotting libraries.

#### **Task 2.2: Create a New `SQLiteLogHandler`**

*   **File to Modify:** `src/tower_iq/core/logging_config.py`
*   **Action:** Create a new logging handler class that writes logs to the database.
*   **New Class Definition:** `SQLiteLogHandler(logging.Handler)`
    *   **`__init__(self, db_service: DatabaseService)`:**
        *   Takes an instance of the `DatabaseService` to communicate with the DB.
    *   **`emit(self, record: logging.LogRecord) -> None:`**
        *   This method is called by the logging system for each log record.
        *   **Logic:**
            1.  The `record` will contain the processed `structlog` dictionary.
            2.  It calls `self.db_service.write_log_entry(record.__dict__)`.

#### **Task 2.3: Update the Logging Configuration**

*   **File to Modify:** `src/tower_iq/core/logging_config.py`
*   **Action:** Modify the `setup_logging` function to use the new handler.
*   **Logic Changes:**
    *   **Remove** the `StdoutJsonHandler` and the `FileFallbackHandler`.
    *   **Instantiate** the new `SQLiteLogHandler`: `sqlite_handler = SQLiteLogHandler(db_service)`.
    *   **Add** this new handler to the root logger. The console handler for developers can remain.
    *   This ensures all logs now go to SQLite instead of `stdout` or files.

---

### **Part 3: Refactoring the UI and Controller**

**Goal:** Replace the web-based dashboard with native PyQt widgets and connect them to the new database service.

#### **Task 3.1: Refactor the Main Window and Dashboard Page**

*   **File to Modify:** `src/tower_iq/gui/main_window.py`
*   **Action:** Remove any `QWebEngineView` that was intended for Grafana.

*   **File to Modify:** `src/tower_iq/gui/components/dashboard_page.py`
*   **Action:** Replace the placeholder `GraphWidget` with a real implementation using `PyQtGraph`.
*   **New `GraphWidget` Implementation:**
    *   **`__init__(...)`:** Creates a `pyqtgraph.PlotWidget` and adds it to the layout.
    *   **`plot_data(self, df: pd.DataFrame) -> None:`**
        *   **Purpose:** Takes a pandas DataFrame and plots it.
        *   **Logic:** Clears any existing plot items. Calls `self.plot_widget.plot(x=df['timestamp'], y=df['value'])`.
    *   **`append_data_point(self, ...) -> None:` (To be removed or redesigned)**
        *   Real-time plotting is more efficient by re-querying and re-plotting recent data rather than appending single points. This method should be re-evaluated.

#### **Task 3.2: Update the `MainController`**

*   **File to Modify:** `src/tower_iq/main_controller.py`
*   **Action:** Update the controller's logic to work with the new synchronous services and UI components.

*   **Logic Changes:**
    *   **Service Initialization:** The `__init__` no longer needs to create `DockerService` or `SetupService`.
    *   **`run()` method:** The startup sequence is now much simpler. It just needs to connect to the database. The `_monitor_system_health` task can be simplified to just check the emulator connection.
    *   **`_handle_game_metric` method:**
        *   The call to `await self.db_service.write_metric(...)` becomes a synchronous call, which must be run in a thread to avoid blocking the event loop: `await asyncio.to_thread(self.db_service.write_metric, ...)`.
        *   After writing, it should fetch the recent data and update the UI: `df = await asyncio.to_thread(self.db_service.get_run_metrics, ...)` followed by `self.new_graph_data.emit("cph_graph", df)`.
    *   **`_handle_game_event` method:** This follows the same pattern: a synchronous database call wrapped in `asyncio.to_thread`.

#### **Task 3.3: Update the Entry Point and Setup Flow**

*   **File to Modify:** `src/tower_iq/main_app_entry.py`
*   **Action:** Remove all logic related to the complex setup wizard.

*   **New Simplified Setup Flow:**
    1.  The `main()` function still creates the core components (`Config`, `Logger`, `Controller`).
    2.  Instead of a complex wizard, the `MainController`'s `run()` method now simply calls `db_service.connect()` and `db_service.run_migrations()`.
    3.  The complex logic for installing WSL and Docker is completely gone. The only prerequisite check needed is to see if an emulator can be found via ADB. This check can now live inside the `EmulatorService`.