# TowerIQ - Advanced Mobile Game Analysis Platform

TowerIQ is a sophisticated platform for analyzing and monitoring mobile games using advanced instrumentation techniques. This implementation provides a complete backend architecture with a PyQt6 GUI for real-time game data collection, analysis, and visualization through Frida instrumentation.

## 🏗️ Architecture Overview

TowerIQ follows a modular, service-oriented architecture designed for robustness and maintainability.

- **`main_app_entry.py`**: The application's entry point, responsible for initializing the PyQt application, the `asyncio` event loop (via `qasync`), and all core components. It orchestrates the startup and graceful shutdown sequences.
- **`MainController`**: The central nervous system of the application. It acts as an orchestrator, managing the lifecycle of all services and facilitating communication between the backend services and the GUI using the PyQt signal/slot mechanism.
- **Service Layer**: A collection of specialized services that handle specific domains:
    - `DatabaseService`: Manages all interactions with the embedded SQLite database, including data storage, retrieval, and schema migrations.
    - `EmulatorService`: Handles all low-level communication with Android devices via ADB, including device discovery, connection, and the entire `frida-server` lifecycle management (download, push, start, and monitor).
    - `FridaService`: Manages the Frida instrumentation process, including attaching to the target process, injecting the JavaScript hook, and managing the bi-directional communication channel.
- **GUI Layer**: A modern user interface built with PyQt6.
    - `MainWindow`: The main application window that contains the navigation structure and hosts the different UI pages.
    - **Components**: Reusable UI widgets, including a `DashboardPage` for data visualization and a stateful `ConnectionStatePanel` that guides the user through the connection process.
- **Core Modules**: Foundational components for configuration, logging, and session management.

```mermaid
graph TD
    subgraph User Interface (PyQt6)
        MainWindow -- contains --> DashboardPage
        DashboardPage -- contains --> ConnectionStatePanel
        DashboardPage -- contains --> GraphWidget
        MainWindow -- manages --> HistoryPage
        MainWindow -- manages --> SettingsPage
    end

    subgraph Backend Services
        MainController
        DatabaseService[(SQLite DB)]
        EmulatorService -- manages --> FridaServer[frida-server on device]
        FridaService -- manages --> FridaHook[JS Hook in Game]
    end

    subgraph Game
        TheTower[The Tower Process] -- instrumented by --> FridaHook
    end

    subgraph Core
        Config[Configuration]
        Logger[Logging]
        Session[Session State]
    end

    %% Interactions
    main_app_entry(main_app_entry.py) --> MainController
    MainController -- uses --> Config
    MainController -- uses --> Logger
    MainController -- uses --> Session
    MainController -- orchestrates --> DatabaseService
    MainController -- orchestrates --> EmulatorService
    MainController -- orchestrates --> FridaService

    MainWindow -- interacts with --> MainController
    ConnectionStatePanel -- signals to --> MainController
    MainController -- sends data to --> DashboardPage

    EmulatorService -- talks to --> ADB[ADB Server]
    ADB -- talks to --> TheTower
    FridaService -- attaches to --> TheTower
```

## 📁 Project Structure

```
TowerIQ/
├── config/
│   ├── main_config.yaml      # Main application configuration
│   └── hook_contract.yaml    # Frida hook contract specification
├── data/                       # Default location for the SQLite database
├── logs/                       # Application log files
├── resources/
│   ├── assets/               # UI assets (icons)
│   └── hooks/                # (Not used, hooks are compiled from src)
├── src/
│   └── tower_iq/
│       ├── core/
│       │   ├── config.py         # Configuration management
│       │   ├── logging_config.py # Unified logging system
│       │   └── session.py        # Session state management
│       ├── gui/
│       │   ├── main_window.py    # Main application window
│       │   ├── assets.py         # Asset management
│       │   └── components/
│       │       ├── dashboard_page.py        # Dashboard with metrics
│       │       ├── connection_state_panel.py # Multi-stage connection wizard
│       │       ├── history_page.py          # Run history page
│       │       └── settings_page.py         # Settings page
│       ├── services/
│       │   ├── database_service.py # SQLite database management
│       │   ├── emulator_service.py # ADB & frida-server management
│       │   └── frida_service.py    # Frida instrumentation & communication
│       ├── scripts/
│       │   ├── hook.js             # The source Frida hook script
│       │   └── hook_compiled.js    # The compiled hook for injection
│       ├── main_controller.py      # Application orchestrator
│       └── main_app_entry.py       # Application entry point
├── pyproject.toml              # Project dependencies and metadata
└── README.md                   # This file
```

## 📚 Key Modules and Methods

This section provides a detailed overview of the application's key components and their responsibilities.

### `main_app_entry.py`
The single entry point for the application.
- **`main()`**: Initializes all core components (`ConfigurationManager`, logging), sets up the `QApplication` and the `qasync` event loop, instantiates the `MainController` and `MainWindow`, and manages the application's run and graceful shutdown sequence.

### `main_controller.py`
The central orchestrator of the application. It connects the backend services to the GUI.
- **`__init__()`**: Initializes all services (`DatabaseService`, `EmulatorService`, `FridaService`, `SessionManager`).
- **`run()`**: The main async method started by the entry point. It connects to the database and initiates the device connection workflow (either automatically or by preparing the UI for manual connection).
- **`stop()`**: Handles graceful shutdown of the application, ensuring all services are stopped and resources are released.
- **`on_*_requested()` slots**: A series of PyQt slots that respond to user actions from the `ConnectionStatePanel` (e.g., `on_scan_devices_requested`). These trigger async `_handle_*` methods to perform the actual work.
- **`_listen_for_frida_messages()`**: An async task that continuously listens for messages from the `FridaService` queue and dispatches them to appropriate handlers (e.g., `_handle_game_metric`).
- **`_emit_signal_safely()`**: A thread-safe utility to emit PyQt signals from `asyncio` tasks, preventing cross-thread exceptions.

### `services/database_service.py`
Manages all database operations for the encrypted SQLite database.
- **`connect()`**: Establishes the database connection and enables Write-Ahead Logging (WAL) for better concurrency.
- **`close()`**: Gracefully closes the connection, ensuring WAL files are checkpointed and cleaned up.
- **`run_migrations()`**: Creates the database schema (`runs`, `metrics`, `events`, `logs`, `settings` tables) if it doesn't exist.
- **`write_metric()` / `write_event()`**: Methods to persist time-series data and discrete events from the game.

### `services/emulator_service.py`
Handles all low-level device interaction via ADB and manages the `frida-server` lifecycle. This service contains numerous fixes to handle quirks of different Android emulators.
- **`find_and_connect_device()`**: Scans for and connects to an ADB device.
- **`ensure_frida_server_is_running()`**: A critical, idempotent method that handles the entire `frida-server` setup: checks for a responsive server, downloads the correct binary for the device's architecture if needed, pushes it to the device (handling `adb` quirks), and starts it as a detached process using `setsid`.
- **`is_frida_server_responsive()`**: A reliable check that attempts a real Frida connection to see if the server is active.
- **`get_game_pid()`**: Finds the process ID of the target application.
- **`get_installed_third_party_packages()`**: Retrieves a list of installed applications for the process selection UI.

### `services/frida_service.py`
The bridge between the Python application and the JavaScript hooks running in the game.
- **`attach()`**: Attaches Frida to the target process.
- **`detach()`**: Detaches cleanly, using a "poison pill" message and timeouts to prevent the application from hanging on shutdown.
- **`inject_and_run_script()`**: Injects the compiled JavaScript hook into the target process.
- **`check_local_hook_compatibility()`**: Validates that the hook is compatible with the target game version by checking against a `hook_contract.yaml` file.
- **`_on_message()`**: The callback that receives messages from the Frida hook. It places them onto an `asyncio.Queue` for thread-safe processing.
- **`get_message()`**: The async method used by the `MainController` to retrieve messages from the queue. It is designed to be shutdown-aware to prevent deadlocks.

### `gui/main_window.py`
The main application window and UI container.
- **`__init__()`**: Sets up the main window, including the navigation panel and the `QStackedWidget` for managing different pages.
- **`_connect_signals()`**: Connects signals from the `MainController` to slots in the UI pages (e.g., to update graphs) and vice-versa.
- **`closeEvent()`**: Overridden to ensure a clean shutdown and proper cleanup of UI timers.

### `gui/components/dashboard_page.py`
The main page for displaying data visualizations.
- **`set_connection_active()`**: Toggles the view between the data dashboard and the connection panel overlay.
- **`GraphWidget`**: A reusable component that encapsulates a `pyqtgraph` plot for displaying real-time data.
- **`update_metric_display()`**: A PyQt slot that receives new data from the controller and updates the appropriate graph.

### `gui/components/connection_state_panel.py`
A stateful wizard that guides the user through the connection process.
- **Multi-Stage UI**: Presents a three-step process for Device Selection, Process Selection, and Hook Activation.
- **Signal Emission**: Emits signals (e.g., `scan_devices_requested`) to the `MainController` when the user interacts with the panel.
- **State Updates**: Provides public methods that the controller calls to populate the UI with data (e.g., lists of devices and processes).

## 🚀 Current Implementation Status

### ✅ Completed Features
- **Project Structure & Dependencies**: Poetry-based dependency management.
- **Core Systems**: YAML-based configuration, `structlog`-based logging, and thread-safe session management.
- **Main Controller**: `QObject`-based orchestrator with signal/slot architecture.
- **Database Service**: Embedded SQLite with WAL mode and data persistence for runs, metrics, events, and logs.
- **Emulator Service**: Robust ADB device discovery and comprehensive `frida-server` lifecycle management with fixes for common emulator issues.
- **Frida Service**: Secure script injection and thread-safe, bi-directional communication with the in-game hook.
- **GUI**: A complete PyQt6-based user interface with a multi-page design, real-time plotting with `pyqtgraph`, and a guided connection wizard.
- **Embedded Architecture**: Fully self-contained desktop application with no external service dependencies (like Docker or WSL).

## 🏃‍♂️ Running the Application

### Development Mode

```bash
# Using Poetry (recommended)
poetry install
poetry run python -m src.tower_iq.main_app_entry
```

### Target Game Setup

1. **Install "The Tower" game** on your Android device/emulator
   - Package name: `com.TechTreeGames.TheTower`
   - Available on Google Play Store

2. **Enable USB Debugging** on your Android device

3. **Connect device** via USB or start emulator

4. **Launch TowerIQ** - it will automatically:
   - Discover connected devices
   - Install frida-server
   - Detect the game process
   - Inject monitoring hooks

## 🔄 Application Workflow

### Automatic Connection Flow

TowerIQ can be configured to automatically connect on startup:

1.  **Device Discovery**: Automatically scans for and connects to an ADB device.
2.  **Frida Setup**: Installs and starts the correct `frida-server` on the target device.
3.  **Game Detection**: Finds the running process for the configured game package.
4.  **Hook Injection**: Validates compatibility and injects the monitoring script.
5.  **Data Collection**: Streams metrics and events from the game to the backend.

### Manual Connection Flow

If automatic connection is disabled or fails, the `ConnectionStatePanel` guides the user:
1. **Stage 1**: User clicks "Scan for Devices" and selects a device from the list.
2. **Stage 2**: User clicks "Refresh Process List" and selects the target game process.
3. **Stage 3**: User reviews the selections and clicks "Activate Hook" to begin monitoring.

### Message Flow Architecture

```
Game Process → Frida Hook → FridaService → MessageQueue → MainController → DatabaseService
                                                                   ↓
                                                          PyQt Signals → GUI Components → PyQtGraph
```

## 📊 Logging and Monitoring

TowerIQ implements a sophisticated logging system with database integration:

### Log Storage

- **SQLite Database**: All logs stored in encrypted database
- **Console Output**: Colored development logs
- **Structured Format**: JSON-compatible log entries

### Log Sources

Logs are tagged by source for easy filtering:
- `MainController`: Application orchestration and message dispatch
- `DatabaseService`: Database operations and migrations
- `EmulatorService`: ADB device management and frida-server control
- `FridaService`: Script injection and message handling
- `GUI`: User interface events

### Example Log Entry

```json
{
  "timestamp": 1703123456789,
  "level": "INFO",
  "source": "FridaService",
  "event": "Script injected successfully",
  "game_version": "1.2.3",
  "pid": 12345,
  "run_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 🔒 Security Features

- **Hook Contract Validation**: The `hook_contract.yaml` can be used to restrict hooking to specific game versions.
- **Environment Variable Isolation**: Sensitive data can be stored in a `.env` file.

## Command Line Usage

You can run the main application as usual:

```
poetry run tower-iq
```

### Frida Server Reset Command

To update and start the frida-server on the first connected Android device (without launching the GUI), use:

```
poetry run tower-iq --reset-frida
```

This will:
- Scan for connected ADB devices
- Update and push the correct frida-server binary to the first device found
- Start frida-server and verify it is running
- Print success or error to the console and exit

If no device is found, or if the operation fails, an error message will be printed and the process will exit with a nonzero code.

## Database and Metrics

- All metrics and events are now associated with a run identifier that matches the `roundSeed` generated by the game itself. This ensures that all data is grouped and queried by the same seed value used in-game.
- The previous system used a randomly generated UUID for each run; this has been replaced by the in-game `roundSeed` for full alignment with game logic and data.

## Database Schema Changes

- The `runs` table now includes:
  - `CPH`: Coins per hour (calculated as coins_earned / (duration_realtime in hours))
  - `round_cells`: Final aggregate value of cells earned this round
  - `round_gems`: Final aggregate value of gems earned this round
  - `round_cash`: Final aggregate value of cash earned this round
- `duration_realtime` is now stored in seconds (auto-converted from ms if needed).

---

**Implementation Status**: All core features are implemented in a fully embedded architecture using Python, PyQt6, and SQLite. The application is ready for further development or refactoring.