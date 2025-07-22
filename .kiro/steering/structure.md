# TowerIQ Project Structure

## Architecture Pattern
- **Service-Oriented Architecture**: Modular services managed by MainController
- **PyQt Signal/Slot**: Event-driven communication between GUI and backend
- **Async/Await**: Non-blocking operations with qasync bridge

## Directory Organization

### Core Application (`src/tower_iq/`)
- `main_app_entry.py`: Single application entry point
- `main_controller.py`: Central orchestrator (QObject with signals/slots)

### Core Modules (`src/tower_iq/core/`)
- `config.py`: YAML configuration management
- `logging_config.py`: Structured logging setup
- `session.py`: Session state management
- `utils.py`: Common utilities

### Services (`src/tower_iq/services/`)
- `database_service.py`: SQLite operations and migrations
- `emulator_service.py`: ADB device management and frida-server lifecycle
- `frida_service.py`: Script injection and message handling
- `frida_manager.py`: High-level Frida coordination

### GUI (`src/tower_iq/gui/`)
- `main_window.py`: Main application window (QStackedWidget)
- `connection_page.py`: Multi-stage connection wizard
- `dashboards_page.py`: Real-time data visualization
- `settings_page.py`: Application settings
- `assets.py`: Resource management

### Scripts (`src/tower_iq/scripts/`)
- `hook.js`: Source Frida hook (TypeScript)
- `hook_compiled.js`: Compiled JavaScript for injection

## Configuration (`config/`)
- `main_config.yaml`: Application settings
- `hook_contract.yaml`: Supported game versions and compatibility

## Data Storage
- `data/`: SQLite databases and runtime data
- `logs/`: Application log files
- `memory/`: Development notes and documentation

## Key Patterns

### Service Initialization
Services are initialized in MainController and communicate via PyQt signals:
```python
self.db_service = DatabaseService(config, logger)
self.emulator_service = EmulatorService(config, logger)
self.frida_service = FridaService(config, logger)
```

### Message Flow
```
Game → Frida Hook → FridaService → MessageQueue → MainController → GUI
```

### Error Handling
- Services raise specific exceptions (e.g., `FridaServerSetupError`)
- MainController handles errors and emits status signals
- GUI displays user-friendly error messages

### Async Patterns
- Use `asyncio.Queue` for thread-safe message passing
- `qasync` bridges PyQt6 event loop with asyncio
- Services implement async methods for non-blocking operations