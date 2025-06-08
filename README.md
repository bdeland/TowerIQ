# TowerIQ v1.0 - Advanced Mobile Game Analysis Platform

TowerIQ is a sophisticated platform for analyzing and monitoring mobile games using advanced instrumentation techniques. This implementation provides a complete backend architecture with PyQt6 GUI for real-time game data collection, analysis, and visualization through Frida instrumentation.

## 🏗️ Architecture Overview

TowerIQ follows a modular, service-oriented architecture with the following key components:

- **Core Foundation**: Configuration management, unified logging, and thread-safe session state
- **Service Layer**: SQLite database management, emulator control, and Frida instrumentation
- **Controller Layer**: Message dispatch pattern with PyQt signals for UI communication
- **GUI Layer**: Modern PyQt6-based user interface with PyQtGraph visualization
- **Data Layer**: Encrypted SQLite for all data storage with time-series metrics support

## 📁 Project Structure

```
TowerIQ/
├── config/                     # Configuration files
│   ├── main_config.yaml       # Main application configuration
│   └── hook_contract.yaml     # Frida hook contract specification
├── src/tower_iq/              # Main application source
│   ├── core/                  # Core foundation modules
│   │   ├── config.py         # Configuration management
│   │   ├── logging_config.py # Unified logging system
│   │   └── session.py        # Session state management
│   ├── services/              # Service layer
│   │   ├── database_service.py # SQLite database management
│   │   ├── emulator_service.py # ADB device management
│   │   └── frida_service.py   # Frida instrumentation
│   ├── gui/                   # User interface
│   │   ├── main_window.py    # Main application window
│   │   ├── assets.py         # Asset management
│   │   └── components/       # UI components
│   │       ├── dashboard_page.py   # Dashboard with metrics
│   │       ├── status_indicator.py # Status display widget
│   │       ├── history_page.py     # Run history page
│   │       └── settings_page.py    # Settings page
│   ├── main_controller.py     # Application orchestrator with PyQt signals
│   └── main_app_entry.py      # Application entry point
├── resources/                 # Static resources
│   └── assets/               # UI assets and icons
├── memory/                   # Development documentation
│   ├── part1.md             # Foundation implementation (completed)
│   ├── part2.md             # Core services implementation (completed)
│   ├── part3.md             # GUI implementation (completed)
│   └── part4.md             # Embedded refactoring (completed)
├── data/                     # Application data directory
├── logs/                     # Application logs
├── pyproject.toml            # Project dependencies and metadata
└── README.md                # This file
```

## 🚀 Current Implementation Status

### ✅ Completed (Part 1: Foundation)

1. **Project Structure & Dependencies**
   - Complete directory structure with proper Python packages
   - Poetry-based dependency management with PyQt6, PyQtGraph, and all required dependencies
   - Python 3.11+ support

2. **Core Configuration System**
   - YAML-based configuration with `.env` override support
   - Dot-notation access to nested configuration values
   - Comprehensive validation and error handling

3. **Unified Logging System**
   - Structlog-based pipeline with multiple output formats
   - JSON logs for machine processing
   - Colored console output for development
   - Source-based filtering system
   - Database integration for log storage

4. **Session Management**
   - Thread-safe session state management with properties
   - Run ID generation and tracking with UUIDs
   - Connection status monitoring (emulator, frida-server, hook)
   - Monitoring state management (NORMAL/HIGH_RESOLUTION)

### ✅ Completed (Part 2: Core Logic & Services)

5. **Main Controller**
   - **PyQt QObject** with signal/slot architecture
   - **Message Dispatch Pattern** for Frida communication
   - Application lifecycle management with async support
   - Service orchestration with background task management
   - Health monitoring and error handling

6. **Database Service (Embedded SQLite)**
   - **Encrypted SQLite** with mandatory SQLCipher encryption
   - Time-series metrics storage with run tracking
   - Application state and settings management
   - Database migrations system
   - Pandas DataFrame integration for data analysis

7. **Emulator Service**
   - **ADB device discovery** and automatic connection
   - Device architecture detection for frida-server compatibility
   - **Frida-server installation** and lifecycle management
   - Game process detection by package name
   - Connection health monitoring

8. **Frida Service**
   - **Secure script injection** with signature verification
   - Process attachment and detachment management
   - **Async message queue** for script communication
   - Script download and verification workflow
   - Thread-safe message bridging to asyncio

### ✅ Completed (Part 3: GUI Implementation)

9. **Main Window**
   - PyQt6-based main application window
   - Navigation and stacked widget layout
   - Status indicator integration
   - Asset management for bundled resources

10. **Dashboard Components**
    - Dashboard page with real-time metric displays
    - Status indicator widget for connection status
    - History page for run tracking
    - Settings page for configuration
    - PyQtGraph integration for live data visualization

### ✅ Completed (Part 4: Embedded Architecture)

11. **Fully Embedded Stack**
    - Removed all Docker/WSL dependencies
    - Self-contained SQLite-only architecture
    - PyQtGraph-based native visualization
    - Complete desktop application with no external dependencies

## 🛠️ Installation & Setup

### Prerequisites

- Python 3.11 or higher
- ADB (Android Debug Bridge) - part of Android SDK Platform Tools
- Android emulator or physical device with USB debugging enabled

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd TowerIQ
   ```

2. **Install dependencies**
   ```bash
   # Using Poetry (recommended)
   poetry install
   
   # Or using pip
   pip install -e .
   ```

3. **Configure the application**
   ```bash
   # Copy and edit configuration
   cp .env.example .env
   # Edit .env with your specific settings
   ```

## 🔧 Configuration

### Main Configuration (`config/main_config.yaml`)

The main configuration file controls all aspects of the application:

- **Application settings**: Name, version, debug mode
- **Logging configuration**: Levels, outputs, source filtering
- **Database settings**: Encrypted SQLite configuration
- **Emulator settings**: ADB path, target package (`com.TechTreeGames.TheTower`)
- **Frida settings**: Server port, script validation, security options
- **GUI settings**: Theme, window size, auto-connect options
- **Monitoring settings**: Polling intervals, resolution modes

### Environment Variables (`.env`)

Sensitive configuration is stored in environment variables:

- `SQLITE_ENCRYPTION_KEY`: SQLite database encryption key (mandatory)
- `FRIDA_SIGNATURE_KEY`: Frida script signature validation key
- `DEBUG_MODE`: Override debug mode setting

## 🏃‍♂️ Running the Application

### Development Mode

```bash
# Run the main application
python -m tower_iq.main_app_entry

# Or using Poetry
poetry run python -m tower_iq.main_app_entry

# Or using the entry point script
poetry run tower-iq
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

TowerIQ implements a zero-touch approach for device connection:

1. **Device Discovery**: Automatically scans for ADB devices on startup
2. **Frida Setup**: Installs and starts frida-server on the target device
3. **Game Detection**: Finds the running Tower game process
4. **Hook Injection**: Securely downloads and injects monitoring scripts
5. **Data Collection**: Streams metrics and events to the database

### Message Flow Architecture

```
Game Process → Frida Script → FridaService → MessageQueue → MainController → DatabaseService
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
  "timestamp_ms": 1703123456789,
  "level": "INFO",
  "source": "FridaService",
  "event": "Script injected successfully",
  "game_version": "1.2.3",
  "pid": 12345,
  "run_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 🗄️ Database Schema

### SQLite Schema (Encrypted)

- **runs**: `(run_id, start_time, end_time, game_version, tier)`
- **metrics**: `(run_id, timestamp, name, value)` - Time-series game metrics
- **events**: `(run_id, timestamp, name, data)` - Discrete game events
- **logs**: `(timestamp, level, source, event, data)` - Application logs
- **settings**: `(key, value)` - Application configuration storage

All data is encrypted using SQLCipher with mandatory encryption keys.

## 🔒 Security Features

- **Mandatory Database Encryption**: All SQLite databases use SQLCipher encryption
- **Script Signature Verification**: Frida scripts validated before injection
- **Secure Script Download**: Encrypted script delivery with hash verification
- **Environment Variable Isolation**: Sensitive data in environment variables
- **Source-based Access Control**: Log filtering and access management

## 🧪 Testing

### Development Testing

Test the application components:

```bash
# Run with Poetry
poetry run python -m tower_iq.main_app_entry

# Check database connection
python -c "from src.tower_iq.services.database_service import DatabaseService; print('Database module loaded successfully')"
```

## 📈 Performance Considerations

- **Async Architecture**: Non-blocking I/O for all services using asyncio
- **PyQt Integration**: qasync bridge for seamless Qt/asyncio integration
- **Thread Safety**: Proper locking in SessionManager and message queues
- **Memory Management**: Careful resource cleanup with context managers
- **Background Monitoring**: Efficient health checks and status updates
- **Database Optimization**: Indexed queries and prepared statements
- **Native Visualization**: PyQtGraph for efficient real-time plotting

## 🎯 Game Analysis Features

### Real-time Metrics
- **Coins per Hour (CPH)**: Live calculation and tracking
- **Elevator Performance**: Speed and efficiency metrics
- **Resource Management**: Coin generation and spending patterns
- **Progress Tracking**: Floor progression and achievement monitoring

### Event Detection
- **Game State Changes**: Round start/end, prestige events
- **User Actions**: Purchases, upgrades, strategic decisions
- **Performance Milestones**: Achievement unlocks and progress markers

### Data Visualization
- **PyQtGraph Charts**: Real-time metric plotting with smooth updates
- **Dashboard Widgets**: Live metric displays with historical context
- **Run History**: Complete analysis of past gaming sessions

## 🤝 Contributing

1. Follow the established architecture patterns
2. Maintain comprehensive logging with structured output
3. Add tests for new functionality
4. Update documentation and type hints
5. Follow the message dispatch pattern for new features

## 🆘 Troubleshooting

### Common Issues

1. **Device not detected**: Check ADB installation and USB debugging
2. **Frida-server fails**: Ensure device has root access or use ADB root
3. **Game not found**: Verify "The Tower" is installed and running
4. **Database errors**: Check SQLite encryption key in .env file
5. **GUI not loading**: Ensure PyQt6 is properly installed

### Debug Information

```bash
# Check ADB devices
adb devices

# Verify game process
adb shell ps | grep tower

# Check application logs in database or console output
poetry run python -m tower_iq.main_app_entry
```

---

**Implementation Status**: Complete! All parts 1-4 implemented with fully embedded SQLite architecture, PyQt6 GUI, PyQtGraph visualization, and zero external dependencies. 