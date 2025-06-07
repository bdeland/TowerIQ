# TowerIQ v1.0 - Advanced Mobile Game Analysis Platform

TowerIQ is a sophisticated platform for analyzing and monitoring mobile games using advanced instrumentation techniques. This implementation provides the foundational architecture for real-time game data collection, analysis, and visualization.

## 🏗️ Architecture Overview

TowerIQ follows a modular, service-oriented architecture with the following key components:

- **Core Foundation**: Configuration management, unified logging, and session state
- **Service Layer**: Docker orchestration, database management, emulator control, and Frida instrumentation
- **GUI Layer**: Modern PyQt6-based user interface with async support
- **Data Layer**: InfluxDB for time-series data and encrypted SQLite for application state

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
│   │   ├── docker_service.py # Docker orchestration
│   │   ├── database_service.py # Database management
│   │   ├── emulator_service.py # Emulator control (planned)
│   │   └── frida_service.py   # Frida instrumentation (planned)
│   ├── gui/                   # User interface (planned)
│   ├── main_controller.py     # Application orchestrator
│   └── main_app_entry.py      # Application entry point
├── resources/                 # Static resources
│   ├── docker/               # Docker configuration
│   │   ├── docker-compose.yml
│   │   └── toweriq_backend/  # Backend container
│   └── assets/               # UI assets (planned)
├── pyproject.toml            # Project dependencies and metadata
└── test_foundation.py        # Foundation testing script
```

## 🚀 Current Implementation Status

### ✅ Completed (Part 1: Foundation)

1. **Project Structure & Dependencies**
   - Complete directory structure
   - Poetry-based dependency management
   - Python 3.11+ requirement

2. **Core Configuration System**
   - YAML-based configuration with `.env` override support
   - Dot-notation access to nested configuration values
   - Comprehensive validation and error handling

3. **Unified Logging System**
   - Structlog-based pipeline with multiple output formats
   - JSON logs for machine processing
   - Colored console output for development
   - Rotating file logs with configurable retention
   - Source-based filtering system

4. **Session Management**
   - Thread-safe session state management
   - Run ID generation and tracking
   - Connection status monitoring
   - Monitoring state management (NORMAL/HIGH_RESOLUTION)

5. **Docker Service**
   - Docker Compose orchestration
   - Health monitoring for containerized services
   - Async container management
   - Log retrieval and monitoring

6. **Database Service**
   - InfluxDB integration for time-series data
   - Encrypted SQLite for application state
   - Database migrations system
   - Automated backup and retention

7. **Main Controller**
   - Application lifecycle management
   - Service orchestration
   - Background task management
   - Graceful shutdown handling

### 🔄 In Progress (Part 2: Core Services)

- Emulator Service (ADB integration)
- Frida Service (instrumentation framework)
- GUI Framework (PyQt6 with qasync)

### 📋 Planned (Part 3: Advanced Features)

- Real-time data visualization
- Hook script management
- Performance monitoring
- Export and reporting features

## 🛠️ Installation & Setup

### Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose
- Poetry (recommended) or pip

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

# Note: This will install sqlcipher3-wheels which includes 
# a self-contained SQLCipher implementation with mandatory encryption
   ```

3. **Configure the application**
   ```bash
   # Copy and edit configuration
   cp .env.example .env
   # Edit .env with your specific settings
   ```

4. **Test the foundation**
   ```bash
   python test_foundation.py
   ```

## 🔧 Configuration

### Main Configuration (`config/main_config.yaml`)

The main configuration file controls all aspects of the application:

- **Application settings**: Name, version, debug mode
- **Logging configuration**: Levels, outputs, source filtering
- **Database settings**: InfluxDB and SQLite configuration
- **Docker settings**: Compose file location, health endpoints
- **Emulator settings**: ADB path, target package
- **Frida settings**: Server port, script validation
- **GUI settings**: Theme, window size, auto-start options

### Environment Variables (`.env`)

Sensitive configuration is stored in environment variables:

- `INFLUXDB_TOKEN`: InfluxDB authentication token
- `SQLITE_ENCRYPTION_KEY`: SQLite database encryption key
- `FRIDA_SIGNATURE_KEY`: Frida script signature validation key
- `DEBUG_MODE`: Override debug mode setting

## 🏃‍♂️ Running the Application

### Development Mode

```bash
# Run the foundation test
python test_foundation.py

# Run the main application (when GUI is implemented)
python -m tower_iq.main_app_entry

# Or using Poetry
poetry run tower-iq
```

### Docker Backend

The application uses Docker for backend services:

```bash
# Start backend services
docker-compose -f resources/docker/docker-compose.yml up -d

# Check service health
docker-compose -f resources/docker/docker-compose.yml ps

# Stop services
docker-compose -f resources/docker/docker-compose.yml down
```

## 📊 Logging and Monitoring

TowerIQ implements a sophisticated logging system:

### Log Outputs

1. **JSON Logs**: Machine-readable logs for processing
2. **Console Logs**: Colored output for development
3. **File Logs**: Rotating files with configurable retention

### Log Sources

Logs are tagged by source for easy filtering:
- `MainController`: Application orchestration
- `DockerService`: Container management
- `DatabaseService`: Database operations
- `EmulatorService`: Device communication
- `FridaService`: Instrumentation activities
- `GUI`: User interface events

### Example Log Entry

```json
{
  "timestamp_ms": 1703123456789,
  "level": "INFO",
  "source": "MainController",
  "event": "Application started successfully",
  "version": "1.0.0",
  "run_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 🗄️ Database Schema

### InfluxDB (Time-Series Data)

- **Measurements**: Game metrics, performance data, events
- **Tags**: Run ID, game version, device info
- **Fields**: Numeric values, timestamps, metadata

### SQLite (Application State)

- **settings**: Key-value configuration storage
- **run_sessions**: Monitoring session tracking
- **hook_activity**: Frida hook execution logs

## 🔒 Security Features

- **Encrypted SQLite**: Mandatory database encryption for all sensitive data using SQLCipher ([sqlcipher3-wheels](https://github.com/laggykiller/sqlcipher3))
- **Script Validation**: Frida script signature verification
- **Secure Configuration**: Environment variable isolation
- **Access Control**: Source-based log filtering

## 🧪 Testing

### Foundation Tests

Run the foundation test to verify core components:

```bash
python test_foundation.py
```

This tests:
- Configuration loading and validation
- Logging system initialization
- Session manager functionality
- Service initialization
- Basic health checks

### Unit Tests (Planned)

```bash
# When implemented
poetry run pytest tests/
```

## 📈 Performance Considerations

- **Async Architecture**: Non-blocking I/O for all services
- **Connection Pooling**: Efficient database connections
- **Log Rotation**: Automatic cleanup of old log files
- **Memory Management**: Careful resource cleanup
- **Background Tasks**: Separate threads for monitoring

## 🤝 Contributing

1. Follow the established architecture patterns
2. Maintain comprehensive logging
3. Add tests for new functionality
4. Update documentation
5. Follow Python type hints and docstring conventions

## 📄 License

[License information to be added]

## 🆘 Support

For issues and questions:
1. Check the logs in `logs/tower_iq.log`
2. Run the foundation test to verify setup
3. Review configuration files
4. Check Docker service status

---

**Note**: This is Part 1 of the TowerIQ implementation. The foundation is complete and ready for building the remaining components (Emulator Service, Frida Service, and GUI). 