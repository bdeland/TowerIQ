# TowerIQ Technology Stack

## Build System & Package Management
- **Python**: Poetry for dependency management (`pyproject.toml`)
- **JavaScript**: npm for Frida hook compilation (`package.json`)
- **Entry Point**: `poetry run tower-iq` or `python -m src.tower_iq.main_app_entry`

## Core Technologies
- **Python 3.11-3.12**: Main application runtime
- **PyQt6**: Desktop GUI framework with qasync for async integration
- **Frida 15.2.2**: Dynamic instrumentation toolkit
- **SQLite**: Embedded database with SQLCipher encryption
- **structlog**: Structured logging with colorama for console output

## Key Libraries
- **GUI**: PyQt6, PyQtGraph (real-time plotting), PyQt6-Frameless-Window
- **Data**: pandas, numpy for data processing
- **Async**: qasync (PyQt6 + asyncio bridge), aiohttp
- **Config**: PyYAML, python-dotenv
- **Crypto**: pycryptodome for database encryption

## JavaScript/Frida Stack
- **TypeScript**: For hook development with type safety
- **frida-compile**: Compiles TypeScript hooks to JavaScript
- **frida-il2cpp-bridge**: Unity/IL2CPP game instrumentation
- **@types/frida-gum**: Type definitions for Frida APIs

## Common Commands

### Development
```bash
# Install dependencies
poetry install

# Run application
poetry run tower-iq

# Run with flags
poetry run tower-iq --reset-frida
poetry run tower-iq --test-mode

# Compile Frida hooks
npm run build  # (if configured)
```

### Database
- SQLite with WAL mode enabled
- Encrypted using SQLCipher
- Auto-migration on startup

### Logging
- Structured JSON logs to database
- Console output with colors
- File rotation (50MB, 5 backups)