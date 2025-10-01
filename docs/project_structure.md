# TowerIQ Project Structure

**Last Updated:** September 30, 2025

## Overview

TowerIQ uses a clean, organized structure separating frontend and backend:

```
TowerIQ/
├── frontend/           # React/Tauri desktop app
├── backend/            # Python FastAPI server
├── config/             # App configuration
├── data/               # Runtime data (databases, frida-server)
├── resources/          # Static assets (shared)
├── tests/              # Test suite
├── scripts/            # Dev utilities & migrations
├── docs/               # Documentation
├── .archive/           # Archived PyQt6 GUI
├── .dev/               # Dev notes (hidden)
└── start.py            # Main entry point
```

## Key Directories

### `frontend/` - React/Tauri Application
Modern TypeScript/React UI with desktop integration.
- **Tech:** React, TypeScript, Vite, Tauri, ECharts, Material UI
- **Structure:** `src/` (components, pages, hooks, services), `src-tauri/` (Rust)

### `backend/` - Python Backend
FastAPI server with business logic.
- **Tech:** FastAPI, SQLAlchemy, Frida, structlog
- **Structure:** `api_server.py`, `core/`, `services/`, `models/`, `scripts/`

### `config/` - Configuration
- `main_config.yaml` - Main settings
- `database_schema.py` - DB schema

### `data/` - Runtime Data
- `toweriq.sqlite` - Main database
- `frida-server/` - Frida binaries

### `resources/` - Assets
Shared fonts, icons, sprites, lookups

### `tests/` - Tests
Unit & integration tests with pytest

### `scripts/` - Development
- `start_backend.py` - Backend-only starter
- Migration scripts
- Test scripts

### `.archive/` - Archived Code
Old PyQt6 GUI (archived 2025-09-30). See `.archive/README.md`.

## Entry Points

**Main (Production):**
```bash
python start.py  # Starts both frontend + backend
```

**Development:**
```bash
python scripts/start_backend.py  # Backend only
cd frontend && npm run tauri dev  # Frontend only
```

## Migration from Old Structure

**Before (2025-09-30):**
```
src/tower_iq/  # Backend with embedded PyQt6 GUI
src/gui/TowerIQ/  # React frontend
```

**After:**
```
backend/   # Clean backend
frontend/  # Clean frontend
.archive/  # Old PyQt6 code
```

**Benefits:**
- Clear separation of concerns
- Easier navigation (no deep nesting)
- Simpler import paths
- Industry-standard layout

## Architecture

```
Desktop (Tauri+React)
        ↓ HTTP API
FastAPI Backend
        ↓
SQLite + Frida + Android Emulator
```

## Development Workflow

1. Start: `python start.py`
2. Test: `pytest tests/`
3. Build: `cd frontend && npm run tauri build`

## Additional Info

- **Logs:** `logs/tower_iq.log`
- **Frontend builds:** `frontend/dist/`
- **Test data:** `data/test_mode.sqlite` (if test mode)
- **Config:** Customize via `config/main_config.yaml`
