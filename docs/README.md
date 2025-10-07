# TowerIQ

TowerIQ - Advanced mobile game analysis and monitoring platform

## Description

TowerIQ provides advanced analysis and monitoring capabilities for mobile games, with real-time instrumentation using Frida, comprehensive data collection, and powerful visualization through dashboards.

## Features

- Real-time mobile game monitoring and instrumentation
- Frida-based dynamic analysis
- Interactive dashboards for data visualization
- Module simulation and analysis
- Database-backed data persistence
- React + Tauri desktop application

## Installation

### Quick Setup (Recommended)

**Windows:**

```cmd
scripts\setup.bat
```

**Unix/Linux/macOS:**

```bash
./scripts/setup.sh
```

**Manual (any platform):**

```bash
python scripts/setup_environment.py
```

### Manual Development Setup

1. **Prerequisites:**

   - Python 3.11+
   - Node.js 18+ LTS
   - Poetry (auto-installed by setup script)

2. **Clone the repository:**

   ```bash
   git clone https://github.com/your-repo/TowerIQ.git
   cd TowerIQ
   ```

3. **Install Python dependencies:**

   ```bash
   poetry install
   ```

4. **Install frontend dependencies:**

   ```bash
   cd frontend
   npm install
   cd ..
   ```

5. **Install root Node.js dependencies:**
   ```bash
   npm install
   ```

> **For Cursor IDE users:** See [Cursor Environment Setup Guide](docs/cursor_environment_setup.md) for detailed configuration.

## Running TowerIQ

### Quick Start

Run both backend and frontend together:

```bash
python start.py
```

### Backend Only

```bash
python scripts/start_backend.py
```

The API will be available at `http://localhost:8000`
API documentation at `http://localhost:8000/docs`

### Frontend Only

```bash
cd frontend
npx tauri dev
```

## Project Structure

```
TowerIQ/
├── src/
│   └── tower_iq/          # Main Python package
│       ├── api/           # FastAPI routes and models
│       ├── core/          # Core functionality
│       ├── services/      # Business logic services
│       └── models/        # Data models
├── frontend/              # React + Tauri desktop app
├── config/                # Configuration files
├── scripts/               # Utility scripts
└── tests/                 # Test suite
```

## Development

### Code Quality

Run linting:

```bash
python scripts/lint.py
```

### Type Checking

Run type checker:

```bash
pyright src/tower_iq
```

## License

Copyright © 2025 TowerIQ Team
