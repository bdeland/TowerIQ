# TowerIQ - New GUI Integration

This document explains how to use the new React/Tauri frontend integrated with the existing Python backend.

## Architecture Overview

The new system consists of three main components:

1. **FastAPI Backend Server** (`src/tower_iq/api_server.py`)
   - Provides HTTP API endpoints for the frontend
   - Integrates with existing Python backend services
   - Runs on `http://localhost:8000`

2. **Tauri Frontend** (`src/gui/TowerIQ/`)
   - React/TypeScript application with Material-UI
   - Communicates with backend via Tauri commands
   - Runs on `http://localhost:1420`

3. **Startup Script** (`start_toweriq.py`)
   - Orchestrates launching both backend and frontend
   - Ensures proper startup order and health checks

## Quick Start

### Prerequisites

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Install Node.js dependencies:
   ```bash
   cd src/gui/TowerIQ
   npm install
   ```

3. Install Rust and Tauri CLI (if not already installed):
   ```bash
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Install Tauri CLI
   cargo install tauri-cli
   ```

### Running the Application

#### Option 1: Using the Startup Script (Recommended)

```bash
python start_toweriq.py
```

This will:
- Start the FastAPI backend server
- Wait for it to be healthy
- Launch the Tauri frontend
- Provide status updates and cleanup on exit

#### Option 2: Manual Startup

1. Start the backend server:
   ```bash
   python src/tower_iq/api_server.py
   ```

2. In another terminal, start the Tauri frontend:
   ```bash
   cd src/gui/TowerIQ
   npm run tauri dev
   ```

## Features

### Backend Integration

The new frontend integrates with the existing Python backend through:

- **Database Service**: Full access to the existing database functionality
- **Configuration Management**: Uses the existing configuration system
- **Logging**: Integrates with the existing logging setup
- **Test Mode**: Supports the existing test mode functionality

### Frontend Features

- **Real-time Status**: Shows backend connection status and session state
- **Test Mode Controls**: Toggle test mode on/off from the UI
- **Device Connection**: Connect to devices through the UI
- **Modern UI**: Material-UI based interface with responsive design

### API Endpoints

The FastAPI server provides these endpoints:

- `GET /api/status` - Get backend status and session state
- `POST /api/connect-device` - Connect to a device
- `POST /api/activate-hook` - Activate a hook script
- `POST /api/test-mode` - Set test mode configuration
- `GET /api/devices` - Get available devices

## Development

### Backend Development

The FastAPI server is located at `src/tower_iq/api_server.py`. To add new endpoints:

1. Add new Pydantic models for request/response types
2. Create new endpoint functions
3. Update the Tauri backend commands in `src/gui/TowerIQ/src-tauri/src/lib.rs`
4. Update the React hook in `src/gui/TowerIQ/src/hooks/useBackend.ts`

### Frontend Development

The Tauri frontend is located at `src/gui/TowerIQ/`. Key files:

- `src/App.tsx` - Main application layout
- `src/hooks/useBackend.ts` - Backend communication hook
- `src/pages/` - Page components
- `src-tauri/src/lib.rs` - Tauri backend commands

### Adding New Pages

1. Create a new page component in `src/pages/`
2. Add the route to `src/App.tsx`
3. Add navigation item to the sidebar

## Troubleshooting

### Backend Not Starting

- Check that all Python dependencies are installed
- Verify the configuration file exists at `config/main_config.yaml`
- Check logs for specific error messages

### Frontend Not Starting

- Ensure Node.js dependencies are installed (`npm install`)
- Check that Rust and Tauri CLI are properly installed
- Verify the backend server is running on port 8000

### Connection Issues

- Ensure the backend server is running on `http://localhost:8000`
- Check CORS settings in the FastAPI server
- Verify the Tauri backend is making requests to the correct URL

## Migration from Old GUI

The new GUI is designed to be a drop-in replacement for the existing PyQt6 GUI. The backend services remain the same, only the frontend interface has changed.

To migrate:

1. Stop the old PyQt6 application
2. Start the new integrated system using `python start_toweriq.py`
3. All existing data and configurations will be preserved

## Future Enhancements

- Add more comprehensive device management UI
- Implement real-time data visualization
- Add user authentication and settings management
- Create mobile-responsive design
- Add offline mode support
