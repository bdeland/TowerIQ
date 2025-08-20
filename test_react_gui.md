# React GUI Test Guide

## Overview
I've successfully created a new Connection page in the React GUI with a vertical stepper interface similar to the Material-UI example you provided. The page is now integrated into the navigation and ready for testing.

## ⚠️ Important: Backend Server Requirement

**Before testing the React GUI, you MUST start the FastAPI backend server first!**

The React GUI communicates with a Python FastAPI backend server that handles device scanning, process listing, and other operations. Without this server running, the device scanning will fail and may cause the app to hang.

### Starting the Backend Server

1. **Open a new terminal** (keep this running)
2. **Navigate to the project root:**
   ```bash
   cd C:\Users\delan\Documents\GitHub\TowerIQ
   ```
3. **Start the backend server:**
   ```bash
   python start_backend.py
   ```
4. **Wait for the message:** "TowerIQ is now running"

### Alternative: Start Backend Only

If you want to start just the backend server for testing:

```bash
python src/tower_iq/api_server.py
```

## Testing the React GUI

### Method 1: Using the Startup Script (Recommended)

1. **Open a new terminal**
2. **Navigate to the project root:**
   ```bash
   cd C:\Users\delan\Documents\GitHub\TowerIQ
   ```
3. **Run the startup script:**
   ```bash
   python start_toweriq.py
   ```
4. **Wait for both backend and frontend to start**
5. **The React GUI should open automatically in your browser**

### Method 2: Manual Tauri Development

1. **Start the backend server first** (see above)
2. **Open a new terminal**
3. **Navigate to the Tauri directory:**
   ```bash
   cd src/gui/TowerIQ
   ```
4. **Install dependencies (if not already done):**
   ```bash
   npm install
   ```
5. **Start the Tauri development server:**
   ```bash
   npx @tauri-apps/cli dev
   ```

## Troubleshooting

### No Logs Appearing in Terminal

If you're not seeing any logs in your terminal, try these steps:

1. **Test logging configuration:**
   ```bash
   python debug_logging.py
   ```
   This will show you if logging is working properly.

2. **Check logging settings in config:**
   The logging configuration is in `config/main_config.yaml`. Make sure:
   - `logging.console.enabled: true`
   - `logging.console.level: "DEBUG"` (for maximum visibility)

3. **Force console output:**
   If you're still not seeing logs, the issue might be with the terminal. Try:
   - Running in a different terminal (PowerShell, Command Prompt, or Git Bash)
   - Adding `--verbose` flag if available

### Device Scanning Issues

If device scanning gets stuck or fails:

1. **Check if ADB is working:**
   ```bash
   adb devices
   ```
   This should show your connected devices.

2. **Check backend server health:**
   Open `http://localhost:8000/docs` in your browser to see the API documentation.

3. **Check backend logs:**
   The backend server should show logs in the terminal where you started it.

### Common Issues

1. **"Backend server failed to start"**
   - Make sure no other process is using port 8000
   - Check if Python dependencies are installed: `pip install -r requirements.txt`

2. **"Frontend stopped unexpectedly"**
   - Check if Node.js and npm are installed
   - Try running `npm install` in the `src/gui/TowerIQ` directory

3. **"Device scanning timed out"**
   - Make sure your Android device/emulator is connected
   - Check if ADB is in your PATH
   - Try restarting the ADB server: `adb kill-server && adb start-server`

## API Endpoints

The backend server provides these endpoints:

- `GET /api/devices` - List available devices
- `POST /api/devices/{device_id}/connect` - Connect to a device
- `GET /api/devices/{device_id}/processes` - List running processes
- `GET /api/status` - Get server status
- `GET /api/hook-scripts` - Get available hook scripts

## Development Notes

- The React GUI uses Tauri for the desktop app wrapper
- The backend uses FastAPI for the API server
- Device scanning has been optimized to prevent infinite loops
- All API calls have proper timeouts and error handling
- Logging is configured to show detailed information for debugging

### Status Polling

The React GUI polls the backend status every 30 seconds to check if the backend is still responsive. This is why you see periodic `GET /api/status` requests in the logs. This polling:

- **Purpose**: Ensures the frontend knows if the backend becomes unavailable
- **Frequency**: Every 30 seconds (reduced from 5 seconds to minimize log spam)
- **Shared**: Multiple components share the same polling mechanism to avoid duplicate requests
- **Disable**: Set `DISABLE_POLLING = true` in `src/gui/TowerIQ/src/hooks/useBackend.ts` to disable polling entirely

### Reducing Log Noise

If you want to reduce the status polling logs, you can:

1. **Disable polling entirely** (for development):
   ```typescript
   // In src/gui/TowerIQ/src/hooks/useBackend.ts
   const DISABLE_POLLING = true;
   ```

2. **Increase polling interval** (for production):
   ```typescript
   // Change from 30000ms to 60000ms (1 minute)
   globalPollingInterval = setInterval(pollStatus, 60000);
   ```

3. **Filter logs** in your terminal to exclude status requests:
   ```bash
   # In PowerShell, filter out status requests
   python start_toweriq.py | Where-Object { $_ -notmatch "GET /api/status" }
   ```

## Next Steps

1. Test device discovery and connection
2. Test process listing and selection
3. Test hook script injection
4. Report any issues or unexpected behavior
