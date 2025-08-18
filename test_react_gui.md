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
3. **Activate your virtual environment:**
   ```bash
   .venv\Scripts\activate
   ```
4. **Start the backend server:**
   ```bash
   python start_backend.py
   ```
5. **Verify the server is running** - you should see:
   ```
   Starting TowerIQ Backend Server...
   Server will be available at: http://127.0.0.1:8000
   INFO:     Started server process [xxxx]
   INFO:     Waiting for application startup.
   INFO:     Application startup complete.
   INFO:     Uvicorn running on http://127.0.0.1:8000
   ```

### Recent Fixes Applied

I've fixed the infinite loop issue you experienced by:

1. **Reduced network device scanning** - Limited port scanning to only the most common emulator ports
2. **Added timeouts** - All operations now have proper timeouts to prevent hanging
3. **Better error handling** - The UI will show informative error messages instead of getting stuck
4. **Graceful degradation** - If device scanning fails, the app continues to work with basic functionality

## What Was Created

### 1. ConnectionPage Component (`src/gui/TowerIQ/src/pages/ConnectionPage.tsx`)
- **Vertical Stepper**: 4-step process for device connection
- **Step 1**: Device Selection - Choose from available devices
- **Step 2**: Process Selection - Select target process on device
- **Step 3**: Hook Script Configuration (Optional) - Configure injection scripts
- **Step 4**: Connection - Establish connection with summary

### 2. Enhanced Backend Hook (`src/gui/TowerIQ/src/hooks/useBackend.ts`)
- Added connection-related methods: `scanDevices`, `getProcesses`, `getHookScripts`, `startConnectionFlow`
- Added TypeScript interfaces for `Device`, `Process`, `HookScript`
- **Now uses real backend integration** with proper error handling and timeouts

### 3. Navigation Integration
- Added "Connection" to the sidebar navigation
- Added route `/connection` in the main App component
- Uses `Link` icon from Material-UI

## Features

### UI Components
- **Material-UI Stepper**: Vertical orientation with step icons
- **Device List**: Shows available devices with status chips
- **Process List**: Shows running processes with PID and package info
- **Script Selection**: Optional hook script configuration with preview
- **Connection Summary**: Shows selected options before connecting
- **Loading States**: Progress indicators and disabled states during operations
- **Error Handling**: Alert messages for connection failures

### Real Backend Integration
- **Device Scanning**: Uses `emulator_service.list_devices_with_details()` to get real Android devices
- **Process Listing**: Uses `emulator_service.get_processes()` to get running third-party apps
- **Hook Scripts**: Uses `hook_script_manager.get_available_scripts()` to get actual scripts from `test_frida_scripts/` directory
- **Connection**: Uses real device connection via `connect_device` API endpoint

## How to Test

### 1. Start the Backend Server (REQUIRED)
```bash
# In a new terminal
cd C:\Users\delan\Documents\GitHub\TowerIQ
.venv\Scripts\activate
python start_backend.py
```

### 2. Start the Development Server
```bash
# In another terminal
cd src/gui/TowerIQ
npm run dev
```

### 3. Navigate to Connection Page
- Open the app in your browser
- Click "Connection" in the sidebar navigation
- You should see the vertical stepper with 4 steps

### 4. Test the Flow
1. **Step 1**: Select a device from the list (should load quickly now)
2. **Step 2**: Choose a process (should load after device selection)
3. **Step 3**: Optionally enable hook script and select one
4. **Step 4**: Review summary and click "Connect"

### 5. Test Features
- **Refresh buttons**: Click to reload devices/processes
- **Back/Continue navigation**: Move between steps
- **Error handling**: Try connecting multiple times (20% failure rate)
- **Loading states**: Watch for progress indicators
- **Reset**: Complete the flow and test the reset button

## Troubleshooting

### If Device Scanning Still Hangs
1. **Check if backend server is running** at http://127.0.0.1:8000
2. **Check ADB connectivity** - run `adb devices` in terminal
3. **Check for Android devices/emulators** - ensure they're connected and visible to ADB
4. **Check firewall settings** - ensure port 8000 is not blocked

### If You Get "Backend not initialized" Errors
- The backend server needs to be running before starting the React GUI
- Make sure you started `python start_backend.py` first

### If You Get Network Timeout Errors
- The app now has proper timeouts and will show error messages instead of hanging
- Check your network connection and firewall settings

## Integration Points

### Backend Integration Complete
The React GUI now uses real backend methods:
- `scanDevices()` - Calls `invoke('scan_devices')` → `emulator_service.list_devices_with_details()`
- `getProcesses(deviceId)` - Calls `invoke('get_processes', { deviceId })` → `emulator_service.get_processes(deviceId)`
- `getHookScripts()` - Calls `invoke('get_hook_scripts')` → `hook_script_manager.get_available_scripts()`
- `startConnectionFlow(deviceId, processId, hookScriptContent)` - Calls `invoke('connect_device', { deviceSerial: deviceId })`

### State Management
- Connection status syncs with backend session state
- Error messages display from both local and backend errors
- Loading states prevent multiple simultaneous operations

## Next Steps

1. **Test the UI**: Run the dev server and verify the connection flow works with real devices
2. **Backend Server**: Start the FastAPI backend server (`python start_backend.py`)
3. **Device Connection**: Ensure ADB is available and devices are connected
4. **Hook Scripts**: Add hook scripts to `test_frida_scripts/` directory with proper metadata

## Files Modified/Created
- ✅ `src/gui/TowerIQ/src/pages/ConnectionPage.tsx` (NEW)
- ✅ `src/gui/TowerIQ/src/hooks/useBackend.ts` (ENHANCED - now uses real backend with timeouts)
- ✅ `src/gui/TowerIQ/src/App.tsx` (UPDATED - added navigation and routing)
- ✅ `src/gui/TowerIQ/src-tauri/src/lib.rs` (ENHANCED - added new Tauri commands with timeouts)
- ✅ `src/tower_iq/api_server.py` (ENHANCED - added device/process/script endpoints)
- ✅ `src/tower_iq/services/emulator_service.py` (FIXED - reduced network scanning, added timeouts)
- ✅ `src/tower_iq/services/hook_script_manager.py` (ENHANCED - added get_available_scripts method)
- ✅ `start_backend.py` (NEW - backend server starter script)

The React GUI connection page is now complete with real backend integration and proper error handling!
