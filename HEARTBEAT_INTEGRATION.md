# Heartbeat Integration Guide

## Overview

The TowerIQ backend now handles all heartbeat management automatically. Hook scripts should send heartbeat messages to the backend API instead of the GUI polling for status.

## Backend Heartbeat Management

The Python backend now includes:

1. **SessionManager** - Manages script status and heartbeat monitoring
2. **MainController** - Provides API methods for script status
3. **API Server** - Exposes `/api/heartbeat` endpoint for receiving heartbeats

## Hook Script Integration

### Sending Heartbeat Messages

Hook scripts should send POST requests to `/api/heartbeat` with the following data:

```javascript
// Example heartbeat message from hook script
const heartbeatData = {
  is_game_reachable: true,  // Whether the game process is still reachable
  error_count: 0,           // Number of errors encountered
  last_error: null          // Last error message (if any)
};

// Send heartbeat to backend
fetch('http://127.0.0.1:8000/api/heartbeat', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify(heartbeatData)
});
```

### Heartbeat Interval

- **Recommended interval**: 15-30 seconds
- **Timeout threshold**: 3x the heartbeat interval (45-90 seconds)
- **Backend monitoring**: Checks every 5 seconds for timeouts

### Example Hook Script Integration

```javascript
// In your Frida hook script
let heartbeatInterval;

function startHeartbeat() {
  heartbeatInterval = setInterval(() => {
    const heartbeatData = {
      is_game_reachable: true,  // Check if game process is still alive
      error_count: 0,           // Track errors in your script
      last_error: null          // Last error message
    };
    
    // Send heartbeat to backend
    fetch('http://127.0.0.1:8000/api/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(heartbeatData)
    }).catch(err => {
      console.log('Failed to send heartbeat:', err);
    });
  }, 15000); // Send heartbeat every 15 seconds
}

function stopHeartbeat() {
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
  }
}

// Start heartbeat when script is loaded
startHeartbeat();

// Stop heartbeat when script is unloaded
Process.on('unload', () => {
  stopHeartbeat();
});
```

## GUI Changes

The GUI no longer polls for script status. Instead:

1. **Initial load**: Loads script status when connection is established
2. **Manual refresh**: Users can click refresh button to get latest status
3. **Real-time updates**: Backend automatically detects timeouts and updates status

## API Endpoints

### GET /api/script-status
Returns current script status information.

### POST /api/heartbeat
Receives heartbeat messages from hook scripts.

## Benefits

1. **Reduced API calls**: No more excessive polling from GUI
2. **Real-time monitoring**: Backend actively monitors script health
3. **Automatic timeout detection**: Scripts are marked inactive when heartbeats stop
4. **Better error handling**: Centralized error tracking and reporting
5. **Scalable**: Multiple scripts can send heartbeats without GUI overhead

## Migration

To migrate existing hook scripts:

1. Remove any polling logic from the GUI
2. Add heartbeat sending logic to hook scripts
3. Update script activation to use the new heartbeat system
4. Test heartbeat timeout detection

The backend will automatically handle all heartbeat management and status updates.

