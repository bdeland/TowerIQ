/** TOWERIQ_HOOK_METADATA
{
    "contractVersion": "1.1",
    "fileName": "test.js",
    "scriptName": "test script",
    "scriptDescription": "A simple test script to verify database functionality.",
    "targetApp": "The Tower",
    "targetPackage": "com.TechTreeGames.TheTower",
    "supportedVersions": ["27.0.2"],
    "features": [
        "test_messages",
        "database_verification"
    ]
}
*/

// Simple test hook script to verify Frida communication and database storage
console.log("Simple test hook script loaded");

// Send a test message immediately
send({ 
    type: "test_message", 
    payload: { 
        message: "Hook script is working!", 
        timestamp: Date.now() 
    } 
});

// Send test game data message to verify database storage
send({ 
    type: "game_metric", 
    payload: { 
        roundSeed: 12345,
        currentWave: 1,
        coins: 100,
        gems: 5,
        cells: 2,
        cash: 50,
        stones: 1,
        metrics: {
            round_coins: 100,
            wave_coins: 50,
            coins: 100,
            gems: 5,
            round_cells: 2,
            wave_cells: 1,
            cells: 2,
            round_cash: 50,
            cash: 50,
            stones: 1
        },
        timestamp: Date.now(),
        gameTimestamp: Date.now()
    } 
});

// Send a test game event
send({ 
    type: "game_event", 
    payload: { 
        event_type: "test_event",
        run_id: "test_run_12345",
        message: "Test game event",
        timestamp: Date.now()
    } 
});

// Send a heartbeat every 5 seconds
setInterval(() => {
    send({ 
        type: "hook_log", 
        payload: { 
            event: "frida_heartbeat", 
            message: "Heartbeat from test script", 
            level: "INFO", 
            timestamp: Date.now(),
            isGameReachable: false
        } 
    });
}, 5000);

// Try to access Il2Cpp if available
try {
    if (typeof Il2Cpp !== 'undefined') {
        send({ 
            type: "hook_log", 
            payload: { 
                event: "frida_log", 
                message: "Il2Cpp is available", 
                level: "INFO", 
                timestamp: Date.now() 
            } 
        });
    } else {
        send({ 
            type: "hook_log", 
            payload: { 
                event: "frida_log", 
                message: "Il2Cpp is not available", 
                level: "WARNING", 
                timestamp: Date.now() 
            } 
        });
    }
} catch (error) {
    send({ 
        type: "hook_log", 
        payload: { 
            event: "frida_log", 
            message: "Error checking Il2Cpp: " + error.message, 
            level: "ERROR", 
            timestamp: Date.now() 
        } 
    });
}