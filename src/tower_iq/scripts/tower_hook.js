/** TOWERIQ_HOOK_METADATA
{
    "contractVersion": "1.1",
    "fileName": "tower_hook.js",
    "scriptName": "test script",
    "scriptDescription": "A comprehensive logger for all major in-game events and currencies.",
    "targetApp": "The Tower",
    "targetPackage": "com.TechTreeGames.TheTower",
    "supportedVersions": ["27.0.2"],
    "features": [
        "round_start_end_events",
        "per_wave_metric_bundle",
        "detailed_gem_tracking"
    ]
}
*/

// Simple test hook script to verify Frida communication
console.log("Simple test hook script loaded");

// Send a test message immediately
send({ 
    type: "test_message", 
    payload: { 
        message: "Hook script is working!", 
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
