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
