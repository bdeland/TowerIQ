// tower_hook_integrated_v24.js

// This script is a long-running data logger.
// v24: Fixes a critical bug by removing the 'gameSpeed' field from the standard
//      payload, ensuring it is ONLY sent via the 'gameSpeedChanged' event as intended.

import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    log("INFO", "Il2Cpp Bridge is ready and running in the emulated realm.");

    // --- SHARED STATE ---
    let currentRoundSeed = 0;
    let currentRoundStartTime = 0; 
    let lastKnownGameSpeed = -1;

    // --- HELPER FUNCTIONS ---

    function log(level, message) {
        console.log(`[${level.toUpperCase()}] ${message}`);
        send({ type: "hook_log", payload: { event: "frida_log", message, level: level.toUpperCase(), timestamp: Date.now() } });
    }

    function getTypedFieldValue(instanceObject, fieldName) {
        try {
            const field = instanceObject.class.field(fieldName);
            const typeName = field.type.name;
            const value = instanceObject.field(fieldName).value;
            if (typeName.includes("Int")) return parseInt(value);
            return value;
        } catch (e) {
            log("ERROR", `Error reading instance field '${fieldName}': ${e.message}`);
            return null;
        }
    }
    
    function sendStatefulMessage(context, messageType, customPayload = {}) {
        const timestamp = Date.now();
        
        if (currentRoundStartTime === 0 && getTypedFieldValue(context, "roundActiveBool")) {
            const realTimeThisRound = getTypedFieldValue(context, "realTimeThisRound");
            currentRoundStartTime = timestamp - (realTimeThisRound * 1000);
        }

        const basePayload = {
            timestamp: timestamp,
            roundStartTime: currentRoundStartTime,
            gameTimestamp: getTypedFieldValue(context, "gameplayTimeThisRound"),
            roundSeed: currentRoundSeed,
            isRoundActive: getTypedFieldValue(context, "roundActiveBool"),
            currentWave: getTypedFieldValue(context, "currentWave")
            // --- THE FIX: 'gameSpeed' has been removed from the standard payload ---
        };
        
        const finalPayload = { ...basePayload, ...customPayload };
        send({ type: messageType, payload: finalPayload });
    }

    function sendMetricsBundle(context) {
        const metrics = {
            coins: getTypedFieldValue(context, "coinsEarnedThisRound"),
            gems: getTypedFieldValue(context, "gems")
        };
        sendStatefulMessage(context, "game_metric", { metrics: metrics });
    }

    function findMainInstance() {
        try {
            return Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Main").method("get_Instance").invoke();
        } catch (e) { return null; }
    }

    try {
        const Main = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Main");

        // --- HOOKS ---
        
        log("INFO", "Performing proactive check for an in-progress round...");
        const mainInstance = findMainInstance();
        if (mainInstance && !mainInstance.isNull()) {
            if (getTypedFieldValue(mainInstance, "roundActiveBool") === true) {
                currentRoundSeed = getTypedFieldValue(mainInstance, "roundSeed");
                log("INFO", `Proactive check successful. Joined active round with Seed: ${currentRoundSeed}`);
                sendStatefulMessage(mainInstance, "game_event", { 
                    event: "startNewRound",
                    tier: getTypedFieldValue(mainInstance, "currentTier")
                });
            }
        }

        Main.method("StartNewRound").implementation = function (...args) {
            const returnValue = this.method("StartNewRound").invoke(...args);
            currentRoundStartTime = Date.now();
            currentRoundSeed = getTypedFieldValue(this, "roundSeed");
            const currentTier = getTypedFieldValue(this, "currentTier");
            log("INFO", `New round detected! Seed: ${currentRoundSeed}, Tier: ${currentTier}`);
            sendStatefulMessage(this, "game_event", { 
                event: "startNewRound",
                tier: currentTier
            });
            return returnValue;
        };
        log("INFO", "Hook on Main.StartNewRound is live.");

        Main.method("GameOver", 1).implementation = function (allowSecondWind) {
            log("INFO", `Intercepted Main.GameOver(bool)!`);
            if (currentRoundSeed !== 0) {
                log("INFO", `Capturing final stats for round seed: ${currentRoundSeed}`);
                sendStatefulMessage(this, "game_event", {
                    event: "gameOver",
                    coinsEarned: getTypedFieldValue(this, "coinsEarnedThisRound"),
                });
                log("INFO", "Round over. Resetting state.");
                currentRoundSeed = 0;
                currentRoundStartTime = 0;
            }
            return this.method("GameOver", 1).invoke(allowSecondWind);
        };
        log("INFO", "Hook on Main.GameOver is live.");

        Main.method("Pause", 0).implementation = function (...args) {
            log("INFO", "Game Paused (Main.Pause called).");
            sendStatefulMessage(this, "game_event", { event: "gamePaused" });
            return this.method("Pause", 0).invoke(...args);
        };
        log("INFO", "Hook on Main.Pause is live.");

        Main.method("Unpause", 0).implementation = function (...args) {
            log("INFO", "Game Resumed (Main.Unpause called).");
            sendStatefulMessage(this, "game_event", { event: "gameResumed" });
            return this.method("Unpause", 0).invoke(...args);
        };
        log("INFO", "Hook on Main.Unpause is live.");
        
        Main.method("NewWave").implementation = function (...args) {
            const gameSpeed = Main.field("gameSpeed").value;
            if (lastKnownGameSpeed !== gameSpeed) {
                log("INFO", `Game speed changed to ${gameSpeed.toFixed(2)}x`);
                // Note: This call to sendStatefulMessage will now correctly OMIT gameSpeed from its own payload.
                sendStatefulMessage(this, "game_event", { event: "gameSpeedChanged", value: gameSpeed });
                lastKnownGameSpeed = gameSpeed;
            }
            if (currentRoundSeed !== 0) sendMetricsBundle(this);
            return this.method("NewWave").invoke(...args);
        };
        log("INFO", "Hook on Main.NewWave is live.");

    } catch(e) {
        log("ERROR", `An error occurred in the bridge: ${e.stack}`);
    }
});