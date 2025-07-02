// tower_hook_integrated_v25.js

// This script is a long-running data logger.
// v25: Refactored round start logic into a single 'processRoundStart' function to
//      eliminate code duplication and improve maintainability.
//      Also fixed 'lastKnownGameSpeed' not being reset on game over.

import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    log("INFO", "Il2Cpp Bridge is ready and running in the emulated realm.");

    // --- SHARED STATE ---
    let currentRoundSeed = 0;
    let currentRoundStartTime = 0; 
    let lastKnownGameSpeed = -1;

    // --- HELPER FUNCTIONS ---

    function log(level, message) {
        send({ type: "hook_log", payload: { event: "frida_log", message, level: level.toUpperCase(), timestamp: Date.now() } });
    }

    function getTypedFieldValue(instanceObject, fieldName) {
        try {
            const field = instanceObject.class.field(fieldName);
            const typeName = field.type.name;
            const value = instanceObject.field(fieldName).value;
            // A simple check for integer types
            if (typeName.includes("Int")) return parseInt(value);
            return value;
        } catch (e) {
            log("ERROR", `Error reading instance field '${fieldName}': ${e.message}`);
            return null;
        }
    }
    
    function sendStatefulMessage(context, messageType, customPayload = {}) {
        const timestamp = Date.now();
        
        // This clever logic attempts to reconstruct the start time if we hook mid-round.
        if (currentRoundStartTime === 0 && getTypedFieldValue(context, "roundActiveBool")) {
            const realTimeThisRound = getTypedFieldValue(context, "realTimeThisRound");
            if (realTimeThisRound !== null) {
                currentRoundStartTime = timestamp - (realTimeThisRound * 1000);
            }
        }

        const basePayload = {
            timestamp: timestamp,
            roundStartTime: currentRoundStartTime,
            gameTimestamp: getTypedFieldValue(context, "gameplayTimeThisRound"),
            roundSeed: currentRoundSeed,
            isRoundActive: getTypedFieldValue(context, "roundActiveBool"),
            currentWave: getTypedFieldValue(context, "currentWave")
        };
        
        const finalPayload = { ...basePayload, ...customPayload };
        send({ type: messageType, payload: finalPayload });
    }

    function sendMetricsBundle(context) {
        const metrics = {
            round_coins: getTypedFieldValue(context, "coinsEarnedThisRound"),
            wave_coins: getTypedFieldValue(context, "coinsEarnedThisWave"),
            coins: getTypedFieldValue(context, "coins"),
            round_gems: getTypedFieldValue(context, "gemBlocksThisRound"),
            gems: getTypedFieldValue(context, "gems"),
            round_cells: getTypedFieldValue(context, "cellsEarnedThisRound"),
            wave_cells: getTypedFieldValue(context, "cellsEarnedThisWave"),
            cells: getTypedFieldValue(context, "cells"),
            round_cash: getTypedFieldValue(context, "cashEarnedThisRound"),
            cash: getTypedFieldValue(context, "cash"),
            stones: getTypedFieldValue(context, "stones")
        };
        sendStatefulMessage(context, "game_metric", { metrics: metrics });
    }

    function findMainInstance() {
        try {
            return Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Main").method("get_Instance").invoke();
        } catch (e) { return null; }
    }

    // --- NEW CENTRALIZED FUNCTION FOR ROUND START LOGIC ---
    function processRoundStart(instance, isProactiveCheck = false) {
        const seed = getTypedFieldValue(instance, "roundSeed");
        const tier = getTypedFieldValue(instance, "currentTier");

        // Update global state
        currentRoundSeed = seed;
        currentRoundStartTime = Date.now();

        const logMessage = isProactiveCheck
            ? `Proactive check successful. Joined active round with Seed: ${seed}, Tier: ${tier}`
            : `New round detected! Seed: ${seed}, Tier: ${tier}`;
        log("INFO", logMessage);

        sendStatefulMessage(instance, "game_event", { 
            event: "startNewRound",
            tier: tier
        });
    }

    try {
        const Main = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Main");

        // --- HOOKS ---
        
        // Proactive check now uses the centralized function
        log("INFO", "Performing proactive check for an in-progress round...");
        const mainInstance = findMainInstance();
        if (mainInstance && !mainInstance.isNull()) {
            if (getTypedFieldValue(mainInstance, "roundActiveBool") === true) {
                processRoundStart(mainInstance, true);
            }
        }

        // Hook on StartNewRound now uses the centralized function
        Main.method("StartNewRound").implementation = function (...args) {
            const returnValue = this.method("StartNewRound").invoke(...args);
            processRoundStart(this); // 'this' is the Main instance here
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
                lastKnownGameSpeed = -1; // <-- REVIEW FIX: Reset game speed state as well
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
            // Note: This reads a static field from the Main class
            const gameSpeed = Main.field("gameSpeed").value;
            if (lastKnownGameSpeed !== gameSpeed) {
                log("INFO", `Game speed changed to ${gameSpeed.toFixed(2)}x`);
                sendStatefulMessage(this, "game_event", { event: "gameSpeedChanged", value: gameSpeed });
                lastKnownGameSpeed = gameSpeed;
            }
            if (currentRoundSeed !== 0) {
                sendMetricsBundle(this);
            }
            return this.method("NewWave").invoke(...args);
        };
        log("INFO", "Hook on Main.NewWave is live.");

    } catch(e) {
        log("ERROR", `An error occurred in the bridge: ${e.stack}`);
    }
});