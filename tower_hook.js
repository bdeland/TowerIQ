
/** TOWERIQ_HOOK_METADATA
{
    "contractVersion": "1.1",
    "fileName": "tower_hook_compiled.js",
    "scriptName": "The Tower - Full Data Logger",
    "scriptDescription": "A comprehensive logger for all major in-game events and currencies.",
    "targetApp": "The Tower",
    "targetPackage": "com.TechTreeGames.TheTower",
    "supportedVersions": ["27.0.4"],
    "features": [
        "round_start_end_events",
        "per_wave_metric_bundle",
        "detailed_gem_tracking"
    ]
}
*/
// tower_hook_integrated_v30.js
// This script is a long-running data logger.
// v30: Added heartbeat and handshake mechanism for robust communication monitoring.
// v29: Fixed script initialization error by removing duplicated hook implementations
//      that were causing 'already been replaced by a thunk' errors.
// v28: Simplified Ad Gem tracking by removing the 'wasAdFreeClaim' field.
// v27: Correctly implemented Ad Gem tracking by hooking Ads.AdGemRewardClaim(bool).
// v26: Added detailed gem tracking for multiple sources.
// v25: Refactored round start logic.
import "frida-il2cpp-bridge";
Il2Cpp.perform(() => {
    log("INFO", "Il2Cpp Bridge is ready and running in the emulated realm.");
    // --- SHARED STATE ---
    let currentRoundSeed = 0;
    let currentRoundStartTime = 0;
    let lastKnownGameSpeed = -1;
    const GEM_VALUE_BLOCK = 2;
    const GEM_VALUE_AD = 5;
    // --- HELPER FUNCTIONS ---
    function log(level, message) {
        send({ type: "hook_log", payload: { event: "frida_log", message, level: level.toUpperCase(), timestamp: Date.now() } });
    }
    function getTypedFieldValue(instanceObject, fieldName) {
        try {
            const field = instanceObject.class.field(fieldName);
            const typeName = field.type.name;
            const value = instanceObject.field(fieldName).value;
            if (typeName.includes("Int"))
                return parseInt(value);
            return value;
        }
        catch (e) {
            log("ERROR", `Error reading instance field '${fieldName}': ${e.message}`);
            return null;
        }
    }
    function sendStatefulMessage(context, messageType, customPayload = {}) {
        const timestamp = Date.now();
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
        const gemBlocksTapped = getTypedFieldValue(context, "gemBlocksThisRound") || 0;
        const adGemsClaimed = getTypedFieldValue(context, "totalGemsEarnedFromTapjoy") || 0;
        const guardianGems = getTypedFieldValue(context, "totalGemsByGuardianThisRound") || 0;
        const metrics = {
            round_coins: getTypedFieldValue(context, "coinsEarnedThisRound"),
            wave_coins: getTypedFieldValue(context, "coinsEarnedThisWave"),
            coins: getTypedFieldValue(context, "coins"),
            gems: getTypedFieldValue(context, "gems"),
            round_cells: getTypedFieldValue(context, "cellsEarnedThisRound"),
            wave_cells: getTypedFieldValue(context, "cellsEarnedThisWave"),
            cells: getTypedFieldValue(context, "cells"),
            round_cash: getTypedFieldValue(context, "cashEarnedThisRound"),
            cash: getTypedFieldValue(context, "cash"),
            stones: getTypedFieldValue(context, "stones"),
            round_gems_from_blocks_count: gemBlocksTapped,
            round_gems_from_blocks_value: gemBlocksTapped * GEM_VALUE_BLOCK,
            round_gems_from_ads_count: adGemsClaimed,
            round_gems_from_ads_value: adGemsClaimed * GEM_VALUE_AD,
            round_gems_from_guardian: guardianGems,
        };
        sendStatefulMessage(context, "game_metric", { metrics: metrics });
    }
    function findMainInstance() {
        try {
            return Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Main").method("get_Instance").invoke();
        }
        catch (e) {
            return null;
        }
    }
    function processRoundStart(instance, isProactiveCheck = false) {
        const seed = getTypedFieldValue(instance, "roundSeed");
        const tier = getTypedFieldValue(instance, "currentTier");
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
        const Ads = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Ads");
        // --- NEW: HEARTBEAT & HANDSHAKE ---
        // 1. Heartbeat: Frida -> Application ("I'm alive")
        const HEARTBEAT_INTERVAL_MS = 15000; // 15 seconds
        setInterval(() => {
            const mainInstance = findMainInstance();
            send({
                type: "hook_log",
                payload: {
                    event: "frida_heartbeat",
                    timestamp: Date.now(),
                    message: "Frida script is alive.",
                    isGameReachable: (mainInstance && !mainInstance.isNull())
                }
            });
        }, HEARTBEAT_INTERVAL_MS);
        log("INFO", `Heartbeat initiated. Will send a signal every ${HEARTBEAT_INTERVAL_MS / 1000} seconds.`);
        // 2. Handshake Listener: Application -> Frida ("Are you there?")
        recv('handshake', (message) => {
            const payloadText = (message && message.payload && message.payload.text) ? message.payload.text : "No text provided.";
            log("INFO", `Handshake received from application: "${payloadText}"`);
            // Optionally, send an acknowledgement back.
            send({
                type: "hook_log",
                payload: {
                    event: "frida_handshake_ack",
                    timestamp: Date.now(),
                    message: "Acknowledged handshake from application."
                }
            });
        });
        log("INFO", "Handshake receiver is active. Ready for messages from the application.");
        // --- HOOKS ---
        log("INFO", "Performing proactive check for an in-progress round...");
        const mainInstance = findMainInstance();
        if (mainInstance && !mainInstance.isNull()) {
            if (getTypedFieldValue(mainInstance, "roundActiveBool") === true) {
                processRoundStart(mainInstance, true);
            }
        }
        // --- Standard Main class hooks ---
        Main.method("StartNewRound").implementation = function (...args) {
            const returnValue = this.method("StartNewRound").invoke(...args);
            processRoundStart(this);
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
                lastKnownGameSpeed = -1;
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
                sendStatefulMessage(this, "game_event", { event: "gameSpeedChanged", value: gameSpeed });
                lastKnownGameSpeed = gameSpeed;
            }
            if (currentRoundSeed !== 0) {
                sendMetricsBundle(this);
            }
            return this.method("NewWave").invoke(...args);
        };
        log("INFO", "Hook on Main.NewWave is live.");
        // --- GEM TRACKING HOOKS ---
        Main.method("GemBlockTap").implementation = function (...args) {
            log("INFO", "Gem Block tapped by player.");
            sendStatefulMessage(this, "game_event", {
                event: "gemBlockTapped",
                gemValue: GEM_VALUE_BLOCK
            });
            return this.method("GemBlockTap").invoke(...args);
        };
        log("INFO", "Hook on Main.GemBlockTap is live.");
        Main.method("GemBlockSpawn").implementation = function (...args) {
            log("DEBUG", "Gem Block has spawned.");
            sendStatefulMessage(this, "game_event", { event: "gemBlockSpawned" });
            return this.method("GemBlockSpawn").invoke(...args);
        };
        log("INFO", "Hook on Main.GemBlockSpawn is live.");
        // --- SIMPLIFIED AD GEM HOOK ---
        Ads.method("AdGemRewardClaim", 1).implementation = function (isFree) {
            log("INFO", `Ad gem claimed via Ads.AdGemRewardClaim.`);
            const mainContext = findMainInstance();
            if (mainContext && !mainContext.isNull()) {
                sendStatefulMessage(mainContext, "game_event", {
                    event: "adGemClaimed",
                    gemValue: GEM_VALUE_AD
                });
            }
            else {
                log("WARN", "Could not find Main instance when AdGemRewardClaim was called. Event not sent.");
            }
            return this.method("AdGemRewardClaim", 1).invoke(isFree);
        };
        log("INFO", "Hook on Ads.AdGemRewardClaim is live.");
    }
    catch (e) {
        log("ERROR", `An error occurred in the bridge: ${e.stack}`);
    }
});