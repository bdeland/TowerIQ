// tower_hook_integrated_v6.js

// This script is a long-running data logger.
// v6: Makes 'timestamp' a standard item in the generic message sender,
//     ensuring all events are consistently time-stamped.

import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    console.log("[+] Il2Cpp Bridge is ready and running in the emulated realm.");

    // --- SHARED STATE ---
    let currentRoundSeed = 0;

    // --- GENERIC MESSAGE SENDER ---
    /**
     * A centralized function to send messages with standard state information attached.
     * @param {Il2Cpp.Object} context - The 'this' object from a hook, or a found instance.
     * @param {string} messageType - The type of the event (e.g., 'game_metric', 'round_over').
     * @param {object} customPayload - The specific data unique to this message.
     */
    function sendStatefulMessage(context, messageType, customPayload = {}) {
        // Create the base payload with standard items we want in every message.
        const basePayload = {
            timestamp: Date.now(), // --- NEW: Timestamp is now a standard field ---
            roundSeed: currentRoundSeed,
            roundActive: context.field("roundActiveBool").value,
            currentWave: context.field("currentWave").value
        };

        const finalPayload = { ...basePayload, ...customPayload };

        send({
            type: messageType,
            payload: finalPayload
        });
    }

    /**
     * Finds the single, active instance of the Main class.
     * @returns {Il2Cpp.Object | null} The Main instance object or null if not found.
     */
    function findMainInstance() {
        try {
            const Main = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Main");
            const getInstanceMethod = Main.method("get_Instance");
            const instance = getInstanceMethod.invoke();
            if (instance && !instance.isNull()) {
                return instance;
            }
        } catch (e) { /* Fails silently */ }
        return null;
    }

    try {
        const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp");
        const Main = AssemblyCSharp.image.class("Main");

        // --- 1. PROACTIVE SEED CHECK ---
        console.log("[*] Performing proactive check for an in-progress round...");
        const mainInstance = findMainInstance();
        if (mainInstance) {
            try {
                if (mainInstance.field("roundActiveBool").value === true) {
                    currentRoundSeed = mainInstance.field("roundSeed").value;
                    console.log(`[+] Proactive check successful. Joined active round with Seed: ${currentRoundSeed}`);
                    // The custom payload is now empty, as the sender handles everything.
                    sendStatefulMessage(mainInstance, "new_round_started");
                } else {
                     console.log("[*] Proactive check: Game is not currently in a round.");
                }
            } catch (e) { /* Fails silently */ }
        }

        // --- 2. HOOK FOR NEW ROUNDS ---
        const startRoundMethod = Main.method("StartNewRound");
        startRoundMethod.implementation = function (...args) {
            const returnValue = this.method("StartNewRound").invoke(...args);
            currentRoundSeed = this.field("roundSeed").value;
            console.log(`\n[+] New round detected! Seed updated to: ${currentRoundSeed}`);
            // The custom payload is now empty.
            sendStatefulMessage(this, "new_round_started");
            return returnValue;
        };
        console.log("[+] Hook on Main.StartNewRound is live.");

        // --- 3. HOOK FOR GAME OVER ---
        const gameOverMethod = Main.method("GameOver", 1);
        gameOverMethod.implementation = function (allowSecondWind) {
            console.log(`\n[+] Intercepted Main.GameOver(bool)! allowSecondWind: ${allowSecondWind}`);
            if (currentRoundSeed !== 0) {
                console.log(`[+] Capturing final stats for round seed: ${currentRoundSeed}`);
                // The custom payload only contains data specific to this event.
                sendStatefulMessage(this, "round_over", {
                    roundTime: this.field("roundTime").value,
                    coinsEarned: this.field("coinsEarnedThisRound").value,
                    cashEarned: this.field("cashEarnedThisRound").value,
                    damageDealt: this.field("damageDealtThisRound").value,
                    enemiesKilled: this.field("totalEnemiesDestroyedThisRound").value
                });
                console.log("[+] Round over. Resetting currentRoundSeed to 0.");
                currentRoundSeed = 0;
            }
            return this.method("GameOver", 1).invoke(allowSecondWind);
        };
        console.log("[+] Hook on Main.GameOver is live.");

        // --- 4. HOOK FOR PER-WAVE METRICS ---
        const newWaveMethod = Main.method("NewWave");
        newWaveMethod.implementation = function (...args) {
            if (currentRoundSeed !== 0) {
                // The custom payload only contains data specific to this event.
                sendStatefulMessage(this, "game_metric", {
                    name: "coins",
                    value: this.field("coins").value
                });
            }
            return this.method("NewWave").invoke(...args);
        };
        console.log("[+] Hook on Main.NewWave is live. Waiting for game events.");

    } catch(e) {
        console.error(`[-] An error occurred in the bridge: ${e.stack}`);
    }
});