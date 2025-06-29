// tower_hook_integrated_v3.js

// This script is a long-running data logger.
// v3: Adds a hook for Main.GameOver to capture end-of-round statistics
// and signal the end of the data logging for that round.

import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    console.log("[+] Il2Cpp Bridge is ready and running in the emulated realm.");

    // --- SHARED STATE ---
    let currentRoundSeed = 0;

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
                    send({ type: "new_round_started", payload: { roundSeed: currentRoundSeed, timestamp: Date.now() } });
                } else {
                     console.log("[*] Proactive check: Game is not currently in a round.");
                }
            } catch (e) { /* Fails silently */ }
        }

        // --- 2. HOOK FOR NEW ROUNDS ---
        const startRoundMethod = Main.method("StartNewRound");
        startRoundMethod.implementation = function (...args) {
            const returnValue = this.method("StartNewRound").invoke(...args);
            const newSeed = this.field("roundSeed").value;
            currentRoundSeed = newSeed;
            console.log(`\n[+] New round detected! Seed updated to: ${currentRoundSeed}`);
            send({ type: "new_round_started", payload: { roundSeed: currentRoundSeed, timestamp: Date.now() } });
            return returnValue;
        };
        console.log("[+] Hook on Main.StartNewRound is live.");

        // --- 3. HOOK FOR GAME OVER (END OF ROUND) ---
        // We use .method(name, argCount) to select the correct overload.
        const gameOverMethod = Main.method("GameOver", 1);
        gameOverMethod.implementation = function (allowSecondWind) {
            console.log(`\n[+] Intercepted Main.GameOver(bool)! allowSecondWind: ${allowSecondWind}`);

            // Only process game over if we are tracking an active round.
            if (currentRoundSeed !== 0) {
                console.log(`[+] Capturing final stats for round seed: ${currentRoundSeed}`);

                // Send a single, comprehensive "round_over" event with all final stats.
                send({
                    type: "round_over",
                    payload: {
                        roundSeed: currentRoundSeed,
                        timestamp: Date.now(),
                        finalWave: this.field("currentWave").value,
                        roundTime: this.field("roundTime").value,
                        coinsEarned: this.field("coinsEarnedThisRound").value,
                        cashEarned: this.field("cashEarnedThisRound").value,
                        damageDealt: this.field("damageDealtThisRound").value,
                        enemiesKilled: this.field("totalEnemiesDestroyedThisRound").value,
                        // Add any other '...ThisRound' fields you find interesting here.
                    }
                });
                
                // CRITICAL: Reset the seed to 0 so we stop logging metrics for this round.
                console.log("[+] Round over. Resetting currentRoundSeed to 0.");
                currentRoundSeed = 0;
            }

            // Call the original GameOver function to let the game proceed.
            return this.method("GameOver", 1).invoke(allowSecondWind);
        };
        console.log("[+] Hook on Main.GameOver is live.");


        // --- 4. HOOK FOR PER-WAVE METRICS ---
        const newWaveMethod = Main.method("NewWave");
        newWaveMethod.implementation = function (...args) {
            // Only send metrics if we are in an active, tracked round.
            if (currentRoundSeed !== 0) {
                send({
                    type: "game_metric",
                    payload: {
                        roundSeed: currentRoundSeed,
                        name: "coins",
                        value: this.field("coins").value,
                        wave: this.field("currentWave").value + 1, // +1 because NewWave is called before currentWave is incremented
                        timestamp: Date.now()
                    }
                });
            }
            return this.method("NewWave").invoke(...args);
        };
        console.log("[+] Hook on Main.NewWave is live. Waiting for game events.");

    } catch(e) {
        console.error(`[-] An error occurred in the bridge: ${e.stack}`);
    }
});