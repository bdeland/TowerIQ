// tower_hook_readonly_final.js

// This script is designed to be run with the --realm=emulated flag.
// It will only log information and will NOT modify any game values.

import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    console.log("[+] Il2Cpp Bridge is ready and running in the emulated realm.");

    try {
        const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp");
        const Main = AssemblyCSharp.image.class("Main");
        const newWaveMethod = Main.method("NewWave"); // Correct casing

        console.log(`[+] Found Main.NewWave method at: ${newWaveMethod.handle}`);
        console.log("[+] Hook is live. Waiting for the game to call it.");

        // Attach to the method using the bridge's clean syntax.
        newWaveMethod.implementation = function (...args) {
            console.log("\n[+] Intercepted Main.NewWave()!");

            // READ-ONLY: Access the field and log its value.
            const currentCoins = this.field("coins").value;
            console.log(`[+] Current coins (read-only): ${currentCoins}`);
            
            // --- NO MEMORY MODIFICATION ---
            
            // THE FIX: Call the original method correctly.
            // We get the method from the instance (`this`) and pass the original arguments.
            return this.method("NewWave").invoke(...args);
        };

    } catch(e) {
        console.error(`[-] An error occurred in the bridge: ${e.stack}`);
    }
});