// tower_hook_investigator.js - v2 (Robust Initialization)

// Use Java.perform to ensure we're in the right thread context on Android
Java.perform(function () {
    console.log("[Frida] Inside Java.perform. Waiting for Il2Cpp to be available...");

    // Use a small interval to check for Il2Cpp availability.
    // This is the most reliable way to wait for the frida-il2cpp-bridge to initialize.
    var il2cpp_check_interval = setInterval(function () {
        if (Il2Cpp.available) {
            // Once Il2Cpp is available, stop checking.
            clearInterval(il2cpp_check_interval);
            console.log("[Frida] Il2Cpp is available. Proceeding with hooks.");

            // Now that we know Il2Cpp is ready, we can run the main logic.
            main();
        }
    }, 100); // Check every 100ms
});


// Main function to contain all our hooks and logic
function main() {
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
            send({ type: "hook_log", payload: { event: "frida_log", message: message, level: level.toUpperCase(), timestamp: Date.now() } });
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
        
        // ... (The rest of your helper functions: sendStatefulMessage, sendMetricsBundle, findMainInstance, processRoundStart) ...
        // They are all correct and don't need changes. For brevity, I'll omit them here, but make sure they are in your file.
        function sendStatefulMessage(context, messageType, customPayload = {}) {
            const timestamp = Date.now();
            if (currentRoundStartTime === 0 && getTypedFieldValue(context, "roundActiveBool")) {
                const realTimeThisRound = getTypedFieldValue(context, "realTimeThisRound");
                if (realTimeThisRound !== null) {
                    currentRoundStartTime = timestamp - (realTimeThisRound * 1000);
                }
            }
            const basePayload = {
                timestamp: timestamp, roundStartTime: currentRoundStartTime, gameTimestamp: getTypedFieldValue(context, "gameplayTimeThisRound"),
                roundSeed: currentRoundSeed, isRoundActive: getTypedFieldValue(context, "roundActiveBool"), currentWave: getTypedFieldValue(context, "currentWave")
            };
            const finalPayload = { ...basePayload, ...customPayload };
            send({ type: messageType, payload: finalPayload });
        }

        function findMainInstance() {
            try {
                return Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Main").method("get_Instance").invoke();
            } catch (e) { return null; }
        }

        // --- INVESTIGATIVE HOOKS (CONTROLLED BY PYTHON SCRIPT) ---
        
        function logObjectState(instance) {
            if (!instance || instance.isNull()) { return { "error": "Instance is null" }; }
            const state = {};
            try {
                instance.class.fields.forEach(field => {
                    try {
                        state[field.name] = field.value;
                    } catch (e) {
                        state[field.name] = `(Error: ${e.message})`;
                    }
                });
            } catch (e) {
                state["error"] = `Could not read fields: ${e.message}`;
            }
            return state;
        }

        function findClasses(searchTerm) {
            log("INFO", `Searching for classes containing '${searchTerm}'...`);
            const matchingClasses = [];
            Il2Cpp.domain.assemblies.forEach(assembly => {
                assembly.image.classes.forEach(klass => {
                    if (klass.name.toLowerCase().includes(searchTerm.toLowerCase())) {
                        matchingClasses.push(klass.toString());
                    }
                });
            });
            log("SUCCESS", `Found ${matchingClasses.length} matching classes.`);
            send({type: "investigation_result", payload: { command: "findClasses", results: matchingClasses }});
        }

        function traceClass(className) {
            log("INFO", `Attempting to trace all methods in class: ${className}`);
            try {
                const targetClass = Il2Cpp.findClass(className);
                if (!targetClass) {
                    log("ERROR", `Could not find class: ${className}`);
                    return;
                }

                let methodsAttached = 0;
                targetClass.methods.forEach(method => {
                    if (method.virtualAddress.isNull() || method.name.startsWith('.')) return; // Skip methods without an implementation or special compiler-generated ones

                    try {
                        const originalImpl = method.implementation;
                        method.implementation = function (...args) {
                            const callDetails = {
                                event: "method_trace", className: className, methodName: method.name,
                                args: args.map(arg => String(arg)), // Convert args to string for serialization
                                state_before: logObjectState(this),
                            };
                            
                            const retval = originalImpl.apply(this, args);
                            
                            callDetails.state_after = logObjectState(this);
                            callDetails.return_value = String(retval);
                            
                            send({ type: "investigation", payload: callDetails });
                            return retval;
                        }
                        methodsAttached++;
                    } catch (e) {
                        log("WARN", `Could not attach to method ${method.name}: ${e.message}`);
                    }
                });
                log("SUCCESS", `Successfully attached tracers to ${methodsAttached} methods in ${className}.`);

            } catch (e) {
                log("ERROR", `Failed to trace class ${className}: ${e.stack}`);
            }
        }
        
        // --- RPC EXPORTS ---
        rpc.exports = {
            findClasses: findClasses,
            traceClass: traceClass
        };

        log("SUCCESS", "Investigative RPC functions are ready. Use the Python controller to begin.");
    });
}