import "frida-il2cpp-bridge";

function log(level, message) { console.log(`[${level.toUpperCase()}] ${message}`); }

global.traceRandom = function() {
    log("ACTION", "Arming the randomness tracer...");
    try {
        const UnityEngine = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
        const Random = UnityEngine.class("UnityEngine.Random");

        // Hook the function that returns a float between 0.0 and 1.0 (used for all percentage checks)
        const getValueMethod = Random.method("get_value");
        Interceptor.attach(getValueMethod.handle, {
            onLeave: function(retval) {
                const stack = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n');
                
                // We only care about dice rolls made by the ModuleManager
                if (stack.includes("ModuleManager")) {
                    const randomValue = retval.readFloat();
                    log("RANDOM", `Random.get_value() returned: ${randomValue.toFixed(4)}`);
                    console.log(`--- Called by ---\\n${stack}\\n-----------------\\n`);
                }
            }
        });
        
        log("SUCCESS", "Tracer is live on 'UnityEngine.Random'. Please buy a module in the game.");
    } catch (e) {
        log("ERROR", `Failed to attach tracer: ${e.stack}`);
    }
};

Il2Cpp.perform(() => {
    log("SUCCESS", "Tracer script is ready. Call traceRandom() to arm the tracer.");
});