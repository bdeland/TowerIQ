// src/index.js - FINAL VERSION
// This script bypasses all high-level bridge APIs and uses the low-level exports directly.

import "frida-il2cpp-bridge";

function log(message) {
    console.log(`[${new Date().toISOString()}] ${message}`);
}

// A global flag to ensure our main logic only runs once.
let isInitialized = false;

/**
 * This is our main hooking function. It will be called once the library is ready.
 */
function initializeHooks() {
    if (isInitialized) return;
    isInitialized = true;

    log("libil2cpp.so is ready. Setting up hooks using low-level bridge exports...");

    // We use a `setImmediate` to ensure the call stack is clear before we begin.
    setImmediate(() => {
        try {
            // --- Configuration ---
            const CLASS_NAME = "Main";
            const METHOD_NAME = "NewWave";
            const FIELD_NAME = "coins";

            // --- Step 1: Get the 'Il2CppImage' for Assembly-CSharp.dll ---
            // We use the low-level Il2Cpp.domain object.
            const domain = Il2Cpp.domain;
            const assemblies = domain.assemblies;
            const csharpAssembly = assemblies.find(a => a.name == "Assembly-CSharp.dll");
            if (!csharpAssembly) throw new Error("Could not find Assembly-CSharp.dll");
            const image = csharpAssembly.image;
            log(`Found Assembly-CSharp image at ${image.handle}`);
            
            // --- Step 2: Find the 'Il2CppClass' pointer for "Main" ---
            // We use the low-level export function directly.
            const mainClassPtr = Il2Cpp.exports.classFromName(image.handle, Memory.allocUtf8String(""), Memory.allocUtf8String(CLASS_NAME));
            if (mainClassPtr.isNull()) throw new Error(`Could not find class: ${CLASS_NAME}`);
            log(`Found Main class pointer at ${mainClassPtr}`);

            // --- Step 3: Find the 'MethodInfo' pointer for "NewWave" ---
            const newWaveMethodPtr = Il2Cpp.exports.classGetMethodFromName(mainClassPtr, Memory.allocUtf8String(METHOD_NAME), 0);
            if (newWaveMethodPtr.isNull()) throw new Error(`Could not find method: ${METHOD_NAME}`);
            log(`Found NewWave method pointer at ${newWaveMethodPtr}`);

            // --- Step 4: Find the offset for the "coins" field ---
            const coinsFieldPtr = Il2Cpp.exports.classGetFieldFromName(mainClassPtr, Memory.allocUtf8String(FIELD_NAME));
            if (coinsFieldPtr.isNull()) throw new Error(`Could not find field: ${FIELD_NAME}`);
            const coinsFieldOffset = Il2Cpp.exports.fieldGetOffset(coinsFieldPtr);
            log(`Found 'coins' field at offset: ${coinsFieldOffset}`);

            // --- Step 5: Hook the method using the standard Frida Interceptor ---
            Interceptor.attach(newWaveMethodPtr, {
                onEnter: function (args) {
                    // args[0] is the 'this' pointer, which is the instance of the Main class.
                    const mainInstance = args[0];
                    log(`-> HOOK TRIGGERED: ${METHOD_NAME}() was called!`);
                    
                    // Manually read the field using the instance pointer and the offset.
                    const coinsAddress = mainInstance.add(coinsFieldOffset);
                    const coinsValue = coinsAddress.readDouble(); // 'coins' is a double
                    
                    log(`   READING FIELD -> Value of '${FIELD_NAME}': ${coinsValue.toFixed(0)}`);
                }
            });

            log(`SUCCESS: Hook for ${CLASS_NAME}.${METHOD_NAME} is active.`);

        } catch (error) {
            log(`!!!! SCRIPT SETUP FAILED: ${error.message}\n${error.stack}`);
        }
    });
}

// ===================================================================
// --- GLOBAL ENTRY POINT: Our robust waiter logic ---
// ===================================================================
log("Script loaded. Waiting for libil2cpp.so...");

// We use Java.perform as the most stable entry point to avoid context issues.
Java.perform(() => {
    const module = Process.findModuleByName("libil2cpp.so");
    if (module) {
        log("libil2cpp.so is already loaded. Initializing now.");
        initializeHooks();
    } else {
        log("libil2cpp.so not loaded yet. Hooking dlopen to wait for it.");
        const dlopen = Module.findExportByName(null, "android_dlopen_ext") || Module.findExportByName(null, "dlopen");
        
        if (dlopen) {
            const listener = Interceptor.attach(dlopen, {
                onEnter: function (args) {
                    const path = args[0].readCString();
                    if (path && path.includes("libil2cpp.so")) {
                        listener.detach();
                        log("dlopen is loading libil2cpp.so. Initializing hooks...");
                        initializeHooks();
                    }
                }
            });
        } else {
            log("FATAL: Could not find a dlopen function to hook.");
        }
    }
});