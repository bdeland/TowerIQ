// dummy_with_bridge_placeholder.js
import "frida-il2cpp-bridge"; // We import it, but won't call Il2Cpp.perform() yet

console.log("[DummyWithBridge] Script loaded! (frida-il2cpp-bridge was imported)");

send({ 
    script: "DummyWithBridge",
    type: "status", 
    event: "loaded_with_bridge_import", 
    timestamp: new Date().toISOString(),
    data: { message: "Hello from DummyWithBridge!" } 
});

// Check if Il2Cpp object is available (it should be if import worked and bridge is set up)
if (typeof Il2Cpp !== 'undefined') {
    console.log("[DummyWithBridge] Il2Cpp object IS defined globally.");
    send({ 
        script: "DummyWithBridge",
        type: "status", 
        event: "il2cpp_object_defined", 
        timestamp: new Date().toISOString(),
        data: { message: "Il2Cpp symbol is present." } 
    });
} else {
    console.log("[DummyWithBridge] Il2Cpp object IS NOT defined globally.");
    send({ 
        script: "DummyWithBridge",
        type: "error", 
        event: "il2cpp_object_not_defined", 
        timestamp: new Date().toISOString(),
        data: { message: "Il2Cpp symbol is NOT present after import." } 
    });
}