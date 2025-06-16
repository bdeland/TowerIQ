// src/test_bridge.js
import "frida-il2cpp-bridge";

// This is the only test we need.
// If the bridge initializes correctly, it will print a large object
// full of functions. If it fails, it will print 'undefined' or crash.
console.log(JSON.stringify(Il2Cpp, null, 2));