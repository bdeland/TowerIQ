📦
1296 /tower_hook.js.map
1923 /tower_hook.js
✄
{"version":3,"file":"tower_hook.js","sourceRoot":"C:/Users/delan/Documents/GitHub/TowerIQ/src/tower_iq/scripts/","sources":["tower_hook.js"],"names":[],"mappings":"AAAA;;;;;;;;;;;;;;;EAeE;AAEF,wDAAwD;AACxD,OAAO,CAAC,GAAG,CAAC,gCAAgC,CAAC,CAAC;AAE9C,kCAAkC;AAClC,IAAI,CAAC;IACD,IAAI,EAAE,cAAc;IACpB,OAAO,EAAE;QACL,OAAO,EAAE,yBAAyB;QAClC,SAAS,EAAE,IAAI,CAAC,GAAG,EAAE;KACxB;CACJ,CAAC,CAAC;AAEH,mCAAmC;AACnC,WAAW,CAAC,GAAG,EAAE;IACb,IAAI,CAAC;QACD,IAAI,EAAE,UAAU;QAChB,OAAO,EAAE;YACL,KAAK,EAAE,iBAAiB;YACxB,OAAO,EAAE,4BAA4B;YACrC,KAAK,EAAE,MAAM;YACb,SAAS,EAAE,IAAI,CAAC,GAAG,EAAE;YACrB,eAAe,EAAE,KAAK;SACzB;KACJ,CAAC,CAAC;AACP,CAAC,EAAE,IAAI,CAAC,CAAC;AAET,oCAAoC;AACpC,IAAI;IACA,IAAI,OAAO,MAAM,KAAK,WAAW,EAAE;QAC/B,IAAI,CAAC;YACD,IAAI,EAAE,UAAU;YAChB,OAAO,EAAE;gBACL,KAAK,EAAE,WAAW;gBAClB,OAAO,EAAE,qBAAqB;gBAC9B,KAAK,EAAE,MAAM;gBACb,SAAS,EAAE,IAAI,CAAC,GAAG,EAAE;aACxB;SACJ,CAAC,CAAC;KACN;SAAM;QACH,IAAI,CAAC;YACD,IAAI,EAAE,UAAU;YAChB,OAAO,EAAE;gBACL,KAAK,EAAE,WAAW;gBAClB,OAAO,EAAE,yBAAyB;gBAClC,KAAK,EAAE,SAAS;gBAChB,SAAS,EAAE,IAAI,CAAC,GAAG,EAAE;aACxB;SACJ,CAAC,CAAC;KACN;CACJ;AAAC,OAAO,KAAK,EAAE;IACZ,IAAI,CAAC;QACD,IAAI,EAAE,UAAU;QAChB,OAAO,EAAE;YACL,KAAK,EAAE,WAAW;YAClB,OAAO,EAAE,yBAAyB,GAAG,KAAK,CAAC,OAAO;YAClD,KAAK,EAAE,OAAO;YACd,SAAS,EAAE,IAAI,CAAC,GAAG,EAAE;SACxB;KACJ,CAAC,CAAC;CACN"}
✄
/** TOWERIQ_HOOK_METADATA
{
    "contractVersion": "1.1",
    "fileName": "tower_hook.js",
    "scriptName": "test script",
    "scriptDescription": "A comprehensive logger for all major in-game events and currencies.",
    "targetApp": "The Tower",
    "targetPackage": "com.TechTreeGames.TheTower",
    "supportedVersions": ["27.0.2"],
    "features": [
        "round_start_end_events",
        "per_wave_metric_bundle",
        "detailed_gem_tracking"
    ]
}
*/
// Simple test hook script to verify Frida communication
console.log("Simple test hook script loaded");
// Send a test message immediately
send({
    type: "test_message",
    payload: {
        message: "Hook script is working!",
        timestamp: Date.now()
    }
});
// Send a heartbeat every 5 seconds
setInterval(() => {
    send({
        type: "hook_log",
        payload: {
            event: "frida_heartbeat",
            message: "Heartbeat from test script",
            level: "INFO",
            timestamp: Date.now(),
            isGameReachable: false
        }
    });
}, 5000);
// Try to access Il2Cpp if available
try {
    if (typeof Il2Cpp !== 'undefined') {
        send({
            type: "hook_log",
            payload: {
                event: "frida_log",
                message: "Il2Cpp is available",
                level: "INFO",
                timestamp: Date.now()
            }
        });
    }
    else {
        send({
            type: "hook_log",
            payload: {
                event: "frida_log",
                message: "Il2Cpp is not available",
                level: "WARNING",
                timestamp: Date.now()
            }
        });
    }
}
catch (error) {
    send({
        type: "hook_log",
        payload: {
            event: "frida_log",
            message: "Error checking Il2Cpp: " + error.message,
            level: "ERROR",
            timestamp: Date.now()
        }
    });
}