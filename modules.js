// module_tool_final.js
// This is the final, working script.
// 1. getLocked(): Correctly reads and prints the STRING NAMES of locked substats.
// 2. getAllPossible(): Prints a clean, human-readable list of all substats in the game.

import "frida-il2cpp-bridge";

function log(level, message) { console.log(`[${level.toUpperCase()}] ${message}`); }

// --- Global Helper Functions ---

function getInspectedModule() {
    try {
        const moduleUI = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleUI").method("get_Instance").invoke();
        const detailsPanel = moduleUI.field("moduleDetailsUI").value;
        return detailsPanel.field("_moduleItem").value;
    } catch (e) {
        log("ERROR", `Could not get the inspected module. Is the module details panel open?`);
        return null;
    }
}

global.getLocked = function() {
    const moduleItem = getInspectedModule();
    if (!moduleItem) return;

    log("ACTION", "Querying locked substats for the current module...");
    try {
        const moduleManager = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleManager").field("Instance").value;
        const lockedList = moduleManager.method("GetLockedSubstats", 1).invoke(moduleItem);
        const listSize = lockedList.method("get_Count").invoke();
        log("INFO", `Found ${listSize} locked substat(s).`);

        if (listSize > 0) {
            const itemValues = [];
            // CORRECTED: The most reliable way to get the enum's representation is
            // to call its toString() method, as proven by our diagnostic logs.
            for (let i = 0; i < listSize; i++) {
                const item = lockedList.method("get_Item", 1).invoke(i);
                itemValues.push(item.toString());
            }
            log("DETAIL", `Locked Substat Names: [${itemValues.join(", ")}]`);
        }
    } catch (e) {
        log("ERROR", `Failed to get locked substats: ${e.stack}`);
    }
};

global.getAllPossible = function() {
    // This function is complete and correct.
    log("ACTION", "Dumping all possible module substats from the master list...");
    try {
        const moduleManager = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleManager").field("Instance").value;
        const allEffectsArray = moduleManager.field("effects").value;
        const len = allEffectsArray.length;
        log("INFO", `Master list contains ${len} total possible effects.`);
        
        for (let i = 0; i < len; i++) {
            const effect = allEffectsArray.get(i);
            const effectData = [
                `Cluster: ${effect.field("clusterIndex").value}`,
                `Rarity: ${effect.field("rarity").value}`,
                `Benefit: ${effect.field("benefit").value.toFixed(2)}`
            ];
            log("DETAIL", `[${i}] { ${effectData.join(", ")} }`);
        }
    } catch(e) {
        log("ERROR", `Failed to get master effect list: ${e.stack}`);
    }
};

Il2Cpp.perform(() => {
    log("SUCCESS", "Analysis tool is ready.");
    log("INFO", "Open a module's detail page in-game.");
    log("ACTION", "Call 'getLocked()' and 'getAllPossible()' from the Frida console.");
});