// module_reroll_analyzer_final.js
// Description: This script hooks into the module rerolling logic to determine
// if locking a substat removes it from the pool of potential outcomes.
// FINAL: Updated with the correct method overload (2 arguments) for GetPotentialEffectsForModule.

import "frida-il2cpp-bridge";

// --- CONFIGURATION ---
// Keep this 'true' for the first run to see the structure of the effect objects.
const DEBUG_MODE = true;

Il2Cpp.perform(() => {

    function log(level, message) {
        console.log(`[${level.toUpperCase()}] ${message}`);
    }

    function logEffectList(effectList, contextMessage) {
        if (!effectList || effectList.isNull()) {
            log("WARN", `Effect list is null or invalid during: ${contextMessage}`);
            return;
        }

        try {
            const listSize = effectList.method("get_Count").invoke();
            log("INFO", `--- Dumping Reroll Pool (Context: ${contextMessage}) ---`);
            log("INFO", `Found ${listSize} possible effect(s) in the pool.`);

            if (listSize === 0) {
                 log("INFO", `--- End of Dump ---`);
                 return;
            }

            const firstEffectItem = effectList.method("get_Item", 1).invoke(0);

            if (DEBUG_MODE) {
                log("DEBUG", `Inspecting structure of the first effect item...`);
                log("DEBUG", `Item Class: ${firstEffectItem.class.name}`);
                log("DEBUG", "Available fields on this item:");
                firstEffectItem.class.fields.forEach(f => {
                    log("DEBUG", `  - Name: '${f.name}', Type: '${f.type.name}'`);
                });
            }

            for (let i = 0; i < listSize; i++) {
                const effectItem = effectList.method("get_Item", 1).invoke(i);
                
                // IMPORTANT: You may need to change these field names based on the DEBUG output above.
                const effectId = effectItem.field("id").value;
                const effectDescription = effectItem.field("description").value.toString();
                
                log("DETAIL", `  [${i}] ID: ${effectId} | Description: "${effectDescription}"`);
            }
            log("INFO", `--- End of Dump ---`);

        } catch (e) {
            log("ERROR", `Failed to process effect list. Error: ${e.stack}`);
            log("HINT", "Check the DEBUG output above. You likely need to change the field names ('id', 'description') in the script to match what the game uses.");
        }
    }

    try {
        log("INFO", "Il2Cpp Bridge is ready. Setting up module analysis hooks...");

        const Assembly = Il2Cpp.domain.assembly("Assembly-CSharp");
        const ModuleManager = Assembly.image.class("ModuleManager");
        const EffectViewer = Assembly.image.class("EffectViewer");

        EffectViewer.method("UpdateLockState").implementation = function (isLocked) {
            const lockedState = isLocked ? "LOCKED" : "UNLOCKED";
            log("ACTION", `Substat lock state changed to: ${lockedState}`);
            return this.method("UpdateLockState").invoke(isLocked);
        };
        log("SUCCESS", "Hook on EffectViewer.UpdateLockState is live.");

        const targetMethodName = "GetPotentialEffectsForModule";
        const paramCount = 2; // Confirmed from the lister script!

        ModuleManager.method(targetMethodName, paramCount).implementation = function (...args) {
            log("INTERCEPT", `SUCCESS! Hook for ModuleManager.${targetMethodName} was triggered.`);
            
            const resultList = this.method(targetMethodName, paramCount).invoke(...args);
            logEffectList(resultList, "After GetPotentialEffectsForModule call");
            return resultList;
        };

        log("SUCCESS", `Hook on ModuleManager.${targetMethodName} with ${paramCount} arguments is live.`);
        log("INFO", "Ready for analysis. Please perform a module reroll in the game.");

    } catch (e) {
        log("ERROR", `A critical error occurred during hook setup: ${e.stack}`);
    }
});