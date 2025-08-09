// frida_scripts/export_modules.js
// This is the definitive, production-ready exporter script.
// It correctly handles initialization and exports all module data in a compact,
// integer-based format for the Python application.

import "frida-il2cpp-bridge";

// Helper to safely convert Frida Strings to primitive JS strings.
function toJsString(fridaString) {
    if (!fridaString || fridaString.isNull()) {
        return "None";
    }
    // A robust way to unwrap the string from a Frida String object
    return fridaString.toString();
}

// This is the core logic of our exporter.
const exportLogic = () => {
    try {
        const allModulesData = [];
        const moduleManager = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleManager").field("Instance").value;
        const allEffectsArray = moduleManager.field("effects").value;
        
        const inventoryList = moduleManager.field("inventory").value;
        const equippedArray = moduleManager.field("equipped").value;
        
        const combinedList = [];
        const invSize = inventoryList.method("get_Count").invoke();
        for (let i = 0; i < invSize; i++) { combinedList.push(inventoryList.method("get_Item", 1).invoke(i)); }
        for (let i = 0; i < equippedArray.length; i++) {
            const item = equippedArray.get(i);
            if (item && !item.isNull()) { combinedList.push(item); }
        }
        
        combinedList.forEach(moduleItem => {
            const infoIndex = moduleItem.field("infoIndex").value;
            const moduleInfo = moduleItem.method("GetInfo").invoke();
            
            const substats = [];
            const effectsArray = moduleItem.field("effects").value;
            const effectLockedArray = moduleItem.field("effectLocked").value;
            for (let j = 0; j < effectsArray.length; j++) {
                const effectId = effectsArray.get(j);
                const effectInfo = allEffectsArray.get(effectId);
                const clusterName = effectInfo.field("clusterIndex").value.toString();
                
                if (clusterName !== "None") {
                    // Substat Schema: [ slot, clusterIndex, rarity, locked ]
                    substats.push([
                        j,
                        effectInfo.field("clusterIndex").value.value,
                        effectInfo.field("rarity").value.value,
                        effectLockedArray.get(j)
                    ]);
                }
            }
            
            const frameSprite = moduleManager.method("GetModuleFrame", 2).invoke(moduleInfo.field("type").value, moduleItem.field("currentRarity").value);
            const iconSprite = moduleManager.method("GetModuleIcon", 1).invoke(infoIndex);

            // --- Complete Module Schema (Order is critical) ---
            allModulesData.push([
                toJsString(moduleItem.field("guid").value),
                infoIndex,
                moduleItem.field("level").value,
                moduleItem.field("currentRarity").value.value,
                moduleItem.field("isNew").value,
                moduleItem.field("coinsSpent").value,
                moduleItem.field("shardsSpent").value,
                moduleItem.field("favorite").value,
                moduleInfo.field("type").value.value,
                moduleManager.method("IsEquipped", 1).invoke(moduleItem),
                toJsString(frameSprite?.method("get_name").invoke()),
                toJsString(iconSprite?.method("get_name").invoke()),
                substats
            ]);
        });
        
        send(allModulesData);
        
    } catch (e) {
        send({error: e.stack});
    }
};

// Define the export SYNCHRONOUSLY so Python can see it immediately.
rpc.exports = {
    exportAllModules: function () {
        // Inside the function, we check if the bridge is ready.
        if (Il2Cpp.available) {
            exportLogic();
        } else {
            // If not, queue the logic to run as soon as it IS ready.
            Il2Cpp.perform(() => {
                exportLogic();
            });
        }
    }
};