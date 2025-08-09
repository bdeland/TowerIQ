// frida_scripts/export_modules.js
// This script exports ALL module data, capturing every field from the
// ModuleItem class in a compact, array-of-arrays format.

import "frida-il2cpp-bridge";

rpc.exports = {
    exportAllModules: function () {
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
                        substats.push([
                            j,
                            effectInfo.field("clusterIndex").value.value,
                            effectInfo.field("rarity").value.value,
                            effectLockedArray.get(j)
                        ]);
                    }
                }
                
                // --- Complete Module Schema ---
                allModulesData.push([
                    moduleItem.field("guid").value.toString(),
                    infoIndex,
                    moduleItem.field("level").value,
                    moduleItem.field("currentRarity").value.value,
                    moduleItem.field("isNew").value,
                    moduleItem.field("coinsSpent").value,
                    moduleItem.field("shardsSpent").value,
                    moduleItem.field("favorite").value,
                    moduleInfo.field("type").value.value,
                    moduleManager.method("IsEquipped", 1).invoke(moduleItem),
                    (moduleManager.method("GetModuleFrame", 2).invoke(moduleInfo.field("type").value, moduleItem.field("currentRarity").value)?.method("get_name").invoke().toString() || "None"),
                    (moduleManager.method("GetModuleIcon", 1).invoke(infoIndex)?.method("get_name").invoke().toString() || "None"),
                    substats
                ]);
            });
            
            send(allModulesData); // Send the compact data back to Python
            
        } catch (e) {
            send({error: e.stack});
        }
    }
};