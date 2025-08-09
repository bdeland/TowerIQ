// full_inventory_inspector_final.js
// The complete module analysis tool. Dumps ALL stats, including the newly
// requested fields, for every module a player has.

import "frida-il2cpp-bridge";

function log(level, message) { console.log(`[${level.toUpperCase()}] ${message}`); }

// --- Global Helper Function ---

global.inspectInventory = function() {
    log("ACTION", "Inspecting ALL modules (inventory and equipped)...");
    
    let moduleManager, allEffectsArray;
    try {
        moduleManager = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleManager").field("Instance").value;
        allEffectsArray = moduleManager.field("effects").value;
    } catch (e) { log("ERROR", "Could not get ModuleManager. Is the game fully loaded?"); return; }

    try {
        const inventoryList = moduleManager.field("inventory").value;
        const equippedArray = moduleManager.field("equipped").value;

        const allModuleItems = [];

        const inventorySize = inventoryList.method("get_Count").invoke();
        for (let i = 0; i < inventorySize; i++) {
            allModuleItems.push(inventoryList.method("get_Item", 1).invoke(i));
        }
        for (let i = 0; i < equippedArray.length; i++) {
            const moduleItem = equippedArray.get(i);
            if (moduleItem && !moduleItem.isNull()) {
                allModuleItems.push(moduleItem);
            }
        }

        const totalSize = allModuleItems.length;
        log("INFO", `Found ${totalSize} total modules.`);
        console.log("=============================================");

        for (let i = 0; i < totalSize; i++) {
            const moduleItem = allModuleItems[i];

            // --- Capture ALL ModuleItem fields ---
            const infoIndex = moduleItem.field("infoIndex").value;
            const moduleLevel = moduleItem.field("level").value;
            const moduleRarity = moduleItem.field("currentRarity").value;
            const guid = moduleItem.field("guid").value.toString();
            const isNew = moduleItem.field("isNew").value;
            const favorite = moduleItem.field("favorite").value;
            const coinsSpent = moduleItem.field("coinsSpent").value;
            const shardsSpent = moduleItem.field("shardsSpent").value;
            
            // --- Derived Data (from helper functions and other objects) ---
            const moduleInfo = moduleItem.method("GetInfo").invoke();
            const moduleType = moduleInfo.field("type").value;
            const isEquipped = moduleManager.method("IsEquipped", 1).invoke(moduleItem);
            
            let moduleName = "Unknown Name";
            const moduleNameObject = moduleManager.method("GetModuleName", 1).invoke(infoIndex);
            if (moduleNameObject && !moduleNameObject.isNull()) {
                moduleName = moduleNameObject.toString();
            }

            const rarityString = moduleRarity ? moduleRarity.toString() : "Unknown Rarity";
            
            const frameSprite = moduleManager.method("GetModuleFrame", 2).invoke(moduleType, moduleRarity);
            const iconSprite = moduleManager.method("GetModuleIcon", 1).invoke(infoIndex);
            
            const frameSpriteName = frameSprite ? frameSprite.method("get_name").invoke().toString() : "None";
            const iconSpriteName = iconSprite ? iconSprite.method("get_name").invoke().toString() : "None";

            // --- Build Status Flags for the Header ---
            const statusFlags = [];
            if (isEquipped) statusFlags.push("Equipped");
            if (favorite) statusFlags.push("Favorite");
            if (isNew) statusFlags.push("New");
            const statusString = statusFlags.length > 0 ? ` - [${statusFlags.join(", ")}]` : "";

            // --- Print the Comprehensive Report ---
            console.log(`[${i + 1}/${totalSize}] "${moduleName}" (Level ${moduleLevel}, ${rarityString})${statusString}`);
            console.log(`    GUID -> ${guid}`);
            console.log(`    Stats -> Coins Spent: ${coinsSpent.toFixed(0)}, Shards Spent: ${shardsSpent}`);
            console.log(`    Sprites -> Frame: '${frameSpriteName}', Icon: '${iconSpriteName}'`);

            const effects = moduleItem.field("effects").value;
            const effectLocked = moduleItem.field("effectLocked").value;
            for (let j = 0; j < effects.length; j++) {
                const effectId = effects.get(j);
                const isLocked = effectLocked.get(j);
                const effectInfo = allEffectsArray.get(effectId);
                const clusterName = effectInfo.field("clusterIndex").value.toString();
                
                if (clusterName !== "None") {
                    const rarity = effectInfo.field("rarity").value.toString();
                    console.log(`    Substat ${j} -> ${clusterName} (${rarity}) | Locked: ${isLocked}`);
                }
            }
            console.log("---------------------------------------------");
        }
        log("INFO", "Full inventory inspection complete.");

    } catch (e) {
        log("ERROR", `An error occurred while inspecting the inventory: ${e.stack}`);
    }
};

Il2Cpp.perform(() => {
    log("SUCCESS", "Full Inventory Inspection Tool is ready.");
    log("ACTION", "Call 'inspectInventory()' from the Frida console to dump all modules.");
});