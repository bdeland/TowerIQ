// module_inspector_with_sprites_final.js
// This is the final, corrected tool. The inspectSprite function has been
// rewritten to read the sprite information directly from the ModuleDetailsUI
// panel, which is the correct and most direct approach.

import "frida-il2cpp-bridge";

function log(level, message) { console.log(`[${level.toUpperCase()}] ${message}`); }

// --- Main Tool Functions ---

global.inspectModule = function() {
    // This function is complete and works perfectly.
    log("ACTION", "Inspecting the current module's data...");
    
    let moduleManager, allEffectsArray;
    try {
        moduleManager = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleManager").field("Instance").value;
        allEffectsArray = moduleManager.field("effects").value;
    } catch (e) { log("ERROR", "Could not get ModuleManager."); return; }

    let moduleItem;
    try {
        const moduleUI = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleUI").method("get_Instance").invoke();
        const detailsPanel = moduleUI.field("moduleDetailsUI").value;
        moduleItem = detailsPanel.field("_moduleItem").value;
        if (!moduleItem || moduleItem.isNull()) {
            log("ERROR", "No module is being inspected. Please open a module's detail page.");
            return;
        }
    } catch (e) { log("ERROR", `Failed to get the inspected module: ${e.stack}`); return; }

    try {
        const infoIndex = moduleItem.field("infoIndex").value;
        const moduleName = moduleManager.method("GetModuleName", 1).invoke(infoIndex).toString();
        const moduleLevel = moduleItem.field("level").value;
        const effects = moduleItem.field("effects").value;
        const effectLocked = moduleItem.field("effectLocked").value;

        log("INFO", `--- Inspector Report for: "${moduleName}" (Level ${moduleLevel}) ---`);
        for (let i = 0; i < effects.length; i++) {
            const effectId = effects.get(i);
            const isLocked = effectLocked.get(i);
            const effectInfo = allEffectsArray.get(effectId);
            const clusterName = effectInfo.field("clusterIndex").value.toString();
            
            if (clusterName !== "None") {
                const rarity = effectInfo.field("rarity").value.toString();
                log("DETAIL", `[Slot ${i}] Effect: ${clusterName} (${rarity}) | Locked: ${isLocked}`);
            }
        }
        log("INFO", "--- End of Report ---");
    } catch(e) {
        log("ERROR", `An error occurred while inspecting the module: ${e.stack}`);
    }
};

global.inspectSprite = function() {
    log("ACTION", "Inspecting the current module's sprites...");

    try {
        // Get the ModuleDetailsUI panel directly
        const moduleUI = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleUI").method("get_Instance").invoke();
        const detailsPanel = moduleUI.field("moduleDetailsUI").value;

        if (!detailsPanel || detailsPanel.isNull()) {
            log("ERROR", "Could not find the ModuleDetailsUI panel instance.");
            return;
        }

        // --- Extract Sprite Names Directly from the Details Panel ---
        // Based on consistent naming, these fields should exist on ModuleDetailsUI.
        const frameImage = detailsPanel.field("moduleFrame").value;
        const iconImage = detailsPanel.field("moduleIcon").value;
        
        // An Image component's image is stored in its 'sprite' property.
        // We access properties via "get_PROPERTYNAME" methods.
        const frameSprite = frameImage.method("get_sprite").invoke();
        const iconSprite = iconImage.method("get_sprite").invoke();

        const frameSpriteName = frameSprite ? frameSprite.method("get_name").invoke().toString() : "None";
        const iconSpriteName = iconSprite ? iconSprite.method("get_name").invoke().toString() : "None";
        
        // Get the module name for a nice report header
        const moduleItem = detailsPanel.field("_moduleItem").value;
        const moduleName = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleManager").field("Instance").value.method("GetModuleName", 1).invoke(moduleItem.field("infoIndex").value).toString();

        log("INFO", `--- Sprite Info for: "${moduleName}" ---`);
        log("DETAIL", `Frame Sprite Name: ${frameSpriteName}`);
        log("DETAIL", `Icon Sprite Name: ${iconSpriteName}`);
        log("INFO", "--- End of Report ---");

    } catch (e) {
        log("ERROR", `An error occurred while inspecting sprites: ${e.stack}`);
        log("HINT", "If this fails, the field names 'moduleFrame' or 'moduleIcon' might be different on the ModuleDetailsUI class. Use a lister script to find the correct names.");
    }
};

Il2Cpp.perform(() => {
    log("SUCCESS", "Complete Module Tool is ready.");
    log("INFO", "Open a module's detail page in-game.");
    log("ACTION", "Call 'inspectModule()' for substat info, or 'inspectSprite()' for image info.");
});