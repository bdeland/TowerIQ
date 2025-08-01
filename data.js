// generate_module_data_definitive.js
// This is the definitive version of the generator. It uses GetUniqueBenefit for
// raw numerical data and gracefully handles modules that do not have a
// unique effect, preventing the "error" output.

import "frida-il2cpp-bridge";

global.generate = function() {
    console.log("modules:");
    try {
        const ModuleManager = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleManager").field("Instance").value;
        const ModuleRarity = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("ModuleRarity").enum;

        const modulesInfoArray = ModuleManager.field("modulesInfo").value;
        const totalModules = modulesInfoArray.length;

        for (let i = 0; i < totalModules; i++) {
            const moduleInfo = modulesInfoArray.get(i);
            
            const name = ModuleManager.method("GetModuleName", 1).invoke(i).toString();
            const type = moduleInfo.field("type").value.toString();
            
            // --- CORRECTED: Handle null or empty descriptions gracefully ---
            let desc = "";
            const descObject = ModuleManager.method("GetModuleUniqueDescription", 1).invoke(i);
            if (descObject && !descObject.isNull()) {
                const tempDesc = descObject.toString();
                if (tempDesc) {
                    desc = tempDesc.replace(/\{0\}/g, "{X}");
                }
            }

            console.log(`  ${i}:`);
            console.log(`    name: "${name}"`);
            console.log(`    type: "${type}"`);
            console.log(`    unique_effect_description: "${desc}"`);
            
            // Only try to get values if a description actually exists.
            if (desc) {
                console.log(`    unique_effect_values:`);
                for (const rarityName in ModuleRarity) {
                    // We only care about the string names of the enum
                    if (isNaN(rarityName)) { 
                        const rarityEnum = ModuleRarity[rarityName];
                        
                        // Use the superior GetUniqueBenefit method to get a pure number
                        const benefitValue = ModuleManager.method("GetUniqueBenefit", 2).invoke(i, rarityEnum);
                        
                        if (benefitValue > 0) {
                            const formattedValue = (benefitValue % 1 === 0) ? benefitValue.toFixed(0) : benefitValue.toFixed(2);
                            console.log(`      ${rarityName}: ${formattedValue}`);
                        }
                    }
                }
            }
        }
        console.log("\n[ACTION] Copy the 'modules:' block above into your lookups.yml file.");
    } catch (e) {
        console.log(`\n[ERROR] An error occurred: ${e.stack}`);
    }
};

Il2Cpp.perform(() => {
    console.log("[SUCCESS] Definitive Module Data Generator is ready. Call generate()");
});