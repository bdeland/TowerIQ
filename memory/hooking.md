### **TowerIQ v1.0 - Final MVP Task List (with Local Validation)**

**Objective:** To build the complete TowerIQ application, sourcing the hook script from a local file and validating its compatibility against a local manifest before allowing injection.

---

### **Part 1: Foundational Setup (with Hook Contract)**

**Goal:** Establish the core modules and the local manifest file that defines hook compatibility.

#### **Task 1.1: Create the Local Hook Contract**

*   **Goal:** To create the metadata file that maps the bundled script to the game versions it supports.
*   **File to Create/Modify:** `config/hook_contract.yaml`
*   **Action:** Create this YAML file and populate it with the following structure. This file now becomes the single source of truth for compatibility.
    ```yaml
    # config/hook_contract.yaml

    # Describes the local hook script bundled with this version of TowerIQ.
    contract_version: "1.0"

    script_info:
      # The relative path to the script file from the project root.
      path: "src/tower_iq/scripts/main_hook.js"
      
      # An explicit list of game versions this script is known to work with.
      # The application will only allow injection if the detected game version
      # is present in this list.
      supported_versions:
        - "0.21.5"
        - "0.21.4"
        - "0.20.1"
    ```

#### **Task 1.2 through 1.5 (No Changes)**

*   The tasks for implementing `ConfigurationManager`, `SessionManager`, `DatabaseService`, and the `logging_config` remain the same. They are the solid foundation we need.

---

### **Part 2: The Backend Services (with Validation Logic)**

**Goal:** To implement the service-layer logic for checking compatibility based on the local contract file.

#### **Task 2.1: Implement `EmulatorService` (No Changes)**

*   The `EmulatorService`'s job is still to find devices and report on installed packages. This task list remains the same.

#### **Task 2.2: Implement `FridaService` with Local Validation**

*   **Goal:** To modify the `FridaService` to perform a compatibility check by reading the local `hook_contract.yaml`.
*   **File to Modify:** `src/tower_iq/services/frida_service.py`
*   **Action:**

    1.  **Implement `check_local_hook_compatibility`:**
        *   This method is no longer for remote checks; it is for local validation.
        *   **New Signature:** `def check_local_hook_compatibility(self, game_version: str) -> bool:` (This can now be a synchronous method as it's just reading a local file).
        *   **New Logic:**
            1.  Get the path to the `hook_contract.yaml` from the `ConfigurationManager`.
            2.  Load and parse the YAML file.
            3.  Safely access the `script_info.supported_versions` list from the parsed data.
            4.  Return `True` if the provided `game_version` is in the list. Otherwise, return `False`.
            5.  Handle potential `FileNotFoundError` or `yaml.YAMLError` by logging an error and returning `False`.

    2.  **Simplify `inject_and_run_script`:**
        *   This method now assumes compatibility has already been checked by the controller.
        *   Its only job is to get the script path from the `hook_contract.yaml`, read the file content, and inject it.
        *   **Revised Logic:**
            ```python
            # ...
            contract_path = self.config.get("frida.hook_contract_path")
            manifest = yaml.safe_load(open(contract_path))
            script_path = manifest['script_info']['path']
            
            # Resolve script_path relative to the project root
            full_script_path = self.config.get("project_root") / script_path

            with open(full_script_path, "r") as f:
                script_content = f.read()

            self.script = self.session.create_script(script_content)
            # ... rest of the injection logic
            ```

---

### **Part 3: The Application Core & UI (with Validation Flow)**

**Goal:** To orchestrate the validation flow within the `MainController` and display the result clearly in the UI.

#### **Task 3.1: Implement `MainController` with Validation Step**

*   **Goal:** To ensure the controller checks for compatibility *after* a process is selected and *before* enabling the final activation step.
*   **File to Modify:** `src/tower_iq/main_controller.py`
*   **Action:** Modify the logic for the `on_select_process_requested` slot.

    *   **Revised Logic for `@pyqtSlot(dict) on_select_process_requested(self, process_info)`:**
        1.  Update the `SessionManager` with all the selected process info: `selected_target_package`, `selected_target_pid`, and `selected_target_version`.
        2.  **Call the validation method:**
            ```python
            is_compatible = self.frida_service.check_local_hook_compatibility(
                game_version=self.session.selected_target_version
            )
            ```
        3.  **Update the session with the result:** `self.session.is_hook_compatible = is_compatible`.
        4.  **Signal the UI:** Emit the signal that tells the UI to refresh its state. The UI will now have all the information it needs (the selected process *and* the compatibility result) to render Stage 3 correctly.

#### **Task 3.2: Implement the `ConnectionStatePanel` UI for Displaying Validation**

*   **Goal:** To make the UI clearly show whether the selected game version is compatible.
*   **File to Modify:** `src/tower_iq/gui/components/connection_panel.py`
*   **Action:** Modify the `update_state` method to handle the `is_hook_compatible` flag.

    *   **Revised Logic within `update_state(self, session: SessionManager)`:**
        *   This method now has access to `session.is_hook_compatible`.
        *   When rendering **Stage 3**, it must check this boolean:
            *   **If `session.is_hook_compatible` is `True`:**
                *   Display a green checkmark and a status message like: "✅ Compatible Hook Found".
                *   **Enable** the "Activate Monitoring" button.
            *   **If `session.is_hook_compatible` is `False`:**
                *   Display a red "X" icon and a status message like: "❌ Incompatible Game Version. Please update TowerIQ."
                *   **Disable** the "Activate Monitoring" button, preventing the user from proceeding.