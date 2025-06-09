### **TowerIQ v1.0 - Development Task List (Part 5, Revision 2)**

**Objective:** To implement a stateful, multi-stage connection panel that provides intelligent filtering, manual user confirmation at each step, and persists its state across the application.

### **Task 5.1: Enhance Backend Services for Rich UI Data**

*   **Goal:** To add new methods to the existing services that provide the detailed information required by the new, interactive UI.
*   **Component to Modify:** `src/tower_iq/services/emulator_service.py`
*   **Actions:**
    1.  **Create a high-level process information method:**
        *   **New Method:** `async def get_installed_third_party_packages(self, device_id: str) -> list[dict]:`
        *   **Purpose:** To get a list of all user-installed apps and their status, pre-filtered to hide system processes.
        *   **Returns:** A list of dictionaries. Each dictionary must have the following keys: `'name'` (the user-friendly application name), `'package'` (e.g., `com.techtreegames.thetower`), `'version'` (e.g., `0.21.5`), `'is_running'` (boolean), and `'pid'` (integer or `None`).
        *   **Implementation:** This method will internally call existing ADB commands like `pm list packages -3`, `ps -A`, and `dumpsys package` to assemble this rich data.

*   **Component to Modify:** `src/tower_iq/services/frida_service.py`
*   **Actions:**
    1.  **Create a hook compatibility check method:**
        *   **New Method:** `async def check_hook_compatibility(self, game_version: str) -> bool:`
        *   **Purpose:** To check if a valid, signed hook script exists for the selected game version *before* attempting to inject.
        *   **Implementation:** This method will load the `config/hook_contract.yaml` manifest file, parse it, and check if an entry exists for the provided `game_version`. It should not download anything at this stage. It simply confirms if a known hook is available.

### **Task 5.2: Enhance `SessionManager` for Stateful Flow**

*   **Goal:** To add the state variables necessary to track the user's progress through the multi-stage connection flow.
*   **Component to Modify:** `src/tower_iq/core/session.py`
*   **Action:** Add the following state variables to the `SessionManager` class, ensuring they are managed with thread-safe properties (`@property` and `@prop.setter` with locks).
    *   `connected_emulator_serial: Optional[str] = None`
    *   `available_emulators: list[dict] = []`
    *   `available_processes: list[dict] = []`
    *   `selected_target_package: Optional[str] = None`
    *   `selected_target_pid: Optional[int] = None`
    *   `selected_target_version: Optional[str] = None`
    *   `is_hook_compatible: bool = False`

### **Task 5.3: Enhance `EmulatorService` with Intelligent Filtering**

*   **Goal:** To provide the UI with pre-filtered and enriched process information, including user-friendly application names.
*   **Component to Modify:** `src/tower_iq/services/emulator_service.py`
*   **Action:** Create a new, high-level method for getting process details, incorporating the technique from the provided article.

    *   **New Method:** `async def get_installed_third_party_packages(self, device_id: str) -> list[dict]:`
        *   **Purpose:** To get a list of all user-installed apps and their status.
        *   **Returns:** A list of dictionaries. Each dictionary must have the following keys: `'name'` (the user-friendly application name), `'package'` (e.g., `com.techtreegames.thetower`), `'version'` (e.g., `0.21.5`), `'is_running'` (boolean), and `'pid'` (integer or `None`).
        *   **Implementation Logic:**
            1.  **Get Running Processes:** Run `adb -s <device_id> shell ps -A` to get a mapping of all running package names to their PIDs. Store this in a temporary dictionary (e.g., `running_processes = {'com.package.name': 1234, ...}`).
            2.  **Get Third-Party Packages:** Run `adb -s <device_id> shell pm list packages -3` to get the list of all user-installed package names. The output will be `package:com.example.app`. Parse this to get a clean list.
            3.  **Create an empty results list:** `results = []`.
            4.  **Loop through each third-party package name:**
                *   For each `package_name` in the list from step 2:
                *   **Get Rich Package Info:** Run the command:
                    ```bash
                    adb -s <device_id> shell "dumpsys package <package_name> | grep -E 'versionName|application-label:'"
                    ```
                *   **Parse the Output:**
                    *   Parse the `versionName=` line to get the version string.
                    *   Parse the `application-label:` line to get the user-friendly application name. **This directly implements the technique from the article.**
                *   **Check Running Status:** Look up the `package_name` in the `running_processes` dictionary from step 1 to determine the `is_running` status and get the `pid`.
                *   **Assemble the Dictionary:** Create the final dictionary with all the collected information (`name`, `package`, `version`, `is_running`, `pid`).
                *   Append this dictionary to the `results` list.
            5.  **Return the sorted list:** Return the `results` list, sorted alphabetically by the `'name'` key.

### **Task 5.4: Integrate the Panel into the `DashboardPage`**

*   **Goal:** To make the `ConnectionStatePanel` appear as a contextual overlay on the dashboard.
*   **Component to Modify:** `src/tower_iq/gui/components/dashboard_page.py`
*   **Actions:**
    1.  In the `__init__` method, create an instance of your new `ConnectionStatePanel`.
    2.  Use a `QStackedLayout` to manage the content. Layer 0 will be the dashboard's graphs and metrics. Layer 1 will be a semi-transparent overlay widget. Layer 2 will be the `ConnectionStatePanel` itself.
    3.  **Create a public slot:** `def set_connection_active(self, is_active: bool) -> None:`.
        *   If `is_active` is `True`, hide the overlay and the connection panel by setting the layout's current index to 0.
        *   If `is_active` is `False`, show the overlay and connection panel.

### **Task 5.5: Implement the Main Controller's Connection Logic**

*   **Goal:** To write the central logic in `MainController` that orchestrates the entire interactive flow.
*   **Component to Modify:** `src/tower_iq/main_controller.py`
*   **Actions:**

    1.  **Modify Startup Logic (`run` method):**
        *   The existing automatic connection flow should be wrapped in a new method `async def _run_automatic_connection() -> bool:`.
        *   In `run()`, call `_run_automatic_connection()`. If it returns `True`, emit a signal to the dashboard to go into "active" mode.
        *   If it returns `False`, call `self.session.reset_connection_state()` and then call `self.dashboard.connection_panel.update_state(self.session)` to ensure the user is presented with the manual connection panel at Stage 1.

    2.  **Implement New Public Slots:** Connect these slots to the signals from your `ConnectionStatePanel`.
        *   **`@pyqtSlot()` - `on_scan_devices_requested(self)`:**
            *   Calls `await self.emulator_service.find_connected_devices()`.
            *   Stores the result in `self.session.available_emulators`.
            *   Calls `self.dashboard.connection_panel.update_state(self.session)` to refresh the UI with the device list.
        *   **`@pyqtSlot(str)` - `on_connect_device_requested(self, device_id)`:**
            *   Updates `self.session.connected_emulator_serial = device_id`.
            *   Calls `update_state` to advance the UI.
            *   Automatically calls the logic for refreshing processes (so the user doesn't have to click again).
        *   **`@pyqtSlot()` - `on_refresh_processes_requested(self)`:**
            *   Calls `await self.emulator_service.get_installed_third_party_packages(...)`.
            *   Stores the result in `self.session.available_processes`.
            *   Calls `update_state` to refresh the process list.
        *   **`@pyqtSlot(dict)` - `on_select_process_requested(self, process_info)`:**
            *   Updates all relevant session variables: `selected_target_package`, `pid`, `version`.
            *   Calls `await self.frida_service.check_hook_compatibility(...)`.
            *   Updates `self.session.is_hook_compatible` with the result.
            *   Calls `update_state` to advance to Stage 3 and show compatibility status.
        *   **`@pyqtSlot()` - `on_activate_hook_requested(self)`:**
            *   Calls `await self.frida_service.inject_and_run_script(...)`.
            *   If successful, sets `self.session.is_hook_active = True` and tells the dashboard to hide the panel and go live.
            *   If it fails, it calls `update_state` to show an error message in Stage 3.
