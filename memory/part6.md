Of course. The design process is complete. We have a final, vetted, and robust architecture.

Here is the **complete, multi-part, exhaustive master development task list** to build TowerIQ v1.0 from your current codebase. This list is designed to be executed by an AI coding agent, with each task being a logical, self-contained unit of work that builds upon the solid foundation you already have.

---

### **TowerIQ v1.0 - Master Development Task List (Final)**

**Objective:** To build the complete TowerIQ application by implementing the final controller logic, refactoring the UI to a state-driven model, and replacing all placeholder code in the backend services with production-ready implementations.

---

### **Part 1: Service Layer Finalization & Hardening**

**Goal:** To complete the backend services by replacing all placeholder logic with the final, robust implementations we designed.

#### **Task 1.1: Finalize `FridaService` Security and Compatibility Logic**

*   **Component:** `src/tower_iq/services/frida_service.py`
*   **Actions:**
    1.  **Implement `check_hook_compatibility`:** Rewrite the method to correctly parse the `config/hook_contract.yaml` file. It should load the YAML and check if the provided `game_version` exists within a `supported_versions` list in the manifest.
    2.  **Implement Real Network Fetching:** Rewrite `_fetch_remote_manifest` to use `aiohttp` to perform a `GET` request to the manifest URL defined in `main_config.yaml`. It must handle network errors and invalid JSON responses.
    3.  **Implement Real Script Downloading:** Rewrite `_download_encrypted_script` to use `aiohttp` to download the binary content (`bytes`) from the URL specified in the manifest.
    4.  **Implement Real Signature Verification:** Rewrite `_verify_signature` to use the `pycryptodome` library. It must load a bundled public key, create a SHA256 hash of the downloaded encrypted content, and use the appropriate signature scheme (e.g., `PKCS1_v1_5` or `pss`) to validate the signature from the manifest.
    5.  **Implement Real Decryption:** Rewrite `_decrypt_script` to use `pycryptodome`. It must use the secret key from the manifest to decrypt the script content using a secure mode like AES-GCM.

#### **Task 1.2: Implement Intelligent `frida-server` Management in `EmulatorService`**

*   **Component:** `src/tower_iq/services/emulator_service.py`
*   **Actions:**
    1.  **Create the Orchestration Method:**
        *   **New Method:** `async def ensure_frida_server_is_running(self, device_id: str) -> None:`
        *   **Purpose:** This method will execute the full idempotent setup logic.
        *   **Implementation:** It will call the helper methods below in sequence: get arch -> ensure local binary -> check if outdated -> push if needed -> start if needed. It must raise a specific `FridaServerSetupError` on any failure.
    2.  **Implement Helper Methods:**
        *   **`_ensure_local_frida_server_exists(self, arch: str) -> Path:`** Checks for the pre-bundled `frida-server` binary in the `resources/` directory for the given architecture. (The download logic can be a future enhancement; for now, assume it's bundled).
        *   **`_check_if_device_server_is_outdated(self, device_id: str, local_path: Path, device_path: str) -> bool:`** Implements the hash comparison. It must execute `adb shell md5sum <device_path>` (or similar), parse the output, calculate the hash of the local file, and return `True` if the remote file is missing or the hashes do not match.
        *   **`push_file(self, device_id: str, local_path: Path, device_path: str) -> None:`** A new robust method that first attempts to `rm` the old server file on the device before running `adb push`.

---

### **Part 2: The Core Logic - Controller Implementation**

**Goal:** To implement the central `MainController` logic that drives the entire application by orchestrating the UI and the backend services.

#### **Task 2.1: Implement the `MainController`'s Connection State Machine**

*   **Component:** `src/tower_iq/main_controller.py`
*   **Actions:**
    1.  **Define Public Slots:** Create the public slot methods that will be connected to the UI's signals. These methods are the entry points for all user-driven connection actions.
        *   `@pyqtSlot() on_scan_devices_requested(self)`
        *   `@pyqtSlot(str) on_connect_device_requested(self, device_id)`
        *   `@pyqtSlot() on_refresh_processes_requested(self)`
        *   `@pyqtSlot(dict) on_select_process_requested(self, process_info)`
        *   `@pyqtSlot(bool) on_activate_hook_requested(self, remember_settings)`
    2.  **Implement Slot Logic:**
        *   For each slot, implement the logic to call the appropriate `EmulatorService` or `FridaService` method.
        *   After each service call, update the `SessionManager` with the new state (e.g., `self.session.available_emulators = devices`).
        *   After updating the session, emit a signal to the UI to trigger a visual refresh: `self.connection_state_updated.emit(self.session)`.
        *   The `on_connect_device_requested` slot should orchestrate the call to `emulator_service.ensure_frida_server_is_running` and, on success, automatically trigger `on_refresh_processes_requested`.
    3.  **Wrap Blocking Calls:** All synchronous calls to services (especially the `DatabaseService`) must be wrapped in `await asyncio.to_thread(...)` to prevent blocking the async event loop.

#### **Task 2.2: Implement the Automatic Connection Flow**

*   **Component:** `src/tower_iq/main_controller.py`
*   **Actions:**
    1.  **Create `_run_automatic_connection` Method:**
        *   **Method:** `async def _run_automatic_connection(self) -> bool:`
        *   **Logic:**
            1.  Loads `auto_connect_serial` and `auto_connect_package` settings from the `DatabaseService`. Returns `False` if not found.
            2.  Executes the entire connection and hooking sequence non-interactively by calling the same service methods as the manual flow.
            3.  If any step fails, it immediately logs the error and returns `False`.
            4.  If all steps succeed, it updates all `SessionManager` state variables and returns `True`.
    2.  **Update Main `run` Method:**
        *   In the `MainController`'s main `run` method, it should first `await self._run_automatic_connection()`.
        *   Based on the result, it will either set the session to the fully "Hooked" state or leave it in the default "Disconnected" state, letting the UI decide which panel to show.

---

### **Part 3: The User Interface - Refactoring and Integration**

**Goal:** To build the user-facing connection UI and connect it to the `MainController`'s logic, creating a polished, state-driven experience.

#### **Task 3.1: Create the `ConnectionStatePanel` UI**

*   **File:** `src/tower_iq/gui/components/connection_panel.py`
*   **Action:** Create the `ConnectionStatePanel(QWidget)` class.
    1.  **Define Custom Signals:** `scan_devices_requested`, `connect_device_requested(str)`, `refresh_processes_requested`, `select_process_requested(dict)`, `activate_hook_requested(bool)`.
    2.  **Build UI:** Create the three-stage layout. Use `QTableWidget` for the device and process lists. The "Action" column in these tables will contain `QPushButton`s.
    3.  **Connect Internal Signals:** Connect the `clicked` signal of each button (e.g., "Scan", "Connect" in a table row) to a lambda that emits the appropriate custom signal from the panel itself.
    4.  **Implement `update_state(self, session: SessionManager)`:** This is the core method for redrawing the UI. It should be able to take a `SessionManager` object and make the entire panel's visual state (enabled/disabled boxes, table contents, status labels) perfectly reflect the state of the session object.

#### **Task 3.2: Integrate Panel into `DashboardPage`**

*   **Component:** `src/tower_iq/gui/components/dashboard_page.py`
*   **Actions:**
    1.  In `__init__`, create an instance of `ConnectionStatePanel`.
    2.  Use a `QStackedLayout` to manage the content. Layer 0: the dashboard graphs. Layer 1: a semi-transparent overlay. Layer 2: the `ConnectionStatePanel`.
    3.  **Create Public Slot:** `def on_connection_status_changed(self, is_active: bool)`
        *   If `is_active` is `True`, hide the overlay and panel.
        *   If `is_active` is `False`, show the overlay and panel.

#### **Task 3.3: Connect UI to Controller**

*   **Component:** `src/tower_iq/main_controller.py`
*   **Action:** In the controller's `__init__`, after the `MainWindow` is created, connect all signals and slots.
    *   **Connect UI to Controller:** `main_window.dashboard_page.connection_panel.scan_devices_requested.connect(self.on_scan_devices_requested)` (and so on for all UI-driven actions).
    *   **Connect Controller to UI:** `self.connection_state_updated.connect(main_window.dashboard_page.connection_panel.update_state)` and `self.hook_status_changed.connect(main_window.dashboard_page.on_connection_status_changed)`.

#### **Task 3.4: Finalize the Main Application Entry Point**

*   **Component:** `src/tower_iq/main_app_entry.py`
*   **Action:** Ensure the `main` function correctly orchestrates the startup sequence.
    1.  Create `ConfigurationManager` and load config.
    2.  Create `DatabaseService` and connect/migrate.
    3.  Call `setup_logging`, passing the config and `db_service`.
    4.  Instantiate the `QApplication`, `qasync` loop, `MainController`, and `MainWindow`.
    5.  Start the `controller.run()` task and the event loop.

This completes the master task list. Executing these tasks will result in a fully functional application that matches the final, robust architecture we have designed.