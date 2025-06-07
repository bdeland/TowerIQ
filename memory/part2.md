# TowerIQ v1.0 - Development Task List (Part 2: Core Logic & Services)

This document details the core application logic and the remaining backend services. It defines the `MainController`, the `SetupService` that orchestrates the entire onboarding flow, and the services responsible for interacting with the Android emulator and the Frida instrumentation toolkit.

---

## **7. Core Application Logic: The Main Controller**

**Goal:** Create the central coordinator that connects the UI, services, and session state.

### **File: `src/tower_iq/main_controller.py`**

*   **Purpose:** This module defines the `MainController` class, the "brain" of the application.

#### **Class: `MainController(QObject)`**

*   **Inherits from:** `PyQt6.QtCore.QObject` to support signals and slots.
*   **Purpose:** To orchestrate the entire application lifecycle after startup, acting as the bridge between the UI and the backend services. It runs in a background `asyncio` event loop.

*   **PyQt Signals:**
    *   `log_received = pyqtSignal(dict)`: Emits a structured log dictionary for the UI's log viewer.
    *   `status_changed = pyqtSignal(str, str)`: Emits a status update (e.g., `("docker", "healthy")`).
    *   `new_metric_received = pyqtSignal(str, object)`: Emits new game metrics for the UI dashboard (e.g., `("cph", 12345)`).
    *   `setup_finished = pyqtSignal(bool)`: Emits `True` if the initial setup was successful, `False` otherwise.

*   **Methods:**
    *   `__init__(self, config: ConfigurationManager, logger: Any) -> None:`
        *   **Purpose:** Initializes the controller and all its required services.
        *   **Arguments:** Receives the core application dependencies via dependency injection.
        *   **State:**
            *   `self.logger = logger.bind(source="MainController")`
            *   `self.config: ConfigurationManager`
            *   `self.session: SessionManager = SessionManager()`
            *   `self.db_service: DatabaseService = DatabaseService(...)`
            *   `self.docker_service: DockerService = DockerService(...)`
            *   `self.setup_service: SetupService = SetupService(...)`
            *   `self.emulator_service: EmulatorService = EmulatorService(...)`
            *   `self.frida_service: FridaService = FridaService(...)`
            *   `self._message_handlers: dict` (Initialized by `_register_handlers()`)
            *   `self._is_running: bool = False`

    *   `async run(self) -> None:`
        *   **Purpose:** The main entry point for the controller's lifecycle. This method is started in the background by `main_app_entry.py`.
        *   **Logic:**
            1.  `self._is_running = True`
            2.  Calls `self._register_handlers()`.
            3.  Calls `await self.setup_service.run_initial_setup()`. Emits `setup_finished` signal with the result.
            4.  If setup was successful, it starts the main monitoring tasks using `asyncio.gather()`.
                *   `asyncio.gather(self._listen_for_frida_messages(), self._monitor_system_health())`

    *   `async stop(self) -> None:`
        *   **Purpose:** Gracefully shuts down all services.
        *   **Logic:**
            1.  `self._is_running = False`
            2.  `await self.frida_service.detach()`
            3.  `await self.docker_service.stop_stack()`
            4.  `await self.db_service.close()`

    *   `_register_handlers(self) -> None:`
        *   **Purpose:** Implements the **Dispatch Pattern**. It maps incoming message types from Frida to handler methods within this class.
        *   **Logic:** Populates the `self._message_handlers` dictionary.
            ```python
            self._message_handlers = {
                "game_metric": self._handle_game_metric,
                "game_event": self._handle_game_event,
                "hook_log": self._handle_hook_log,
            }
            ```

    *   `async _listen_for_frida_messages(self) -> None:`
        *   **Purpose:** A long-running task that continuously waits for messages from the `FridaService` queue.
        *   **Logic:**
            ```python
            while self._is_running:
                message = await self.frida_service.get_message() # Blocks until a message is available
                handler = self._message_handlers.get(message.get("type"))
                if handler:
                    await handler(message)
                else:
                    self.logger.warn("unhandled_message", message_type=message.get("type"))
            ```

    *   **Handler Methods:**
        *   `async _handle_game_metric(self, message: dict) -> None:`
            *   **Purpose:** Processes metric data.
            *   **Logic:** Extracts `measurement`, `fields`, `tags` from the message payload and calls `await self.db_service.write_metric(...)`. Also emits the `new_metric_received` signal for the UI.
        *   `async _handle_game_event(self, message: dict) -> None:`
            *   **Purpose:** Processes discrete game events (e.g., round start, perk chosen).
            *   **Logic:** Extracts relevant data and calls `await self.db_service.write_event(...)`. Manages `SessionManager` state (e.g., `self.session.start_new_run()`).
        *   `async _handle_hook_log(self, message: dict) -> None:`
            *   **Purpose:** Processes log messages originating from the Frida script.
            *   **Logic:** Forwards the log into the `structlog` system. `self.logger.info(message['payload']['event'], **message['payload'])`.

    *   `async _monitor_system_health(self) -> None:`
        *   **Purpose:** A long-running task that periodically checks the health of backend services.
        *   **Logic:** Runs a `while self._is_running:` loop with an `await asyncio.sleep(60)`. In the loop, it calls `self.docker_service.is_healthy()` and `self.emulator_service.is_connected()` and emits `status_changed` signals.

*   **Testing:**
    *   **Unit:** Test the handler registration and dispatch logic. Mock the services. Send a test message and assert that the correct handler method is called and that the service method is called with the correct arguments.
    *   **Integration:** A full integration test would involve running the controller and asserting that messages sent from a mock `FridaService` queue end up as calls to a mock `DatabaseService`.

---

## **8. Foundational Service: Onboarding & Setup**

**Goal:** Create a service to orchestrate the entire first-time setup and subsequent health checks.

### **File: `src/tower_iq/services/setup_service.py`**

*   **Purpose:** Defines the `SetupService` class, which handles the complex, linear process of getting the user's environment ready.

#### **Class: `SetupService`**

*   **Purpose:** To provide a clean interface for the setup flow, hiding the complex details of WSL and Docker installation from the `MainController`.
*   **Methods:**
    *   `__init__(self, config: ConfigurationManager, logger: Any, docker_service: DockerService, db_service: DatabaseService, ui_signal_emitter: QObject) -> None:`
        *   **Purpose:** Initializes the service with its dependencies.
        *   **State:**
            *   `self.logger = logger.bind(source="SetupService")`
            *   `self.config: ConfigurationManager`
            *   `self.docker_service: DockerService`
            *   `self.db_service: DatabaseService`
            *   `self.ui_signal_emitter = ui_signal_emitter` (Used to send progress updates to the GUI).

    *   `async run_initial_setup(self) -> bool:`
        *   **Purpose:** The main entry point for the setup wizard/first-time flow.
        *   **Returns:** `True` if setup completed successfully, `False` otherwise.
        *   **Logic:** Executes a series of private setup methods in a specific order, wrapped in a `try...except` block. If any step fails, it logs the error and returns `False`.
            1.  `await self._check_and_install_wsl()`
            2.  `await self._import_wsl_distro()`
            3.  `await self._install_docker_in_wsl()`
            4.  `await self.docker_service.start_stack()`
            5.  `await self.db_service.connect()`
            6.  `await self.db_service.run_migrations()`
            7.  `await self._mark_setup_as_complete()`

    *   `async validate_environment(self) -> bool:`
        *   **Purpose:** A non-interactive check run on every application start (after the first).
        *   **Returns:** `True` if the environment is healthy, `False` otherwise.
        *   **Logic:** Runs health checks on WSL, Docker, and the database connection without attempting any installations.

    *   `async _check_and_install_wsl(self) -> None:`
        *   **Purpose:** Checks if WSL is installed. If not, prompts the user for permission via a UI signal and runs `wsl --install` with elevated privileges.
        *   **Throws:** `SetupStepFailedError` on failure.

    *   `async _import_wsl_distro(self) -> None:`
        *   **Purpose:** Checks if the dedicated `TowerIQ-Backend` WSL distro exists. If not, it imports it from the bundled `.tar.gz` file.
        *   **Throws:** `SetupStepFailedError` on failure.

    *   `async _install_docker_in_wsl(self) -> None:`
        *   **Purpose:** Runs `apt-get` commands inside the dedicated WSL distro to install `docker.io` and `docker-compose`. Idempotent; checks if already installed.
        *   **Throws:** `SetupStepFailedError` on failure.

    *   `async _mark_setup_as_complete(self) -> None:`
        *   **Purpose:** Creates a marker file (`.toweriq_setup_complete`) in the user's application data directory to signify that the first-time setup is done.

*   **Testing:**
    *   **Integration:** This service is extremely difficult to unit test. The primary testing method will be end-to-end integration tests on a clean Windows environment, verifying that the entire setup process completes successfully. Individual steps can be tested by mocking `subprocess` calls.

---

## **9. Backend Service: Emulator Interaction**

**Goal:** Create a robust service for all ADB communication.

### **File: `src/tower_iq/services/emulator_service.py`**

*   **Purpose:** Defines `EmulatorService` for managing the Android emulator and `frida-server`.

#### **Class: `EmulatorService`**

*   **Methods:**
    *   `__init__(self, config: ConfigurationManager, logger: Any) -> None:`
    *   `async find_and_connect_device(self, device_id: Optional[str] = None) -> Optional[str]:`
        *   **Purpose:** Scans for ADB devices. If one is found, it connects. If multiple, it returns the list. If a specific `device_id` is provided, it tries to connect to that one.
        *   **Returns:** The serial ID of the connected device, or `None` if no device is found.
    *   `async get_device_architecture(self, device_id: str) -> str:`
        *   **Purpose:** Runs `adb -s <device_id> shell getprop ro.product.cpu.abi`.
        *   **Returns:** The architecture string (e.g., "x86_64").
    *   `async install_frida_server(self, device_id: str) -> bool:`
        *   **Purpose:** Orchestrates the `frida-server` installation.
        *   **Logic:**
            1.  Calls `get_device_architecture()`.
            2.  Downloads the correct binary using a (to-be-created) `DependencyDownloader` utility.
            3.  Pushes the binary to `/data/local/tmp/` on the device.
            4.  Sets executable permissions (`chmod 755`).
    *   `async start_frida_server(self, device_id: str) -> bool:`
        *   **Purpose:** Starts the `frida-server` process as root.
    *   `async is_frida_server_running(self, device_id: str) -> bool:`
        *   **Purpose:** Checks `ps -A` on the device for the `frida-server` process.
    *   `async get_game_pid(self, device_id: str, package_name: str) -> Optional[int]:`
        *   **Purpose:** Finds the Process ID for the running game package.

*   **Testing:**
    *   **Integration:** Requires a running ADB server and emulator. Tests should connect to the emulator, push a test file, check for a test process, and clean up.

---

## **10. Backend Service: Frida Injection**

**Goal:** Create a focused service to manage the Frida injection lifecycle securely.

### **File: `src/tower_iq/services/frida_service.py`**

*   **Purpose:** Defines `FridaService`.

#### **Class: `FridaService`**

*   **Methods:**
    *   `__init__(self, config: ConfigurationManager, logger: Any) -> None:`
        *   **State:** `self.message_queue: asyncio.Queue = asyncio.Queue()`
    *   `async get_message(self) -> dict:`
        *   **Purpose:** Allows the `MainController` to consume messages from Frida.
        *   **Returns:** A message dictionary from the queue.
    *   `async attach(self, pid: int) -> bool:`
        *   **Purpose:** Attaches Frida to the specified process ID.
    *   `async detach(self) -> None:`
        *   **Purpose:** Detaches from the process and unloads the script.
    *   `async inject_script(self, game_version: str) -> bool:`
        *   **Purpose:** The core secure injection method.
        *   **Logic:**
            1.  `await self._download_and_verify_script(game_version)`
            2.  Reads the decrypted script content into memory.
            3.  Uses `session.create_script()` and `script.load()`. Registers `self._on_message` as the callback.
    *   `async _download_and_verify_script(self, game_version: str) -> str:`
        *   **Purpose:** Implements the secure hook update workflow.
        *   **Returns:** The decrypted script content as a string.
        *   **Logic:**
            1.  Fetches the remote `manifest.json`.
            2.  Finds the entry for the `game_version`.
            3.  Downloads the encrypted script file.
            4.  Verifies the signature of the encrypted file.
            5.  Decrypts the file in memory.
            6.  Verifies the SHA256 hash of the decrypted content.
            7.  Returns the content or raises `SecurityException` on failure.
    *   `def _on_message(self, message: dict, data: Any) -> None:`
        *   **Purpose:** The synchronous callback function that Frida requires.
        *   **Logic:**
            *   Parses the message from Frida.
            *   Uses `self.message_queue.put_nowait(parsed_message)` to hand the message off to the async world. This is a thread-safe way to bridge Frida's thread and our `asyncio` loop.

*   **Testing:**
    *   **Unit:** Mock the `frida` library. Test the `attach` and `detach` logic.
    *   **Integration:** A more complex test could involve running a simple "victim" process and using the `FridaService` to inject a script that sends a known message back, asserting that the message is correctly placed on the queue.

---

This concludes **Part 2** of the development task list. We have now defined the entire backend application logic. **Part 3** will cover the final layer: the GUI (`main_app_entry.py`, `main_window.py`, and supporting UI components).