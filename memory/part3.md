# TowerIQ v1.0 - Development Task List (Part 3: The User Interface)

This document details the final layer of the application: the graphical user interface (GUI) built with PyQt6. It covers the main application entry point, the structure of the `MainWindow`, the setup wizard dialog, and the core UI components that will display data and handle user interactions.

---

## **11. Application Entry Point**

**Goal:** Create the executable entry point that initializes the entire application stack.

### **File: `src/tower_iq/main_app_entry.py`**

*   **Purpose:** The single, definitive entry point for starting the TowerIQ GUI application. It is responsible for setting up the async environment, creating the core application objects, and launching the UI.

#### **Function: `main() -> None`**

*   **Purpose:** Orchestrates the entire application startup sequence.
*   **Logic:**
    1.  **Initialize Paths & Environment:** Set up any necessary system paths.
    2.  **Create Core Components:**
        *   `config = ConfigurationManager(...)`
        *   `config.load_and_validate()`
        *   `setup_logging(config)` (Initializes the unified logging system immediately).
        *   `logger = structlog.get_logger("main_entry")`
    3.  **Initialize PyQt Application:**
        *   `qt_app = QApplication(sys.argv)`
    4.  **Instantiate Controller:**
        *   `controller = MainController(config, logger)`
    5.  **Set up Async Bridge (`qasync`):**
        *   `loop = qasync.QEventLoop(qt_app)`
        *   `asyncio.set_event_loop(loop)`
        *   This is the critical step that makes PyQt and asyncio work together.
    6.  **Instantiate Main Window:**
        *   `main_window = MainWindow(controller)`
    7.  **Run the Application:**
        *   Use `try...finally` to ensure cleanup.
        *   `main_window.show()`
        *   `asyncio.create_task(controller.run())` (Starts the controller's main loop in the background).
        *   `loop.run_forever()` (Starts the combined Qt/asyncio event loop).
    8.  **Cleanup:**
        *   In the `finally` block, call `asyncio.run(controller.stop())` to gracefully shut down backend services.

*   **Testing:**
    *   **Manual/E2E:** This file is primarily tested by running the application itself. Automated testing is difficult as it involves the entire application stack.

---

## **12. Main User Interface Window**

**Goal:** Define the main shell of the application that holds all other UI components.

### **File: `src/tower_iq/gui/main_window.py`**

*   **Purpose:** Defines the `MainWindow` class, the primary window for the application.

#### **Class: `MainWindow(QMainWindow)`**

*   **Inherits from:** `PyQt6.QtWidgets.QMainWindow`.
*   **Purpose:** To serve as the main container for the application's UI, including the navigation bar, dashboard panels, and status indicators.
*   **Methods:**
    *   `__init__(self, controller: MainController) -> None:`
        *   **Purpose:** Initializes the main window, sets up the UI layout, and connects UI signals to the controller's slots.
        *   **State:**
            *   `self.controller = controller`
            *   `self.setWindowTitle("TowerIQ")`
            *   `self.setWindowIcon(...)`
        *   **Calls:**
            *   `self._init_ui()`
            *   `self._connect_signals()`

    *   `_init_ui(self) -> None:`
        *   **Purpose:** Creates and arranges all the widgets in the main window.
        *   **Logic:**
            1.  Create a central widget and a main horizontal layout.
            2.  **Left Panel (Navigation):** Create a `QFrame` for the navigation bar. Add `QPushButton` widgets with icons for "Dashboard," "Run History," "Settings," etc.
            3.  **Right Panel (Main Content):** Create a `QStackedWidget`. This widget will allow switching between different "pages" (Dashboard, History, etc.).
            4.  Create instances of the page widgets (`DashboardPage`, `SettingsPage`, etc.) and add them to the `QStackedWidget`.
            5.  Create a status bar at the bottom and add the global `StatusIndicator` widget to it.

    *   `_connect_signals(self) -> None:`
        *   **Purpose:** Connects UI widget signals to `MainController` slots and controller signals to UI update slots.
        *   **Logic (Examples):**
            *   `self.nav_dashboard_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.dashboard_page))`
            *   `self.controller.new_metric_received.connect(self.dashboard_page.update_metric_display)`
            *   `self.controller.status_changed.connect(self.status_indicator.update_status)`

*   **Testing:**
    *   **Component Testing (with `pytest-qt`):** Test that clicking navigation buttons correctly changes the visible widget in the `QStackedWidget`. Test that signals from a mock controller correctly call the update slots on the child widgets.

---

## **13. UI Component: Setup Wizard**

**Goal:** Create the guided setup flow for the first-time user.

### **File: `src/tower_iq/gui/setup_wizard_dialog.py`**

*   **Purpose:** Defines the `SetupWizardDialog`, a modal dialog that guides the user through the initial application setup.

#### **Class: `SetupWizardDialog(QDialog)`**

*   **Purpose:** To provide a step-by-step visual guide for the setup process orchestrated by the `SetupService`.
*   **Methods:**
    *   `__init__(self, controller: MainController) -> None:`
        *   **Purpose:** Initializes the dialog.
        *   **State:** `self.controller = controller`
        *   **Calls:** `self._init_ui()`, `self._connect_signals()`

    *   `_init_ui(self) -> None:`
        *   **Purpose:** Creates the UI for the wizard.
        *   **Logic:**
            1.  Set the dialog to be modal (`setModal(True)`).
            2.  Create a `QVBoxLayout`.
            3.  Create labels and status icons for each setup step (e.g., "Check for WSL2," "Start Docker Services").
            4.  Create a `QTextEdit` or `QListWidget` to display progress messages.
            5.  Create a `QProgressBar` for visual feedback.
            6.  Create "Start Setup," "Cancel," and "Finish" buttons.

    *   `_connect_signals(self) -> None:`
        *   **Purpose:** Connects UI actions and controller signals.
        *   **Logic:**
            *   `self.start_button.clicked.connect(self.run_setup)`
            *   Connect signals from the `SetupService` (emitted via the controller) to UI update slots.
                *   `self.controller.setup_progress_updated.connect(self.on_progress_update)`
                *   `self.controller.setup_step_status_changed.connect(self.on_step_status_change)`
                *   `self.controller.setup_finished.connect(self.on_setup_finished)`

    *   **Public Slots:**
        *   `run_setup(self) -> None:`
            *   **Purpose:** Called when the user clicks "Start Setup."
            *   **Logic:** Disables the start button and calls `asyncio.create_task(self.controller.setup_service.run_initial_setup())`.
        *   `on_progress_update(self, message: str) -> None:`
            *   **Purpose:** Updates the text log with new progress messages.
        *   `on_step_status_change(self, step_name: str, status: str) -> None:`
            *   **Purpose:** Updates the status icon (e.g., a checkmark, spinner, or X) next to a specific setup step.
        *   `on_setup_finished(self, success: bool) -> None:`
            *   **Purpose:** Called when the entire setup process is complete.
            *   **Logic:** If `success` is `True`, it enables the "Finish" button. If `False`, it displays an error message box and keeps the dialog open.

*   **Testing:**
    *   **Component Testing:** Test that the dialog correctly updates its UI elements when its public slots are called. Use a mock controller to simulate the setup process signals.

---

## **14. UI Component: Dashboard Page**

**Goal:** Create the primary view for displaying live game metrics.

### **File: `src/tower_iq/gui/components/dashboard_page.py`**

*   **Purpose:** Defines the `DashboardPage` widget, which will be placed inside the `MainWindow`'s `QStackedWidget`.

#### **Class: `DashboardPage(QWidget)`**

*   **Purpose:** To display all live metrics and graphs related to the current game run.
*   **Methods:**
    *   `__init__(self, controller: MainController) -> None:`
        *   **Logic:** Sets up the layout (e.g., `QGridLayout`) and creates all the child display widgets (`MetricDisplayWidget`, `GraphWidget`).

    *   **Public Slots:**
        *   `update_metric_display(self, metric_name: str, value: Any) -> None:`
            *   **Purpose:** Receives a signal from the `MainController` with a new metric value.
            *   **Logic:** Finds the appropriate child `MetricDisplayWidget` and updates its value (e.g., `self.cph_display.set_value(value)`).
        *   `update_graph(self, graph_name: str, data: object) -> None:`
            *   **Purpose:** Receives new data points for a graph.
            *   **Logic:** Finds the correct `GraphWidget` and tells it to append the new data.

#### **Child Widgets (defined within the same file or a sub-module)**

*   **Class: `MetricDisplayWidget(QFrame)`**
    *   **Purpose:** A reusable component to display a single metric.
    *   **UI:** Contains a `QLabel` for the metric name (e.g., "Coins per Hour") and another larger `QLabel` for the value.
    *   **Methods:** `set_value(self, value: Any) -> None:` (formats the value and updates the label text).

*   **Class: `GraphWidget(QWidget)`**
    *   **Purpose:** A widget to display a chart.
    *   **Implementation:** This will be a complex component. For the MVP, it can use a simple plotting library like `pyqtgraph`. In the future, this could be a `QWebEngineView` that embeds a live Grafana panel.
    *   **Methods:** `append_data_point(self, x: float, y: float) -> None:`.

*   **Testing:**
    *   **Component Testing:** Test the `DashboardPage` by calling its `update_metric_display` slot and asserting that the text on the correct child `MetricDisplayWidget` is updated.

---

## **15. Asset Management**

**Goal:** Provide a clean way to access bundled application assets like icons.

### **File: `src/tower_iq/gui/assets.py`**

*   **Purpose:** A simple module to manage paths to asset files, ensuring they work correctly when bundled into a PyInstaller executable.

#### **Function: `get_asset_path(asset_name: str) -> str`**

*   **Purpose:** To resolve the path to a bundled asset.
*   **Logic:**
    *   Checks if the application is running in a bundled state (by checking for `sys._MEIPASS`).
    *   If bundled, it constructs the path relative to the temporary bundle directory.
    *   If not bundled (running from source), it constructs the path relative to the project's `resources/assets` directory.
    *   This function is then used throughout the UI code to load icons and other resources (e.g., `QIcon(get_asset_path("icons/connected.svg"))`).

---

This concludes **Part 3** of the development task list. We have now defined the entire application stack, from the foundational services to the core logic and the user-facing interface. The blueprint is complete and ready for implementation.