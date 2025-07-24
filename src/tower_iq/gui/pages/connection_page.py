"""
TowerIQ Connection Page

This module provides the ConnectionPage widget for managing device connections,
process selection, and hook activation in the TowerIQ application.
"""

import structlog
from ..utils.utils_gui import ThemeAwareWidget, get_text_color, get_title_font
from PyQt6.QtWidgets import (
    QHBoxLayout, QVBoxLayout, QLabel, QStackedWidget, QWidget,
    QGroupBox, QTextEdit, QFrame, QHeaderView, QTableWidgetItem
)
from qfluentwidgets import (SwitchButton, FluentIcon, PushButton, TableWidget, TableItemDelegate, isDarkTheme,
                            ProgressRing, BodyLabel, InfoBar, InfoBarPosition)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QPalette, QColor

class CustomTableItemDelegate(TableItemDelegate):
    """Custom table item delegate for the device table status column."""
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        # Only apply to device_table's status column
        model = index.model()
        parent = None
        try:
            # Defensive: check if model has sourceModel (proxy model case)
            source_model_fn = getattr(model, 'sourceModel', None)
            if callable(source_model_fn):
                source_model = source_model_fn()
                parent_fn = getattr(source_model, 'parent', None)
                if callable(parent_fn):
                    parent = parent_fn()
            else:
                parent_fn = getattr(model, 'parent', None)
                if callable(parent_fn):
                    parent = parent_fn()
        except Exception:
            parent = None
        if parent is not None and hasattr(parent, 'objectName') and parent.objectName() == "device_table" and index.column() == 3:
            status = index.data()
            color_map = {
                "Online": ("#2ecc71", "#27ae60"),
                "Offline": ("#e74c3c", "#c0392b"),
                "Unauthorized": ("#f39c12", "#e67e22"),
                "No Permissions": ("#e74c3c", "#c0392b"),
            }
            default_color = ("#f1c40f", "#f39c12")
            dark_color, light_color = color_map.get(status, default_color)
            color = QColor(dark_color) if isDarkTheme() else QColor(light_color)
            option.palette.setColor(QPalette.ColorRole.Text, color)
            option.palette.setColor(QPalette.ColorRole.HighlightedText, color)

class ConnectionPanel(ThemeAwareWidget):
    # --- Signals for upward communication ---
    scan_devices_requested = pyqtSignal()
    connect_device_requested = pyqtSignal(str)
    refresh_processes_requested = pyqtSignal()
    select_process_requested = pyqtSignal(dict)
    activate_hook_requested = pyqtSignal()
    back_to_stage_requested = pyqtSignal(int)
    
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.logger = structlog.get_logger().bind(source="ConnectionPanel")
        layout = QVBoxLayout(self)
        self.stacked = QStackedWidget(self)

        # --- Stage Creation ---
        self.stage0_device_discovery = self._create_device_discovery_stage()
        self.stage1_process_selection = self._create_process_selection_stage()
        self.stage2_activation = self._create_activation_stage()
        self.stage3_hook_active = self._create_hook_active_stage()

        # --- Add Widgets to Stack ---
        self.stacked.addWidget(self.stage0_device_discovery)   # Index 0
        self.stacked.addWidget(self.stage1_process_selection) # Index 1
        self.stacked.addWidget(self.stage2_activation)      # Index 2
        self.stacked.addWidget(self.stage3_hook_active)       # Index 3
        layout.addWidget(self.stacked)

        self.update_theme_styles()

        # --- Connect to SessionManager signals for reactive updates ---
        # REFACTOR: Standardized signal and slot names for clarity
        self.session_manager.available_emulators_changed.connect(self.update_device_table)
        self.session_manager.available_processes_changed.connect(self.update_process_table)
        self.session_manager.connection_state_changed.connect(self._on_hook_state_changed)
        self.session_manager.emulator_connection_state_changed.connect(self._on_emulator_connection_state_changed)
        self.session_manager.hook_activation_stage_changed.connect(self.update_activation_view)
        self.session_manager.hook_activation_message_changed.connect(self.update_activation_view)
        
        # Initial state update
        self.update_device_table(self.session_manager.available_emulators)

    def _create_standard_table(self, headers: list[str]) -> TableWidget:
        """REFACTOR: Factory method to create a consistently styled table."""
        table = TableWidget(self)
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        
        table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(TableWidget.SelectionMode.SingleSelection)
        table.setBorderVisible(True)
        table.setBorderRadius(8)
        table.setWordWrap(False)
        table.setSortingEnabled(False)
        
        vertical_header = table.verticalHeader()
        if vertical_header is not None:
            vertical_header.setMinimumSectionSize(30)
            vertical_header.setDefaultSectionSize(40)
            vertical_header.setMaximumSectionSize(50)
            vertical_header.hide()
            
        return table

    def _create_device_discovery_stage(self) -> QWidget:
        """REFACTOR: Create the device discovery stage using the standardized layout."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Top Bar: Refresh button, right-aligned
        top_bar_layout = QHBoxLayout()
        top_bar_layout.addStretch(1)
        self.refresh_button = PushButton(FluentIcon.SYNC, "Refresh Device List")
        self.refresh_button.clicked.connect(self.scan_devices_requested)
        top_bar_layout.addWidget(self.refresh_button)
        layout.addLayout(top_bar_layout)
        
        # Device Table: Created with the factory method - Enhanced with emulator column
        self.device_table = self._create_standard_table(["Serial", "Model", "Android", "Emulator", "Status"])
        self.device_table.setObjectName("device_table") # For the delegate
        self.device_table.setItemDelegate(CustomTableItemDelegate(self.device_table))
        
        header = self.device_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Serial
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)           # Model
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Android
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Emulator
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Status
        layout.addWidget(self.device_table)

        # Bottom Bar: Connect button, right-aligned
        bottom_bar_layout = QHBoxLayout()
        bottom_bar_layout.addStretch(1)
        self.connect_button = PushButton(FluentIcon.LINK, "Connect")
        self.connect_button.setEnabled(False)
        self.connect_button.clicked.connect(self._on_connect_clicked)
        bottom_bar_layout.addWidget(self.connect_button)
        layout.addLayout(bottom_bar_layout)
        
        self.device_table.itemSelectionChanged.connect(self._on_device_selection_changed)
        
        return widget

    def _create_process_selection_stage(self) -> QWidget:
        """REFACTOR: Create the process selection stage using the standardized layout."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Top Bar: Refresh button, right-aligned
        top_bar_layout = QHBoxLayout()
        top_bar_layout.addStretch(1)
        self.refresh_processes_button = PushButton(FluentIcon.SYNC, "Refresh Processes")
        self.refresh_processes_button.clicked.connect(self.refresh_processes_requested)
        top_bar_layout.addWidget(self.refresh_processes_button)
        layout.addLayout(top_bar_layout)

        # Process Table: Created with the factory method
        self.process_table = self._create_standard_table(["App Name", "Package", "Version", "PID", "Status"])
        self.process_table.itemSelectionChanged.connect(self._on_process_selection_changed)
        
        header = self.process_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.process_table)

        # Bottom Bar: Activate Hook button, right-aligned
        bottom_bar_layout = QHBoxLayout()
        bottom_bar_layout.addStretch(1)
        self.activate_hook_button = PushButton(FluentIcon.PLAY_SOLID, "Activate Hook")
        self.activate_hook_button.setEnabled(False)
        self.activate_hook_button.clicked.connect(self.activate_hook_requested)
        bottom_bar_layout.addWidget(self.activate_hook_button)
        layout.addLayout(bottom_bar_layout)
        
        return widget

    def _create_activation_stage(self) -> QWidget:
        """Create the enhanced hook activation stage widget with detailed multi-stage progress."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setSpacing(20)

        # Title section
        title_layout = QVBoxLayout()
        title_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.activation_title = BodyLabel("Establishing Connection...")
        self.activation_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.activation_title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        title_layout.addWidget(self.activation_title)
        
        self.activation_subtitle = BodyLabel("Please wait while we set up the connection")
        self.activation_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.activation_subtitle.setStyleSheet("color: gray; margin-bottom: 20px;")
        title_layout.addWidget(self.activation_subtitle)
        
        layout.addLayout(title_layout)

        # Progress steps section
        steps_container = QGroupBox("Connection Progress")
        steps_layout = QVBoxLayout(steps_container)
        steps_layout.setSpacing(12)

        # Define all connection stages with detailed descriptions
        self.activation_steps = {}
        steps_to_create = {
            "frida_server_check": {
                "title": "Checking Frida Server",
                "description": "Verifying if Frida server is already running on device"
            },
            "frida_server_install": {
                "title": "Installing Frida Server", 
                "description": "Downloading and installing Frida server binary"
            },
            "frida_server_start": {
                "title": "Starting Frida Server",
                "description": "Starting Frida server process on device"
            },
            "frida_server_verify": {
                "title": "Verifying Frida Server",
                "description": "Testing Frida server connection and functionality"
            },
            "hook_compatibility_check": {
                "title": "Validating Hook Script",
                "description": "Checking hook script compatibility with target app"
            },
            "process_attachment": {
                "title": "Attaching to Process",
                "description": "Attaching Frida to the target application process"
            },
            "script_injection": {
                "title": "Injecting Hook Script",
                "description": "Loading and executing the hook script in target process"
            }
        }

        for step_name, step_info in steps_to_create.items():
            step_widget = self._create_progress_step(step_name, step_info["title"], step_info["description"])
            steps_layout.addWidget(step_widget)
            
        layout.addWidget(steps_container)

        # Action buttons section
        button_layout = QHBoxLayout()
        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        button_layout.setSpacing(10)
        
        self.cancel_button = PushButton("Cancel")
        self.cancel_button.clicked.connect(lambda: self.back_to_stage_requested.emit(1))
        button_layout.addWidget(self.cancel_button)
        
        self.retry_button = PushButton("Retry")
        self.retry_button.setVisible(False)  # Hidden by default, shown on failure
        self.retry_button.clicked.connect(self.activate_hook_requested)
        button_layout.addWidget(self.retry_button)
        
        layout.addLayout(button_layout)
        layout.addStretch()

        return widget

    def _create_progress_step(self, step_name: str, title: str, description: str) -> QWidget:
        """Create a single progress step widget."""
        step_widget = QWidget()
        step_layout = QHBoxLayout(step_widget)
        step_layout.setContentsMargins(10, 8, 10, 8)
        step_layout.setSpacing(15)

        # Status icon (spinner, checkmark, or error)
        icon_container = QWidget()
        icon_container.setFixedSize(24, 24)
        icon_layout = QVBoxLayout(icon_container)
        icon_layout.setContentsMargins(0, 0, 0, 0)
        icon_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Create different icons for different states
        spinner = ProgressRing()
        spinner.setFixedSize(20, 20)
        spinner.hide()
        
        status_label = BodyLabel("⏳")
        status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_label.setStyleSheet("font-size: 16px;")
        
        icon_layout.addWidget(spinner)
        icon_layout.addWidget(status_label)
        
        step_layout.addWidget(icon_container)

        # Step content
        content_layout = QVBoxLayout()
        content_layout.setSpacing(2)
        
        title_label = BodyLabel(title)
        title_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        content_layout.addWidget(title_label)
        
        desc_label = BodyLabel(description)
        desc_label.setStyleSheet("color: gray; font-size: 12px;")
        content_layout.addWidget(desc_label)
        
        step_layout.addLayout(content_layout)
        step_layout.addStretch()

        # Store references for easy access
        self.activation_steps[step_name] = {
            'widget': step_widget,
            'spinner': spinner,
            'status_label': status_label,
            'title_label': title_label,
            'desc_label': desc_label
        }

        return step_widget

    def _create_hook_active_stage(self) -> QWidget:
        """(Unchanged) Create the hook active stage widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)

        card = QGroupBox("Hook Active", self)
        card_layout = QVBoxLayout(card)

        title_layout = QHBoxLayout()
        icon_label = QLabel("✅")
        icon_label.setStyleSheet("font-size: 24px;")
        title_label = BodyLabel("Connection Established")
        title_layout.addWidget(icon_label)
        title_layout.addWidget(title_label)
        card_layout.addLayout(title_layout)

        self.active_device_label = BodyLabel("Device: N/A")
        self.active_process_label = BodyLabel("Process: N/A")
        card_layout.addWidget(self.active_device_label)
        card_layout.addWidget(self.active_process_label)

        self.disconnect_button = PushButton(FluentIcon.CANCEL, "Disconnect")
        self.disconnect_button.clicked.connect(lambda: self.back_to_stage_requested.emit(0))
        card_layout.addWidget(self.disconnect_button, 0, Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(card)
        return widget

    # --- Reactive Slots for State Changes ---
    def _on_emulator_connection_state_changed(self, is_connected: bool):
        """Reacts to SessionManager's emulator connection state."""
        self.set_stage(1 if is_connected else 0)
            
    def _on_hook_state_changed(self, is_active: bool):
        """Reacts to SessionManager's hook activation state."""
        if is_active:
            self.set_stage(3)
            self.update_hook_active_view()

    # --- UI Update Methods ---
    def update_device_table(self, emulators: list):
        """Populates the device table with enhanced device data."""
        self.device_table.setRowCount(len(emulators))
        for row, emulator in enumerate(emulators):
            # Format Android version display
            android_version = emulator.get('android_version', 'Unknown')
            api_level = emulator.get('api_level', 0)
            android_display = f"{android_version}" if api_level == 0 else f"{android_version} (API {api_level})"
            
            # Format model display with manufacturer if available
            model = emulator.get('model', 'Unknown')
            manufacturer = emulator.get('manufacturer', '')
            if manufacturer and manufacturer != 'Unknown' and manufacturer not in model:
                model_display = f"{manufacturer} {model}"
            else:
                model_display = model
            
            # Enhanced emulator detection
            emulator_display = self._detect_emulator_type(emulator)
            
            items = [
                QTableWidgetItem(str(emulator.get('serial', ''))),
                QTableWidgetItem(model_display),
                QTableWidgetItem(android_display),
                QTableWidgetItem(emulator_display),
                QTableWidgetItem(str(emulator.get('status', 'Unknown')))
            ]
            
            for item in items:
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

            # Store full device data in the first column for easy access
            items[0].setData(Qt.ItemDataRole.UserRole, emulator)

            self.device_table.setItem(row, 0, items[0])
            self.device_table.setItem(row, 1, items[1])
            self.device_table.setItem(row, 2, items[2])
            self.device_table.setItem(row, 3, items[3])
            self.device_table.setItem(row, 4, items[4])
        
        self.device_table.resizeRowsToContents()

    def _detect_emulator_type(self, emulator: dict) -> str:
        """
        Detect specific emulator type based on device properties.
        
        Args:
            emulator: Device information dictionary
            
        Returns:
            String indicating emulator type or "Physical"
        """
        is_emulator = emulator.get('is_emulator', False)
        if not is_emulator:
            return "Physical"
        
        # Get device properties for emulator detection
        model = emulator.get('model', '').lower()
        device_name = emulator.get('device_name', '').lower()
        manufacturer = emulator.get('manufacturer', '').lower()
        
        # Check for specific emulator types
        if any(keyword in model or keyword in device_name or keyword in manufacturer 
               for keyword in ['mumu', 'mumuglobal']):
            return "MuMu"
        elif any(keyword in model or keyword in device_name 
                for keyword in ['bluestacks', 'bst']):
            return "BlueStacks"
        elif any(keyword in model or keyword in device_name 
                for keyword in ['nox', 'noxplayer']):
            return "Nox"
        elif any(keyword in model or keyword in device_name 
                for keyword in ['ldplayer', 'ld']):
            return "LDPlayer"
        elif any(keyword in model or keyword in device_name 
                for keyword in ['genymotion', 'geny']):
            return "Genymotion"
        elif any(keyword in model or keyword in device_name 
                for keyword in ['sdk', 'emulator', 'generic']):
            return "Android Emulator"
        else:
            return "Emulator"

    def update_process_table(self, processes: list):
        """Populates the process table with enhanced app information."""
        self.process_table.setRowCount(len(processes))
        for row, process in enumerate(processes):
            is_running = process.get('is_running', False)
            status_text = "Running" if is_running else "Not Running"
            
            # Enhanced app name display - now shows actual app names instead of package names
            app_name = process.get('name', 'N/A')
            package_name = process.get('package', '')
            
            # If app name is the same as package name, it means we couldn't get a display name
            if app_name == package_name and package_name:
                app_name = package_name.split('.')[-1].title()  # Use last part of package name as fallback
            
            # Format version display
            version = process.get('version', 'Unknown')
            version_code = process.get('version_code', 0)
            if version != 'Unknown' and version_code > 0:
                version_display = f"{version} ({version_code})"
            else:
                version_display = version
            
            items = [
                QTableWidgetItem(app_name),
                QTableWidgetItem(package_name),
                QTableWidgetItem(version_display),
                QTableWidgetItem(str(process.get('pid', 'N/A'))),
                QTableWidgetItem(status_text)
            ]

            for item in items:
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            
            # Since we now only show running apps, we don't need the gray-out logic
            # But keep it for backward compatibility in case non-running apps are passed
            if not is_running:
                for item in items:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
                    item.setForeground(QColor("gray"))
            
            # Store full process data in the first column for easy access
            items[0].setData(Qt.ItemDataRole.UserRole, process)

            for col, item in enumerate(items):
                self.process_table.setItem(row, col, item)

        self.process_table.resizeColumnsToContents()
    
    def update_activation_view(self):
        """Updates the activation stage UI based on session state with detailed multi-stage progress."""
        stage = self.session_manager.hook_activation_stage
        message = self.session_manager.hook_activation_message
        
        # Update title and subtitle
        if message:
            self.activation_title.setText(message)
        else:
            self.activation_title.setText("Establishing Connection...")
        
        # Define the complete pipeline matching ConnectionStageManager stages
        pipeline = [
            "frida_server_check",
            "frida_server_install", 
            "frida_server_start",
            "frida_server_verify",
            "hook_compatibility_check",
            "process_attachment",
            "script_injection"
        ]
        
        # Map legacy stage names to new pipeline for backward compatibility
        stage_mapping = {
            "checking_frida": "frida_server_check",
            "validating_hook": "hook_compatibility_check", 
            "attaching": "process_attachment"
        }
        
        # Use mapped stage name if available
        current_stage = stage_mapping.get(stage, stage)
        
        try:
            current_stage_index = pipeline.index(current_stage)
        except ValueError:
            current_stage_index = -1
        
        # Update each step's visual state
        for i, step_name in enumerate(pipeline):
            if step_name not in self.activation_steps:
                continue
                
            step_ui = self.activation_steps[step_name]
            spinner = step_ui['spinner']
            status_label = step_ui['status_label']
            title_label = step_ui['title_label']
            desc_label = step_ui['desc_label']
            
            if stage == "failed":
                # Show failure state
                spinner.hide()
                status_label.show()
                status_label.setText("❌")
                status_label.setStyleSheet("font-size: 16px; color: #e74c3c;")
                title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #e74c3c;")
                desc_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
                
            elif stage == "success" or stage == "completed":
                # Show all completed
                spinner.hide()
                status_label.show()
                status_label.setText("✅")
                status_label.setStyleSheet("font-size: 16px; color: #2ecc71;")
                title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #2ecc71;")
                desc_label.setStyleSheet("color: gray; font-size: 12px;")
                
            elif i < current_stage_index:
                # Completed steps
                spinner.hide()
                status_label.show()
                status_label.setText("✅")
                status_label.setStyleSheet("font-size: 16px; color: #2ecc71;")
                title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #2ecc71;")
                desc_label.setStyleSheet("color: gray; font-size: 12px;")
                
            elif i == current_stage_index:
                # Currently active step
                status_label.hide()
                spinner.show()
                try:
                    if hasattr(spinner, 'isSpinning') and not spinner.isSpinning():
                        spinner.start()
                    elif not hasattr(spinner, 'isSpinning'):
                        spinner.start()
                except Exception:
                    pass  # Ignore spinner errors
                title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #3498db;")
                desc_label.setStyleSheet("color: #3498db; font-size: 12px;")
                
            else:
                # Pending steps
                spinner.hide()
                status_label.show()
                status_label.setText("⏳")
                status_label.setStyleSheet("font-size: 16px; color: gray;")
                title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: gray;")
                desc_label.setStyleSheet("color: gray; font-size: 12px;")
        
        # Update button states
        if stage == "failed":
            self.cancel_button.setText("Go Back")
            self.retry_button.setVisible(True)
        else:
            self.cancel_button.setText("Cancel")
            self.retry_button.setVisible(False)

    def update_hook_active_view(self):
        """Updates the hook active stage UI with session data."""
        self.active_device_label.setText(f"Device: {self.session_manager.connected_emulator_serial or 'N/A'}")
        self.active_process_label.setText(f"Process: {self.session_manager.selected_target_package or 'N/A'}")

    # --- UI Action Handlers ---
    def _on_connect_clicked(self):
        """Emits the selected device serial for the parent to handle."""
        selected_items = self.device_table.selectedItems()
        if selected_items:
            item = self.device_table.item(selected_items[0].row(), 0)
            if item is not None and hasattr(item, 'text'):
                serial = item.text()
                self.connect_device_requested.emit(serial)

    def _on_device_selection_changed(self):
        self.connect_button.setEnabled(bool(self.device_table.selectedItems()))

    def _on_process_selection_changed(self):
        selected_items = self.process_table.selectedItems()
        self.activate_hook_button.setEnabled(bool(selected_items))
        if selected_items:
            item = self.process_table.item(selected_items[0].row(), 0)
            if item is not None and hasattr(item, 'data'):
                process_data = item.data(Qt.ItemDataRole.UserRole)
                self.select_process_requested.emit(process_data)
            
    def set_stage(self, index: int):
        """Public method to allow the parent (MainWindow) to control the visible stage."""
        if 0 <= index < self.stacked.count():
            self.stacked.setCurrentIndex(index)

    def update_theme_styles(self):
        # This method can be simplified or expanded as needed
        pass

    def stop_scanning(self):
        # TODO: Implement scanning animation stop logic
        pass

    def show_error(self, msg: str):
        # TODO: Implement error display logic (e.g., show a message box or set a label)
        self.logger.error("Connection panel error", message=msg)

    def show_success(self, msg: str):
        # TODO: Implement success display logic (e.g., show a message box or set a label)
        self.logger.info("Connection panel success", message=msg)

    def update_state(self, session):
        # TODO: Implement state update logic for the panel
        pass

    def trigger_device_scan(self):
        """Public method to trigger a device scan (emits scan_devices_requested)."""
        self.scan_devices_requested.emit()

class SettingsAndLogsPanel(ThemeAwareWidget):
    def __init__(self, config_manager, log_signal=None, parent=None):
        super().__init__(parent)
        self.config_manager = config_manager
        layout = QVBoxLayout()

        # Auto-Connect Settings Card
        settings_group = QGroupBox("Auto-Connect Settings")
        settings_layout = QVBoxLayout()
        self.auto_connect_switch = SwitchButton("Auto-connect on Startup")
        auto_connect = self.config_manager.get('gui.auto_connect_emulator', False)
        # Ensure the value is a boolean
        if isinstance(auto_connect, str):
            auto_connect = auto_connect.lower() in ('true', '1', 'yes', 'on')
        self.auto_connect_switch.setChecked(bool(auto_connect))
        self.auto_connect_switch.checkedChanged.connect(self.on_auto_connect_toggled)
        settings_layout.addWidget(self.auto_connect_switch)
        
        # Clear saved connection button
        self.clear_saved_button = PushButton("Clear Saved Connection")
        self.clear_saved_button.clicked.connect(self.on_clear_saved_connection)
        settings_layout.addWidget(self.clear_saved_button)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # Live Log Viewer
        log_group = QGroupBox("Live Connection Log")
        log_layout = QVBoxLayout()
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setFrameShape(QFrame.Shape.StyledPanel)
        log_layout.addWidget(self.log_viewer)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        layout.addStretch()
        self.setLayout(layout)
        self.update_theme_styles()

    def on_auto_connect_toggled(self, checked):
        self.config_manager.set('gui.auto_connect_emulator', checked)

    def on_clear_saved_connection(self):
        self.config_manager.set('connection.last_device_serial', '')
        self.config_manager.set('connection.last_package_name', '')
        try:
            InfoBar.success("Cleared", "Saved connection settings have been cleared.", duration=3000, parent=self)
        except Exception:
            pass  # InfoBar creation might fail in some contexts

    def update_theme_styles(self):
        color = get_text_color()
        self.auto_connect_switch.setStyleSheet(f"color: {color};")
        self.log_viewer.setStyleSheet(f"color: {color}; background: transparent;")
        self.setStyleSheet(f"background: transparent;")

class ConnectionPage(ThemeAwareWidget):
    def __init__(self, session_manager, config_manager, log_signal=None, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.config_manager = config_manager
        self.log_signal = log_signal

        layout = QHBoxLayout()
        self.connection_panel = ConnectionPanel(session_manager)
        self.settings_logs_panel = SettingsAndLogsPanel(config_manager, log_signal)
        layout.addWidget(self.connection_panel, 7)
        layout.addWidget(self.settings_logs_panel, 3)
        self.setLayout(layout)
        self.update_theme_styles()

    def update_theme_styles(self):
        self.setStyleSheet(f"background: transparent;")
        self.connection_panel.update_theme_styles()
        self.settings_logs_panel.update_theme_styles()