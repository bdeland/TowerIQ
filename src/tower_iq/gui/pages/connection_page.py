"""
TowerIQ Connection Page

This module provides the ConnectionPage widget for managing device connections,
process selection, and hook activation using a vertical stepper interface.
"""

import structlog
from typing import Dict, List, Any

from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QWidget, QTableWidgetItem, QHeaderView, QTextEdit, QCheckBox
)
from PyQt6.QtCore import pyqtSignal, Qt

from qfluentwidgets import (
    BodyLabel, PushButton, FluentIcon, TableWidget,
    ComboBox, InfoBar, InfoBarPosition, SimpleCardWidget, ProgressRing, SearchLineEdit, CheckBox
)

from ..utils.content_page import ContentPage
from ..utils.vertical_stepper import VerticalStepper, StepStatus
from ...core.session import ConnectionState


class DeviceSelectionWidget(QWidget):
    """Widget for device selection step."""
    
    device_selected = pyqtSignal(str)  # Emits device serial when selected
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = structlog.get_logger().bind(source="DeviceSelectionWidget")
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the device selection UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        # Device table
        self.device_table = TableWidget(self)
        self.device_table.setColumnCount(5)
        self.device_table.setHorizontalHeaderLabels(["Serial", "Model", "Android", "Emulator", "Status"])
        self.device_table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self.device_table.setSelectionMode(TableWidget.SelectionMode.SingleSelection)
        
        # Configure table headers
        header = self.device_table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(self.device_table)
        
        # Refresh button
        refresh_layout = QHBoxLayout()
        refresh_layout.addStretch(1)
        
        self.refresh_button = PushButton(FluentIcon.SYNC, "Refresh Devices", self)
        self.refresh_button.clicked.connect(self._on_refresh_clicked)
        refresh_layout.addWidget(self.refresh_button)
        
        layout.addLayout(refresh_layout)
        
        # Connect signals
        self.device_table.itemSelectionChanged.connect(self._on_device_selection_changed)
        
    def update_devices(self, devices: List[Dict[str, Any]]):
        """Update the device table with new device data."""
        self.device_table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            # Format Android version display
            android_version = device.get('android_version', 'Unknown')
            api_level = device.get('api_level', 0)
            android_display = f"{android_version}" if api_level == 0 else f"{android_version} (API {api_level})"
            
            # Format model display
            model = device.get('model', 'Unknown')
            manufacturer = device.get('manufacturer', '')
            if manufacturer and manufacturer != 'Unknown' and manufacturer not in model:
                model_display = f"{manufacturer} {model}"
            else:
                model_display = model
            
            # Detect emulator type
            emulator_display = self._detect_emulator_type(device)
            
            # Status
            status = str(device.get('status', 'Unknown'))
            
            items = [
                QTableWidgetItem(str(device.get('serial', ''))),
                QTableWidgetItem(model_display),
                QTableWidgetItem(android_display),
                QTableWidgetItem(emulator_display),
                QTableWidgetItem(status)
            ]
            
            for item in items:
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            
            # Store device data
            items[0].setData(Qt.ItemDataRole.UserRole, device)
            
            for col, item in enumerate(items):
                self.device_table.setItem(row, col, item)
        
        self.device_table.resizeRowsToContents()
        
    def show_loading_state(self, loading: bool):
        """Show or hide loading state."""
        if loading:
            # Show skeleton loading state
            self.device_table.setRowCount(3)  # Show 3 skeleton rows
            for row in range(3):
                for col in range(5):
                    item = QTableWidgetItem("")
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.device_table.setItem(row, col, item)
            
            # Disable refresh button
            self.refresh_button.setEnabled(False)
        else:
            # Re-enable refresh button
            self.refresh_button.setEnabled(True)
            
    def _detect_emulator_type(self, device: Dict[str, Any]) -> str:
        """Detect emulator type based on device properties."""
        is_emulator = device.get('is_emulator', False)
        if not is_emulator:
            return "Physical"
        
        model = device.get('model', '').lower()
        device_name = device.get('device_name', '').lower()
        manufacturer = device.get('manufacturer', '').lower()
        
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
            
    def _on_refresh_clicked(self):
        """Handle refresh button click."""
        self.logger.info("Refresh devices requested")
        # This will be handled by the parent connection page
        
    def _on_device_selection_changed(self):
        """Handle device selection change."""
        selected_items = self.device_table.selectedItems()
        if selected_items:
            item = self.device_table.item(selected_items[0].row(), 0)
            if item:
                serial = item.text()
                self.device_selected.emit(serial)


class ProcessSelectionWidget(QWidget):
    """Widget for process selection step."""
    
    process_selected = pyqtSignal(dict)  # Emits process data when selected
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = structlog.get_logger().bind(source="ProcessSelectionWidget")
        self.all_processes = []  # Store all processes for filtering
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the process selection UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        # Search and filter controls
        search_layout = QHBoxLayout()
        
        # Search bar
        self.search_input = SearchLineEdit(self)
        self.search_input.setPlaceholderText("Search processes...")
        self.search_input.textChanged.connect(self._on_search_changed)
        search_layout.addWidget(self.search_input)
        
        # Show only third party processes checkbox
        self.third_party_checkbox = CheckBox("Show Only Third Party Processes", self)
        self.third_party_checkbox.setChecked(True)  # Default to checked
        self.third_party_checkbox.stateChanged.connect(self._on_filter_changed)
        search_layout.addWidget(self.third_party_checkbox)
        
        layout.addLayout(search_layout)
        
        # Process table
        self.process_table = TableWidget(self)
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["App Name", "Package", "Version", "PID", "Status"])
        self.process_table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self.process_table.setSelectionMode(TableWidget.SelectionMode.SingleSelection)
        
        # Configure table headers
        header = self.process_table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(self.process_table)
        
        # Refresh button
        refresh_layout = QHBoxLayout()
        refresh_layout.addStretch(1)
        
        self.refresh_button = PushButton(FluentIcon.SYNC, "Refresh Processes", self)
        self.refresh_button.clicked.connect(self._on_refresh_clicked)
        refresh_layout.addWidget(self.refresh_button)
        
        layout.addLayout(refresh_layout)
        
        # Connect signals
        self.process_table.itemSelectionChanged.connect(self._on_process_selection_changed)
        
    def update_processes(self, processes: List[Dict[str, Any]]):
        """Update the process table with new process data."""
        self.all_processes = processes
        self._apply_filters()
        
    def _apply_filters(self):
        """Apply search and filter to the process list."""
        search_term = self.search_input.text().lower()
        show_only_third_party = self.third_party_checkbox.isChecked()
        
        filtered_processes = []
        
        for process in self.all_processes:
            # Check search term
            matches_search = (
                search_term in process.get('name', '').lower() or
                search_term in process.get('package', '').lower()
            )
            
            if not matches_search:
                continue
                
            # Check third party filter
            if show_only_third_party:
                package = process.get('package', '')
                is_third_party = (
                    package and
                    not package.startswith('com.android.') and
                    not package.startswith('android.') and
                    not package.startswith('system') and
                    not package.startswith('com.google.android.') and
                    not package.startswith('com.samsung.') and
                    not package.startswith('com.sec.') and
                    not package.startswith('com.qualcomm.')
                )
                
                if not is_third_party:
                    continue
            
            filtered_processes.append(process)
        
        # Update table with filtered processes
        self._populate_table(filtered_processes)
        
    def _populate_table(self, processes: List[Dict[str, Any]]):
        """Populate the table with the given processes."""
        self.process_table.setRowCount(len(processes))
        
        for row, process in enumerate(processes):
            is_running = process.get('is_running', False)
            status_text = "Running" if is_running else "Not Running"
            
            # App name display
            app_name = process.get('name', 'N/A')
            package_name = process.get('package', '')
            
            if app_name == package_name and package_name:
                app_name = package_name.split('.')[-1].title()
            
            # Version display
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
            
            # Store process data
            items[0].setData(Qt.ItemDataRole.UserRole, process)
            
            for col, item in enumerate(items):
                self.process_table.setItem(row, col, item)
        
        self.process_table.resizeRowsToContents()
        
    def show_loading_state(self, loading: bool):
        """Show or hide loading state."""
        if loading:
            # Show skeleton loading state
            self.process_table.setRowCount(5)  # Show 5 skeleton rows
            for row in range(5):
                for col in range(5):
                    item = QTableWidgetItem("")
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.process_table.setItem(row, col, item)
            
            # Disable search and filter controls
            self.search_input.setEnabled(False)
            self.third_party_checkbox.setEnabled(False)
            self.refresh_button.setEnabled(False)
        else:
            # Re-enable controls
            self.search_input.setEnabled(True)
            self.third_party_checkbox.setEnabled(True)
            self.refresh_button.setEnabled(True)
            
            # Apply filters to show actual data
            self._apply_filters()
        
    def _on_search_changed(self):
        """Handle search text change."""
        self._apply_filters()
        
    def _on_filter_changed(self):
        """Handle filter checkbox change."""
        self._apply_filters()
        
    def _on_refresh_clicked(self):
        """Handle refresh button click."""
        self.logger.info("Refresh processes requested")
        
    def _on_process_selection_changed(self):
        """Handle process selection change."""
        selected_items = self.process_table.selectedItems()
        if selected_items:
            item = self.process_table.item(selected_items[0].row(), 0)
            if item:
                process_data = item.data(Qt.ItemDataRole.UserRole)
                if process_data:
                    self.process_selected.emit(process_data)


class HookScriptWidget(QWidget):
    """Widget for hook script selection and configuration."""
    
    script_selected = pyqtSignal(dict)  # Emits script data when selected
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = structlog.get_logger().bind(source="HookScriptWidget")
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the hook script selection UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        # Script selection
        script_layout = QHBoxLayout()
        script_layout.addWidget(BodyLabel("Hook Script:"))
        
        self.script_combo = ComboBox(self)
        self.script_combo.setEnabled(False)
        script_layout.addWidget(self.script_combo)
        
        layout.addLayout(script_layout)
        
        # Script preview
        preview_label = BodyLabel("Script Preview:", self)
        layout.addWidget(preview_label)
        
        self.script_preview = QTextEdit(self)
        self.script_preview.setMaximumHeight(200)
        self.script_preview.setReadOnly(True)
        self.script_preview.setPlaceholderText("Select a script to preview its contents...")
        layout.addWidget(self.script_preview)
        
        # Options
        options_layout = QVBoxLayout()
        
        self.auto_activate_checkbox = QCheckBox("Automatically activate hook after connection", self)
        self.auto_activate_checkbox.setChecked(True)
        options_layout.addWidget(self.auto_activate_checkbox)
        
        self.verbose_logging_checkbox = QCheckBox("Enable verbose logging", self)
        self.verbose_logging_checkbox.setChecked(False)
        options_layout.addWidget(self.verbose_logging_checkbox)
        
        layout.addLayout(options_layout)
        
        # Connect signals
        self.script_combo.currentIndexChanged.connect(self._on_script_selection_changed)
        
    def update_scripts(self, scripts: List[Dict[str, Any]]):
        """Update the script combo box with available scripts."""
        self.script_combo.clear()
        
        for script in scripts:
            name = script.get('scriptName', script.get('fileName', 'Script'))
            self.script_combo.addItem(name, userData=script)
        
        self.script_combo.setEnabled(len(scripts) > 0)
        
    def _on_script_selection_changed(self):
        """Handle script selection change."""
        current_data = self.script_combo.currentData()
        if current_data:
            # Update preview
            script_content = current_data.get('content', '')
            self.script_preview.setText(script_content)
            
            # Emit selection
            self.script_selected.emit(current_data)


class ConnectionPage(ContentPage):
    """Connection page with vertical stepper for device connection flow."""
    
    # Signals
    scan_devices_requested = pyqtSignal()
    connect_device_requested = pyqtSignal(str)
    disconnect_device_requested = pyqtSignal()
    refresh_processes_requested = pyqtSignal()
    select_process_requested = pyqtSignal(dict)
    activate_hook_requested = pyqtSignal(dict)
    compatible_scripts_requested = pyqtSignal(str, str)
    
    def __init__(self, session_manager, config_manager, log_signal=None, parent=None):
        super().__init__(
            title="Device Connection",
            description="Connect to a device, select a process, and activate hook scripts",
            parent=parent
        )
        
        self.session_manager = session_manager
        self.config_manager = config_manager
        self.log_signal = log_signal
        self.logger = structlog.get_logger().bind(source="ConnectionPage")
        
        # Connection state tracking
        self.selected_device_serial = None
        self.selected_process_data = None
        self.selected_script_data = None
        
        # Setup UI
        self.setup_ui()
        self.setup_connections()
        
        # Initial state
        self.update_ui_for_connection_state(self.session_manager.connection_main_state)
        
    def setup_ui(self):
        """Set up the connection page UI."""
        content_container = self.get_content_container()
        layout = QVBoxLayout(content_container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)
        
        # Create vertical stepper
        self.stepper = VerticalStepper(self)
        layout.addWidget(self.stepper)
        
        # Add steps to the stepper
        self._setup_stepper_steps()
        
        # Connect stepper signals
        self.stepper.step_changed.connect(self._on_step_changed)
        self.stepper.all_steps_completed.connect(self._on_all_steps_completed)
        
    def _setup_stepper_steps(self):
        """Set up the stepper steps with their content widgets."""
        # Step 1: Device Selection
        device_widget = DeviceSelectionWidget()
        device_widget.device_selected.connect(self._on_device_selected)
        self.stepper.add_step(
            "Select Device",
            "Choose a device to connect to",
            device_widget
        )
        
        # Step 2: Process Selection
        process_widget = ProcessSelectionWidget()
        process_widget.process_selected.connect(self._on_process_selected)
        self.stepper.add_step(
            "Select Process",
            "Choose the target application process",
            process_widget
        )
        
        # Step 3: Hook Script Configuration
        hook_widget = HookScriptWidget()
        hook_widget.script_selected.connect(self._on_script_selected)
        self.stepper.add_step(
            "Configure Hook Script",
            "Select and configure the hook script to inject",
            hook_widget,
            optional=True
        )
        
        # Step 4: Connection
        connection_widget = self._create_connection_widget()
        self.stepper.add_step(
            "Establish Connection",
            "Connect to the device and activate the hook",
            connection_widget
        )
        
    def _create_connection_widget(self) -> QWidget:
        """Create the connection status widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        # Status card
        status_card = SimpleCardWidget()
        status_layout = QVBoxLayout(status_card)
        
        self.status_label = BodyLabel("Ready to connect", status_card)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_layout.addWidget(self.status_label)
        
        self.progress_ring = ProgressRing(status_card)
        self.progress_ring.setVisible(False)
        status_layout.addWidget(self.progress_ring, alignment=Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(status_card)
        
        # Connection button
        button_layout = QHBoxLayout()
        button_layout.addStretch(1)
        
        self.connect_button = PushButton("Connect", widget)
        self.connect_button.clicked.connect(self._on_connect_clicked)
        button_layout.addWidget(self.connect_button)
        
        layout.addLayout(button_layout)
        
        return widget
        
    def setup_connections(self):
        """Set up signal connections."""
        # Session manager connections
        self.session_manager.available_emulators_changed.connect(self._on_devices_updated)
        self.session_manager.available_processes_changed.connect(self._on_processes_updated)
        self.session_manager.connection_main_state_changed.connect(self._on_connection_state_changed)
        
        # Get device selection widget
        device_widget = self.stepper.get_step_content_widget(0)
        if device_widget and isinstance(device_widget, DeviceSelectionWidget):
            device_widget.refresh_button.clicked.connect(self.scan_devices_requested)
            
        # Get process selection widget
        process_widget = self.stepper.get_step_content_widget(1)
        if process_widget and isinstance(process_widget, ProcessSelectionWidget):
            process_widget.refresh_button.clicked.connect(self.refresh_processes_requested)
            
    def _on_device_selected(self, device_serial: str):
        """Handle device selection."""
        self.logger.info("Device selected", device_serial=device_serial)
        self.selected_device_serial = device_serial
        
        # Update stepper status
        self.stepper.update_step_status(0, StepStatus.COMPLETED)
        
        # Auto-advance to next step
        self.stepper.set_active_step(1)
        
    def _on_process_selected(self, process_data: dict):
        """Handle process selection."""
        self.logger.info("Process selected", process_data=process_data)
        self.selected_process_data = process_data
        
        # Update stepper status
        self.stepper.update_step_status(1, StepStatus.COMPLETED)
        
        # Request compatible scripts
        package = process_data.get('package', '')
        version = process_data.get('version', 'Unknown')
        self.compatible_scripts_requested.emit(package, version)
        
        # Auto-advance to next step
        self.stepper.set_active_step(2)
        
    def _on_script_selected(self, script_data: dict):
        """Handle script selection."""
        self.logger.info("Script selected", script_data=script_data)
        self.selected_script_data = script_data
        
        # Update stepper status
        self.stepper.update_step_status(2, StepStatus.COMPLETED)
        
        # Auto-advance to next step
        self.stepper.set_active_step(3)
        
    def _on_step_changed(self, step_index: int):
        """Handle step change."""
        self.logger.info("Step changed", step_index=step_index)
        
    def _on_all_steps_completed(self):
        """Handle all steps completion."""
        self.logger.info("All steps completed")
        
    def _on_connect_clicked(self):
        """Handle connect button click."""
        if not self.selected_device_serial:
            self._show_error("No device selected", "Please select a device first.")
            return
            
        if not self.selected_process_data:
            self._show_error("No process selected", "Please select a process first.")
            return
            
        self.logger.info("Starting connection", 
                        device=self.selected_device_serial,
                        process=self.selected_process_data)
        
        # Update UI to show progress
        self._update_connection_ui(True, "Connecting...")
        
        # Emit connection request
        self.connect_device_requested.emit(self.selected_device_serial)
        
    def _on_devices_updated(self, devices: List[Dict[str, Any]]):
        """Handle device list update."""
        device_widget = self.stepper.get_step_content_widget(0)
        if device_widget and isinstance(device_widget, DeviceSelectionWidget):
            device_widget.update_devices(devices)
            
    def _on_processes_updated(self, processes: List[Dict[str, Any]]):
        """Handle process list update."""
        process_widget = self.stepper.get_step_content_widget(1)
        if process_widget and isinstance(process_widget, ProcessSelectionWidget):
            process_widget.update_processes(processes)
            
    def _on_connection_state_changed(self, state: ConnectionState):
        """Handle connection state change."""
        self.logger.info("Connection state changed", state=state.value)
        self.update_ui_for_connection_state(state)
        
    def update_ui_for_connection_state(self, state: ConnectionState):
        """Update UI based on connection state."""
        if state == ConnectionState.CONNECTING:
            self._update_connection_ui(True, "Connecting to device...")
            self.stepper.update_step_status(3, StepStatus.ACTIVE, progress_percent=50)
            
        elif state == ConnectionState.CONNECTED:
            self._update_connection_ui(False, "Connected successfully!")
            self.stepper.update_step_status(3, StepStatus.COMPLETED)
            
        elif state == ConnectionState.ACTIVE:
            self._update_connection_ui(False, "Hook activated successfully!")
            self.stepper.update_step_status(3, StepStatus.COMPLETED)
            
        elif state == ConnectionState.ERROR:
            error_info = self.session_manager.get_last_error_info()
            error_message = error_info.user_message if error_info else "Connection failed"
            self._update_connection_ui(False, f"Error: {error_message}")
            self.stepper.update_step_status(3, StepStatus.FAILED, error_message)
            
        elif state == ConnectionState.DISCONNECTED:
            self._update_connection_ui(False, "Ready to connect")
            self.stepper.update_step_status(3, StepStatus.PENDING)
            
    def _update_connection_ui(self, connecting: bool, message: str):
        """Update the connection UI elements."""
        self.status_label.setText(message)
        self.progress_ring.setVisible(connecting)
        self.connect_button.setEnabled(not connecting)
        
        if connecting:
            # ProgressRing doesn't have start/stop methods, just show/hide
            pass
        else:
            # ProgressRing doesn't have start/stop methods, just show/hide
            pass
            
    def _show_error(self, title: str, content: str):
        """Show an error infobar."""
        InfoBar.error(
            title=title,
            content=content,
            duration=5000,
            parent=self,
            position=InfoBarPosition.BOTTOM_RIGHT
        )
        
    def update_compatible_scripts(self, scripts: List[Dict[str, Any]]):
        """Update the script selection with compatible scripts."""
        hook_widget = self.stepper.get_step_content_widget(2)
        if hook_widget and isinstance(hook_widget, HookScriptWidget):
            hook_widget.update_scripts(scripts)
            
    def on_page_shown(self):
        """Called when the connection page is navigated to."""
        # Trigger device scan if no devices are available
        if not self.session_manager.available_emulators:
            self.scan_devices_requested.emit()
            
        self.logger.info("Connection page shown")