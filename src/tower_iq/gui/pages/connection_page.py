"""
TowerIQ Connection Page

This module provides the ConnectionPage widget for managing device connections,
process selection, and hook activation in the TowerIQ application.
"""

import structlog

from ..utils.expandable_settings_card import ExpandableCardGroup
from ..utils.content_page import ContentPage
from ...core.session import ConnectionState, ConnectionSubState
from .activation_status_widget import ActivationStatusWidget
from PyQt6.QtWidgets import (
    QHBoxLayout, QVBoxLayout, QLabel, QStackedWidget, QWidget,
    QGroupBox, QTextEdit, QFrame, QHeaderView, QTableWidgetItem, QSizePolicy
)
from qfluentwidgets import (SwitchButton, FluentIcon, PushButton, TableWidget, TableItemDelegate, isDarkTheme,
                            ProgressRing, BodyLabel, InfoBar, InfoBarPosition, CardWidget, SimpleCardWidget, ComboBox)
from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QPalette, QColor

# NOTE: CustomTableItemDelegate remains unchanged as it's already well-designed.
class CustomTableItemDelegate(TableItemDelegate):
    # ... (no changes needed here) ...
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
        if parent is not None and hasattr(parent, 'objectName') and parent.objectName() == "device_table" and index.column() == 4:
            status = index.data()
            color_map = {
                "Online": ("#2ecc71", "#27ae60"),
                "Connected": ("#3498db", "#2980b9"),  # Blue color for connected status
                "Offline": ("#e74c3c", "#c0392b"),
                "Unauthorized": ("#f39c12", "#e67e22"),
                "No Permissions": ("#e74c3c", "#c0392b"),
            }
            default_color = ("#f1c40f", "#f39c12")
            dark_color, light_color = color_map.get(status, default_color)
            color = QColor(dark_color) if isDarkTheme() else QColor(light_color)
            option.palette.setColor(QPalette.ColorRole.Text, color)
            option.palette.setColor(QPalette.ColorRole.HighlightedText, color)


class ConnectionPage(QWidget):
    # --- Signals ---
    scan_devices_requested = pyqtSignal()
    connect_device_requested = pyqtSignal(str)
    disconnect_device_requested = pyqtSignal()  # New signal for disconnect requests
    refresh_processes_requested = pyqtSignal()
    select_process_requested = pyqtSignal(dict)
    activate_hook_requested = pyqtSignal(object)  # Emits selected hook script dict
    compatible_scripts_requested = pyqtSignal(str, str)  # package, version
    back_to_stage_requested = pyqtSignal(int)
    
    def __init__(self, session_manager, config_manager, log_signal=None, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.config_manager = config_manager
        self.log_signal = log_signal
        self.logger = structlog.get_logger().bind(source="ConnectionPage")
        
        # Flag to track if device card has been expanded
        self._device_card_expanded = False
        
        # Track connection state for infobar management
        self._last_connection_state = ConnectionState.DISCONNECTED
        self._connection_infobar = None
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(10) # Reduced spacing for a tighter card look
        
        # --- REFACTORED: Create sections using new card components ---
        self.status_section = self._create_status_section() # Status section remains a GroupBox
        self.device_card = self._create_device_card()
        self.process_card = self._create_process_card()
        # Activation Status section
        self.activation_section = QGroupBox("Activation Status", self)
        activation_layout = QVBoxLayout(self.activation_section)
        self.activation_status_container = QWidget(self.activation_section)
        self.activation_status_layout = QVBoxLayout(self.activation_status_container)
        self.activation_status_layout.setContentsMargins(0, 0, 0, 0)
        activation_layout.addWidget(self.activation_status_container)
        
        # Add sections to layout
        layout.addWidget(self.status_section)
        layout.addWidget(self.device_card)
        layout.addWidget(self.process_card)
        layout.addWidget(self.activation_section)
        layout.addStretch(1) # Push all content to the top
        
        # --- Connect signals ---
        self.session_manager.available_emulators_changed.connect(self.update_device_table)
        self.session_manager.available_processes_changed.connect(self.update_process_table)
        self.session_manager.connection_main_state_changed.connect(self._on_connection_state_changed)
        self.session_manager.connection_sub_state_changed.connect(self._on_connection_sub_state_changed)
        # Live stage updates for activation status UI
        if hasattr(self.session_manager, 'connection_stages_changed'):
            self.session_manager.connection_stages_changed.connect(self._on_connection_stages_changed)
        
        # Connect activation widget signals (disabled for debugging)
        # self.activation_section.cancel_clicked.connect(self._on_cancel_clicked)
        # self.activation_section.retry_clicked.connect(self.activate_hook_requested)
        

        
        # --- Initial state update ---
        self._on_connection_state_changed(self.session_manager.connection_main_state)
        self.update_device_table(self.session_manager.available_emulators)
        
        # Note: Device scan will be triggered by on_page_shown() when page is navigated to
        # No need to scan during initialization as the page might not be visible yet

    def _show_connection_infobar(self, title: str, content: str, icon: FluentIcon, duration: int = 3000):
        """Show an infobar notification for connection events."""
        self.logger.info("Showing connection infobar", title=title, content=content, duration=duration)
        
        # Close any existing connection infobar
        if self._connection_infobar:
            self._connection_infobar.close()
            self._connection_infobar = None
        
        # Create and show new infobar
        self._connection_infobar = InfoBar(
            icon=icon,
            title=title,
            content=content,
            duration=duration,
            position=InfoBarPosition.BOTTOM_RIGHT,
            parent=self
        )
        self._connection_infobar.show()

    def _show_connecting_infobar(self, device_serial: str):
        """Show connecting infobar with indeterminate progress."""
        self.logger.info("Showing connecting infobar", device_serial=device_serial)
        self._show_connection_infobar(
            title="Connecting to device",
            content=f"Establishing connection to {device_serial}...",
            icon=FluentIcon.SYNC,
            duration=0  # No auto-close, will be closed manually
        )

    def _show_connection_success_infobar(self, device_serial: str):
        """Show successful connection infobar."""
        self.logger.info("Showing connection success infobar", device_serial=device_serial)
        
        # Close any existing connection infobar
        if self._connection_infobar:
            self._connection_infobar.close()
            self._connection_infobar = None
        
        # Use InfoBar.success static method
        InfoBar.success(
            title="Successfully connected to device",
            content=f"Device {device_serial} is now connected and ready.",
            duration=4000,
            parent=self,
            position=InfoBarPosition.BOTTOM_RIGHT,
        )

    def _show_connection_error_infobar(self, device_serial: str, error_message: str):
        """Show connection error infobar."""
        self.logger.info("Showing connection error infobar", device_serial=device_serial, error_message=error_message)
        
        # Close any existing connection infobar
        if self._connection_infobar:
            self._connection_infobar.close()
            self._connection_infobar = None
        
        # Use InfoBar.error static method
        InfoBar.error(
            title="Connection failed",
            content=f"Failed to connect to {device_serial}: {error_message}",
            duration=5000,
            parent=self,
            position=InfoBarPosition.BOTTOM_RIGHT,
        )



    def _on_process_card_toggle_changed(self, expanded: bool):
        """Handle process card expansion/collapse."""
        if expanded:
            # When process card is expanded, force layout update to fix width issues
            pass  # Removed QTimer hack - tables now use proper size policies

    def _on_device_card_toggle_changed(self, expanded: bool):
        """Handle device card expansion/collapse."""
        # No special handling needed for device card
        pass

    def _create_standard_table(self, headers: list[str]) -> TableWidget:
        # This factory method is still useful and remains unchanged.
        # ... (no changes needed here) ...
        table = TableWidget(self)
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        
        table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(TableWidget.SelectionMode.SingleSelection)
        table.setBorderVisible(True)
        table.setBorderRadius(8)
        table.setWordWrap(False)
        table.setSortingEnabled(False)
        
        # Set size policy to allow natural resizing
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.MinimumExpanding)
        
        vertical_header = table.verticalHeader()
        if vertical_header is not None:
            vertical_header.setMinimumSectionSize(30)
            vertical_header.setDefaultSectionSize(40)
            vertical_header.setMaximumSectionSize(50)
            vertical_header.setStretchLastSection(False)  # Prevent extra space after last row
            vertical_header.hide()
            
        return table


    def _create_status_section(self) -> QGroupBox:
        # This section remains a simple QGroupBox as requested.
        # ... (no changes needed here) ...
        status_group = QGroupBox("Status")
        layout = QVBoxLayout(status_group)
        
        # Status indicator
        self.status_indicator = BodyLabel("Not Connected")
        self.status_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_indicator.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(self.status_indicator)
        
        # Connection details
        self.connection_details = BodyLabel("No device connected")
        self.connection_details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.connection_details.setStyleSheet("color: gray; padding: 5px;")
        layout.addWidget(self.connection_details)
        
        return status_group


    def _create_device_card(self) -> ExpandableCardGroup:
        """Create the device section as an expandable card."""
        device_card_group = ExpandableCardGroup(
            title="Device",
            content="Select a device to begin",
            #TODO: add a better device icon
            header_icon=FluentIcon.DEVELOPER_TOOLS
        )
        # Hide the toggle switch as it's not needed for this card
        device_card_group.header_card.toggle_switch.setVisible(False)

        # Create a content card to hold the table and buttons
        content_card = SimpleCardWidget()
        content_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        content_layout = QVBoxLayout(content_card)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(10)

        # Create the device table (logic moved from old _create_device_section)
        self.device_table = self._create_standard_table(["Serial", "Model", "Android", "Emulator", "Status"])
        self.device_table.setObjectName("device_table") # Keep object name for the delegate
        self.device_table.setItemDelegate(CustomTableItemDelegate(self.device_table))
        header = self.device_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        content_layout.addWidget(self.device_table, 0)  # Add with stretch factor 0 to prevent expansion

        # Create the bottom button bar
        bottom_bar_layout = QHBoxLayout()
        bottom_bar_layout.addStretch(1)
        self.refresh_button = PushButton(FluentIcon.SYNC, "Refresh")
        self.refresh_button.clicked.connect(self.trigger_device_scan)
        bottom_bar_layout.addWidget(self.refresh_button)
        
        self.connect_button = PushButton(FluentIcon.LINK, "Connect")
        self.connect_button.setEnabled(False)
        self.connect_button.clicked.connect(self._on_connect_clicked)
        bottom_bar_layout.addWidget(self.connect_button)
        
        # Add disconnect button (initially hidden)
        self.disconnect_button = PushButton(FluentIcon.CLOSE, "Disconnect")
        self.disconnect_button.setVisible(False)
        self.disconnect_button.clicked.connect(self._on_disconnect_clicked)
        bottom_bar_layout.addWidget(self.disconnect_button)
        
        content_layout.addLayout(bottom_bar_layout)
        
        self.device_table.itemSelectionChanged.connect(self._on_device_selection_changed)
        
        # Add the single content card to the expandable group
        device_card_group.add_card(content_card)
        
        # Connect the toggle signal to handle manual expansion
        device_card_group.toggle_changed.connect(self._on_device_card_toggle_changed)
        
        return device_card_group

    def _create_process_card(self) -> ExpandableCardGroup:
        """Create the process section as an expandable card."""
        process_card_group = ExpandableCardGroup(
            title="Process",
            content="Connect to a device to see available processes",
            header_icon=FluentIcon.APPLICATION
        )
        # Hide the toggle switch
        process_card_group.header_card.toggle_switch.setVisible(False)

        # Create a content card for the table and buttons
        content_card = SimpleCardWidget()
        content_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        content_layout = QVBoxLayout(content_card)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(10)

        # Script selection bar
        script_bar = QHBoxLayout()
        script_bar.addWidget(BodyLabel("Hook Script:"))
        self.hook_script_combo = ComboBox(self)
        self.hook_script_combo.setEnabled(False)
        script_bar.addWidget(self.hook_script_combo)
        content_layout.addLayout(script_bar)

        # Create the process table
        self.process_table = self._create_standard_table(["App Name", "Package", "Version", "PID", "Status"])
        self.process_table.itemSelectionChanged.connect(self._on_process_selection_changed)
        header = self.process_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        content_layout.addWidget(self.process_table, 0)  # Add with stretch factor 0 to prevent expansion

        # Create the bottom button bar
        bottom_bar_layout = QHBoxLayout()
        bottom_bar_layout.addStretch(1)
        self.refresh_processes_button = PushButton(FluentIcon.SYNC, "Refresh")
        self.refresh_processes_button.clicked.connect(self.refresh_processes_requested)
        self.refresh_processes_button.setEnabled(False) # Enabled when device is connected
        bottom_bar_layout.addWidget(self.refresh_processes_button)
        
        self.activate_hook_button = PushButton(FluentIcon.PLAY_SOLID, "Activate Hook")
        self.activate_hook_button.setEnabled(False) # Enabled when process is selected
        self.activate_hook_button.clicked.connect(self._emit_activate_hook)
        bottom_bar_layout.addWidget(self.activate_hook_button)
        content_layout.addLayout(bottom_bar_layout)
        
        # Add the content card to the expandable group
        process_card_group.add_card(content_card)
        
        # Connect the toggle signal to handle manual expansion
        process_card_group.toggle_changed.connect(self._on_process_card_toggle_changed)
        
        return process_card_group




    # --- Reactive Slots for State Changes ---
    def _on_connection_state_changed(self, state):
        """Reacts to SessionManager's main connection state."""
        self.logger.info("Connection main state changed", state=state.value)
        
        # Handle infobar notifications
        if state == ConnectionState.CONNECTING and self._last_connection_state != ConnectionState.CONNECTING:
            # Show connecting infobar
            device_serial = self.session_manager.connected_emulator_serial or "device"
            self._show_connecting_infobar(device_serial)
            
        elif state == ConnectionState.CONNECTED and self._last_connection_state != ConnectionState.CONNECTED:
            # Show success infobar and close connecting infobar
            if self._connection_infobar:
                self._connection_infobar.close()
                self._connection_infobar = None
            device_serial = self.session_manager.connected_emulator_serial or "device"
            self._show_connection_success_infobar(device_serial)
            
        elif state == ConnectionState.ERROR and self._last_connection_state != ConnectionState.ERROR:
            # Show error infobar
            if self._connection_infobar:
                self._connection_infobar.close()
                self._connection_infobar = None
            device_serial = self.session_manager.connected_emulator_serial or "device"
            error_info = self.session_manager.get_last_error_info()
            error_message = error_info.user_message if error_info else "Unknown error"
            self._show_connection_error_infobar(device_serial, error_message)
            
        elif state == ConnectionState.DISCONNECTED and self._last_connection_state != ConnectionState.DISCONNECTED:
            # Close any existing infobar
            if self._connection_infobar:
                self._connection_infobar.close()
                self._connection_infobar = None
        
        # Update UI
        self._update_ui_for_state(state)
        
        # Update activation view
        self.update_activation_view()
        
        # Update last state
        self._last_connection_state = state

    def _on_connection_sub_state_changed(self, sub_state):
        """Reacts to SessionManager's connection sub-state."""
        self.logger.info("Connection sub state changed", sub_state=sub_state.value if sub_state else "None")
        
        # Update activation view when sub-state changes
        self.update_activation_view()
        
        # Clear sub-state when connection is established
        if self.session_manager.connection_main_state in [ConnectionState.CONNECTED, ConnectionState.ACTIVE]:
            self.logger.info("Connection sub state cleared")



    def _update_ui_for_state(self, state: ConnectionState):
        """Centralized method to update all UI components based on the main state."""
        # Update section visibility and enabled status
        is_connected = state == ConnectionState.CONNECTED
        is_active = state == ConnectionState.ACTIVE
        
        # Handle card transitions based on connection state
        if state == ConnectionState.CONNECTED and self._last_connection_state != ConnectionState.CONNECTED:
            # Device just connected - expand process card but keep device card open
            self.logger.info("Device connected - expanding process card")
            self.process_card.set_expanded(True)
            # Force layout update to fix width issue
            pass  # Removed QTimer hack - tables now use proper size policies
            
        elif state == ConnectionState.DISCONNECTED and self._last_connection_state != ConnectionState.DISCONNECTED:
            # Device disconnected - collapse process card but keep device card open
            self.logger.info("Device disconnected - collapsing process card")
            self.process_card.set_expanded(False)
            
        elif state == ConnectionState.ACTIVE and self._last_connection_state != ConnectionState.ACTIVE:
            # Hook activated - close process card
            self.logger.info("Hook activated - closing process card")
            self.process_card.set_expanded(False)
        
        # Process card is always enabled but content is disabled when no device connected
        self.process_card.setEnabled(True)
        self.refresh_processes_button.setEnabled(is_connected or is_active)
        self.activate_hook_button.setEnabled(False)  # Will be enabled when process is selected
        self.activation_section.setVisible(is_active or is_connected)
        
        # Update device card button visibility based on connection state
        if is_connected or is_active:
            # Device is connected - show disconnect button, hide connect button
            self.connect_button.setVisible(False)
            self.disconnect_button.setVisible(True)
        else:
            # Device is not connected - show connect button, hide disconnect button
            self.connect_button.setVisible(True)
            self.disconnect_button.setVisible(False)
        
        # Update header card descriptions
        if is_active or is_connected:
            serial = self.session_manager.connected_emulator_serial
            self.device_card.header_card.content_label.setText(f"Connected to {serial}")
        else:
            self.device_card.header_card.content_label.setText("Select a device to begin")

        if is_active:
            process_name = self.session_manager.selected_target_app_name or "N/A"
            self.process_card.header_card.content_label.setText(f"Hooked: {process_name}")
        elif is_connected:
            self.process_card.header_card.content_label.setText("Select a process to hook")
        else:
            self.process_card.header_card.content_label.setText("Connect to a device to see available processes")
        
        # Update process table and button states based on connection
        if is_connected or is_active:
            # Enable process table and buttons
            self.process_table.setEnabled(True)
            self.refresh_processes_button.setEnabled(True)
        else:
            # Disable process table and buttons when no device connected
            self.process_table.setEnabled(False)
            self.refresh_processes_button.setEnabled(False)
            # Clear the process table when no device is connected
            self.process_table.setRowCount(0)
        
        # Automatically refresh processes when device is connected
        if is_connected and not is_active:
            # Only refresh if we don't already have processes loaded
            if not self.session_manager.available_processes:
                self.logger.info("Auto-refreshing processes for newly connected device")
                self.refresh_processes_requested.emit()
        
        # Update device table when connection state changes to reflect connected status
        if self.session_manager.available_emulators:
            self.update_device_table(self.session_manager.available_emulators)
            
        # Update the top-level status indicator
        self._update_status_section(state)

    def _update_status_section(self, state: ConnectionState):
        """Update the top status section based on current connection state."""
        # This method is now only responsible for the top status box
        if state == ConnectionState.ACTIVE:
            self.status_indicator.setText("✅ Connected & Active")
            self.status_indicator.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px; color: #2ecc71;")
            device_info = self.session_manager.connected_emulator_serial or "N/A"
            process_info = self.session_manager.selected_target_app_name or "N/A"
            self.connection_details.setText(f"Device: {device_info} | Process: {process_info}")
        elif state == ConnectionState.CONNECTED:
            self.status_indicator.setText("🔗 Device Connected")
            self.status_indicator.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px; color: #3498db;")
            device_info = self.session_manager.connected_emulator_serial or "N/A"
            self.connection_details.setText(f"Device: {device_info} | Select a process to continue")
        elif state == ConnectionState.CONNECTING:
            self.status_indicator.setText("🔄 Connecting...")
            self.status_indicator.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px; color: #f39c12;")
            self.connection_details.setText("Establishing connection...")
        elif state == ConnectionState.ERROR:
            self.status_indicator.setText("❌ Connection Error")
            self.status_indicator.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px; color: #e74c3c;")
            error_info = self.session_manager.get_last_error_info()
            self.connection_details.setText(f"Error: {error_info.user_message}" if error_info else "An error occurred.")
        else: # DISCONNECTED
            self.status_indicator.setText("❌ Not Connected")
            self.status_indicator.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px; color: #e74c3c;")
            self.connection_details.setText("No device connected")

    # --- UI Update and Action Handler methods remain largely the same ---
    # ... (update_device_table, _detect_emulator_type, update_process_table, etc. have no changes) ...
    # ... (_on_connect_clicked, _on_device_selection_changed, etc. have no changes) ...
    def update_device_table(self, emulators: list):
        """Populates the device table with enhanced device data."""
        self.logger.info("Received device table update signal", device_count=len(emulators))
        
        # Get the currently connected device serial
        connected_serial = self.session_manager.connected_emulator_serial
        
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
            
            # Determine status - show "Connected" for the currently connected device
            device_serial = emulator.get('serial', '')
            if device_serial == connected_serial:
                status = "Connected"
            else:
                status = str(emulator.get('status', 'Unknown'))
            
            items = [
                QTableWidgetItem(str(device_serial)),
                QTableWidgetItem(model_display),
                QTableWidgetItem(android_display),
                QTableWidgetItem(emulator_display),
                QTableWidgetItem(status)
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
        

        
        self.logger.info("Device table updated successfully", rows=len(emulators))

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
        """Updates the activation section UI based on session state with detailed multi-stage progress."""
        # Temporarily disabled for debugging
        pass
        # stage = self.session_manager.hook_activation_stage
        # message = self.session_manager.hook_activation_message
        # self.activation_section.update_view(stage, message)

    # --- UI Action Handlers ---
    def _on_connect_clicked(self):
        """Emits the selected device serial for the parent to handle."""
        selected_items = self.device_table.selectedItems()
        if selected_items:
            item = self.device_table.item(selected_items[0].row(), 0)
            if item is not None and hasattr(item, 'text'):
                serial = item.text()
                self.logger.info("Connect button clicked", device_serial=serial)
                self.connect_device_requested.emit(serial)

    def _on_device_selection_changed(self):
        self.connect_button.setEnabled(bool(self.device_table.selectedItems()))

    def _on_process_selection_changed(self):
        selected_items = self.process_table.selectedItems()
        # Only enable activate hook button if device is connected and process is selected
        is_connected = self.session_manager.connection_main_state in [ConnectionState.CONNECTED, ConnectionState.ACTIVE]
        self.activate_hook_button.setEnabled(bool(selected_items) and is_connected)
        if selected_items:
            item = self.process_table.item(selected_items[0].row(), 0)
            if item is not None and hasattr(item, 'data'):
                process_data = item.data(Qt.ItemDataRole.UserRole)
                self.select_process_requested.emit(process_data)
                # Request compatible scripts
                package = process_data.get('package', '')
                version = process_data.get('version', 'Unknown')
                self.hook_script_combo.clear()
                self.hook_script_combo.setEnabled(False)
                self.compatible_scripts_requested.emit(package, version)

    def _on_cancel_clicked(self):
        """Handle cancel button clicks based on current state."""
        # Use session_manager.connection_main_state to determine action
        connection_state = self.session_manager.connection_main_state
        
        if connection_state == ConnectionState.ACTIVE:
            # If hook is active, disconnect
            self.back_to_stage_requested.emit(0)
        else:
            # If in activation process, go back to process selection
            self.back_to_stage_requested.emit(1)

    def _on_disconnect_clicked(self):
        """Handle disconnect button clicks."""
        self.logger.info("Disconnect button clicked")
        self.disconnect_device_requested.emit()

    def update_theme_styles(self):
        """Update theme styles for all sections."""
        self.setStyleSheet("background: transparent;")

    def trigger_device_scan(self):
        """Public method to trigger a device scan."""
        self.logger.info("Manual device scan triggered by user (refresh button)")
        self.scan_devices_requested.emit()
        self.logger.info("Device scan signal emitted to main window")

    # --- New helpers for script selection and activation status ---
    def update_compatible_scripts(self, scripts: list):
        """Populate the combo with compatible scripts and enable controls."""
        self.hook_script_combo.clear()
        for script in scripts or []:
            name = script.get('scriptName', script.get('fileName', 'Script'))
            self.hook_script_combo.addItem(name, userData=script)
        has_items = self.hook_script_combo.count() > 0
        self.hook_script_combo.setEnabled(has_items)
        self.activate_hook_button.setEnabled(has_items)

    def _emit_activate_hook(self):
        data = self.hook_script_combo.currentData()
        self.activate_hook_requested.emit(data if isinstance(data, dict) else {})

    def _on_connection_stages_changed(self, stages: list):
        # Clear existing widgets
        while self.activation_status_layout.count():
            item = self.activation_status_layout.takeAt(0)
            if item is None:
                continue
            w = item.widget()
            if w is not None:
                w.deleteLater()
        # Rebuild status rows
        for stage in stages or []:
            row = QHBoxLayout()
            status = getattr(stage, 'status', None)
            status_value = getattr(status, 'value', None)
            if status_value is None:
                status_value = str(status) if status is not None else "pending"
            icon_label = BodyLabel("⏳" if status_value in ("pending", "active") else ("✅" if status_value == "completed" else "❌"))
            row.addWidget(icon_label)
            name_label = BodyLabel(getattr(stage, 'display_name', getattr(stage, 'stage_name', 'Stage')))
            row.addWidget(name_label)
            msg_label = BodyLabel(getattr(stage, 'message', ''))
            row.addWidget(msg_label)
            container = QWidget()
            layout = QHBoxLayout(container)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addLayout(row)
            self.activation_status_layout.addWidget(container)

    def showEvent(self, event):
        """Override showEvent to expand device card when page is shown."""
        super().showEvent(event)
        
        # Expand device card if not already expanded
        if not self._device_card_expanded and hasattr(self, 'device_card') and self.device_card:
            self.device_card.set_expanded(True)
            self._device_card_expanded = True
            self.logger.info("Device card expanded in showEvent")

    def on_page_shown(self):
        """Called when the connection page is navigated to."""
        # Trigger device scan only if no devices are currently available
        # This prevents duplicate scans when navigating to the page
        if not self.session_manager.available_emulators:
            self.scan_devices_requested.emit()
        
        self.logger.info("Connection page shown - scan triggered if needed")