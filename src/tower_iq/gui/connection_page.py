from .utils_gui import ThemeAwareWidget, get_text_color, get_title_font
from PyQt6.QtWidgets import (
    QHBoxLayout, QVBoxLayout, QLabel, QStackedWidget, QPushButton, QWidget, 
    QGroupBox, QTextEdit, QFrame, QHeaderView, QTableWidgetItem
)
from qfluentwidgets import (SwitchButton, FluentIcon, PushButton, TableWidget, TableItemDelegate, isDarkTheme, 
                            ProgressRing, BodyLabel, InfoBar, InfoBarPosition)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QPalette, QColor

class CustomTableItemDelegate(TableItemDelegate):
    """Custom table item delegate for the device table"""
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        # Change color of the Status column
        if index.column() == 2:  # Status column
            status = index.data()
            if status == "Connected":
                color = QColor("#2ecc71") if isDarkTheme() else QColor("#27ae60")  # Green
            elif status == "Disconnected":
                color = QColor("#e74c3c") if isDarkTheme() else QColor("#c0392b")  # Red
            else:
                color = QColor("#f1c40f") if isDarkTheme() else QColor("#f39c12")  # Yellow/Orange
            
            option.palette.setColor(QPalette.ColorRole.Text, color)
            option.palette.setColor(QPalette.ColorRole.HighlightedText, color)

class ConnectionPanel(ThemeAwareWidget):
    scan_devices_requested = pyqtSignal()
    connect_device_requested = pyqtSignal(str)
    refresh_processes_requested = pyqtSignal()
    select_process_requested = pyqtSignal(dict)
    activate_hook_requested = pyqtSignal()
    back_to_stage_requested = pyqtSignal(int)
    
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        layout = QVBoxLayout()
        self.stacked = QStackedWidget()

        # Stage 1: Device Discovery (keep existing implementation for now)
        self.stage1 = self._create_device_discovery_stage()

        # Create new stage widgets
        self.stage2_process_selection = self._create_process_selection_stage()
        self.stage3_activation = self._create_activation_stage()
        self.stage4_hook_active = self._create_hook_active_stage()

        # Add widgets to stacked widget
        self.stacked.addWidget(self.stage1)  # Index 0
        self.stacked.addWidget(self.stage2_process_selection)  # Index 1
        self.stacked.addWidget(self.stage3_activation)  # Index 2
        self.stacked.addWidget(self.stage4_hook_active)  # Index 3

        layout.addWidget(self.stacked)
        self.setLayout(layout)
        self.update_theme_styles()

        # Connect to session_manager signals for reactive updates
        self.session_manager.available_emulators_changed.connect(self.update_device_table)
        self.session_manager.available_processes_changed.connect(self.update_process_table)
        self.session_manager.connection_state_changed.connect(self._on_hook_state_changed)
        self.session_manager.emulator_connection_changed.connect(self._on_emulator_connection_changed)
        self.session_manager.hook_activation_stage_changed.connect(self.update_activation_view)
        self.session_manager.hook_activation_message_changed.connect(self.update_activation_view)
        
        # Initial update
        self.update_device_table(self.session_manager.available_emulators)
    
    def _create_device_discovery_stage(self) -> QWidget:
        """Create the device discovery stage (existing stage1 logic)"""
        stage1 = QWidget()
        s1_layout = QVBoxLayout()
        self.stage1_label = QLabel("Stage 1: Device Discovery")
        s1_layout.addWidget(self.stage1_label)
        
        # Button container
        button_layout = QHBoxLayout()
        
        # Refresh button
        self.refresh_button = PushButton(FluentIcon.SYNC, "Refresh Device List")
        self.refresh_button.clicked.connect(self._on_refresh_clicked)
        button_layout.addWidget(self.refresh_button)
        
        # Connect button
        self.connect_button = PushButton(FluentIcon.LINK, "Connect")
        self.connect_button.setEnabled(False)  # Disabled by default
        self.connect_button.clicked.connect(self._on_connect_clicked)
        button_layout.addWidget(self.connect_button)
        
        button_layout.addStretch()  # Push buttons to the left
        s1_layout.addLayout(button_layout)
        
        # Enhanced table widget
        self.device_table = TableWidget(self)
        self.device_table.setColumnCount(3)
        self.device_table.setHorizontalHeaderLabels(["Serial", "Model", "Status"])
        self.device_table.setBorderVisible(True)
        self.device_table.setBorderRadius(8)
        self.device_table.setWordWrap(False)
        
        # Set row height constraints
        vertical_header = self.device_table.verticalHeader()
        if vertical_header is not None:
            vertical_header.setMinimumSectionSize(30)  # Minimum row height
            vertical_header.setDefaultSectionSize(40)  # Default row height
            vertical_header.setMaximumSectionSize(50)  # Maximum row height
            vertical_header.hide()  # Hide vertical header
        
        # Set selection behavior
        self.device_table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self.device_table.setSelectionMode(TableWidget.SelectionMode.SingleSelection)
        self.device_table.setItemDelegate(CustomTableItemDelegate(self.device_table))
        self.device_table.setSortingEnabled(False)  # Disable sorting
        
        # Connect selection signal
        self.device_table.itemSelectionChanged.connect(self._on_table_selection_changed)
        
        # Set stretch mode for columns
        header = self.device_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Serial
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # Model
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Status
        
        s1_layout.addWidget(self.device_table)
        stage1.setLayout(s1_layout)
        return stage1

    def _create_process_selection_stage(self) -> QWidget:
        """Create the process selection stage widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 1. Top Bar
        top_bar_layout = QHBoxLayout()
        self.back_to_devices_button = PushButton(FluentIcon.CARE_LEFT_SOLID, "Back to Devices")
        self.back_to_devices_button.clicked.connect(lambda: self.back_to_stage_requested.emit(0))
        self.refresh_processes_button = PushButton(FluentIcon.SYNC, "Refresh Processes")
        self.refresh_processes_button.clicked.connect(self.refresh_processes_requested)
        top_bar_layout.addWidget(self.back_to_devices_button)
        top_bar_layout.addStretch(1)
        top_bar_layout.addWidget(self.refresh_processes_button)
        layout.addLayout(top_bar_layout)

        # 2. Process Table
        self.process_table = TableWidget(self)
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["App Name", "Package", "Version", "PID", "Status"])
        # Configure table properties like in stage1
        self.process_table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self.process_table.setSelectionMode(TableWidget.SelectionMode.SingleSelection)
        self.process_table.itemSelectionChanged.connect(self._on_process_selection_changed)
        self.process_table.setBorderVisible(True)
        self.process_table.setBorderRadius(8)
        self.process_table.setWordWrap(False)
        
        # Set row height constraints
        process_vertical_header = self.process_table.verticalHeader()
        if process_vertical_header is not None:
            process_vertical_header.setMinimumSectionSize(30)
            process_vertical_header.setDefaultSectionSize(40)
            process_vertical_header.setMaximumSectionSize(50)
            process_vertical_header.hide()
        
        # Set stretch mode for columns
        process_header = self.process_table.horizontalHeader()
        if process_header is not None:
            process_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # App Name
            process_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # Package
            process_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Version
            process_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # PID
            process_header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Status
        
        layout.addWidget(self.process_table)

        # 3. Bottom Bar
        bottom_bar_layout = QHBoxLayout()
        bottom_bar_layout.addStretch(1)
        self.activate_hook_button = PushButton(FluentIcon.PLAY_SOLID, "Activate Hook")
        self.activate_hook_button.setEnabled(False)
        self.activate_hook_button.clicked.connect(self.activate_hook_requested)
        bottom_bar_layout.addWidget(self.activate_hook_button)
        layout.addLayout(bottom_bar_layout)
        
        return widget

    def _create_activation_stage(self) -> QWidget:
        """Create the hook activation stage widget"""
        widget = QWidget()
        self.main_layout = QVBoxLayout(widget)
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.activation_title = BodyLabel("Activating Hook...")
        self.activation_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.main_layout.addWidget(self.activation_title)

        # Create a dictionary to hold the UI elements for each step
        self.activation_steps = {}

        steps_to_create = {
            "checking_frida": "Checking Frida Server...",
            "validating_hook": "Validating Hook Script...",
            "attaching": "Attaching to Process..."
        }

        for name, text in steps_to_create.items():
            step_layout = QHBoxLayout()
            step_layout.setSpacing(15)
            
            icon = ProgressRing()
            icon.setFixedSize(20, 20)
            
            label = BodyLabel(text)
            
            step_layout.addWidget(icon)
            step_layout.addWidget(label)
            step_layout.addStretch(1)
            
            self.main_layout.addLayout(step_layout)
            self.activation_steps[name] = {'icon': icon, 'label': label, 'layout': step_layout}

        self.cancel_button = PushButton("Cancel")
        self.cancel_button.clicked.connect(lambda: self.back_to_stage_requested.emit(1))
        self.main_layout.addWidget(self.cancel_button, 0, Qt.AlignmentFlag.AlignCenter)

        return widget

    def _create_hook_active_stage(self) -> QWidget:
        """Create the hook active stage widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)

        # Using CardWidget for a nice container
        card = QGroupBox("Hook Active", self)
        card_layout = QVBoxLayout(card)

        # Icon and Title
        title_layout = QHBoxLayout()
        icon_label = QLabel()
        # Note: FluentIcon isn't a widget. You'd typically set it on a button or use a QPixmap.
        # For simplicity, we use a text-based icon.
        icon_label.setText("✅") 
        icon_label.setStyleSheet("font-size: 24px;")
        title_label = BodyLabel("Connection Established")
        title_layout.addWidget(icon_label)
        title_layout.addWidget(title_label)
        card_layout.addLayout(title_layout)

        # Details
        self.active_device_label = BodyLabel("Device: N/A")
        self.active_process_label = BodyLabel("Process: N/A")
        card_layout.addWidget(self.active_device_label)
        card_layout.addWidget(self.active_process_label)

        # Disconnect Button
        self.disconnect_button = PushButton(FluentIcon.CANCEL, "Disconnect")
        self.disconnect_button.clicked.connect(lambda: self.back_to_stage_requested.emit(0))
        card_layout.addWidget(self.disconnect_button, 0, Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(card)
        return widget

    # Reactive slots for state changes
    def _on_emulator_connection_changed(self, is_connected: bool):
        """Handle emulator connection state changes from SessionManager"""
        print(f"[DEBUG] _on_emulator_connection_changed called with is_connected: {is_connected}")
        if is_connected:
            # Device connected - go to process selection stage
            print(f"[DEBUG] Setting stage to 1 (process selection)")
            self.set_stage(1)
        else:
            # Device disconnected - go back to device list
            print(f"[DEBUG] Setting stage to 0 (device list)")
            self.set_stage(0)
            
    def _on_hook_state_changed(self, is_active: bool):
        """Handle hook activation state changes from SessionManager"""
        if is_active:
            # Hook is active - go to hook active stage
            self.set_stage(3)
            self.update_hook_active_view()
        # If hook becomes inactive, emulator disconnection will handle stage transition
            


    def _update_all_views(self):
        """A single method to call all individual update methods."""
        self.update_device_table(self.session_manager.available_emulators)
        self.update_process_table(self.session_manager.available_processes)
        self.update_activation_view()
        self.update_hook_active_view()

    def update_process_table(self, processes: list):
        """Update the process table with compatibility checking"""
        if not hasattr(self, 'process_table'):
            return  # Process table not created yet
            
        self.process_table.setRowCount(len(processes))
        for row, process in enumerate(processes):
            # Pre-check compatibility
            package = process.get('package', '')
            version = process.get('version', '')
            
            # For compatibility checking, we'll rely on the MainController to handle this
            # The UI will show all processes and the controller will validate compatibility
            # when a process is selected
            is_compatible = True  # Assume compatible initially
            
            # Create items
            name_item = QTableWidgetItem(process.get('name', 'N/A'))
            package_item = QTableWidgetItem(package)
            version_item = QTableWidgetItem(version)
            pid_item = QTableWidgetItem(str(process.get('pid', 'N/A')))
            
            is_running = process.get('is_running', False)
            status_text = "Running" if is_running else "Not Running"
            if not is_compatible:
                status_text += " (Incompatible)"
            status_item = QTableWidgetItem(status_text)
            
            # Visually disable incompatible rows
            if not is_compatible or not is_running:
                for item in [name_item, package_item, version_item, pid_item, status_item]:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)  # Disable selection
                    item.setForeground(QColor("gray"))

            # Store full process info in the first item for retrieval
            name_item.setData(Qt.ItemDataRole.UserRole, process)

            # Set items in table
            self.process_table.setItem(row, 0, name_item)
            self.process_table.setItem(row, 1, package_item)
            self.process_table.setItem(row, 2, version_item)
            self.process_table.setItem(row, 3, pid_item)
            self.process_table.setItem(row, 4, status_item)
        
        self.process_table.resizeColumnsToContents()
    
    def _on_process_selection_changed(self):
        """Handle process selection changes"""
        if not hasattr(self, 'process_table') or not hasattr(self, 'activate_hook_button'):
            return
            
        selected_items = self.process_table.selectedItems()
        is_selection_valid = bool(selected_items)
        self.activate_hook_button.setEnabled(is_selection_valid)
        
        if is_selection_valid:
            # On valid selection, emit the signal to inform the controller
            first_item = self.process_table.item(selected_items[0].row(), 0)
            if first_item is not None:
                process_data = first_item.data(Qt.ItemDataRole.UserRole)
                self.select_process_requested.emit(process_data)

    def update_activation_view(self):
        """
        Update the activation view based on current stage and message.
        This method is called reactively when hook_activation_stage or hook_activation_message changes.
        """
        if not hasattr(self, 'session_manager'):
            return
            
        stage = self.session_manager.hook_activation_stage
        message = self.session_manager.hook_activation_message

        # Set the main title/error message
        if hasattr(self, 'activation_title'):
            self.activation_title.setText(message or f"Activating Hook (Stage: {stage})...")

        # Define stage progression
        pipeline = ["checking_frida", "validating_hook", "attaching"]
        
        try:
            current_stage_index = pipeline.index(stage)
        except ValueError:
            current_stage_index = -1  # For 'idle', 'failed', 'success'

        # Update each step's UI based on the current stage
        for i, step_name in enumerate(pipeline):
            if step_name not in self.activation_steps:
                continue
                
            step_ui = self.activation_steps[step_name]
            icon = step_ui['icon']
            label = step_ui['label']
            
            if stage == "failed":
                # Make all icons hidden after failure
                icon.hide()
                label.setText(f"❌ {step_name.replace('_', ' ').title()}")
            elif i < current_stage_index:
                # Completed step
                icon.hide()
                label.setText(f"✅ {step_name.replace('_', ' ').title()}")
            elif i == current_stage_index:
                # Current step - show the spinner
                icon.show()
                label.setText(f"➡️ {step_name.replace('_', ' ').title()}")
            else:
                # Future step
                icon.hide()
                label.setText(f"⏳ {step_name.replace('_', ' ').title()}")
                
        if hasattr(self, 'cancel_button'):
            if stage == "failed":
                self.cancel_button.setText("Go Back")
                # Show error info bar
                try:
                    InfoBar.error("Activation Failed", message, duration=5000, parent=self)
                except Exception:
                    pass  # InfoBar creation might fail in some contexts
            elif stage == "idle":
                self.cancel_button.setText("Cancel")
            elif stage == "success":
                # Show success info bar
                try:
                    InfoBar.success("Success!", "Hook activated successfully.", duration=3000, parent=self)
                except Exception:
                    pass  # InfoBar creation might fail in some contexts

    def update_hook_active_view(self):
        """Update the hook active view with current connection details"""
        if not hasattr(self, 'active_device_label') or not hasattr(self, 'active_process_label'):
            return  # Hook active UI not created yet
            
        device_serial = self.session_manager.connected_emulator_serial
        package = self.session_manager.selected_target_package
        pid = self.session_manager.selected_target_pid
        
        self.active_device_label.setText(f"Device: {device_serial or 'N/A'}")
        self.active_process_label.setText(f"Process: {package or 'N/A'} (PID: {pid or 'N/A'})")

    def _on_refresh_clicked(self):
        self.scan_devices_requested.emit()

    def trigger_device_scan(self):
        self.scan_devices_requested.emit()

    def set_stage(self, stage_index):
        if 0 <= stage_index < self.stacked.count():
            self.stacked.setCurrentIndex(stage_index)

    def update_device_table(self, emulators):
        self.device_table.setRowCount(len(emulators))
        for row, emulator in enumerate(emulators):
            serial = emulator.get('serial', '')
            model = emulator.get('model', '')
            status = emulator.get('status', '')
            
            # Create items with proper alignment
            serial_item = QTableWidgetItem(str(serial))
            serial_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            
            model_item = QTableWidgetItem(str(model))
            model_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            
            status_item = QTableWidgetItem(str(status))
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
            
            self.device_table.setItem(row, 0, serial_item)
            self.device_table.setItem(row, 1, model_item)
            self.device_table.setItem(row, 2, status_item)
        
        self.device_table.resizeRowsToContents()
        header = self.device_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(False)

    def update_theme_styles(self):
        color = get_text_color()
        font = get_title_font()
        # Only update stage1_label since it still exists
        if hasattr(self, 'stage1_label'):
            self.stage1_label.setFont(font)
            self.stage1_label.setStyleSheet(f"color: {color};")
        if hasattr(self, 'device_table'):
            self.device_table.setStyleSheet(f"color: {color}; background: transparent;")
        self.setStyleSheet(f"background: transparent;")

    def stop_scanning(self):
        # TODO: Implement scanning animation stop logic
        pass

    def show_error(self, msg: str):
        # TODO: Implement error display logic (e.g., show a message box or set a label)
        print(f"[ConnectionPanel ERROR] {msg}")

    def show_success(self, msg: str):
        # TODO: Implement success display logic (e.g., show a message box or set a label)
        print(f"[ConnectionPanel SUCCESS] {msg}")

    def update_state(self, session):
        # TODO: Implement state update logic for the panel
        pass

    def _on_connect_clicked(self):
        """Handle connect button click"""
        print(f"[DEBUG] Connect button clicked")
        selected_rows = self.device_table.selectedItems()
        if selected_rows:
            row = selected_rows[0].row()
            item = self.device_table.item(row, 0)
            if item:
                serial = item.text()
                print(f"[DEBUG] Emitting connect_device_requested signal for device: {serial}")
                self.connect_device_requested.emit(serial)
        else:
            print(f"[DEBUG] No device selected when connect button clicked")

    def _on_table_selection_changed(self):
        """Enable/disable connect button based on table selection"""
        self.connect_button.setEnabled(bool(self.device_table.selectedItems()))

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
        self.auto_connect_switch.setChecked(auto_connect)
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