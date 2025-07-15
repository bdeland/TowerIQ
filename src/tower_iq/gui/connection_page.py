from .utils_gui import ThemeAwareWidget, get_text_color, get_title_font
from PyQt6.QtWidgets import (
    QHBoxLayout, QVBoxLayout, QLabel, QStackedWidget, QPushButton, QWidget, 
    QGroupBox, QTextEdit, QFrame, QHeaderView, QTableWidgetItem
)
from qfluentwidgets import SwitchButton, FluentIcon, PushButton, TableWidget, TableItemDelegate, isDarkTheme
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

        # Stage 1: Device Discovery
        self.stage1 = QWidget()
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
        self.stage1.setLayout(s1_layout)

        # Stage 2: Device Information
        self.stage2 = QWidget()
        s2_layout = QVBoxLayout()
        self.stage2_label = QLabel("Stage 2: Device Information")
        s2_layout.addWidget(self.stage2_label)
        self.stage2.setLayout(s2_layout)

        # Stage 3: Frida Setup
        self.stage3 = QWidget()
        s3_layout = QVBoxLayout()
        self.stage3_label = QLabel("Stage 3: Frida Setup")
        s3_layout.addWidget(self.stage3_label)
        self.stage3.setLayout(s3_layout)

        # Stage 4: Process Selection & Hook Activation
        self.stage4 = QWidget()
        s4_layout = QVBoxLayout()
        self.stage4_label = QLabel("Stage 4: Process Selection & Hook Activation")
        s4_layout.addWidget(self.stage4_label)
        self.stage4.setLayout(s4_layout)

        self.stacked.addWidget(self.stage1)
        self.stacked.addWidget(self.stage2)
        self.stacked.addWidget(self.stage3)
        self.stacked.addWidget(self.stage4)

        layout.addWidget(self.stacked)
        self.setLayout(layout)
        self.update_theme_styles()

        # Connect to session_manager signal
        self.session_manager.available_emulators_changed.connect(self.update_device_table)
        self.update_device_table(self.session_manager.available_emulators)

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
        for label in [self.stage1_label, self.stage2_label, self.stage3_label, self.stage4_label]:
            label.setFont(font)
            label.setStyleSheet(f"color: {color};")
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
        selected_rows = self.device_table.selectedItems()
        if selected_rows:
            row = selected_rows[0].row()
            item = self.device_table.item(row, 0)
            if item:
                serial = item.text()
                self.connect_device_requested.emit(serial)

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