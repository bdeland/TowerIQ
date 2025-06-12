"""
TowerIQ Connection State Panel

This module provides the ConnectionStatePanel widget that implements a stateful,
multi-stage connection panel with intelligent filtering and manual user confirmation.
"""

from typing import Dict, List, Any, Optional

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot, Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QListWidget, QListWidgetItem, QFrame, QProgressBar, QTextEdit, QSizePolicy
)
from PyQt6.QtGui import QFont, QPalette, QColor

from ...core.session import SessionManager


class ConnectionStatePanel(QWidget):
    """
    Interactive connection panel that guides users through device connection,
    process selection, and hook activation with manual confirmation at each step.
    """
    
    # Signals for communicating with the main controller
    scan_devices_requested = pyqtSignal()
    connect_device_requested = pyqtSignal(str)  # device_id
    refresh_processes_requested = pyqtSignal()
    select_process_requested = pyqtSignal(dict)  # process_info
    activate_hook_requested = pyqtSignal()
    back_to_stage_requested = pyqtSignal(int)  # stage_number
    
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        """Initialize the connection state panel."""
        super().__init__(parent)
        
        self.current_stage = 1
        self.selected_device_id: Optional[str] = None
        self.selected_device_data: Optional[Dict[str, Any]] = None
        self.selected_process_info: Optional[Dict[str, Any]] = None
        
        # Animation timer for scanning feedback
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self._update_scanning_animation)
        self.animation_dots = 0
        self.original_scan_text = "Scan for Devices"
        
        # Safety timeout to prevent infinite scanning animation
        self.safety_timer = QTimer()
        self.safety_timer.setSingleShot(True)
        self.safety_timer.timeout.connect(self._on_scanning_timeout)
        
        self._setup_ui()
        self._setup_styles()
    
    def _setup_ui(self) -> None:
        """Set up the user interface."""
        # Define fixed content area size
        content_width = 500
        content_height = 280
        
        # Calculate container size with padding
        container_padding = 40  # 20px on each side
        title_and_progress_height = 80
        navigation_height = 50
        
        total_width = content_width + container_padding
        total_height = content_height + title_and_progress_height + navigation_height + container_padding
        
        self.setFixedSize(total_width, total_height)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        
        # Main container with padding
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(0)
        
        # Connection setup container box
        self.setup_container = QFrame()
        self.setup_container.setObjectName("setupContainer")
        container_layout = QVBoxLayout(self.setup_container)
        container_layout.setContentsMargins(20, 20, 20, 20)
        container_layout.setSpacing(12)
        
        # Title
        title_label = QLabel("TowerIQ Connection Setup")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(title_label)
        
        # Progress indicator with boxes and arrows
        self._create_progress_indicator()
        container_layout.addWidget(self.progress_frame)
        
        # Content area with fixed size
        self.content_frame = QFrame()
        self.content_frame.setFixedSize(content_width, content_height)
        self.content_layout = QVBoxLayout(self.content_frame)
        self.content_layout.setContentsMargins(15, 15, 15, 15)
        
        # Stage 1: Device Selection
        self.stage1_widget = self._create_stage1_widget()
        self.content_layout.addWidget(self.stage1_widget)
        
        # Stage 2: Process Selection
        self.stage2_widget = self._create_stage2_widget()
        self.content_layout.addWidget(self.stage2_widget)
        self.stage2_widget.hide()
        
        # Stage 3: Hook Activation
        self.stage3_widget = self._create_stage3_widget()
        self.content_layout.addWidget(self.stage3_widget)
        self.stage3_widget.hide()
        
        container_layout.addWidget(self.content_frame)
        
        # Bottom navigation buttons
        nav_frame = QFrame()
        nav_layout = QHBoxLayout(nav_frame)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self._on_back_button)
        self.back_button.setVisible(False)  # Hidden on first stage
        nav_layout.addWidget(self.back_button)
        
        nav_layout.addStretch()  # Space between buttons
        
        self.next_button = QPushButton("Next")
        self.next_button.clicked.connect(self._on_next_button)
        self.next_button.setEnabled(False)  # Disabled until selection made
        nav_layout.addWidget(self.next_button)
        
        container_layout.addWidget(nav_frame)
        
        main_layout.addWidget(self.setup_container)
        
        # Update the initial stage
        self._update_stage_indicator()
        self._update_navigation_buttons()
    
    def _create_progress_indicator(self) -> None:
        """Create the progress indicator with boxes and arrows."""
        self.progress_frame = QFrame()
        progress_layout = QHBoxLayout(self.progress_frame)
        progress_layout.setContentsMargins(0, 10, 0, 10)
        progress_layout.setSpacing(15)
        
        self.stage_boxes = []
        stages = ["1. Device", "2. Process", "3. Activate"]
        
        for i, stage_text in enumerate(stages):
            # Create stage box
            stage_box = QFrame()
            stage_box.setObjectName(f"stageBox{i+1}")
            stage_box.setFixedSize(110, 35)
            
            box_layout = QHBoxLayout(stage_box)
            box_layout.setContentsMargins(5, 5, 5, 5)
            
            label = QLabel(stage_text)
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label.setObjectName(f"stageLabel{i+1}")
            box_layout.addWidget(label)
            
            self.stage_boxes.append(stage_box)
            progress_layout.addWidget(stage_box)
            
            # Add arrow between stages (except after the last one)
            if i < len(stages) - 1:
                arrow_label = QLabel("→")
                arrow_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                arrow_label.setStyleSheet("color: #4CAF50; font-size: 16px; font-weight: bold;")
                progress_layout.addWidget(arrow_label)
    
    def _create_stage1_widget(self) -> QWidget:
        """Create Stage 1: Device Selection widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stage title
        stage_title = QLabel("Step 1: Select Android Device")
        stage_title.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 10px;")
        layout.addWidget(stage_title)
        
        # Instruction
        instruction = QLabel("Scan for connected Android devices and select one to continue.")
        instruction.setWordWrap(True)
        layout.addWidget(instruction)
        
        # Scan button
        self.scan_button = QPushButton("Scan for Devices")
        self.scan_button.clicked.connect(self._on_scan_devices)
        layout.addWidget(self.scan_button)
        
        # Device list
        self.device_list = QListWidget()
        self.device_list.setFixedHeight(120)
        self.device_list.itemClicked.connect(self._on_device_item_clicked)
        layout.addWidget(self.device_list)
        
        return widget
    
    def _create_stage2_widget(self) -> QWidget:
        """Create Stage 2: Process Selection widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stage title
        stage_title = QLabel("Step 2: Select Target Process")
        stage_title.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 10px;")
        layout.addWidget(stage_title)
        
        # Device info
        self.device_info_label = QLabel()
        self.device_info_label.setStyleSheet("color: #666; margin-bottom: 10px;")
        layout.addWidget(self.device_info_label)
        
        # Instruction
        instruction = QLabel("Select the running game process you want to monitor:")
        instruction.setWordWrap(True)
        layout.addWidget(instruction)
        
        # Refresh button
        self.refresh_button = QPushButton("Refresh Process List")
        self.refresh_button.clicked.connect(self._on_refresh_processes)
        layout.addWidget(self.refresh_button)
        
        # Process list
        self.process_list = QListWidget()
        self.process_list.setFixedHeight(140)
        self.process_list.itemClicked.connect(self._on_process_item_clicked)
        layout.addWidget(self.process_list)
        
        return widget
    
    def _create_stage3_widget(self) -> QWidget:
        """Create Stage 3: Hook Activation widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stage title
        stage_title = QLabel("Step 3: Activate Hook")
        stage_title.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 10px;")
        layout.addWidget(stage_title)
        
        # Target info
        self.target_info_label = QLabel()
        self.target_info_label.setStyleSheet("color: #666; margin-bottom: 10px;")
        layout.addWidget(self.target_info_label)
        
        # Compatibility status
        self.compatibility_label = QLabel()
        layout.addWidget(self.compatibility_label)
        
        # Status text area
        self.status_text = QTextEdit()
        self.status_text.setFixedHeight(80)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
        return widget
    
    def _setup_styles(self) -> None:
        """Set up the visual styles for the panel."""
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QFrame#setupContainer {
                background-color: #3a3a3a;
                border: 2px solid #555555;
                border-radius: 12px;
            }
            QFrame[objectName^="stageBox"] {
                background-color: #555555;
                border: 2px solid #666666;
                border-radius: 6px;
            }
            QFrame#stageBox1[current="true"] {
                background-color: #4CAF50;
                border-color: #4CAF50;
            }
            QFrame#stageBox2[current="true"] {
                background-color: #4CAF50;
                border-color: #4CAF50;
            }
            QFrame#stageBox3[current="true"] {
                background-color: #4CAF50;
                border-color: #4CAF50;
            }
            QLabel[objectName^="stageLabel"] {
                color: #ffffff;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
            }
            QLabel {
                color: #ffffff;
                background-color: transparent;
            }
            QListWidget {
                border: 1px solid #555555;
                border-radius: 6px;
                background-color: #2b2b2b;
                color: #ffffff;
                padding: 5px;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #444444;
                border-radius: 4px;
                margin: 2px;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #4a4a4a;
            }
            QTextEdit {
                border: 1px solid #555555;
                border-radius: 6px;
                background-color: #2b2b2b;
                color: #ffffff;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                padding: 8px;
            }
            QFrame {
                background-color: transparent;
            }
        """)
    
    def _update_stage_indicator(self) -> None:
        """Update the visual stage indicator."""
        for i, box in enumerate(self.stage_boxes, 1):
            if i == self.current_stage:
                box.setProperty("current", "true")
            else:
                box.setProperty("current", "false")
            box.style().unpolish(box)
            box.style().polish(box)
    
    def _update_navigation_buttons(self) -> None:
        """Update the navigation button states."""
        # Back button visibility
        self.back_button.setVisible(self.current_stage > 1)
        
        # Next button state and text
        if self.current_stage == 1:
            self.next_button.setText("Next")
            self.next_button.setEnabled(self.selected_device_data is not None)
        elif self.current_stage == 2:
            self.next_button.setText("Next")
            self.next_button.setEnabled(self.selected_process_info is not None)
        elif self.current_stage == 3:
            self.next_button.setText("Activate")
            # Enable based on compatibility in stage 3
            self.next_button.setEnabled(True)  # Will be updated by update_state
    
    def _show_stage(self, stage: int) -> None:
        """Show the specified stage and hide others."""
        self.current_stage = stage
        
        # Hide all stages
        self.stage1_widget.hide()
        self.stage2_widget.hide()
        self.stage3_widget.hide()
        
        # Show the current stage
        if stage == 1:
            self.stage1_widget.show()
        elif stage == 2:
            self.stage2_widget.show()
        elif stage == 3:
            self.stage3_widget.show()
        
        self._update_stage_indicator()
        self._update_navigation_buttons()
    
    @pyqtSlot()
    def _on_scan_devices(self) -> None:
        """Handle the scan devices button click."""
        self.scan_button.setEnabled(False)
        self.device_list.clear()
        self.selected_device_data = None
        
        # Start scanning animation
        self.animation_dots = 0
        self.animation_timer.start(500)  # Update every 500ms
        
        # Start safety timeout (15 seconds)
        self.safety_timer.start(15000)
        
        # Add a temporary status message
        if hasattr(self, 'status_text') and self.status_text.isVisible():
            self.status_text.setText("Scanning for connected devices... This may take a few seconds.")
        
        self._update_navigation_buttons()
        self.scan_devices_requested.emit()
    
    def _update_scanning_animation(self) -> None:
        """Update the scanning animation dots."""
        self.animation_dots = (self.animation_dots + 1) % 4
        dots = "." * self.animation_dots
        self.scan_button.setText(f"Scanning{dots}")
    
    def _stop_scanning_animation(self) -> None:
        """Stop the scanning animation and reset button text."""
        self.animation_timer.stop()
        self.safety_timer.stop()
        self.scan_button.setText(self.original_scan_text)
        self.scan_button.setEnabled(True)
    
    def _on_scanning_timeout(self) -> None:
        """Handle scanning timeout - force stop animation and show error."""
        self._stop_scanning_animation()
        if hasattr(self, 'status_text') and self.status_text.isVisible():
            self.status_text.setText("Error: Device scanning timed out. ADB may be unresponsive.")
    
    @pyqtSlot(QListWidgetItem)
    def _on_device_item_clicked(self, item: QListWidgetItem) -> None:
        """Handle device item click (selection only, no auto-advance)."""
        device_data = item.data(Qt.ItemDataRole.UserRole)
        if device_data:
            self.selected_device_data = device_data
            self.selected_device_id = device_data['serial']
            self._update_navigation_buttons()
    
    @pyqtSlot()
    def _on_refresh_processes(self) -> None:
        """Handle the refresh processes button click."""
        self.refresh_button.setText("Refreshing...")
        self.refresh_button.setEnabled(False)
        self.process_list.clear()
        self.selected_process_info = None
        self._update_navigation_buttons()
        self.refresh_processes_requested.emit()
    
    @pyqtSlot(QListWidgetItem)
    def _on_process_item_clicked(self, item: QListWidgetItem) -> None:
        """Handle process item click (selection only, no auto-advance)."""
        process_data = item.data(Qt.ItemDataRole.UserRole)
        if process_data:
            self.selected_process_info = process_data
            self._update_navigation_buttons()
    
    @pyqtSlot()
    def _on_next_button(self) -> None:
        """Handle the next button click."""
        if self.current_stage == 1:
            # Connect to selected device and move to stage 2
            if self.selected_device_data:
                self.connect_device_requested.emit(self.selected_device_id)
                self._show_stage(2)
                self.device_info_label.setText(f"Connected to: {self.selected_device_id}")
        elif self.current_stage == 2:
            # Select process and move to stage 3
            if self.selected_process_info:
                self.select_process_requested.emit(self.selected_process_info)
                self._show_stage(3)
        elif self.current_stage == 3:
            # Activate hook
            self.next_button.setText("Activating...")
            self.next_button.setEnabled(False)
            self.activate_hook_requested.emit()
    
    @pyqtSlot()
    def _on_back_button(self) -> None:
        """Handle the back button click."""
        if self.current_stage > 1:
            # Clear relevant state when going back
            if self.current_stage == 3:
                # Going back from stage 3 to 2
                self._show_stage(2)
            elif self.current_stage == 2:
                # Going back from stage 2 to 1, clear device selection
                self.selected_device_id = None
                self.selected_device_data = None
                self.process_list.clear()
                self.selected_process_info = None
                self._show_stage(1)
            self.back_to_stage_requested.emit(self.current_stage)
    
    def update_state(self, session: SessionManager) -> None:
        """
        Update the panel state based on the current session.
        
        Args:
            session: SessionManager instance with current state
        """
        # Update device list - ALWAYS call this if available_emulators is set (even if empty)
        available_emulators = session.available_emulators
        if available_emulators is not None:  # Changed from "if available_emulators:" to handle empty lists
            self._populate_device_list(available_emulators)
        
        # Update process list if we have available processes
        available_processes = session.available_processes
        if available_processes:
            self._populate_process_list(available_processes)
        
        # Update stage 3 if we're there
        if (self.current_stage == 3 and 
            session.selected_target_package and 
            session.selected_target_version):
            self._update_stage3_info(session)
    
    def _populate_device_list(self, devices: List[Dict[str, Any]]) -> None:
        """Populate the device list with available devices."""
        self.device_list.clear()
        self._stop_scanning_animation()
        
        if not devices:
            # Add a message item if no devices found
            item = QListWidgetItem()
            item.setText("No devices found - click 'Scan for Devices' to try again")
            item.setData(Qt.ItemDataRole.UserRole, None)
            item.setData(Qt.ItemDataRole.ForegroundRole, QColor("#888888"))
            item.setFlags(Qt.ItemFlag.NoItemFlags)  # Make it non-selectable
            self.device_list.addItem(item)
            
            # Update status message
            if hasattr(self, 'status_text') and self.status_text.isVisible():
                self.status_text.setText("No devices found. Make sure ADB is running and devices are connected.")
        else:
            for device in devices:
                item = QListWidgetItem()
                item.setText(f"{device['name']} ({device['serial']})")
                item.setData(Qt.ItemDataRole.UserRole, device)
                self.device_list.addItem(item)
            
            # Clear status message when devices are found
            if hasattr(self, 'status_text') and self.status_text.isVisible():
                self.status_text.setText("Select a device to connect to.")
        
        self._update_navigation_buttons()
    
    def _populate_process_list(self, processes: List[Dict[str, Any]]) -> None:
        """Populate the process list with available running processes only."""
        self.process_list.clear()
        self.refresh_button.setText("Refresh Process List")
        self.refresh_button.setEnabled(True)
        
        # Filter to only show running processes
        running_processes = [process for process in processes if process['is_running']]
        
        if not running_processes:
            # Add a message item if no running processes found
            item = QListWidgetItem()
            item.setText("No running third-party apps found")
            item.setData(Qt.ItemDataRole.UserRole, None)
            item.setData(Qt.ItemDataRole.ForegroundRole, QColor("#888888"))
            item.setFlags(Qt.ItemFlag.NoItemFlags)  # Make it non-selectable
            self.process_list.addItem(item)
        else:
            for process in running_processes:
                item = QListWidgetItem()
                # Since we're only showing running processes, we can simplify the display
                item.setText(f"{process['name']} (v{process['version']})")
                item.setData(Qt.ItemDataRole.UserRole, process)
                
                # Add visual indication for the running process
                item.setData(Qt.ItemDataRole.BackgroundRole, QColor("#2d5a2d"))
                
                self.process_list.addItem(item)
        
        self._update_navigation_buttons()
    
    def _update_stage3_info(self, session: SessionManager) -> None:
        """Update Stage 3 with target and compatibility information."""
        self.target_info_label.setText(
            f"Target: {session.selected_target_package} "
            f"(v{session.selected_target_version}, PID: {session.selected_target_pid})"
        )
        
        if session.is_hook_compatible:
            self.compatibility_label.setText("✓ Hook compatible")
            self.compatibility_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
            self.next_button.setEnabled(True)
            self.status_text.setText("Ready to activate hook. Click 'Activate' to begin monitoring.")
        else:
            self.compatibility_label.setText("✗ Hook not compatible")
            self.compatibility_label.setStyleSheet("color: #f44336; font-weight: bold;")
            self.next_button.setEnabled(False)
            self.status_text.setText(
                "No compatible hook found for this game version. "
                "Hook activation is not available."
            )
    
    def show_error(self, message: str) -> None:
        """Show an error message in the status area."""
        if hasattr(self, 'status_text') and self.status_text.isVisible():
            self.status_text.setText(f"Error: {message}")
        
        # Stop animation and reset button states
        self._stop_scanning_animation()
        self.refresh_button.setText("Refresh Process List")
        self.refresh_button.setEnabled(True)
        self.next_button.setText("Activate" if self.current_stage == 3 else "Next")
        self._update_navigation_buttons()
    
    def show_success(self, message: str) -> None:
        """Show a success message and potentially hide the panel."""
        if hasattr(self, 'status_text') and self.status_text.isVisible():
            self.status_text.setText(f"Success: {message}")
    
    def stop_scanning(self) -> None:
        """Public method to stop scanning animation - can be called from MainController."""
        self._stop_scanning_animation() 