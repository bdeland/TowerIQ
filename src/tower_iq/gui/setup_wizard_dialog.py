"""
TowerIQ v1.0 - Setup Wizard Dialog

This module defines the SetupWizardDialog, a modal dialog that guides the user
through the initial application setup with visual progress indicators.
"""

from typing import TYPE_CHECKING, Dict, Any

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QProgressBar, QTextEdit, QFrame, QMessageBox, QWidget
)
from PyQt6.QtCore import Qt, pyqtSlot, QTimer
from PyQt6.QtGui import QFont, QPixmap, QIcon

if TYPE_CHECKING:
    from tower_iq.core.main_controller import MainController


class SetupStepWidget(QFrame):
    """
    A widget representing a single setup step with status indication.
    """
    
    def __init__(self, step_name: str, step_description: str) -> None:
        """
        Initialize a setup step widget.
        
        Args:
            step_name: The name/title of the setup step
            step_description: A brief description of what this step does
        """
        super().__init__()
        self.step_name = step_name
        
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin: 2px;
                padding: 5px;
            }
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        
        # Status icon
        self.status_icon = QLabel("⏳")  # Default: waiting
        self.status_icon.setFixedSize(20, 20)
        self.status_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_icon)
        
        # Step info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        
        self.title_label = QLabel(step_name)
        title_font = QFont()
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        
        self.desc_label = QLabel(step_description)
        self.desc_label.setStyleSheet("color: #666; font-size: 11px;")
        
        info_layout.addWidget(self.title_label)
        info_layout.addWidget(self.desc_label)
        
        layout.addLayout(info_layout, 1)  # Stretch factor 1
    
    def set_status(self, status: str) -> None:
        """
        Update the status of this setup step.
        
        Args:
            status: One of 'waiting', 'running', 'success', 'error'
        """
        status_icons = {
            'waiting': '⏳',
            'running': '🔄',
            'success': '✅',
            'error': '❌'
        }
        
        status_colors = {
            'waiting': '#999',
            'running': '#2196F3',
            'success': '#4CAF50',
            'error': '#F44336'
        }
        
        icon = status_icons.get(status, '⏳')
        color = status_colors.get(status, '#999')
        
        self.status_icon.setText(icon)
        self.title_label.setStyleSheet(f"color: {color};")


class SetupWizardDialog(QDialog):
    """
    A modal dialog that guides the user through the initial application setup.
    
    Provides a step-by-step visual guide for the setup process orchestrated
    by the SetupService, with progress indicators and log display.
    """
    
    def __init__(self, controller: "MainController") -> None:
        """
        Initialize the setup wizard dialog.
        
        Args:
            controller: The main controller instance
        """
        super().__init__()
        self.controller = controller
        
        # Dialog properties
        self.setModal(True)
        self.setWindowTitle("TowerIQ Setup Wizard")
        self.setFixedSize(600, 500)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)
        
        # Setup state
        self.setup_running = False
        self.setup_steps: Dict[str, SetupStepWidget] = {}
        
        self._init_ui()
        self._connect_signals()
    
    def _init_ui(self) -> None:
        """
        Create the UI for the wizard.
        
        Sets up the layout with title, step indicators, progress display,
        and control buttons.
        """
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title and description
        title_label = QLabel("Welcome to TowerIQ Setup")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        desc_label = QLabel(
            "This wizard will guide you through setting up TowerIQ for first use.\n"
            "The setup process will check your system requirements and configure necessary services."
        )
        desc_label.setWordWrap(True)
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setStyleSheet("color: #666; margin-bottom: 10px;")
        
        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        
        # Setup steps container
        steps_frame = QFrame()
        steps_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        steps_frame.setStyleSheet("""
            QFrame {
                background-color: #f9f9f9;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
        """)
        
        steps_layout = QVBoxLayout(steps_frame)
        steps_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create step widgets based on expected setup steps
        setup_step_configs = [
            ("check_wsl", "Check WSL2 Installation", "Verify that WSL2 is properly installed and configured"),
            ("check_docker", "Check Docker Installation", "Ensure Docker Desktop is installed and running"),
            ("start_services", "Start Backend Services", "Initialize ClickHouse and other required services"),
            ("verify_connection", "Verify Connections", "Test connectivity to all backend services"),
            ("initialize_database", "Initialize Database", "Set up database schema and initial data")
        ]
        
        for step_id, step_name, step_desc in setup_step_configs:
            step_widget = SetupStepWidget(step_name, step_desc)
            self.setup_steps[step_id] = step_widget
            steps_layout.addWidget(step_widget)
        
        layout.addWidget(steps_frame)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, len(self.setup_steps))
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Progress log
        log_label = QLabel("Setup Progress:")
        log_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(log_label)
        
        self.progress_log = QTextEdit()
        self.progress_log.setMaximumHeight(100)
        self.progress_log.setReadOnly(True)
        self.progress_log.setStyleSheet("""
            QTextEdit {
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 10px;
            }
        """)
        layout.addWidget(self.progress_log)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.start_button = QPushButton("Start Setup")
        self.start_button.setMinimumWidth(120)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setMinimumWidth(120)
        
        self.finish_button = QPushButton("Finish")
        self.finish_button.setMinimumWidth(120)
        self.finish_button.setEnabled(False)
        self.finish_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.finish_button)
        
        layout.addLayout(button_layout)
    
    def _connect_signals(self) -> None:
        """
        Connect UI actions and controller signals.
        
        Sets up the communication between the dialog and the controller's
        setup service.
        """
        # Button connections
        self.start_button.clicked.connect(self.run_setup)
        self.cancel_button.clicked.connect(self.reject)
        self.finish_button.clicked.connect(self.accept)
        
        # Controller signal connections (these would be defined in MainController)
        # self.controller.setup_progress_updated.connect(self.on_progress_update)
        # self.controller.setup_step_status_changed.connect(self.on_step_status_change)
        # self.controller.setup_finished.connect(self.on_setup_finished)
    
    @pyqtSlot()
    def run_setup(self) -> None:
        """
        Start the setup process.
        
        Called when the user clicks "Start Setup". Disables the start button
        and initiates the asynchronous setup process.
        """
        if self.setup_running:
            return
        
        self.setup_running = True
        self.start_button.setEnabled(False)
        self.cancel_button.setText("Cancel Setup")
        
        self.progress_log.append("Starting TowerIQ setup process...")
        
        # Reset all steps to waiting state
        for step_widget in self.setup_steps.values():
            step_widget.set_status('waiting')
        
        self.progress_bar.setValue(0)
        
        # Start the setup process via the controller
        # Note: This would be an async call in the actual implementation
        # asyncio.create_task(self.controller.setup_service.run_initial_setup())
        
        # For now, simulate the setup process with a timer (for testing UI)
        self._simulate_setup_process()
    
    def _simulate_setup_process(self) -> None:
        """
        Simulate the setup process for testing purposes.
        
        This method simulates the setup steps with timers to test the UI.
        In the actual implementation, this would be replaced by real
        setup process signals from the controller.
        """
        self.current_step_index = 0
        self.step_names = list(self.setup_steps.keys())
        
        self.setup_timer = QTimer()
        self.setup_timer.timeout.connect(self._advance_simulation)
        self.setup_timer.start(2000)  # 2 seconds per step
    
    def _advance_simulation(self) -> None:
        """Advance the setup simulation to the next step."""
        if self.current_step_index < len(self.step_names):
            step_name = self.step_names[self.current_step_index]
            
            # Mark current step as running
            self.setup_steps[step_name].set_status('running')
            self.progress_log.append(f"Running: {self.setup_steps[step_name].step_name}")
            
            # Simulate completion after a short delay
            QTimer.singleShot(1500, lambda: self._complete_current_step())
        else:
            # All steps completed
            self.setup_timer.stop()
            self.on_setup_finished(True)
    
    def _complete_current_step(self) -> None:
        """Complete the current step in the simulation."""
        if self.current_step_index < len(self.step_names):
            step_name = self.step_names[self.current_step_index]
            
            # Mark step as successful
            self.setup_steps[step_name].set_status('success')
            self.progress_log.append(f"Completed: {self.setup_steps[step_name].step_name}")
            
            # Update progress
            self.progress_bar.setValue(self.current_step_index + 1)
            
            self.current_step_index += 1
    
    @pyqtSlot(str)
    def on_progress_update(self, message: str) -> None:
        """
        Update the progress log with a new message.
        
        Args:
            message: The progress message to display
        """
        self.progress_log.append(message)
        
        # Auto-scroll to bottom
        scrollbar = self.progress_log.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    @pyqtSlot(str, str)
    def on_step_status_change(self, step_name: str, status: str) -> None:
        """
        Update the status of a specific setup step.
        
        Args:
            step_name: The name of the step to update
            status: The new status ('waiting', 'running', 'success', 'error')
        """
        if step_name in self.setup_steps:
            self.setup_steps[step_name].set_status(status)
            
            # Update progress bar based on completed steps
            completed_steps = sum(1 for widget in self.setup_steps.values()
                                if widget.status_icon.text() == '✅')
            self.progress_bar.setValue(completed_steps)
    
    @pyqtSlot(bool)
    def on_setup_finished(self, success: bool) -> None:
        """
        Handle the completion of the setup process.
        
        Args:
            success: True if setup completed successfully, False if it failed
        """
        self.setup_running = False
        
        if success:
            self.progress_log.append("\n✅ Setup completed successfully!")
            self.progress_log.append("TowerIQ is ready to use.")
            
            self.start_button.setVisible(False)
            self.cancel_button.setText("Close")
            self.finish_button.setEnabled(True)
            
            self.progress_bar.setValue(len(self.setup_steps))
            
        else:
            self.progress_log.append("\n❌ Setup failed!")
            self.progress_log.append("Please check the errors above and try again.")
            
            # Show error message
            QMessageBox.critical(
                self,
                "Setup Failed",
                "The setup process encountered errors. Please check the log for details."
            )
            
            self.start_button.setEnabled(True)
            self.start_button.setText("Retry Setup")
    
    def closeEvent(self, event) -> None:
        """
        Handle the dialog close event.
        
        Prevents closing during setup unless the user confirms.
        
        Args:
            event: The close event
        """
        if self.setup_running:
            reply = QMessageBox.question(
                self,
                "Cancel Setup",
                "Setup is currently running. Are you sure you want to cancel?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                # Stop any running setup process
                if hasattr(self, 'setup_timer'):
                    self.setup_timer.stop()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept() 