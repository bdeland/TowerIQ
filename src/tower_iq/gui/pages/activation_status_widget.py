"""
TowerIQ Activation Status Widget

This module provides the ActivationStatusWidget for displaying hook activation progress
and status in the TowerIQ application.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGroupBox
from qfluentwidgets import BodyLabel, PushButton
from PyQt6.QtCore import Qt, pyqtSignal


class ActivationStatusWidget(QGroupBox):
    """Widget for displaying hook activation status and progress."""
    
    # Signals for button actions
    cancel_clicked = pyqtSignal()
    retry_clicked = pyqtSignal()
    
    def __init__(self, parent: QWidget | None = None):
        super().__init__("Activation", parent)
        self._setup_ui()

    def _setup_ui(self):
        """Setup the activation status UI."""
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setSpacing(12)

        # Title section
        title_layout = QVBoxLayout()
        title_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.activation_title = BodyLabel("Ready to Connect")
        self.activation_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.activation_title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        title_layout.addWidget(self.activation_title)
        
        self.activation_subtitle = BodyLabel("Select a device and process to begin")
        self.activation_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.activation_subtitle.setStyleSheet("color: gray; margin-bottom: 20px;")
        title_layout.addWidget(self.activation_subtitle)
        
        layout.addLayout(title_layout)

        # Action buttons section
        button_layout = QHBoxLayout()
        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        button_layout.setSpacing(10)
        
        self.cancel_button = PushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_clicked)
        self.cancel_button.setVisible(False)  # Hidden by default
        button_layout.addWidget(self.cancel_button)
        
        self.retry_button = PushButton("Retry")
        self.retry_button.setVisible(False)  # Hidden by default, shown on failure
        self.retry_button.clicked.connect(self.retry_clicked)
        button_layout.addWidget(self.retry_button)
        
        layout.addLayout(button_layout)

    def update_view(self, stage: str, message: str):
        """Updates the activation section UI based on session state."""
        # Update title and subtitle
        if message:
            self.activation_title.setText(message)
        else:
            self.activation_title.setText("Establishing Connection...")
        
        # Update button states based on stage
        if stage == "failed":
            self.cancel_button.setText("Go Back")
            self.cancel_button.setVisible(True)
            self.retry_button.setVisible(True)
        elif stage in ["success", "completed"]:
            self.cancel_button.setText("Disconnect")
            self.cancel_button.setVisible(True)
            self.retry_button.setVisible(False)
        else:
            self.cancel_button.setText("Cancel")
            self.cancel_button.setVisible(True)
            self.retry_button.setVisible(False) 