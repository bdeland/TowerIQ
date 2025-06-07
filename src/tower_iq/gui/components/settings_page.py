"""
TowerIQ v1.0 - Settings Page

This module defines the SettingsPage widget for configuring application settings.
"""

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea, 
    QFrame, QPushButton, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

if TYPE_CHECKING:
    from tower_iq.core.main_controller import MainController


class SettingsPage(QWidget):
    """
    A placeholder settings page for the TowerIQ application.
    
    This widget will eventually contain configuration options for the application,
    but for now serves as a placeholder in the main window's navigation.
    """
    
    def __init__(self, controller: "MainController") -> None:
        """
        Initialize the settings page.
        
        Args:
            controller: The main controller instance
        """
        super().__init__()
        
        self.controller = controller
        self._init_ui()
    
    def _init_ui(self) -> None:
        """Set up the settings page UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Page title
        title_label = QLabel("Settings")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #333; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        # Placeholder content
        content_frame = QFrame()
        content_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        content_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 20px;
            }
        """)
        
        content_layout = QVBoxLayout(content_frame)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        placeholder_label = QLabel("Settings Panel")
        placeholder_font = QFont()
        placeholder_font.setPointSize(16)
        placeholder_font.setBold(True)
        placeholder_label.setFont(placeholder_font)
        placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_label.setStyleSheet("color: #666; margin-bottom: 10px;")
        
        description_label = QLabel(
            "Configuration options will be available here in future updates.\n"
            "This will include settings for:\n\n"
            "• Game detection preferences\n"
            "• Data collection intervals\n"
            "• Alert thresholds\n"
            "• Export options\n"
            "• System preferences"
        )
        description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description_label.setStyleSheet("color: #888; line-height: 1.5;")
        description_label.setWordWrap(True)
        
        content_layout.addWidget(placeholder_label)
        content_layout.addWidget(description_label)
        
        layout.addWidget(content_frame)
        layout.addStretch()  # Push content to top 