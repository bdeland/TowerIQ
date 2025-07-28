"""
TowerIQ Advanced Settings Page

This module provides the advanced settings content.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QScrollArea
from qfluentwidgets import BodyLabel


class AdvancedSettingsPage(QWidget):
    """Advanced Settings content page."""
    
    def __init__(self, config_manager=None, parent: QWidget | None = None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the advanced settings user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Create scrollable content area
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("border: 0px transparent;")

        content_widget = QWidget()
        content_widget.setObjectName("content_widget")
        content_widget.setStyleSheet("border: 0px transparent; background-color: transparent;")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        # Add settings content
        self.setup_content(content_layout)
        
        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)
        
    def setup_content(self, content_layout: QVBoxLayout):
        """Set up the advanced settings content."""
        placeholder = BodyLabel("Advanced settings will be implemented here.", self)
        content_layout.addWidget(placeholder) 