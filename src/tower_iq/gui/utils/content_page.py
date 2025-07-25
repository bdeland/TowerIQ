"""
TowerIQ Content Page Component

This module provides a reusable ContentPage widget that encapsulates the common pattern
of a title, description, and content area. It can be styled via the stylesheets system.
"""

from typing import Callable
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QWidget, QLabel
from PyQt6.QtGui import QFont
from qfluentwidgets import BodyLabel, CaptionLabel, PushButton, FluentIcon


class ContentPage(QWidget):
    """
    Reusable content page component with title, description, and content area.
    
    This widget encapsulates the common pattern used across the application
    where pages have a title, description, and main content area. It can be
    styled via the stylesheets system using the object name 'content_page'.
    
    Features:
    - Title with large font and theme-aware styling
    - Description with smaller font and opacity
    - Content area that stretches to fill available space
    - Theme-aware styling that updates automatically
    - Configurable margins and spacing
    - Flexible content container that subclasses can customize
    """
    
    def __init__(self, title: str, description: str = "", parent=None):
        """
        Initialize the ContentPage widget.
        
        Args:
            title: The main title text
            description: Optional description text (can be empty)
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Set object name for stylesheet targeting
        self.setObjectName("content_page")
        
        self.title = title
        self.description = description
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the content page's user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)
        
        # Title
        self.title_label = BodyLabel(self.title)
        self.title_label.setObjectName("title_label")
        layout.addWidget(self.title_label)
        
        # Description (only add if provided)
        if self.description:
            self.desc_label = CaptionLabel(self.description)
            self.desc_label.setObjectName("description_label")
            layout.addWidget(self.desc_label)
        else:
            self.desc_label = None
        
        # Create a flexible container widget for the main content
        # Subclasses can add any layout or widgets they want to this container
        self.content_container = QWidget()
        self.content_container.setObjectName("content_container") # For styling

        # Add the container to the main page layout with stretch
        layout.addWidget(self.content_container, 1)
        
    def get_content_container(self) -> QWidget:
        """
        Returns the content container widget that subclasses can customize.
        
        Returns:
            The QWidget container for the content area.
        """
        return self.content_container
        
    def set_title(self, title: str):
        """Update the title text."""
        self.title = title
        if hasattr(self, 'title_label'):
            self.title_label.setText(title)
            
    def set_description(self, description: str):
        """Update the description text."""
        self.description = description
        layout = self.layout()
        if not layout or not isinstance(layout, QVBoxLayout):
            return
            
        if description:
            # Create description label if it doesn't exist
            if not self.desc_label:
                self.desc_label = CaptionLabel(description)
                self.desc_label.setObjectName("description_label")
                # Insert after title, before content
                layout.insertWidget(1, self.desc_label)
            else:
                self.desc_label.setText(description)
        else:
            # Remove description label if it exists
            if self.desc_label:
                layout.removeWidget(self.desc_label)
                self.desc_label.setParent(None)
                self.desc_label = None