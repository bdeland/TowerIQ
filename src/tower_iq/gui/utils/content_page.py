"""
TowerIQ Content Page Component

This module provides a reusable ContentPage widget that encapsulates the common pattern
of a title, description, and content area. It can be styled via the stylesheets system.
"""

from PyQt6.QtWidgets import QVBoxLayout, QWidget

from .page_header import PageHeader


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
        
        # Use the new PageHeader component
        self.page_header = PageHeader(self.title, self.description)
        layout.addWidget(self.page_header)
        
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
        if hasattr(self, 'page_header'):
            self.page_header.set_title(title)
            
    def set_description(self, description: str):
        """Update the description text."""
        self.description = description
        if hasattr(self, 'page_header'):
            self.page_header.set_description(description)