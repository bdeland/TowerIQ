"""
TowerIQ Page Header Component

This module provides a reusable PageHeader widget that encapsulates the common pattern
of a title and description. It can be used independently or as part of ContentPage.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QVBoxLayout, QWidget, QSizePolicy
from qfluentwidgets import TitleLabel, CaptionLabel


class PageHeader(QWidget):
    """
    Reusable page header component with title and description.
    
    This widget encapsulates the common pattern used across the application
    where pages have a title and optional description. It can be styled via
    the stylesheets system using the object name 'page_header'.
    
    Features:
    - Title with large font and theme-aware styling
    - Optional description with smaller font and opacity
    - Theme-aware styling that updates automatically
    - Configurable margins and spacing
    - Flexible layout that can be embedded in any page
    """
    
    def __init__(self, title: str, description: str = "", parent=None):
        """
        Initialize the PageHeader widget.
        
        Args:
            title: The main title text
            description: Optional description text (can be empty)
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Set object name for stylesheet targeting
        self.setObjectName("page_header")
        
        self.title = title
        self.description = description
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the page header's user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)  # Push content to top
        
        # Title
        self.title_label = TitleLabel(self.title, self)
        self.title_label.setObjectName("title_label")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.title_label)
        
        # Description (only add if provided)
        if self.description:
            self.desc_label = CaptionLabel(self.description, self)
            self.desc_label.setObjectName("description_label")
            self.desc_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            layout.addWidget(self.desc_label)
        else:
            self.desc_label = None
        
        # Prevent the PageHeader from expanding vertically
        self.setSizePolicy(self.sizePolicy().horizontalPolicy(), 
                          QSizePolicy.Policy.Preferred)
            
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
                # Insert after title
                layout.insertWidget(1, self.desc_label)
            else:
                self.desc_label.setText(description)
        else:
            # Remove description label if it exists
            if self.desc_label:
                layout.removeWidget(self.desc_label)
                self.desc_label.setParent(None)
                self.desc_label = None 