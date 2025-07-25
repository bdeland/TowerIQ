"""
TowerIQ Settings Page

This module provides the main settings page with Windows 11-style card layout
and navigation to detailed category pages.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QWidget, QGridLayout, QStackedWidget, QGroupBox
from PyQt6.QtGui import QFont
from qfluentwidgets import FluentIcon
from ..utils.settings_category_card import SettingsCategoryCard
from ..utils.page_header import PageHeader

class SettingsPage(QWidget):
    """
    Main settings page with Windows 11-style card layout.
    
    Features:
    - Grid of settings category cards
    - Navigation to detailed category pages
    - Breadcrumb integration
    - Theme-aware styling
    """
    
    # Signal emitted when navigating to a category
    category_navigated = pyqtSignal(str)  # Emits the category name
    
    def __init__(self, config_manager=None, parent=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the settings page's user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setObjectName("settings_page")
        
        # Stacked widget to switch between main view and category pages
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setObjectName("stacked_widget")
        layout.addWidget(self.stacked_widget)
        
        # Create main settings view
        self.main_view = self.create_main_view()
        self.stacked_widget.addWidget(self.main_view)
        
    def create_main_view(self) -> QWidget:
        """Create the main settings view with category cards."""
        # Create a container widget for the main view
        container = QWidget()
        container.setObjectName("main_view_container")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)  # Add proper page margins
        layout.setSpacing(16)  # Add spacing between header and cards
        
        # Use the new PageHeader component for consistent styling
        self.page_header = PageHeader(
            title="Settings",
            description="Customize TowerIQ to your preferences"
        )
        layout.addWidget(self.page_header, 0)  # Add with stretch factor 0 to prevent expansion
        
        # Create the cards grid and add it to the container
        cards_widget = self.create_cards_grid()
        layout.addWidget(cards_widget, 1)  # Add with stretch factor 1 to take remaining space
        
        return container
        
    def create_cards_grid(self) -> QWidget:
        """Create the grid of settings category cards."""
        widget = QWidget()
        widget.setObjectName("cards_grid")
        grid_layout = QGridLayout(widget)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.setSpacing(16)
        
        # Define settings categories
        categories = [
            {
                'name': 'appearance',
                'title': 'Appearance & Theme',
                'description': 'Customize the look and feel of TowerIQ',
                'icon': FluentIcon.PALETTE
            },
            {
                'name': 'logging',
                'title': 'Logging & Diagnostics',
                'description': 'Configure logging levels and diagnostic options',
                'icon': FluentIcon.DOCUMENT
            },
            {
                'name': 'connection',
                'title': 'Connection Settings',
                'description': 'Manage device connection preferences',
                'icon': FluentIcon.CONNECT
            },
            {
                'name': 'database',
                'title': 'Database & Storage',
                'description': 'Configure database and data storage options',
                'icon': FluentIcon.DOCUMENT
            },
            {
                'name': 'frida',
                'title': 'Frida Configuration',
                'description': 'Manage Frida hooks and script settings',
                'icon': FluentIcon.CODE
            },
            {
                'name': 'advanced',
                'title': 'Advanced Settings',
                'description': 'Developer options and experimental features',
                'icon': FluentIcon.SETTING
            }
        ]
        
        # Create and add cards to grid
        row = 0
        col = 0
        max_cols = 2  # 2 columns for better layout
        
        for category in categories:
            card = SettingsCategoryCard(
                title=category['title'],
                description=category['description'],
                icon=category['icon'],
                category=category['name']
            )
            card.clicked.connect(self.on_card_clicked)
            
            grid_layout.addWidget(card, row, col)
            
            # Move to next position
            col += 1
            if col >= max_cols:
                col = 0
                row += 1
        
        return widget
        
    def on_card_clicked(self, category: str):
        """Handle card click to navigate to category page."""
        # Emit signal to let main window handle navigation to separate FluentWindow pages
        self.category_navigated.emit(category)
            
    def on_back_to_main(self):
        """Handle back navigation to main settings view."""
        self.current_category = None
        self.stacked_widget.setCurrentWidget(self.main_view)
        
    def get_current_category(self) -> str:
        """Get the currently active category."""
        return self.current_category or ""
    

    