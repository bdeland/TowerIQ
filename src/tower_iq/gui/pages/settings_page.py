"""
TowerIQ Settings Page

This module provides the main settings page with qfluentwidgets Pivot layout
and content display for each settings category.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QVBoxLayout, QWidget, QStackedWidget
from qfluentwidgets import FluentIcon
from qfluentwidgets.components.navigation.pivot import Pivot

from ..utils.page_header import PageHeader
from .appearance_settings_page import AppearanceSettingsPage
from .logging_settings_page import LoggingSettingsPage
from .connection_settings_page import ConnectionSettingsPage
from .database_settings_page import DatabaseSettingsPage
from .frida_settings_page import FridaSettingsPage
from .advanced_settings_page import AdvancedSettingsPage


class SettingsPage(QWidget):
    """
    Main settings page with qfluentwidgets Pivot layout.
    
    Features:
    - Pivot with settings category navigation at the top
    - Content area below showing selected pivot's content
    - Theme-aware styling
    """
    
    # Signal emitted when navigating to a category
    category_navigated = pyqtSignal(str)  # Emits the category name
    
    def __init__(self, config_manager=None, controller=None, parent=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.controller = controller
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the settings page's user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setObjectName("settings_page")
        
        # Create main settings view
        self.main_view = self.create_main_view()
        layout.addWidget(self.main_view)
        
    def create_main_view(self) -> QWidget:
        """Create the main settings view with Pivot and content area."""
        # Create a container widget for the main view
        container = QWidget()
        container.setObjectName("main_view_container")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)  # Add proper page margins
        layout.setSpacing(16)  # Add spacing between header and pivot
        
        # Use the new PageHeader component for consistent styling
        self.page_header = PageHeader(
            title="Settings",
            description="Customize TowerIQ to your preferences"
        )
        layout.addWidget(self.page_header, 0)  # Add with stretch factor 0 to prevent expansion
        
        # Create the Pivot and add it to the container
        self.pivot = self.create_pivot()
        layout.addWidget(self.pivot, 0)  # Add with stretch factor 0 to prevent expansion
        
        # Create the content area with stacked widget
        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("settings_content_stack")
        layout.addWidget(self.content_stack, 1)  # Add with stretch factor 1 to take remaining space
        
        # Create content widgets for each pivot
        self.create_pivot_content()
        
        return container
        
    def create_pivot(self) -> Pivot:
        """Create the Pivot with settings category navigation."""
        pivot = Pivot()
        pivot.setObjectName("settings_pivot")
        
        # Define settings categories
        categories = [
            {
                'name': 'appearance',
                'title': 'Appearance',
                'description': 'Customize the look and feel of TowerIQ',
                'icon': FluentIcon.PALETTE
            },
            {
                'name': 'logging',
                'title': 'Logging',
                'description': 'Configure logging levels and diagnostic options',
                'icon': FluentIcon.DOCUMENT
            },
            {
                'name': 'connection',
                'title': 'Connection',
                'description': 'Manage device connection preferences',
                'icon': FluentIcon.CONNECT
            },
            {
                'name': 'database',
                'title': 'Database',
                'description': 'Configure database and data storage options',
                'icon': FluentIcon.DOCUMENT
            },
            {
                'name': 'frida',
                'title': 'Frida',
                'description': 'Manage Frida hooks and script settings',
                'icon': FluentIcon.CODE
            },
            {
                'name': 'advanced',
                'title': 'Advanced',
                'description': 'Developer options and experimental features',
                'icon': FluentIcon.SETTING
            }
        ]
        
        # Add items to the Pivot
        for category in categories:
            pivot.addItem(
                routeKey=category['name'],
                text=category['title']
            )
        
        # Calculate and set minimum width for each pivot item based on text content
        self._set_pivot_item_widths(pivot)
        
        # Connect the currentItemChanged signal to handle pivot changes
        pivot.currentItemChanged.connect(self.on_pivot_changed)
        
        return pivot
        
    def create_pivot_content(self):
        """Create content widgets for each pivot."""
        # Create content widgets for each category using the separate page classes
        content_widgets = {
            'appearance': AppearanceSettingsPage(self.config_manager, self),
            'logging': LoggingSettingsPage(self.config_manager, self),
            'connection': ConnectionSettingsPage(self.config_manager, self),
            'database': DatabaseSettingsPage(self.config_manager, self.controller, self),
            'frida': FridaSettingsPage(self.config_manager, self),
            'advanced': AdvancedSettingsPage(self.config_manager, self)
        }
        
        # Add content widgets to the stacked widget
        for category, widget in content_widgets.items():
            self.content_stack.addWidget(widget)
        
        # Set the first pivot as active
        if self.pivot.items:
            first_key = list(self.pivot.items.keys())[0]
            self.pivot.setCurrentItem(first_key)
        
    def on_pivot_changed(self, route_key: str):
        """Handle pivot change event."""
        # Find the index of the content widget for this route key
        content_widgets = {
            'appearance': 0,
            'logging': 1,
            'connection': 2,
            'database': 3,
            'frida': 4,
            'advanced': 5
        }
        
        if route_key in content_widgets:
            index = content_widgets[route_key]
            if index < self.content_stack.count():
                # Switch to the corresponding content widget
                self.content_stack.setCurrentIndex(index)
                
                # Emit the category navigation signal
                self.category_navigated.emit(route_key)
            
    def on_back_to_main(self):
        """Handle back navigation to main settings view."""
        self.current_category = None
        
    def get_current_category(self) -> str:
        """Get the currently active category."""
        return self.pivot.currentRouteKey() or ""
    
    def _set_pivot_item_widths(self, pivot: Pivot):
        """Calculate and set minimum width for each pivot item based on text content."""
        from PyQt6.QtGui import QFontMetrics
        from PyQt6.QtCore import QSize
        
        # Get the font metrics to calculate text width
        font = pivot.font()
        font_metrics = QFontMetrics(font)
        
        # Parse the CSS to get actual padding values
        from ..stylesheets import PIVOT_QSS
        import re
        padding_match = re.search(r'padding:\s*(\d+)px\s+(\d+)px', PIVOT_QSS)
        if padding_match:
            top_bottom_padding = int(padding_match.group(1))
            left_right_padding = int(padding_match.group(2))
            total_padding = left_right_padding * 2  # Left + right padding
        else:
            # Fallback if parsing fails
            total_padding = 40
        
        # Set individual minimum width for each pivot item based on its text content
        for route_key, item in pivot.items.items():
            text_width = font_metrics.horizontalAdvance(item.text())
            min_width = text_width + total_padding
            item.setMinimumWidth(min_width)
        
        # Configure the layout to distribute space evenly
        if hasattr(pivot, 'hBoxLayout') and pivot.hBoxLayout:
            # Set stretch factors to make all items equal width
            for route_key, item in pivot.items.items():
                pivot.hBoxLayout.setStretch(pivot.hBoxLayout.indexOf(item), 1)
    
    def cleanup(self):
        """Clean up all settings pages before destruction."""
        # Clean up all content widgets in the stack
        for i in range(self.content_stack.count()):
            widget = self.content_stack.widget(i)
            if widget:
                # Check if the widget has a cleanup method and call it
                cleanup_method = getattr(widget, 'cleanup', None)
                if cleanup_method and callable(cleanup_method):
                    try:
                        cleanup_method()
                    except Exception:
                        # Ignore cleanup errors
                        pass
    
    def closeEvent(self, event):
        """Override closeEvent to ensure proper cleanup."""
        self.cleanup()
        super().closeEvent(event)
    

    