import sys
import asyncio

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QApplication, QVBoxLayout, QWidget
from PyQt6.QtGui import QCloseEvent
from qfluentwidgets import (FluentWindow, setTheme, Theme, FluentIcon, 
                            NavigationItemPosition, qconfig)  # <-- CORRECTED: Added qconfig

# --- Import our global stylesheet generator ---
from .stylesheets import get_themed_stylesheet

# --- Import all pages from their own files ---
from .utils.header_widget import HeaderWidget
from .pages.home_page import HomePage
from .pages.dashboards_page import DashboardsPage
from .pages.settings_page import SettingsPage
from .pages.connection_page import ConnectionPage


class MainWindow(FluentWindow):

    def __init__(self, session_manager=None, config_manager=None, controller=None, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.config_manager = config_manager
        self.controller = controller

        # Initialize theme and connect the global style handler
        self._initialize_theme()
        
        # --- CORRECTED: Connect to the themeChanged signal via qconfig ---
        qconfig.themeChanged.connect(self.apply_global_stylesheet)
        
        self.init_window()

        # Layout Restructuring - Simplified to avoid layout deletion issues
        try:
            original_stack = self.stackedWidget
            parent_widget = original_stack.parent()
            if isinstance(parent_widget, QWidget):
                parent_layout = parent_widget.layout()
                if parent_layout:
                    new_content_container = QWidget()
                    new_content_container.setStyleSheet("border-radius: 0px !important;")
                    container_layout = QVBoxLayout(new_content_container)
                    container_layout.setContentsMargins(0, 0, 0, 0)
                    container_layout.setSpacing(0)
                    container_layout.addWidget(self.header)
                    parent_layout.replaceWidget(original_stack, new_content_container)
                    container_layout.addWidget(original_stack)
        except Exception as e:
            #TODO: fix this
            pass
        
        self._create_and_add_pages()
        self._connect_signals()
        
        # Apply initial style and set initial page
        self.apply_global_stylesheet()
        self.on_current_interface_changed(self.stackedWidget.currentIndex())

    def _create_and_add_pages(self):
        """Initializes and adds all pages to the main window."""
        self.home_page = HomePage(self)
        self.home_page.setObjectName('home')
        self.dashboards_page = DashboardsPage(self)
        self.dashboards_page.setObjectName('dashboards')
        self.settings_page = SettingsPage(self.config_manager, self.controller, self)
        self.settings_page.setObjectName('settings')
        self.connection_page = ConnectionPage(self.session_manager, self.config_manager)
        self.connection_page.setObjectName('connection')

        if self.controller:
            self.controller.set_dashboard(self.connection_page)

        self._nav_key_to_text = {
            'home': 'Home', 'dashboards': 'Dashboards', 'connection': 'Connection', 'settings': 'Settings'
        }

        # Add main navigation items
        self.addSubInterface(self.home_page, FluentIcon.HOME, 'Home', position=NavigationItemPosition.TOP)
        self.addSubInterface(self.dashboards_page, FluentIcon.TILES, 'Dashboards')
        self.addSubInterface(self.connection_page, FluentIcon.CONNECT, 'Connection', position=NavigationItemPosition.BOTTOM)
        self.addSubInterface(self.settings_page, FluentIcon.SETTING, 'Settings', position=NavigationItemPosition.BOTTOM)
        
    def _connect_signals(self):
        """Connect all signals after the window is fully initialized."""
        # Connect theme change signal
        qconfig.themeChanged.connect(self.apply_global_stylesheet)
        
        # Connect navigation signals
        self.stackedWidget.currentChanged.connect(self.on_current_interface_changed)
        
        # Connect breadcrumb navigation
        self.header.breadcrumb.currentItemChanged.connect(self.on_breadcrumb_item_changed)
        
        # Connect connection page signals
        self.connection_page.connect_device_requested.connect(self.navigate_to_process_selection)
        self.connection_page.scan_devices_requested.connect(self._on_scan_devices_requested)
        
        # Connect settings page signals
        self.settings_page.category_navigated.connect(self.on_settings_category_navigated)

    def apply_global_stylesheet(self):
        """Generates and applies the full stylesheet for the current theme."""
        self.setStyleSheet(get_themed_stylesheet())

    def _initialize_theme(self):
        """Initializes the application theme from configuration."""
        if self.config_manager:
            theme_map = {"light": Theme.LIGHT, "dark": Theme.DARK}
            saved_theme = self.config_manager.get('gui.theme', 'auto')
            setTheme(theme_map.get(saved_theme, Theme.AUTO))
    
    def init_window(self):
        """Initialize the window after all pages are created."""
        self._initialize_theme()
        
        # Always create header first, before anything else
        self.header = HeaderWidget(self)
        
        # Layout Restructuring - Simplified to avoid layout deletion issues
        try:
            original_stack = self.stackedWidget
            parent_widget = original_stack.parent()
            if isinstance(parent_widget, QWidget):
                parent_layout = parent_widget.layout()
                if parent_layout:
                    new_content_container = QWidget()
                    new_content_container.setStyleSheet("border-radius: 0px !important;")
                    container_layout = QVBoxLayout(new_content_container)
                    container_layout.setContentsMargins(0, 0, 0, 0)
                    container_layout.setSpacing(0)
                    container_layout.addWidget(self.header)
                    parent_layout.replaceWidget(original_stack, new_content_container)
                    container_layout.addWidget(original_stack)
        except Exception as e:
            #TODO: fix this
            pass
        
        self._create_and_add_pages()
        # Connect signals directly to avoid qasync timer conflicts
        self._connect_signals()
        self.resize(1200, 800)
        self.setWindowTitle('TowerIQ')
        
        # Apply initial style and set initial page
        self.apply_global_stylesheet()
        self.on_current_interface_changed(self.stackedWidget.currentIndex())

    def on_current_interface_changed(self, index: int):
        widget = self.stackedWidget.widget(index)
        if not widget or not hasattr(self, 'header'):
            return
        
        key = widget.objectName()
        text = self._nav_key_to_text.get(key, "Page")

        self.header.breadcrumb.blockSignals(True)
        
        # Handle settings page breadcrumb
        if key == 'settings':
            self.header.breadcrumb.clear()
            self.header.breadcrumb.addItem('home', 'Home')
            self.header.breadcrumb.addItem('settings', 'Settings')
            # Add the current pivot item to the breadcrumb
            current_route_key = self.settings_page.pivot.currentRouteKey()
            if current_route_key:
                category_names = {
                    'appearance': 'Appearance & Theme',
                    'logging': 'Logging & Diagnostics', 
                    'connection': 'Connection Settings',
                    'database': 'Database & Storage',
                    'frida': 'Frida Configuration',
                    'advanced': 'Advanced Settings'
                }
                category_name = category_names.get(current_route_key, current_route_key.title())
                self.header.breadcrumb.addItem(current_route_key, category_name)
        else:
            # Simplified breadcrumb logic for other pages
            self.header.breadcrumb.clear()
            self.header.breadcrumb.addItem('home', 'Home')
            if key != 'home':
                self.header.breadcrumb.addItem(key, text)
                if key == 'connection':
                    self._update_connection_breadcrumbs()
        
        self.header.breadcrumb.blockSignals(False)

        if key == 'connection':
            self.connection_page.on_page_shown()

    def on_breadcrumb_item_changed(self, key: str):
        if key == 'connection':
            # The new connection page handles navigation automatically via signals
            # No need to manually manage stages
            return
        elif key == 'settings':
            # Navigate to main settings page (first pivot item)
            if self.stackedWidget.currentWidget() == self.settings_page:
                # If already on settings page, switch to first pivot item
                if self.settings_page.pivot.items:
                    first_key = list(self.settings_page.pivot.items.keys())[0]
                    self.settings_page.pivot.setCurrentItem(first_key)
            else:
                # Navigate to settings page
                self.stackedWidget.setCurrentWidget(self.settings_page)
            return
        elif key in ['appearance', 'logging', 'connection', 'database', 'frida', 'advanced']:
            # Navigate to specific settings category pivot item
            if self.settings_page and hasattr(self.settings_page, 'navigate_to_category'):
                self.stackedWidget.setCurrentWidget(self.settings_page)
                # Switch to the category directly after navigation
                self._switch_to_settings_category(key)
            return
        
        # Default navigation for other pages
        for i in range(self.stackedWidget.count()):
            widget = self.stackedWidget.widget(i)
            if widget and widget.objectName() == key and self.stackedWidget.currentWidget() is not widget:
                self.stackedWidget.setCurrentWidget(widget)
                break
                
    def _switch_to_settings_category(self, category: str):
        """Helper method to switch to a specific settings category pivot item."""
        self.settings_page.pivot.setCurrentItem(category)

    def _update_connection_breadcrumbs(self):
        # The new connection page handles breadcrumb updates automatically
        # No need to manually manage breadcrumbs
        pass

    def navigate_to_process_selection(self, device_serial: str):
        # The new connection page handles navigation automatically via signals
        if self.controller:
            self.controller.on_connect_device_requested(device_serial)
    
    def _on_scan_devices_requested(self):
        """Handle device scan requests from the connection page."""
        if self.controller:
            try:
                self.controller.on_scan_devices_requested()
            except Exception as e:
                import traceback
                traceback.print_exc()
        else:
            #TODO: fix this
            pass
        
    def on_settings_category_navigated(self, category: str):
        """Handle settings category navigation for breadcrumb updates only."""
        if not hasattr(self, 'header'):
            return
            
        # Update breadcrumb to show current settings category
        category_names = {
            'appearance': 'Appearance & Theme',
            'logging': 'Logging & Diagnostics', 
            'connection': 'Connection Settings',
            'database': 'Database & Storage',
            'frida': 'Frida Configuration',
            'advanced': 'Advanced Settings'
        }
        
        category_name = category_names.get(category, category.title())
        
        self.header.breadcrumb.blockSignals(True)
        self.header.breadcrumb.clear()
        self.header.breadcrumb.addItem('home', 'Home')
        self.header.breadcrumb.addItem('settings', 'Settings')
        self.header.breadcrumb.addItem(category, category_name)
        self.header.breadcrumb.blockSignals(False)

    def closeEvent(self, event: QCloseEvent):
        if self.controller:
            try:
                # Use a more robust shutdown approach
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Schedule the shutdown task properly
                    future = asyncio.run_coroutine_threadsafe(
                        self.controller.shutdown(), 
                        loop
                    )
                    # Don't wait for completion to avoid blocking the UI
                    future.add_done_callback(lambda f: None)
            except (RuntimeError, AssertionError):
                # If there are any issues with the event loop, just accept the close
                pass
        event.accept()

if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())