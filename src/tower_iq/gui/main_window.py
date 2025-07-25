import sys
import asyncio

from PyQt6.QtCore import Qt, QTimer
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
from .pages.settings_category_page import (
    AppearanceSettingsPage, LoggingSettingsPage, ConnectionSettingsPage,
    DatabaseSettingsPage, FridaSettingsPage, AdvancedSettingsPage
)


class MainWindow(FluentWindow):

    def __init__(self, session_manager=None, config_manager=None, controller=None):
        super().__init__()
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
                    self.header = HeaderWidget(self)
                    new_content_container = QWidget()
                    new_content_container.setStyleSheet("border-radius: 0px !important;")
                    container_layout = QVBoxLayout(new_content_container)
                    container_layout.setContentsMargins(0, 0, 0, 0)
                    container_layout.setSpacing(0)
                    container_layout.addWidget(self.header)
                    parent_layout.replaceWidget(original_stack, new_content_container)
                    container_layout.addWidget(original_stack)
        except Exception as e:
            print(f"Layout restructuring failed: {e}")
            # Fallback: just create the header without restructuring
            self.header = HeaderWidget(self)
        
        self._create_and_add_pages()
        self._connect_signals()
        
        # Apply initial style and set initial page
        QTimer.singleShot(0, self.apply_global_stylesheet)
        QTimer.singleShot(0, lambda: self.on_current_interface_changed(self.stackedWidget.currentIndex()))

    def _create_and_add_pages(self):
        """Initializes and adds all pages to the main window."""
        self.home_page = HomePage(self)
        self.home_page.setObjectName('home')
        self.dashboards_page = DashboardsPage(self.session_manager, self.config_manager, self)
        self.dashboards_page.setObjectName('dashboards')
        self.settings_page = SettingsPage(self.config_manager, self)
        self.settings_page.setObjectName('settings')
        self.connection_page = ConnectionPage(self.session_manager, self.config_manager)
        self.connection_page.setObjectName('connection')

        # Settings category pages
        self.appearance_settings_page = AppearanceSettingsPage(self.config_manager, self)
        self.appearance_settings_page.setObjectName('settings_appearance')
        self.logging_settings_page = LoggingSettingsPage(self.config_manager, self)
        self.logging_settings_page.setObjectName('settings_logging')
        self.connection_settings_page = ConnectionSettingsPage(self.config_manager, self)
        self.connection_settings_page.setObjectName('settings_connection')
        self.database_settings_page = DatabaseSettingsPage(self.config_manager, self)
        self.database_settings_page.setObjectName('settings_database')
        self.frida_settings_page = FridaSettingsPage(self.config_manager, self)
        self.frida_settings_page.setObjectName('settings_frida')
        self.advanced_settings_page = AdvancedSettingsPage(self.config_manager, self)
        self.advanced_settings_page.setObjectName('settings_advanced')

        if self.controller:
            self.controller.set_dashboard(self.connection_page)

        self._nav_key_to_text = {
            'home': 'Home', 'dashboards': 'Dashboards', 'connection': 'Connection', 'settings': 'Settings',
            'settings_appearance': 'Appearance & Theme', 'settings_logging': 'Logging & Diagnostics',
            'settings_connection': 'Connection Settings', 'settings_database': 'Database & Storage',
            'settings_frida': 'Frida Configuration', 'settings_advanced': 'Advanced Settings',
        }

        # Add main navigation items
        self.addSubInterface(self.home_page, FluentIcon.HOME, 'Home', position=NavigationItemPosition.TOP)
        self.addSubInterface(self.dashboards_page, FluentIcon.TILES, 'Dashboards')
        self.addSubInterface(self.connection_page, FluentIcon.CONNECT, 'Connection', position=NavigationItemPosition.BOTTOM)
        self.addSubInterface(self.settings_page, FluentIcon.SETTING, 'Settings', position=NavigationItemPosition.BOTTOM)
        
        # Add settings category pages to stacked widget
        for page in [self.appearance_settings_page, self.logging_settings_page, self.connection_settings_page,
                     self.database_settings_page, self.frida_settings_page, self.advanced_settings_page]:
            self.stackedWidget.addWidget(page)
        
    def _connect_signals(self):
        """Connects all application signals."""
        self.stackedWidget.currentChanged.connect(self.on_current_interface_changed)
        if hasattr(self, 'header'):
            self.header.breadcrumb.currentItemChanged.connect(self.on_breadcrumb_item_changed)
        self.connection_page.connection_panel.connect_device_requested.connect(self.navigate_to_process_selection)
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
        self.resize(1200, 800)
        self.setWindowTitle('TowerIQ')

    def on_current_interface_changed(self, index: int):
        widget = self.stackedWidget.widget(index)
        if not widget or not hasattr(self, 'header'):
            return
        
        key = widget.objectName()
        text = self._nav_key_to_text.get(key, "Page")

        self.header.breadcrumb.blockSignals(True)
        
        if key.startswith('settings_'):
            self.header.breadcrumb.clear()
            self.header.breadcrumb.addItem('home', 'Home')
            self.header.breadcrumb.addItem('settings', 'Settings')
            self.header.breadcrumb.addItem(key, text)
        else:
            self.header.breadcrumb.clear()
            self.header.breadcrumb.addItem('home', 'Home')
            if key != 'home':
                self.header.breadcrumb.addItem(key, text)
                if key == 'connection':
                    self._update_connection_breadcrumbs()
        
        self.header.breadcrumb.blockSignals(False)

        if key == 'connection' and self.connection_page.connection_panel.stacked.currentIndex() == 0:
            self.connection_page.connection_panel.trigger_device_scan()

    def on_breadcrumb_item_changed(self, key: str):
        if key == 'connection':
            stage = self.connection_page.connection_panel.stacked.currentIndex()
            if stage in [2, 3]:
                self.connection_page.connection_panel.set_stage(1)
                if self.controller: self.controller.on_back_to_stage_requested(1)
                return
            elif stage == 1:
                self.connection_page.connection_panel.set_stage(0)
                if self.controller: self.controller.on_back_to_stage_requested(0)
                return
        
        for i in range(self.stackedWidget.count()):
            widget = self.stackedWidget.widget(i)
            if widget and widget.objectName() == key and self.stackedWidget.currentWidget() is not widget:
                self.stackedWidget.setCurrentWidget(widget)
                break

    def _update_connection_breadcrumbs(self):
        stage = self.connection_page.connection_panel.stacked.currentIndex()
        self.header.breadcrumb.clear()
        self.header.breadcrumb.addItem('home', 'Home')
        self.header.breadcrumb.addItem('connection', 'Connection')
        if stage >= 1: self.header.breadcrumb.addItem('process', 'Select Process')
        if stage >= 2: self.header.breadcrumb.addItem('activation', 'Activate Hook')
        if stage >= 3: self.header.breadcrumb.addItem('active', 'Hook Active')

    def navigate_to_process_selection(self, device_serial: str):
        self.header.breadcrumb.blockSignals(True)
        self._update_connection_breadcrumbs()
        self.header.breadcrumb.blockSignals(False)
        if self.controller:
            self.controller.on_connect_device_requested(device_serial)
        self.connection_page.connection_panel.set_stage(1)
        
    def on_settings_category_navigated(self, category: str):
        category_pages = {
            'appearance': self.appearance_settings_page,
            'logging': self.logging_settings_page,
            'connection': self.connection_settings_page,
            'database': self.database_settings_page,
            'frida': self.frida_settings_page,
            'advanced': self.advanced_settings_page
        }
        if category in category_pages:
            self.stackedWidget.setCurrentWidget(category_pages[category])

    def closeEvent(self, event: QCloseEvent):
        if self.controller:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.controller.shutdown())
        event.accept()

if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())