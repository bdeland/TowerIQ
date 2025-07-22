import sys
import asyncio

from PyQt6.QtCore import Qt
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QVBoxLayout, QWidget, QLabel
from PyQt6.QtGui import QCloseEvent
from qfluentwidgets import (FluentIcon, FluentWindow, NavigationItemPosition, 
                            qconfig)

# Import the new ThemeAwareWidget and helpers
from .utils_gui import ThemeAwareWidget, get_text_color, get_title_font

# Import the corrected widgets
from .header_widget import HeaderWidget
from .dashboards_page import DashboardsPage
from .settings_page import SettingsPage
from .connection_page import ConnectionPage


class HomePage(ThemeAwareWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self.label = QLabel("Home Page", self)
        self._layout.addWidget(self.label)
        self._layout.addStretch()
        self.update_theme_styles()  # Set initial style

    def update_theme_styles(self):
        self.label.setFont(get_title_font())
        self.label.setStyleSheet(f"color: {get_text_color()};")


class MainWindow(FluentWindow):

    def __init__(self, session_manager=None, config_manager=None, controller=None):
        super().__init__()
        self.session_manager = session_manager
        self.config_manager = config_manager
        self.controller = controller
        self.init_window()

        # Layout Restructuring (This part is correct)
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
        
        # Create pages
        self.home_page = HomePage(self)
        self.home_page.setObjectName('home')
        self.dashboards_page = DashboardsPage(self.session_manager, self.config_manager, self)
        self.dashboards_page.setObjectName('dashboards')
        self.settings_page = SettingsPage(self)
        self.settings_page.setObjectName('settings')

        # Add ConnectionPage
        self.connection_page = ConnectionPage(self.session_manager, self.config_manager)
        self.connection_page.setObjectName('connection')

        # Set dashboard in MainController if provided
        if self.controller is not None:
            self.controller.set_dashboard(self.connection_page)

        self._nav_key_to_text = {
            'home': 'Home',
            'dashboards': 'Dashboards',
            'connection': 'Connection',
            'settings': 'Settings',
        }

        # Add navigation items
        self.addSubInterface(self.home_page, FluentIcon.HOME, 'Home', position=NavigationItemPosition.TOP)
        self.addSubInterface(self.dashboards_page, FluentIcon.TILES, 'Dashboards')
        self.addSubInterface(self.connection_page, FluentIcon.CONNECT, 'Connection', position=NavigationItemPosition.BOTTOM)
        self.addSubInterface(self.settings_page, FluentIcon.SETTING, 'Settings', position=NavigationItemPosition.BOTTOM)

        # Connect signals
        self.stackedWidget.currentChanged.connect(self.on_current_interface_changed)
        if hasattr(self, 'header'):
            self.header.breadcrumb.currentItemChanged.connect(self.on_breadcrumb_item_changed)
            # Remove itemClicked connection (not available)
        # --- New: Connect ConnectionPanel navigation signal ---
        self.connection_page.connection_panel.connect_device_requested.connect(self.navigate_to_process_selection)
        
        # Initialize first page
        QTimer.singleShot(0, lambda: self.on_current_interface_changed(self.stackedWidget.currentIndex()))

    def init_window(self):
        self.resize(1200, 800)
        self.setWindowTitle('TowerIQ')

    def on_current_interface_changed(self, index: int):
        widget = self.stackedWidget.widget(index)
        if not widget or not hasattr(self, 'header'):
            return
        
        key = widget.objectName()
        text = self._nav_key_to_text.get(key, "Page")

        # Block signals to prevent feedback loop
        self.header.breadcrumb.blockSignals(True)
        
        self.header.breadcrumb.clear()
        self.header.breadcrumb.addItem('home', 'Home')
        if key != 'home':
            self.header.breadcrumb.addItem(key, text)
            # --- Restore breadcrumbs for connection sub-stages ---
            if key == 'connection':
                self._update_connection_breadcrumbs()
        
        # Re-enable signals for user clicks
        self.header.breadcrumb.blockSignals(False)

        # Only trigger device scan if on device selection stage
        if key == 'connection' and self.connection_page.connection_panel.stacked.currentIndex() == 0:
            self.connection_page.connection_panel.trigger_device_scan()
            
    def on_breadcrumb_item_changed(self, key: str):
        # Find widget by object name and switch to it
        for i in range(self.stackedWidget.count()):
            widget = self.stackedWidget.widget(i)
            if widget and widget.objectName() == key and self.stackedWidget.currentWidget() is not widget:
                self.stackedWidget.setCurrentWidget(widget)
                break
        # --- Handle backward navigation for ConnectionPage stages ---
        if key == 'connection':
            stage = self.connection_page.connection_panel.stacked.currentIndex()
            # When clicking "Connection" breadcrumb, go to process selection (stage 1) if we have a connected device
            # This allows users to see the process list and potentially select a different process
            if stage == 3:  # From hook active, go to process selection
                self.header.breadcrumb.blockSignals(True)
                self.connection_page.connection_panel.set_stage(1)
                self._update_connection_breadcrumbs()
                self.header.breadcrumb.blockSignals(False)
                if self.controller is not None:
                    self.controller.on_back_to_stage_requested(1)
            elif stage == 2:  # From activation, go to process selection
                self.header.breadcrumb.blockSignals(True)
                self.connection_page.connection_panel.set_stage(1)
                self._update_connection_breadcrumbs()
                self.header.breadcrumb.blockSignals(False)
                if self.controller is not None:
                    self.controller.on_back_to_stage_requested(1)
            elif stage == 1:  # From process selection, go to device selection
                self.header.breadcrumb.blockSignals(True)
                self.connection_page.connection_panel.set_stage(0)
                self._update_connection_breadcrumbs()
                self.header.breadcrumb.blockSignals(False)
                if self.controller is not None:
                    self.controller.on_back_to_stage_requested(0)

    def _update_connection_breadcrumbs(self):
        """
        Update breadcrumbs to match the current stage of the connection panel.
        """
        stage = self.connection_page.connection_panel.stacked.currentIndex()
        # Always start with home > connection
        self.header.breadcrumb.clear()
        self.header.breadcrumb.addItem('home', 'Home')
        self.header.breadcrumb.addItem('connection', 'Connection')
        if stage >= 1:
            self.header.breadcrumb.addItem('process', 'Select Process')
        if stage >= 2:
            self.header.breadcrumb.addItem('activation', 'Activate Hook')
        if stage >= 3:
            self.header.breadcrumb.addItem('active', 'Hook Active')

    def closeEvent(self, event: QCloseEvent):
        """Handle application close event with proper cleanup."""
        if self.controller is not None:
            # Start shutdown process asynchronously
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Schedule shutdown and accept the close event
                asyncio.create_task(self.controller.shutdown())
                event.accept()
            else:
                # If no event loop, just accept the close
                event.accept()
        else:
            event.accept()

    # --- New: Navigation orchestration methods for ConnectionPage ---
    def navigate_to_process_selection(self, device_serial: str):
        """
        Orchestrates the UI transition from device list to process list.
        Updates breadcrumb, notifies controller, and sets the correct stage.
        """
        # 1. Update the Header: Add a new breadcrumb for the current view.
        self.header.breadcrumb.blockSignals(True)
        self.connection_page.connection_panel.set_stage(1)
        self._update_connection_breadcrumbs()
        self.header.breadcrumb.blockSignals(False)
        # 2. Tell the Controller: Trigger the backend logic to connect and fetch processes.
        if self.controller is not None:
            self.controller.on_connect_device_requested(device_serial)
        # 3. Update the View: Manually tell the ConnectionPanel to show the next stage.
        self.connection_page.connection_panel.set_stage(1)

if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()