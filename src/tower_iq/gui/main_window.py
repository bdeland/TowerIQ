import sys

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QVBoxLayout, QWidget, QLabel
from qfluentwidgets import (FluentIcon, FluentWindow, NavigationItemPosition, 
                            qconfig)

# Import the new ThemeAwareWidget and helpers
from .utils_gui import ThemeAwareWidget, get_text_color, get_title_font

# Import the corrected widgets
from .header_widget import HeaderWidget
from .dashboards_page import DashboardsPage
from .settings_page import SettingsPage


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

    def __init__(self):
        super().__init__()
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
        self.dashboards_page = DashboardsPage(self)
        self.dashboards_page.setObjectName('dashboards')
        self.settings_page = SettingsPage(self)
        self.settings_page.setObjectName('settings')

        self._nav_key_to_text = {
            'home': 'Home',
            'dashboards': 'Dashboards',
            'settings': 'Settings',
        }

        # Add navigation items
        self.addSubInterface(self.home_page, FluentIcon.HOME, 'Home', position=NavigationItemPosition.TOP)
        self.addSubInterface(self.dashboards_page, FluentIcon.TILES, 'Dashboards')
        self.addSubInterface(self.settings_page, FluentIcon.SETTING, 'Settings', position=NavigationItemPosition.BOTTOM)

        # Connect signals
        self.stackedWidget.currentChanged.connect(self.on_current_interface_changed)
        if hasattr(self, 'header'):
            self.header.breadcrumb.currentItemChanged.connect(self.on_breadcrumb_item_changed)
        
        # Initialize first page
        self.on_current_interface_changed(self.stackedWidget.currentIndex())

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
        
        # Re-enable signals for user clicks
        self.header.breadcrumb.blockSignals(False)
            
    def on_breadcrumb_item_changed(self, key: str):
        # Find widget by object name and switch to it
        for i in range(self.stackedWidget.count()):
            widget = self.stackedWidget.widget(i)
            if widget and widget.objectName() == key and self.stackedWidget.currentWidget() is not widget:
                self.stackedWidget.setCurrentWidget(widget)
                break

if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()