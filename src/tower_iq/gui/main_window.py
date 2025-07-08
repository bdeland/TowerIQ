import sys

from PyQt6.QtCore import Qt
from qfluentwidgets import FluentIcon, FluentWindow, NavigationItemPosition
from PyQt6.QtWidgets import QApplication, QVBoxLayout, QWidget

from .dashboards_page import DashboardsPage
from .settings_page import SettingsPage
from .header_widget import HeaderWidget


class MainWindow(FluentWindow):

    def __init__(self):
        super().__init__()
        self.init_window()

        # create sub interface
        self.dashboards_page = DashboardsPage(self)
        self.dashboards_page.setObjectName('dashboards-page')
        self.settings_page = SettingsPage(self)
        self.settings_page.setObjectName('settings-page')

        # --- Layout Surgery ---
        self.header = HeaderWidget(self)
        self.right_container = QWidget()
        self.right_layout = QVBoxLayout(self.right_container)
        self.right_layout.setContentsMargins(0, 0, 0, 0)
        self.right_layout.setSpacing(0)
        
        self.right_layout.addWidget(self.header)
        self.right_layout.addWidget(self.stackedWidget)
        
        self.layout().replaceWidget(self.stackedWidget, self.right_container)
        # --- End Surgery ---

        self.addSubInterface(
            self.dashboards_page, FluentIcon.HOME, 'Dashboards')

        self.addSubInterface(
            self.settings_page,
            FluentIcon.SETTING,
            'Settings',
            position=NavigationItemPosition.BOTTOM
        )

        self.navigationInterface.setCurrentItem(self.dashboards_page.objectName())
        
        self.navigationInterface.currentChanged.connect(self.on_current_interface_changed)
        self.header.breadcrumb.itemClicked.connect(self.navigationInterface.setCurrentItem)

    def init_window(self):
        self.resize(1200, 800)
        self.setWindowTitle('TowerIQ')

    def on_current_interface_changed(self, index: int):
        widget = self.stackedWidget.widget(index)
        if not widget:
            return
        
        item = self.navigationInterface.widgetItemMap.get(widget)
        if not item:
            return

        self.header.breadcrumb.clear()
        self.header.breadcrumb.addItem(item.key(), item.text())


if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec() 