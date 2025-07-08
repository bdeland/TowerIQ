from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from qfluentwidgets import isDarkTheme, qconfig

class DashboardsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self.label = QLabel("Dashboards Page", self)
        self.label.setStyleSheet(self._get_label_style())
        self._layout.addWidget(self.label)
        self._layout.addStretch()
        # Listen for theme changes
        qconfig.themeChanged.connect(self.on_theme_changed)

    def _get_label_style(self):
        if isDarkTheme():
            return "font-size: 24px; font-weight: bold; color: white;"
        else:
            return "font-size: 24px; font-weight: bold; color: black;"

    def on_theme_changed(self):
        self.label.setStyleSheet(self._get_label_style()) 