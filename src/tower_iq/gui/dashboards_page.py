from PyQt6.QtWidgets import QVBoxLayout, QLabel
from .utils_gui import ThemeAwareWidget, get_title_font, get_text_color

class DashboardsPage(ThemeAwareWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self.label = QLabel("Dashboards Page", self)
        self._layout.addWidget(self.label)
        self._layout.addStretch()
        self.update_theme_styles()  # Set initial style

    def update_theme_styles(self):
        self.label.setFont(get_title_font())
        self.label.setStyleSheet(f"color: {get_text_color()};") 