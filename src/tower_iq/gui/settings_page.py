from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from qfluentwidgets import ComboBox, Theme, setTheme, qconfig

class SettingsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        label = QLabel("Settings", self)
        label.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(label)

        # Theme selection
        theme_label = QLabel("Theme:", self)
        layout.addWidget(theme_label)
        self.theme_combo = ComboBox(self)
        self.theme_combo.addItems(["Light", "Dark", "Follow System"])
        layout.addWidget(self.theme_combo)
        layout.addStretch()

        # Set current theme in combo box
        current_theme = qconfig.theme
        if current_theme == Theme.LIGHT:
            self.theme_combo.setCurrentIndex(0)
        elif current_theme == Theme.DARK:
            self.theme_combo.setCurrentIndex(1)
        else:
            self.theme_combo.setCurrentIndex(2)

        self.theme_combo.currentIndexChanged.connect(self.on_theme_changed)

    def on_theme_changed(self, index):
        if index == 0:
            setTheme(Theme.LIGHT)
        elif index == 1:
            setTheme(Theme.DARK)
        else:
            setTheme(Theme.AUTO) 