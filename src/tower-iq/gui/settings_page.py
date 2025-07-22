from PyQt6.QtWidgets import QVBoxLayout, QLabel
from qfluentwidgets import ComboBox, Theme, setTheme, qconfig
from .utils_gui import ThemeAwareWidget, get_title_font, get_text_color

class SettingsPage(ThemeAwareWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.label = QLabel("Settings", self)
        layout.addWidget(self.label)

        # Theme selection
        theme_label = QLabel("Theme:", self)
        layout.addWidget(theme_label)
        self.theme_combo = ComboBox(self)
        self.theme_combo.addItems(["Light", "Dark", "Follow System"])
        layout.addWidget(self.theme_combo)
        layout.addStretch()

        # Set default theme to Follow System
        setTheme(Theme.AUTO)  # Set initial theme to Follow System
        current_theme = qconfig.theme
        if current_theme == Theme.LIGHT:
            self.theme_combo.setCurrentIndex(0)
        elif current_theme == Theme.DARK:
            self.theme_combo.setCurrentIndex(1)
        else:
            self.theme_combo.setCurrentIndex(2)  # Follow System

        self.theme_combo.currentIndexChanged.connect(self.on_theme_combo_changed)

        self.update_theme_styles()  # Set initial style

    def update_theme_styles(self):
        self.label.setFont(get_title_font())
        self.label.setStyleSheet(f"color: {get_text_color()};")
        # Add more theme-dependent styling here if needed

    def on_theme_combo_changed(self, index):
        if index == 0:
            setTheme(Theme.LIGHT)
        elif index == 1:
            setTheme(Theme.DARK)
        else:
            setTheme(Theme.AUTO) 

    