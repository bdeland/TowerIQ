# Centralized theme utilities for TowerIQ PyQt app
from PyQt6.QtWidgets import QWidget
from PyQt6.QtGui import QFont
from qfluentwidgets import isDarkTheme, qconfig

def get_text_color() -> str:
    """Returns the primary text color based on the current theme."""
    return "white" if isDarkTheme() else "black"

def get_border_color() -> str:
    """Returns the border/divider color based on the current theme."""
    return "#3e3e3e" if isDarkTheme() else "#dcdcdc"

def get_title_font() -> QFont:
    """Returns the standard font for page titles."""
    font = QFont()
    font.setPointSize(24)
    font.setBold(True)
    return font

class ThemeAwareWidget(QWidget):
    """
    A base QWidget that automatically connects to the theme change signal
    and calls an update method.
    
    Subclasses MUST implement the `update_theme_styles` method.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        # Automatically connect to the theme change signal
        qconfig.themeChanged.connect(self.update_theme_styles)

    def update_theme_styles(self):
        """
        This method is called automatically when the theme changes.
        Subclasses must implement this method to update their specific styles.
        """
        raise NotImplementedError("Subclasses must implement 'update_theme_styles'")
