# Centralized theme utilities for TowerIQ PyQt app
from PyQt6.QtWidgets import QWidget
from PyQt6.QtGui import QFont
from qfluentwidgets import isDarkTheme, qconfig, setStyleSheet, FluentStyleSheet, ThemeColor, themeColor
from qfluentwidgets.common.style_sheet import StyleSheetManager

# Import stylesheets from the stylesheets package
from ..stylesheets import (
    SETTINGS_PAGE_LIGHT_QSS,
    SETTINGS_PAGE_DARK_QSS,
    SETTINGS_CONTENT_WIDGET_LIGHT_QSS,
    SETTINGS_CONTENT_WIDGET_DARK_QSS,
    LIGHT_THEME_COLORS,
    DARK_THEME_COLORS
)

def get_text_color() -> str:
    """Returns the primary text color based on the current theme."""
    return "white" if isDarkTheme() else "black"

def get_border_color() -> str:
    """Returns the border/divider color based on the current theme."""
    return "#3e3e3e" if isDarkTheme() else "#dcdcdc"

def get_background_color() -> str:
    """Returns the primary background color based on the current theme."""
    return "#1f1f1f" if isDarkTheme() else "#ffffff"

def get_main_content_background_color() -> str:
    """Returns the main content area background color based on the current theme."""
    return "#272727" if isDarkTheme() else "#ffffff"

def get_content_background_color() -> str:
    """Returns the content area background color based on the current theme."""
    return "#2d2d2d" if isDarkTheme() else "#f8f8f8"

def get_title_font() -> QFont:
    """Returns the standard font for page titles."""
    font = QFont()
    font.setPointSize(24)
    font.setBold(True)
    return font

def apply_fluent_style_sheet(widget: QWidget, style_sheet: FluentStyleSheet):
    """Apply a Fluent style sheet to a widget with automatic theme updates."""
    setStyleSheet(widget, style_sheet, register=True)

def apply_custom_style_sheet(widget: QWidget, light_qss: str, dark_qss: str):
    """Apply custom style sheet with light and dark theme variants."""
    # Use direct style sheet application for better compatibility
    if isDarkTheme():
        widget.setStyleSheet(dark_qss)
    else:
        widget.setStyleSheet(light_qss)

class ThemeAwareWidget(QWidget):
    """
    A base QWidget that automatically connects to the theme change signal
    and calls an update method.
    
    Subclasses MUST implement the `update_theme_styles` method.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        # Store custom style sheets for theme changes
        self._light_qss = None
        self._dark_qss = None
        # Automatically connect to the theme change signal
        qconfig.themeChanged.connect(self.update_theme_styles)

    def update_theme_styles(self):
        """
        This method is called automatically when the theme changes.
        Subclasses must implement this method to update their specific styles.
        """
        raise NotImplementedError("Subclasses must implement 'update_theme_styles'")
        
    def apply_fluent_style(self, style_sheet: FluentStyleSheet):
        """Apply a Fluent style sheet to this widget."""
        apply_fluent_style_sheet(self, style_sheet)
        
    def apply_custom_style(self, light_qss: str, dark_qss: str):
        """Apply custom style sheet to this widget."""
        # Store the style sheets for theme changes
        self._light_qss = light_qss
        self._dark_qss = dark_qss
        apply_custom_style_sheet(self, light_qss, dark_qss)
        
    def _reapply_custom_style(self):
        """Reapply custom style sheets when theme changes."""
        if self._light_qss and self._dark_qss:
            apply_custom_style_sheet(self, self._light_qss, self._dark_qss)
