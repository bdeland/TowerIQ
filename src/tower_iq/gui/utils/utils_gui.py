# Centralized theme utilities for TowerIQ PyQt app
from PyQt6.QtWidgets import QWidget
from PyQt6.QtGui import QFont
from qfluentwidgets import isDarkTheme, qconfig, setStyleSheet, FluentStyleSheet, ThemeColor, themeColor
from qfluentwidgets.common.style_sheet import StyleSheetManager

# Import stylesheets from the stylesheets package
from ..stylesheets import (
    get_themed_stylesheet,
    THEME_COLORS,
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


