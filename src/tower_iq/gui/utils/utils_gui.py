# Centralized theme utilities for TowerIQ PyQt app
from PyQt6.QtWidgets import QWidget, QLabel
from PyQt6.QtGui import QFont, QIcon, QTransform
from PyQt6.QtCore import Qt
from qfluentwidgets import isDarkTheme, setStyleSheet, FluentStyleSheet, FluentIcon
from typing import Union

# Import stylesheets from the stylesheets package

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

def rotate_icon(base_icon: FluentIcon, width: int, height: int, angle: int) -> QIcon:
    qicon = base_icon.icon()
    pixmap = qicon.pixmap(width, height)  # size can be adjusted
    transform = QTransform().rotate(angle)
    rotated_pixmap = pixmap.transformed(transform)
    return QIcon(rotated_pixmap)


class FlexibleIconWidget(QLabel):
    """
    A flexible icon widget that can handle FluentIcon, SVG files, and font-based icons.
    """
    
    def __init__(self, icon_source: Union[FluentIcon, str, QIcon] | None = None, 
                 icon_size: int = 16, parent=None):
        super().__init__(parent)
        self.icon_source = icon_source
        self.icon_size = icon_size
        self.setFixedSize(icon_size, icon_size)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        if icon_source is not None:
            self.set_icon(icon_source)
    
    def set_icon(self, icon_source: Union[FluentIcon, str, QIcon]):
        """Set the icon from various sources."""
        self.icon_source = icon_source
        
        if icon_source is None:
            self.clear()
            return
            
        if isinstance(icon_source, FluentIcon):
            # Handle FluentIcon
            qicon = icon_source.icon()
            pixmap = qicon.pixmap(self.icon_size, self.icon_size)
            self.setPixmap(pixmap)
            
        elif isinstance(icon_source, QIcon):
            # Handle QIcon
            pixmap = icon_source.pixmap(self.icon_size, self.icon_size)
            self.setPixmap(pixmap)
            
        elif isinstance(icon_source, str):
            # Handle string paths (SVG, PNG, etc.)
            if icon_source.startswith('\\') or icon_source.startswith('/'):
                # Font-based icon (e.g., Material Symbols)
                self.set_font_icon(icon_source)
            else:
                # File path
                try:
                    qicon = QIcon(icon_source)
                    pixmap = qicon.pixmap(self.icon_size, self.icon_size)
                    self.setPixmap(pixmap)
                except Exception:
                    # Fallback to default icon
                    self.set_default_icon()
        else:
            self.set_default_icon()
    
    def set_font_icon(self, font_icon: str):
        """Set a font-based icon (e.g., Material Symbols)."""
        # Set up font for Material Symbols or other icon fonts
        font = QFont("Material Symbols Rounded")
        font.setPointSize(self.icon_size // 2)
        self.setFont(font)
        self.setText(font_icon)
    
    def set_default_icon(self):
        """Set a default icon when the provided icon cannot be loaded."""
        # Use a simple dot as default
        self.setText("•")
        font = QFont()
        font.setPointSize(self.icon_size // 2)
        self.setFont(font)
