"""
TowerIQ Appearance Settings Page

This module provides the appearance and theme settings content.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QScrollArea
from qfluentwidgets import FluentIcon, Theme, setTheme

from ..utils.settings_item_card import SettingsItemCard


class AppearanceSettingsPage(QWidget):
    """Appearance & Theme settings content page."""
    
    def __init__(self, config_manager=None, parent: QWidget | None = None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the appearance settings user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Create scrollable content area
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("border: 0px transparent;")

        content_widget = QWidget()
        content_widget.setObjectName("content_widget")
        content_widget.setStyleSheet("border: 0px transparent; background-color: transparent;")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        # Add settings content
        self.setup_content(content_layout)
        
        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)
        
    def setup_content(self, content_layout: QVBoxLayout):
        """Set up the appearance settings content using SettingsItemCard."""
        # Theme selection card
        theme_card = SettingsItemCard(
            title="Application theme",
            content="Change the appearance of your application",
            icon=FluentIcon.PALETTE
        )
        self.theme_combo = theme_card.add_dropdown_control(
            items=["Light", "Dark", "Follow System"],
            current_text=self._get_current_theme_text()
        )
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        content_layout.addWidget(theme_card)
        
        # Theme color card
        color_card = SettingsItemCard(
            title="Theme color",
            content="Change the accent color of your application",
            icon=FluentIcon.PALETTE
        )
        # Load theme colors from config
        theme_colors = self.config_manager.get('gui.appearance.theme_colors', ["Default color", "Blue", "Green", "Purple", "Pink"]) if self.config_manager else ["Default color", "Blue", "Green", "Purple", "Pink"]
        current_theme_color = self.config_manager.get('gui.appearance.theme_color', "Default color") if self.config_manager else "Default color"
        color_card.add_dropdown_control(
            items=theme_colors,
            current_text=current_theme_color
        )
        content_layout.addWidget(color_card)
        
        # Interface zoom card
        zoom_card = SettingsItemCard(
            title="Interface zoom",
            content="Change the size of widgets and fonts",
            icon=FluentIcon.ZOOM
        )
        # Load zoom levels from config
        zoom_levels = self.config_manager.get('gui.appearance.zoom_levels', ["Use system setting", "100%", "125%", "150%"]) if self.config_manager else ["Use system setting", "100%", "125%", "150%"]
        current_zoom = self.config_manager.get('gui.appearance.interface_zoom', "Use system setting") if self.config_manager else "Use system setting"
        zoom_card.add_dropdown_control(
            items=zoom_levels,
            current_text=current_zoom
        )
        content_layout.addWidget(zoom_card)
        
    def _get_current_theme_text(self) -> str:
        """Get the current theme text for the dropdown from config or qconfig."""
        saved_theme = self.config_manager.get('gui.theme', 'auto') if self.config_manager else 'auto'
        if saved_theme == "light":
            return "Light"
        elif saved_theme == "dark":
            return "Dark"
        return "Follow System"
        
    def on_theme_changed(self, theme_text: str):
        """Handle theme selection change."""
        theme_map = {
            "Light": (Theme.LIGHT, "light"),
            "Dark": (Theme.DARK, "dark"),
            "Follow System": (Theme.AUTO, "auto")
        }
        theme_enum, theme_value = theme_map.get(theme_text, (Theme.AUTO, "auto"))
        
        setTheme(theme_enum)
        
        if self.config_manager:
            self.config_manager.set('gui.theme', theme_value, description="Application theme setting") 