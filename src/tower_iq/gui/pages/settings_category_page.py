"""
TowerIQ Settings Category Pages

This module provides separate pages for each settings category.
Styling is handled globally by the application's main stylesheet,
and theme-aware widgets from qfluentwidgets are used for automatic
color and font updates.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QScrollArea
from qfluentwidgets import (FluentIcon, ComboBox, SwitchButton, LineEdit, SpinBox,
                            Theme, setTheme, qconfig, TitleLabel, BodyLabel)

from ..utils.settings_item_card import SettingsItemCard
from ..utils.content_page import ContentPage


class SettingsCategoryPage(ContentPage):
    """
    Base class for settings category pages.

    Features:
    - Inherits from ContentPage for consistent title + description + content layout
    - Scrollable content area for holding setting cards
    - Styling is handled globally via the main application stylesheet
    """
    
    def __init__(self, category_title: str, config_manager=None, parent: QWidget | None = None):
        super().__init__(title=category_title, description="", parent=parent)
        self.category_title = category_title
        self.config_manager = config_manager
        
        # Create scrollable content area
        self._create_scrollable_content()
        
    def _create_scrollable_content(self):
        """Create a scrollable content area for settings cards."""
        # Content section (scrollable)
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("border: 0px transparent;")

        self.content_widget = QWidget()
        self.content_widget.setObjectName("content_widget")
        self.content_widget.setStyleSheet("border: 0px transparent; background-color: transparent;")
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(10)
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        scroll_area.setWidget(self.content_widget)
        
        # Add the scroll area to the content container from the base class
        content_container = self.get_content_container()
        layout = QVBoxLayout(content_container)
        layout.addWidget(scroll_area)
        

class AppearanceSettingsPage(SettingsCategoryPage):
    """Appearance & Theme settings page."""
    
    def __init__(self, config_manager=None, parent: QWidget | None = None):
        super().__init__("Appearance & Theme", config_manager, parent)
        self.setup_content()
        
    def setup_content(self):
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
        self.content_layout.addWidget(theme_card)
        
        # Theme color card
        color_card = SettingsItemCard(
            title="Theme color",
            content="Change the accent color of your application",
            icon=FluentIcon.PALETTE
        )
        color_card.add_dropdown_control(
            items=["Default color", "Blue", "Green", "Purple", "Pink"],
            current_text="Default color"
        )
        self.content_layout.addWidget(color_card)
        
        # Interface zoom card
        zoom_card = SettingsItemCard(
            title="Interface zoom",
            content="Change the size of widgets and fonts",
            icon=FluentIcon.ZOOM
        )
        zoom_card.add_dropdown_control(
            items=["Use system setting", "100%", "125%", "150%"],
            current_text="Use system setting"
        )
        self.content_layout.addWidget(zoom_card)
        
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
            self.config_manager.set('gui.theme', theme_value)


class LoggingSettingsPage(SettingsCategoryPage):
    """Logging & Diagnostics settings page."""
    
    def __init__(self, config_manager=None, parent: QWidget | None = None):
        super().__init__("Logging & Diagnostics", config_manager, parent)
        self.setup_content()
        
    def setup_content(self):
        """Set up the logging settings content."""
        placeholder = BodyLabel("Logging settings will be implemented here.", self)
        self.content_layout.addWidget(placeholder)


class ConnectionSettingsPage(SettingsCategoryPage):
    """Connection Settings page."""
    
    def __init__(self, config_manager=None, parent: QWidget | None = None):
        super().__init__("Connection Settings", config_manager, parent)
        self.setup_content()
        
    def setup_content(self):
        """Set up the connection settings content."""
        auto_connect_card = SettingsItemCard(
            title="Auto-connect to emulator",
            content="Automatically connect on startup if an emulator is running",
            icon=FluentIcon.CONNECT
        )
        auto_connect_switch = auto_connect_card.add_switch_control()
        auto_connect_switch.checkedChanged.connect(self.on_auto_connect_changed)

        # Set current value from config
        if self.config_manager:
            is_enabled = self.config_manager.get('gui.auto_connect_emulator', False)
            auto_connect_switch.setChecked(bool(is_enabled))
            
        self.content_layout.addWidget(auto_connect_card)
        
    def on_auto_connect_changed(self, checked: bool):
        """Handle auto-connect setting change."""
        if self.config_manager:
            self.config_manager.set('gui.auto_connect_emulator', checked)


class DatabaseSettingsPage(SettingsCategoryPage):
    """Database & Storage settings page."""
    
    def __init__(self, config_manager=None, parent: QWidget | None = None):
        super().__init__("Database & Storage", config_manager, parent)
        self.setup_content()
        
    def setup_content(self):
        """Set up the database settings content."""
        db_path_card = SettingsItemCard(
            title="Database Path",
            content="The location of the application's SQLite database file",
            icon=FluentIcon.FOLDER
        )
        db_path_edit = LineEdit(self)
        db_path_card.add_control(db_path_edit)
        
        if self.config_manager:
            db_path = self.config_manager.get('database.path', 'data/toweriq.sqlite')
            db_path_edit.setText(db_path)
        
        self.content_layout.addWidget(db_path_card)


class FridaSettingsPage(SettingsCategoryPage):
    """Frida Configuration settings page."""
    
    def __init__(self, config_manager=None, parent: QWidget | None = None):
        super().__init__("Frida Configuration", config_manager, parent)
        self.setup_content()
        
    def setup_content(self):
        """Set up the Frida settings content."""
        placeholder = BodyLabel("Frida configuration settings will be implemented here.", self)
        self.content_layout.addWidget(placeholder)


class AdvancedSettingsPage(SettingsCategoryPage):
    """Advanced Settings page."""
    
    def __init__(self, config_manager=None, parent: QWidget | None = None):
        super().__init__("Advanced Settings", config_manager, parent)
        self.setup_content()
        
    def setup_content(self):
        """Set up the advanced settings content."""
        placeholder = BodyLabel("Advanced settings will be implemented here.", self)
        self.content_layout.addWidget(placeholder)