"""
TowerIQ Logging Settings Widget

This module provides a GUI widget for configuring logging settings
in a user-friendly way with category-based controls.
"""

from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QWidget
)
from PyQt6.QtCore import pyqtSignal
from qfluentwidgets import SwitchButton, ComboBox, SpinBox, PushButton

from .utils_gui import get_text_color
from ...core.logging_config import get_all_available_categories, LOG_SOURCE_CATEGORIES


class LoggingSettingsWidget(QWidget):
    """
    Widget for configuring logging settings with category-based controls.
    """
    
    # Signal emitted when logging settings change
    logging_settings_changed = pyqtSignal()
    
    def __init__(self, config_manager, parent=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.setup_ui()
        self.load_current_settings()
        
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Log Level Configuration
        level_group = QGroupBox("Log Level")
        level_layout = QHBoxLayout()
        
        self.level_label = QLabel("Console Log Level:")
        self.level_label.setStyleSheet(f"color: {get_text_color()};")
        self.level_combo = ComboBox()
        self.level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.level_combo.currentTextChanged.connect(self.on_log_level_changed)
        
        level_layout.addWidget(self.level_label)
        level_layout.addWidget(self.level_combo)
        level_layout.addStretch()
        level_group.setLayout(level_layout)
        layout.addWidget(level_group)
        
        # Log Categories Configuration
        categories_group = QGroupBox("Log Categories")
        categories_layout = QVBoxLayout()
        
        # Get category descriptions
        category_descriptions = get_all_available_categories()
        
        self.category_switches = {}
        for category, description in category_descriptions.items():
            switch = SwitchButton(f"{category.title()}: {description}")
            switch.checkedChanged.connect(self.on_category_changed)
            self.category_switches[category] = switch
            categories_layout.addWidget(switch)
        
        categories_group.setLayout(categories_layout)
        layout.addWidget(categories_group)
        
        # File Logging Configuration
        file_group = QGroupBox("File Logging")
        file_layout = QVBoxLayout()
        
        # Enable file logging
        self.file_enabled_switch = SwitchButton("Enable File Logging")
        self.file_enabled_switch.checkedChanged.connect(self.on_file_logging_changed)
        file_layout.addWidget(self.file_enabled_switch)
        
        # File log level
        file_level_layout = QHBoxLayout()
        self.file_level_label = QLabel("File Log Level:")
        self.file_level_label.setStyleSheet(f"color: {get_text_color()};")
        self.file_level_combo = ComboBox()
        self.file_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.file_level_combo.currentTextChanged.connect(self.on_file_level_changed)
        
        file_level_layout.addWidget(self.file_level_label)
        file_level_layout.addWidget(self.file_level_combo)
        file_level_layout.addStretch()
        file_layout.addLayout(file_level_layout)
        
        # File size settings
        size_layout = QHBoxLayout()
        self.size_label = QLabel("Max File Size (MB):")
        self.size_label.setStyleSheet(f"color: {get_text_color()};")
        self.max_size_spin = SpinBox()
        self.max_size_spin.setRange(1, 1000)
        # Load default value from config
        default_max_size = self.config_manager.get('logging.file.max_size_mb', 50) if self.config_manager else 50
        self.max_size_spin.setValue(default_max_size)
        self.max_size_spin.valueChanged.connect(self.on_max_size_changed)
        
        size_layout.addWidget(self.size_label)
        size_layout.addWidget(self.max_size_spin)
        size_layout.addStretch()
        file_layout.addLayout(size_layout)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Quick Presets
        presets_group = QGroupBox("Quick Presets")
        presets_layout = QHBoxLayout()
        
        self.preset_debug = PushButton("Debug Mode")
        self.preset_debug.clicked.connect(lambda: self.apply_preset("debug"))
        
        self.preset_normal = PushButton("Normal Mode")
        self.preset_normal.clicked.connect(lambda: self.apply_preset("normal"))
        
        self.preset_minimal = PushButton("Minimal Mode")
        self.preset_minimal.clicked.connect(lambda: self.apply_preset("minimal"))
        
        presets_layout.addWidget(self.preset_debug)
        presets_layout.addWidget(self.preset_normal)
        presets_layout.addWidget(self.preset_minimal)
        presets_layout.addStretch()
        
        presets_group.setLayout(presets_layout)
        layout.addWidget(presets_group)
        
        # Apply Button
        self.apply_button = PushButton("Apply Logging Settings")
        self.apply_button.clicked.connect(self.apply_settings)
        layout.addWidget(self.apply_button)
        
        layout.addStretch()
        
    def load_current_settings(self):
        """Load current logging settings from configuration."""
        # Load log level
        current_level = self.config_manager.get('logging.console.level', 'INFO')
        self.level_combo.setCurrentText(current_level)
        
        # Load file settings
        file_enabled = self.config_manager.get('logging.file.enabled', False)
        self.file_enabled_switch.setChecked(file_enabled)
        
        file_level = self.config_manager.get('logging.file.level', 'INFO')
        self.file_level_combo.setCurrentText(file_level)
        
        max_size = self.config_manager.get('logging.file.max_size_mb', 50)
        self.max_size_spin.setValue(max_size)
        
        # Load categories - block signals during initialization to prevent multiple saves
        categories_config = self.config_manager.get('logging.categories', {})
        if not categories_config:
            # Fallback to old sources list - convert to categories
            sources = set(self.config_manager.get('logging.sources', []))
            categories_config = self._sources_to_categories(sources)
        
        # Block signals during category switch initialization
        for switch in self.category_switches.values():
            switch.blockSignals(True)
        
        for category, switch in self.category_switches.items():
            enabled = categories_config.get(category, True)  # Default to True
            switch.setChecked(enabled)
        
        # Unblock signals after all switches are set
        for switch in self.category_switches.values():
            switch.blockSignals(False)
    
    def _sources_to_categories(self, sources: set) -> dict:
        """Convert old sources list to new categories configuration."""
        categories = {}
        for category, category_sources in LOG_SOURCE_CATEGORIES.items():
            # Enable category if any of its sources are in the enabled sources
            categories[category] = bool(sources & category_sources)
        return categories
    
    def on_log_level_changed(self, level: str):
        """Handle log level change."""
        self.config_manager.set('logging.console.level', level)
        self.logging_settings_changed.emit()
    
    def on_category_changed(self, checked: bool):
        """Handle category toggle change."""
        self._update_categories_config()
        self.logging_settings_changed.emit()
    
    def on_file_logging_changed(self, checked: bool):
        """Handle file logging toggle change."""
        self.config_manager.set('logging.file.enabled', checked)
        self.logging_settings_changed.emit()
    
    def on_file_level_changed(self, level: str):
        """Handle file log level change."""
        self.config_manager.set('logging.file.level', level)
        self.logging_settings_changed.emit()
    
    def on_max_size_changed(self, size: int):
        """Handle max file size change."""
        self.config_manager.set('logging.file.max_size_mb', size)
        self.logging_settings_changed.emit()
    
    def _update_categories_config(self):
        """Update the categories configuration based on current switch states."""
        categories_config = {}
        for category, switch in self.category_switches.items():
            categories_config[category] = switch.isChecked()
        
        self.config_manager.set('logging.categories', categories_config)
    
    def apply_preset(self, preset_name: str):
        """Apply a predefined logging preset."""
        if preset_name == "debug":
            # Debug mode: all categories enabled, DEBUG level
            self.level_combo.setCurrentText("DEBUG")
            for switch in self.category_switches.values():
                switch.setChecked(True)
                
        elif preset_name == "normal":
            # Normal mode: most categories enabled, INFO level
            self.level_combo.setCurrentText("INFO")
            for category, switch in self.category_switches.items():
                # Disable system category by default
                switch.setChecked(category != "system")
                
        elif preset_name == "minimal":
            # Minimal mode: only essential categories, WARNING level
            self.level_combo.setCurrentText("WARNING")
            for category, switch in self.category_switches.items():
                # Only enable application and frida
                switch.setChecked(category in ["application", "frida"])
        
        self._update_categories_config()
        self.logging_settings_changed.emit()
    
    def apply_settings(self):
        """Apply all current settings."""
        self._update_categories_config()
        self.logging_settings_changed.emit()
    
    def update_theme_styles(self):
        """Update theme-dependent styles."""
        text_color = get_text_color()
        
        # Update label colors
        if hasattr(self, 'level_label'):
            self.level_label.setStyleSheet(f"color: {text_color};")
        if hasattr(self, 'file_level_label'):
            self.file_level_label.setStyleSheet(f"color: {text_color};")
        if hasattr(self, 'size_label'):
            self.size_label.setStyleSheet(f"color: {text_color};") 