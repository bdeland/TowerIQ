"""
TowerIQ Connection Settings Page

This module provides the connection settings content.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QScrollArea, QHBoxLayout
from qfluentwidgets import FluentIcon, PushButton, CardWidget, BodyLabel, qconfig

from ..utils.settings_item_card import SettingsItemCard
from ..utils.expandable_settings_card import ExpandableCardGroup, SubsettingItem


class ConnectionSettingsPage(QWidget):
    """Connection Settings content page."""
    
    def __init__(self, config_manager=None, parent: QWidget | None = None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.selected_device = None
        self.selected_process = None
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the connection settings user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Connect to theme change signal
        qconfig.themeChanged.connect(self.on_theme_changed)
        
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
        """Set up the connection settings content."""
        # Create the expandable auto-connect card group
        self.auto_connect_card = ExpandableCardGroup(
            title="Auto-Connect",
            content="Automatically connect to an Android emulator and process on startup",
            header_icon=FluentIcon.CONNECT,
            expand_icon=FluentIcon.ARROW_DOWN,
            collapse_icon=FluentIcon.ARROW_DOWN,
        )
        
        # Set current value from config
        if self.config_manager:
            is_enabled = self.config_manager.get('gui.auto_connect_emulator', False)
            self.auto_connect_card.set_toggle_state(bool(is_enabled))
        
        # Connect toggle signal
        self.auto_connect_card.toggle_changed.connect(self.on_auto_connect_changed)
        
        # Create Device subsetting card
        self.device_select_button = PushButton("Select", self)
        self.device_select_button.clicked.connect(self.on_device_select_clicked)
        
        self.device_card = SubsettingItem("Device", self.device_select_button)
        
        # Create Process subsetting card
        self.process_select_button = PushButton("Select", self)
        self.process_select_button.clicked.connect(self.on_process_select_clicked)
        self.process_select_button.setEnabled(False)  # Initially disabled
        
        self.process_card = SubsettingItem("Process", self.process_select_button)
        
        # Add the subsetting cards to the expandable group
        self.auto_connect_card.add_card(self.device_card)
        self.auto_connect_card.add_card(self.process_card)
        
        # Load saved device and process selections
        self.load_saved_selections()
        
        content_layout.addWidget(self.auto_connect_card)
        
    def on_auto_connect_changed(self, checked: bool):
        """Handle auto-connect setting change."""
        if self.config_manager:
            self.config_manager.set('gui.auto_connect_emulator', checked, description="Auto-connect to emulator setting")
            
    def on_device_select_clicked(self):
        """Handle device select button click."""
        # TODO: Open device selector dialog
        # For now, just simulate selecting a device
        self.selected_device = "emulator-5554"  # Mock device
        self.device_select_button.setText("emulator-5554")
        
        # Enable process selection
        self.process_select_button.setEnabled(True)
        
        # Save device selection
        if self.config_manager:
            self.config_manager.set('gui.auto_connect_device', self.selected_device, description="Auto-connect device selection")
            
    def on_process_select_clicked(self):
        """Handle process select button click."""
        # TODO: Open process selector dialog
        # For now, just simulate selecting a process
        self.selected_process = "com.TechTreeGames.TheTower"  # Mock process
        self.process_select_button.setText("The Tower")
        
        # Save process selection
        if self.config_manager:
            self.config_manager.set('gui.auto_connect_process', self.selected_process, description="Auto-connect process selection")
            
    def load_saved_selections(self):
        """Load saved device and process selections from config."""
        if not self.config_manager:
            return
            
        # Load device selection
        saved_device = self.config_manager.get('gui.auto_connect_device', None)
        if saved_device:
            self.selected_device = saved_device
            self.device_select_button.setText(saved_device)
            self.process_select_button.setEnabled(True)
            
        # Load process selection
        saved_process = self.config_manager.get('gui.auto_connect_process', None)
        if saved_process:
            self.selected_process = saved_process
            self.process_select_button.setText(saved_process) 

    def on_theme_changed(self):
        """Handle theme changes by updating the expandable card styling."""
        # Theme changes are now handled automatically by CardWidget inheritance
        pass 