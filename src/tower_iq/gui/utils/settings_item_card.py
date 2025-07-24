"""
TowerIQ Settings Item Card Widget (Improved)

This module provides a settings item widget using QFluentWidgets CardWidget
for displaying individual settings items in a Windows 11-style layout.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (SimpleCardWidget, FluentIcon, IconWidget, SwitchButton, ComboBox, BodyLabel, CaptionLabel)
from typing import Union

class SettingsItemCard(SimpleCardWidget):
    """
    A settings item widget for a Windows 11-style design that is fully
    theme-aware and supports custom controls on the right side.

    This card features an icon on the left, a title/description block, and
    a right-aligned control widget, all vertically centered.
    """
    
    def __init__(self, title: str, content: str, icon: Union[FluentIcon, str], parent: QWidget | None = None):
        super().__init__(parent)
        
        # Store properties
        self.title_text = title
        self.content_text = content
        self.icon_source = icon
        
        # Placeholder for the control widget
        self.control_widget: QWidget | None = None
        
        # Build the UI
        self._setup_ui()
        
    def _setup_ui(self):
        """Set up the card's user interface."""
        # Main horizontal layout for the entire card
        self.main_layout = QHBoxLayout(self)
        self.main_layout.setContentsMargins(15, 12, 15, 12)
        self.main_layout.setSpacing(15)

        # 1. Icon on the left
        self.icon_widget = IconWidget(self.icon_source, self)
        self.icon_widget.setFixedSize(22, 22)
        
        # 2. Vertical layout for Title and Description
        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(2)
        
        # Use theme-aware labels from qfluentwidgets
        self.title_label = BodyLabel(self.title_text, self)
        self.content_label = CaptionLabel(self.content_text, self)
        self.content_label.setWordWrap(True)
        text_layout.addWidget(self.title_label)
        text_layout.addWidget(self.content_label)

        # Add widgets and layouts to the main layout
        self.main_layout.addWidget(self.icon_widget, 0, Qt.AlignmentFlag.AlignVCenter)
        self.main_layout.addLayout(text_layout, 1)
        
    def add_control(self, widget: QWidget):
        """
        Adds a control widget (e.g., SwitchButton, ComboBox) to the
        right side of the card.
        """
        if self.control_widget:
            # Remove any existing control
            self.main_layout.removeWidget(self.control_widget)
            self.control_widget.deleteLater()

        self.control_widget = widget
        widget.setParent(self)
        self.main_layout.addWidget(widget, 0, Qt.AlignmentFlag.AlignVCenter)
        
    def add_switch_control(self, checked: bool = False) -> SwitchButton:
        """Helper to add a theme-aware SwitchButton to the card."""
        switch = SwitchButton(self)
        switch.setChecked(checked)
        self.add_control(switch)
        return switch
        
    def add_dropdown_control(self, items: list, current_text: str | None = None) -> ComboBox:
        """Helper to add a theme-aware ComboBox (dropdown) to the card."""
        dropdown = ComboBox(self)
        dropdown.addItems(items)
        if current_text:
            dropdown.setCurrentText(current_text)
        self.add_control(dropdown)
        return dropdown