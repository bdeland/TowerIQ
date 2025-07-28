"""
TowerIQ Expandable Settings Card Widget

This module provides an expandable settings card widget that mimics the Windows 11
ExpandGroupSettingCard functionality with a toggle switch, dropdown arrow, and subsettings.
"""

from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFrame
from qfluentwidgets import (
    CardWidget, FluentIcon, SwitchButton, 
    BodyLabel, CaptionLabel
)
from typing import Union
from PyQt6.QtGui import QIcon
from ..utils.utils_gui import rotate_icon, FlexibleIconWidget

# A small gap between the header and the content when expanded
SPACING = 4

class HeaderCard(CardWidget):
    """The clickable header card with a toggle and expand/collapse icon."""
    clicked = pyqtSignal()

    def __init__(self, title: str, content: str, 
                 header_icon: Union[FluentIcon, str, QIcon] | None = None,
                 expand_icon: Union[FluentIcon, str, QIcon] | None = None,
                 collapse_icon: Union[FluentIcon, str, QIcon] | None = None, parent=None):
        super().__init__(parent)
        self.is_expanded = False
        self.setObjectName("HeaderCard")

        # Store icons for different states
        self.header_icon = header_icon
        self.expand_icon = expand_icon if expand_icon is not None else FluentIcon.ARROW_DOWN
        self.collapse_icon = collapse_icon if collapse_icon is not None else FluentIcon.ARROW_DOWN

        # Layout for the header content
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 8, 8)
        layout.setSpacing(12)

        # Header icon (left side) - only add if provided
        self.header_icon_widget = None
        if self.header_icon is not None:
            self.header_icon_widget = FlexibleIconWidget(self.header_icon, 22, self)
            layout.addWidget(self.header_icon_widget)

        # Text content (title and description)
        self.title_label = BodyLabel(title, self)
        self.content_label = CaptionLabel(content, self)
        self.content_label.setWordWrap(True)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        text_layout.addWidget(self.title_label)
        text_layout.addWidget(self.content_label)

        layout.addLayout(text_layout,1)

        # Toggle switch
        self.toggle_switch = SwitchButton(self)
        layout.addWidget(self.toggle_switch)

        # Expand/collapse icon (right side)
        self.expand_collapse_icon = FlexibleIconWidget(self.expand_icon, 16, self)
        layout.addWidget(self.expand_collapse_icon)

        # Set initial state
        self.set_expanded(False)

    def mouseReleaseEvent(self, e):
        """Override to emit a simple clicked signal on mouse release."""
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        # Don't call super() as it interferes with CardWidget's own click handling

    def set_expanded(self, expanded: bool):
        """Set the expanded state and update visual properties."""
        self.is_expanded = expanded
        
        # Update the expand/collapse icon based on state
        if expanded:
            self.expand_collapse_icon.set_icon(self.collapse_icon)
        else:
            self.expand_collapse_icon.set_icon(self.expand_icon)


class ExpandableCardGroup(QWidget):
    """
    A container that manages a header and a collapsible group of sub-cards.
    """
    toggle_changed = pyqtSignal(bool)

    def __init__(self, title: str, content: str, 
                 header_icon: Union[FluentIcon, str, QIcon] | None = None,
                 expand_icon: Union[FluentIcon, str, QIcon] | None = None,
                 collapse_icon: Union[FluentIcon, str, QIcon] | None = None,
                 parent: QWidget | None = None):
        super().__init__(parent)
        self.sub_cards = []

        # Main Layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Header Card
        self.header_card = HeaderCard(title, content, 
                                     header_icon=header_icon,
                                     expand_icon=expand_icon,
                                     collapse_icon=collapse_icon,
                                     parent=self)
        self.header_card.toggle_switch.checkedChanged.connect(self.toggle_changed)
        self.header_card.clicked.connect(self._toggle_expansion)

        # Spacer Item (for visual separation)
        self.spacer = QFrame(self)
        self.spacer.setFixedHeight(SPACING)

        # Content Container (for sub-cards)
        self.content_container = QWidget(self)
        self.content_layout = QVBoxLayout(self.content_container)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(SPACING)

        # Add widgets to main layout
        self.main_layout.addWidget(self.header_card)
        self.main_layout.addWidget(self.spacer)
        self.main_layout.addWidget(self.content_container)

        # Set initial state
        self.content_container.setVisible(False)
        self.spacer.setVisible(False)

    def _toggle_expansion(self):
        """Toggle the expansion state of the card group."""
        is_visible = not self.content_container.isVisible()
        
        # Show/hide the content container and spacer
        self.content_container.setVisible(is_visible)
        self.spacer.setVisible(is_visible)
        
        # Explicitly show/hide all sub-cards
        for card in self.sub_cards:
            card.setVisible(is_visible)
        
        self.header_card.set_expanded(is_visible)
        
        # Force layout refresh
        self.main_layout.invalidate()
        self.main_layout.activate()
        self.content_layout.invalidate()
        self.content_layout.activate()
        
        # Force widget updates
        self.updateGeometry()
        self.update()
        self.content_container.updateGeometry()
        self.content_container.update()
        
        # Force parent updates up the widget hierarchy
        parent = self.parent()
        while parent and isinstance(parent, QWidget):
            parent.updateGeometry()
            parent.update()
            parent = parent.parent()

    def add_card(self, card: CardWidget):
        """Add a sub-card to the group."""
        self.sub_cards.append(card)
        self.content_layout.addWidget(card)
        
    def set_toggle_state(self, checked: bool):
        """Set the state of the main toggle switch."""
        self.header_card.toggle_switch.setChecked(checked)
        
    def get_toggle_state(self) -> bool:
        """Get the current state of the main toggle switch."""
        return self.header_card.toggle_switch.isChecked()
        
    def set_expanded(self, expanded: bool):
        """Set the expansion state of the card group."""
        if expanded != self.content_container.isVisible():
            self._toggle_expansion()


class SubsettingItem(CardWidget):
    """
    A subsetting item widget for use within ExpandableCardGroup.
    
    Features:
    - Label on the left
    - Control widget on the right (button, dropdown, etc.)
    - Consistent spacing and alignment
    - Automatic theme handling via CardWidget
    """
    
    def __init__(self, label: str, control_widget: QWidget | None = None, 
                 parent: QWidget | None = None):
        super().__init__(parent)
        
        self.label_text = label
        self.control_widget: QWidget | None = control_widget
        
        self._setup_ui()
        
    def _setup_ui(self):
        """Set up the subsetting item's user interface."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(12)
        
        # Label on the left
        self.label = BodyLabel(self.label_text, self)
        
        layout.addWidget(self.label)
        layout.addStretch()
        
        # Control widget on the right (if provided)
        if self.control_widget:
            self.control_widget.setParent(self)
            layout.addWidget(self.control_widget)
            
    def set_control_widget(self, widget: QWidget):
        """Set or replace the control widget."""
        layout = self.layout()
        if layout is None:
            return
            
        if self.control_widget:
            # Remove existing control widget
            layout.removeWidget(self.control_widget)
            self.control_widget.deleteLater()
            
        self.control_widget = widget
        if widget:
            widget.setParent(self)
            layout.addWidget(widget)


# Backward compatibility alias
ExpandableSettingsCard = ExpandableCardGroup 