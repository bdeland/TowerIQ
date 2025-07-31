"""
TowerIQ Expandable Settings Card Widget

This module provides an expandable settings card widget that mimics the Windows 11
ExpandGroupSettingCard functionality with a toggle switch, dropdown arrow, and subsettings.
Uses a compositional approach with style-aware components for robust corner rounding.
"""

from PyQt6.QtCore import Qt, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFrame
from qfluentwidgets import (
    CardWidget, SimpleCardWidget, FluentIcon, SwitchButton, 
    BodyLabel, CaptionLabel
)
from typing import Union
from PyQt6.QtGui import QIcon
from ..utils.utils_gui import FlexibleIconWidget

# A small gap between the header and the content when expanded
SPACING = 4


class GroupedCardWidget(CardWidget):
    """
    A generic row-based container widget that can be used for various card layouts.
    This replaces the purpose-built HeaderCard with a more flexible approach.
    """
    
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

    def add_row(self, widget: QWidget, show_separator: bool = False):
        """Adds a widget (like a layout or another widget) as a row."""
        self.main_layout.addWidget(widget)
        if show_separator:
            divider = QFrame()
            divider.setFrameShape(QFrame.Shape.HLine)
            divider.setObjectName("GroupRowDivider")
            self.main_layout.addWidget(divider)


class HeaderCard(GroupedCardWidget):
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

        # Create the header row widget
        header_row = self._create_header_row(title, content)
        self.add_row(header_row)

        # Set initial state
        self.set_expanded(False)

    def _create_header_row(self, title: str, content: str) -> QWidget:
        """Create the header row with title, content, toggle, and expand icon."""
        row_widget = QWidget()
        layout = QHBoxLayout(row_widget)
        layout.setContentsMargins(12, 8, 8, 8)
        layout.setSpacing(12)

        # Header icon (left side) - only add if provided
        self.header_icon_widget = None
        if self.header_icon is not None:
            self.header_icon_widget = FlexibleIconWidget(self.header_icon, 22, row_widget)
            layout.addWidget(self.header_icon_widget)

        # Text content (title and description)
        self.title_label = BodyLabel(title, row_widget)
        self.content_label = CaptionLabel(content, row_widget)
        self.content_label.setWordWrap(True)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        text_layout.addWidget(self.title_label)
        text_layout.addWidget(self.content_label)

        layout.addLayout(text_layout, 1)

        # Toggle switch
        self.toggle_switch = SwitchButton(row_widget)
        layout.addWidget(self.toggle_switch)

        # Expand/collapse icon (right side)
        self.expand_collapse_icon = FlexibleIconWidget(self.expand_icon, 16, row_widget)
        layout.addWidget(self.expand_collapse_icon)

        # Make the row widget handle mouse events
        row_widget.mousePressEvent = self._header_row_mouse_press
        row_widget.setCursor(Qt.CursorShape.PointingHandCursor)

        return row_widget

    def _header_row_mouse_press(self, a0):
        """Handle mouse press events on the header row."""
        if a0.button() == Qt.MouseButton.LeftButton:
            # Check if the click was not on the toggle switch
            if not self.toggle_switch.geometry().contains(a0.pos()):
                self.clicked.emit()
        a0.accept()

    def mouseReleaseEvent(self, e):
        """Override to emit a simple clicked signal on mouse release."""
        if e.button() == Qt.MouseButton.LeftButton:
            # Emit clicked signal for header clicks
            self.clicked.emit()
        super().mouseReleaseEvent(e)

    def set_expanded(self, expanded: bool):
        """Set the expanded state and update visual properties."""
        self.is_expanded = expanded
        
        # Update the expand/collapse icon based on state
        if expanded:
            self.expand_collapse_icon.set_icon(self.collapse_icon)
        else:
            self.expand_collapse_icon.set_icon(self.expand_icon)
            
        # The stylesheet will use this property to set the corners
        self.setProperty("expanded", expanded)
        style = self.style()
        if style:
            style.polish(self)


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
        self.is_animating = False

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
        self.spacer.setObjectName("CardSpacer")

        # Content Container (for sub-cards)
        self.content_container = QWidget(self)
        self.content_container.setObjectName("SubCardContainer")
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
        is_expanding = not self.content_container.isVisible()
        
        if is_expanding:
            # Show content immediately
            self.content_container.setVisible(True)
            self.spacer.setVisible(True)
        else:
            # Hide content immediately
            self.content_container.setVisible(False)
            self.spacer.setVisible(False)
        
        self.header_card.set_expanded(is_expanding)

    def add_card(self, card: CardWidget):
        """Add a sub-card to the group."""
        self.sub_cards.append(card)
        self.content_layout.addWidget(card)
        self._update_card_styles()
        
    def _update_card_styles(self):
        """Update the corner rounding styles for sub-cards based on their position."""
        if not self.sub_cards:
            return
            
        # Set position properties for styling
        for i, card in enumerate(self.sub_cards):
            if len(self.sub_cards) == 1:
                card.setProperty("position", "single")
            elif i == 0:
                card.setProperty("position", "first")
            elif i == len(self.sub_cards) - 1:
                card.setProperty("position", "last")
            else:
                card.setProperty("position", "middle")
            
            # Force style update
            card.style().polish(card)
        
    def set_toggle_state(self, checked: bool):
        """Set the state of the main toggle switch."""
        self.header_card.toggle_switch.setChecked(checked)
        
    def get_toggle_state(self) -> bool:
        """Get the current state of the main toggle switch."""
        return self.header_card.toggle_switch.isChecked()
        
    def set_expanded(self, expanded: bool):
        """Set the expansion state of the card group."""
        # Directly set the visibility state instead of toggling
        self.content_container.setVisible(expanded)
        self.spacer.setVisible(expanded)
        self.header_card.set_expanded(expanded)


class SubsettingItem(SimpleCardWidget):
    """
    A subsetting item widget for use within ExpandableCardGroup.
    
    Features:
    - Label on the left
    - Control widget on the right (button, dropdown, etc.)
    - Consistent spacing and alignment
    - Automatic theme handling via CardWidget inheritance
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

 