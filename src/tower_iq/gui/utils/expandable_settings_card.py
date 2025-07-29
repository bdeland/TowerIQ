"""
TowerIQ Expandable Settings Card Widget

This module provides an expandable settings card widget that mimics the Windows 11
ExpandGroupSettingCard functionality with a toggle switch, dropdown arrow, and subsettings.
"""

from PyQt6.QtCore import Qt, pyqtSignal, QPropertyAnimation, QEasingCurve, QParallelAnimationGroup
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFrame, QGraphicsOpacityEffect
from qfluentwidgets import (
    SimpleCardWidget, FluentIcon, IconWidget, SwitchButton, 
    BodyLabel, CaptionLabel, TransparentPushButton
)
from typing import Union

borders = True

class ExpandableSettingsCard(SimpleCardWidget):
    """
    An expandable settings card widget for Windows 11-style design.
    
    Features:
    - Main toggle switch for the primary setting
    - Dropdown arrow to expand/collapse subsettings
    - Collapsible content area for subsettings
    - Theme-aware styling handled by stylesheet
    """
    
    # Signal emitted when the main toggle changes
    toggle_changed = pyqtSignal(bool)
    
    def __init__(self, title: str, content: str, icon: Union[FluentIcon, str], 
                 parent: QWidget | None = None):
        super().__init__(parent)
        
        # Store properties
        self.title_text = title
        self.content_text = content
        self.icon_source = icon
        self.is_expanded = False
        
        # Animation properties
        self.animation_duration = 300  # milliseconds
        self.collapsed_height = 0
        self.expanded_height = 0
        
        # Build the UI
        self._setup_ui()
        
        # Setup animations after UI is built
        self._setup_animations()
        
    def _setup_ui(self):
        """Set up the card's user interface."""
        # Main vertical layout for the entire card
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(15, 12, 15, 12)
        self.main_layout.setSpacing(0)

        # Header row with icon, text, and controls container
        self.header_layout = QHBoxLayout()
        self.header_layout.setContentsMargins(10, 0, 10, 0)
        self.header_layout.setSpacing(15)
        
        # Create header container widget with border
        header_widget = QWidget(self)
        if borders: header_widget.setStyleSheet("border: 2px solid blue; background-color: rgba(0,0,255,0.1);")
        header_layout_container = QHBoxLayout(header_widget)
        header_layout_container.setContentsMargins(10, 0, 10, 0)
        header_layout_container.setSpacing(15)

        # 1. Icon on the left
        self.icon_widget = IconWidget(self.icon_source, self)
        self.icon_widget.setFixedSize(22, 22)
        if borders: self.icon_widget.setStyleSheet("border: 2px solid green; background-color: rgba(0,255,0,0.1);")
        
        # 2. Vertical layout for Title and Description
        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(2)
        
        # Create text container widget with border
        text_widget = QWidget(self)
        if borders: text_widget.setStyleSheet("border: 2px solid orange; background-color: rgba(255,165,0,0.1);")
        text_container_layout = QVBoxLayout(text_widget)
        text_container_layout.setContentsMargins(0, 0, 0, 0)
        text_container_layout.setSpacing(2)
        
        # Use theme-aware labels from qfluentwidgets (styling handled by stylesheet)
        self.title_label = BodyLabel(self.title_text, self)
        self.content_label = CaptionLabel(self.content_text, self)
        self.content_label.setWordWrap(True)
        text_container_layout.addWidget(self.title_label)
        text_container_layout.addWidget(self.content_label)

        # 3. Controls container (toggle + arrow)
        controls_layout = QHBoxLayout()
        controls_layout.setContentsMargins(0, 0, 0, 0)
        controls_layout.setSpacing(8)
        
        # Create controls container widget with border
        controls_widget = QWidget(self)
        if borders: controls_widget.setStyleSheet("border: 2px solid purple; background-color: rgba(128,0,128,0.1);")
        controls_container_layout = QHBoxLayout(controls_widget)
        controls_container_layout.setContentsMargins(0, 0, 0, 0)
        controls_container_layout.setSpacing(8)
        
        # Toggle switch
        self.toggle_switch = SwitchButton(self)
        self.toggle_switch.checkedChanged.connect(self.toggle_changed.emit)
        if borders: self.toggle_switch.setStyleSheet("border: 2px solid yellow; background-color: rgba(255,255,0,0.1);")
        
        # Dropdown arrow button
        self.expand_button = TransparentPushButton(self)
        self.expand_button.setIcon(FluentIcon.CHEVRON_RIGHT)
        self.expand_button.setFixedSize(32, 32)
        self.expand_button.clicked.connect(self._toggle_expansion)
        if borders: self.expand_button.setStyleSheet("border: 2px solid cyan; background-color: rgba(0,255,255,0.1);")
        
        #TODO: fix overlapping of the toggle switch and the expand button
        # Add controls to their own layout
        controls_container_layout.addWidget(self.toggle_switch, 0, Qt.AlignmentFlag.AlignVCenter)
        controls_container_layout.addWidget(self.expand_button, 0, Qt.AlignmentFlag.AlignVCenter)
        
        # Add widgets to header layout
        header_layout_container.addWidget(self.icon_widget, 0, Qt.AlignmentFlag.AlignVCenter)
        header_layout_container.addWidget(text_widget)
        header_layout_container.addStretch(1)
        header_layout_container.addWidget(controls_widget)

        # Add header to main layout
        self.main_layout.addWidget(header_widget)
        
        # 5. Content area for subsettings (initially collapsed)
        self.content_frame = QFrame(self)
        self.content_frame.setObjectName("expandable_content_frame")
        if borders: self.content_frame.setStyleSheet("border: 2px solid magenta; background-color: rgba(255,0,255,0.1);")
        
        # Set up opacity effect for smooth fade animation
        self.opacity_effect = QGraphicsOpacityEffect()
        self.content_frame.setGraphicsEffect(self.opacity_effect)
        
        self.content_layout = QVBoxLayout(self.content_frame)
        self.content_layout.setContentsMargins(37, 12, 0, 0)  # Indent to align with text
        self.content_layout.setSpacing(8)
        
        # Initially set to collapsed state
        self.content_frame.setMaximumHeight(0)
        self.opacity_effect.setOpacity(0.0)
        
        # Add content frame to main layout
        self.main_layout.addWidget(self.content_frame)
        
    def _setup_animations(self):
        """Set up the animations for smooth expand/collapse transitions."""
        # Height animation for the content frame
        self.height_animation = QPropertyAnimation(self.content_frame, b"maximumHeight")
        self.height_animation.setDuration(self.animation_duration)
        self.height_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        # Opacity animation for smooth fade in/out
        self.opacity_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.opacity_animation.setDuration(self.animation_duration)
        self.opacity_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        # Create parallel animation group to run both animations together
        self.animation_group = QParallelAnimationGroup()
        self.animation_group.addAnimation(self.height_animation)
        self.animation_group.addAnimation(self.opacity_animation)
        
    def _calculate_content_height(self):
        """Calculate the natural height of the content frame when expanded."""
        # Temporarily show the content to measure its size
        old_height = self.content_frame.maximumHeight()
        old_opacity = self.opacity_effect.opacity()
        
        self.content_frame.setMaximumHeight(16777215)  # Remove height constraint
        self.opacity_effect.setOpacity(1.0)
        
        # Get the size hint which represents the natural size
        self.content_frame.updateGeometry()
        height = self.content_frame.sizeHint().height()
        
        # Restore previous state
        self.content_frame.setMaximumHeight(old_height)
        self.opacity_effect.setOpacity(old_opacity)
        
        return max(height, 50)  # Minimum height for better UX
        
    def _toggle_expansion(self):
        """Toggle the expansion state of the card with smooth animation."""
        self.is_expanded = not self.is_expanded
        
        # Stop any currently running animation
        if self.animation_group.state() == QPropertyAnimation.State.Running:
            self.animation_group.stop()
        
        if self.is_expanded:
            # Expanding: animate from 0 to natural height
            target_height = self._calculate_content_height()
            
            self.height_animation.setStartValue(0)
            self.height_animation.setEndValue(target_height)
            
            self.opacity_animation.setStartValue(0.0)
            self.opacity_animation.setEndValue(1.0)
            
            # Update arrow icon to down
            self.expand_button.setIcon(FluentIcon.DOWN)
            
        else:
            # Collapsing: animate from current height to 0
            current_height = self.content_frame.height()
            
            self.height_animation.setStartValue(current_height)
            self.height_animation.setEndValue(0)
            
            self.opacity_animation.setStartValue(1.0)
            self.opacity_animation.setEndValue(0.0)
            
            # Update arrow icon to right
            self.expand_button.setIcon(FluentIcon.CHEVRON_RIGHT)
        
        # Start the animation
        self.animation_group.start()
            
    def add_subsetting(self, widget: QWidget):
        """Add a subsetting widget to the expandable content area."""
        self.content_layout.addWidget(widget)
        
        # If currently expanded, we may need to update the height
        if self.is_expanded:
            # Recalculate and update the height smoothly
            new_height = self._calculate_content_height()
            self.height_animation.setStartValue(self.content_frame.height())
            self.height_animation.setEndValue(new_height)
            self.height_animation.setDuration(200)  # Shorter duration for content updates
            self.height_animation.start()
        
    def set_toggle_state(self, checked: bool):
        """Set the state of the main toggle switch."""
        self.toggle_switch.setChecked(checked)
        
    def get_toggle_state(self) -> bool:
        """Get the current state of the main toggle switch."""
        return self.toggle_switch.isChecked()
        
    def set_expanded(self, expanded: bool):
        """Set the expansion state of the card."""
        if expanded != self.is_expanded:
            self._toggle_expansion()
            
    def set_animation_duration(self, duration_ms: int):
        """Set the animation duration in milliseconds."""
        self.animation_duration = duration_ms
        self.height_animation.setDuration(duration_ms)
        self.opacity_animation.setDuration(duration_ms)


class SubsettingItem(QWidget):
    """
    A subsetting item widget for use within ExpandableSettingsCard.
    
    Features:
    - Label on the left
    - Control widget on the right (button, dropdown, etc.)
    - Consistent spacing and alignment
    - Styling handled by stylesheet
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
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        # Label on the left (styling handled by stylesheet)
        self.label = BodyLabel(self.label_text, self)
        self.label.setObjectName("subsetting_label")
        
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