"""
TowerIQ Vertical Stepper Widget

This module provides a vertical stepper widget similar to Material-UI's vertical stepper
for guiding users through multi-step processes like device connection.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout
)
from PyQt6.QtGui import QPainter, QPen, QColor, QFont
from qfluentwidgets import (
    BodyLabel, CaptionLabel, PushButton, SimpleCardWidget
)
from typing import List, Dict, Optional
from enum import Enum


class StepStatus(Enum):
    """Step status enumeration."""
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class StepData:
    """Data structure for a step in the stepper."""
    
    def __init__(self, label: str, description: str = "", 
                 content_widget: Optional[QWidget] = None,
                 optional: bool = False):
        self.label = label
        self.description = description
        self.content_widget = content_widget
        self.optional = optional
        self.status = StepStatus.PENDING
        self.error_message = ""
        self.progress_percent = 0


class StepWidget(QWidget):
    """Individual step widget with label, content, and controls."""
    
    def __init__(self, step_data: StepData, step_index: int, parent=None):
        super().__init__(parent)
        self.step_data = step_data
        self.step_index = step_index
        self.is_expanded = False
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the step widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Step header with icon, label, and status
        self.header_widget = self._create_header()
        layout.addWidget(self.header_widget)
        
        # Step content (initially hidden)
        self.content_widget = self._create_content()
        self.content_widget.setVisible(False)
        layout.addWidget(self.content_widget)
        
        # Step controls (initially hidden)
        self.controls_widget = self._create_controls()
        self.controls_widget.setVisible(False)
        layout.addWidget(self.controls_widget)
        
    def _create_header(self) -> QWidget:
        """Create the step header with icon, label, and status."""
        header = QWidget()
        layout = QHBoxLayout(header)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(12)
        
        # Step icon
        self.icon_widget = StepIconWidget(self.step_index, self.step_data.status, header)
        layout.addWidget(self.icon_widget)
        
        # Step text
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        
        self.label_widget = BodyLabel(self.step_data.label, header)
        self.label_widget.setObjectName("StepLabel")
        
        self.description_widget = CaptionLabel(self.step_data.description, header)
        self.description_widget.setObjectName("StepDescription")
        self.description_widget.setWordWrap(True)
        
        text_layout.addWidget(self.label_widget)
        text_layout.addWidget(self.description_widget)
        
        layout.addLayout(text_layout, 1)
        
        # Optional indicator
        if self.step_data.optional:
            optional_label = CaptionLabel("(Optional)", header)
            optional_label.setObjectName("OptionalLabel")
            layout.addWidget(optional_label)
        
        # Status indicator
        self.status_widget = StepStatusWidget(self.step_data.status, header)
        layout.addWidget(self.status_widget)
        
        return header
        
    def _create_content(self) -> QWidget:
        """Create the step content area."""
        content = SimpleCardWidget()
        content.setObjectName("StepContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        
        # Add the step's content widget if provided
        if self.step_data.content_widget:
            layout.addWidget(self.step_data.content_widget)
        else:
            # Default content
            default_content = BodyLabel("Step content will appear here", content)
            default_content.setObjectName("DefaultStepContent")
            layout.addWidget(default_content)
        
        return content
        
    def _create_controls(self) -> QWidget:
        """Create the step controls (buttons)."""
        controls = QWidget()
        layout = QHBoxLayout(controls)
        layout.setContentsMargins(16, 8, 16, 16)
        layout.setSpacing(8)
        
        layout.addStretch(1)
        
        # Back button
        self.back_button = PushButton("Back", controls)
        self.back_button.setObjectName("StepBackButton")
        
        # Next/Continue button
        self.next_button = PushButton("Continue", controls)
        self.next_button.setObjectName("StepNextButton")
        # Note: setPrimary is not available in this version, using setProperty instead
        self.next_button.setProperty("primary", True)
        
        layout.addWidget(self.back_button)
        layout.addWidget(self.next_button)
        
        return controls
        
    def update_status(self, status: StepStatus, error_message: str = "", progress_percent: int = 0):
        """Update the step status and UI."""
        self.step_data.status = status
        self.step_data.error_message = error_message
        self.step_data.progress_percent = progress_percent
        
        # Update icon and status widget
        self.icon_widget.update_status(status, progress_percent)
        self.status_widget.update_status(status, error_message)
        
        # Update label styling based on status
        if status == StepStatus.COMPLETED:
            self.label_widget.setObjectName("StepLabelCompleted")
        elif status == StepStatus.FAILED:
            self.label_widget.setObjectName("StepLabelFailed")
        elif status == StepStatus.ACTIVE:
            self.label_widget.setObjectName("StepLabelActive")
        else:
            self.label_widget.setObjectName("StepLabel")
            
        # Force style update
        style = self.label_widget.style()
        if style:
            style.unpolish(self.label_widget)
            style.polish(self.label_widget)
        
    def set_expanded(self, expanded: bool):
        """Expand or collapse the step content."""
        self.is_expanded = expanded
        self.content_widget.setVisible(expanded)
        self.controls_widget.setVisible(expanded)
        
    def set_controls_enabled(self, back_enabled: bool, next_enabled: bool):
        """Enable or disable step controls."""
        self.back_button.setEnabled(back_enabled)
        self.next_button.setEnabled(next_enabled)


class StepIconWidget(QWidget):
    """Custom widget for step icons with status indicators."""
    
    def __init__(self, step_number: int, status: StepStatus, parent=None):
        super().__init__(parent)
        self.step_number = step_number
        self.status = status
        self.progress_percent = 0
        
        # Set fixed size for the icon
        self.setFixedSize(32, 32)
        self.setObjectName("StepIconWidget")
        
    def update_status(self, status: StepStatus, progress_percent: int = 0):
        """Update the icon status and progress."""
        self.status = status
        self.progress_percent = progress_percent
        self.update()
        
    def paintEvent(self, event):
        """Custom paint event for the step icon."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Get colors based on status
        colors = self._get_colors_for_status()
        
        # Draw background circle
        painter.setPen(QPen(colors["border"], 2))
        painter.setBrush(colors["background"])
        painter.drawEllipse(2, 2, 28, 28)
        
        # Draw content based on status
        if self.status == StepStatus.COMPLETED:
            # Draw checkmark
            painter.setPen(QPen(colors["text"], 2))
            painter.drawLine(10, 16, 14, 20)
            painter.drawLine(14, 20, 22, 12)
        elif self.status == StepStatus.FAILED:
            # Draw X
            painter.setPen(QPen(colors["text"], 2))
            painter.drawLine(10, 10, 22, 22)
            painter.drawLine(22, 10, 10, 22)
        elif self.status == StepStatus.ACTIVE:
            # Draw progress ring or spinner
            if self.progress_percent > 0:
                # Draw progress arc
                painter.setPen(QPen(colors["text"], 3))
                start_angle = 90 * 16  # Start from top
                span_angle = int((self.progress_percent / 100) * 360 * 16)
                painter.drawArc(4, 4, 24, 24, start_angle, span_angle)
            else:
                # Draw spinner dots
                painter.setPen(QPen(colors["text"], 2))
                painter.drawEllipse(14, 8, 4, 4)
                painter.drawEllipse(20, 14, 4, 4)
                painter.drawEllipse(14, 20, 4, 4)
                painter.drawEllipse(8, 14, 4, 4)
        else:
            # Draw step number
            painter.setPen(QPen(colors["text"], 1))
            font = QFont()
            font.setBold(True)
            font.setPointSize(10)
            painter.setFont(font)
            
            text_rect = painter.boundingRect(0, 0, 32, 32, Qt.AlignmentFlag.AlignCenter, str(self.step_number))
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, str(self.step_number))
            
    def _get_colors_for_status(self) -> Dict[str, QColor]:
        """Get colors for the current status."""
        if self.status == StepStatus.COMPLETED:
            return {
                "background": QColor("#2ecc71"),
                "border": QColor("#27ae60"),
                "text": QColor("#ffffff")
            }
        elif self.status == StepStatus.FAILED:
            return {
                "background": QColor("#e74c3c"),
                "border": QColor("#c0392b"),
                "text": QColor("#ffffff")
            }
        elif self.status == StepStatus.ACTIVE:
            return {
                "background": QColor("#3498db"),
                "border": QColor("#2980b9"),
                "text": QColor("#ffffff")
            }
        else:  # PENDING
            return {
                "background": QColor("#ecf0f1"),
                "border": QColor("#bdc3c7"),
                "text": QColor("#7f8c8d")
            }


class StepStatusWidget(QWidget):
    """Widget for displaying step status and error messages."""
    
    def __init__(self, status: StepStatus, parent=None):
        super().__init__(parent)
        self.status = status
        self.error_message = ""
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the status widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        
        self.status_label = CaptionLabel("", self)
        self.status_label.setObjectName("StepStatusLabel")
        
        self.error_label = CaptionLabel("", self)
        self.error_label.setObjectName("StepErrorLabel")
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)
        
        layout.addWidget(self.status_label)
        layout.addWidget(self.error_label)
        
        self.update_status(self.status)
        
    def update_status(self, status: StepStatus, error_message: str = ""):
        """Update the status display."""
        self.status = status
        self.error_message = error_message
        
        # Update status text
        status_texts = {
            StepStatus.PENDING: "Pending",
            StepStatus.ACTIVE: "In Progress",
            StepStatus.COMPLETED: "Completed",
            StepStatus.FAILED: "Failed",
            StepStatus.SKIPPED: "Skipped"
        }
        
        self.status_label.setText(status_texts.get(status, "Unknown"))
        
        # Update error message
        if error_message and status == StepStatus.FAILED:
            self.error_label.setText(error_message)
            self.error_label.setVisible(True)
        else:
            self.error_label.setVisible(False)
            
        # Update styling
        self.status_label.setObjectName(f"StepStatusLabel{status.value.title()}")
        style = self.status_label.style()
        if style:
            style.unpolish(self.status_label)
            style.polish(self.status_label)


class VerticalStepper(QWidget):
    """Vertical stepper widget similar to Material-UI's vertical stepper."""
    
    # Signals
    step_changed = pyqtSignal(int)  # Emitted when active step changes
    step_completed = pyqtSignal(int)  # Emitted when a step is completed
    all_steps_completed = pyqtSignal()  # Emitted when all steps are completed
    step_failed = pyqtSignal(int, str)  # Emitted when a step fails
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.steps: List[StepData] = []
        self.active_step = 0
        self.step_widgets: List[StepWidget] = []
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the stepper UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Container for step widgets
        self.steps_container = QWidget()
        self.steps_container.setObjectName("StepsContainer")
        steps_layout = QVBoxLayout(self.steps_container)
        steps_layout.setContentsMargins(0, 0, 0, 0)
        steps_layout.setSpacing(0)
        
        layout.addWidget(self.steps_container)
        
    def add_step(self, label: str, description: str = "", 
                 content_widget: Optional[QWidget] = None,
                 optional: bool = False) -> int:
        """Add a step to the stepper."""
        step_data = StepData(label, description, content_widget, optional)
        self.steps.append(step_data)
        
        # Create step widget
        step_widget = StepWidget(step_data, len(self.steps) - 1, self.steps_container)
        self.step_widgets.append(step_widget)
        
        # Connect signals
        step_widget.back_button.clicked.connect(lambda: self._on_back_clicked(step_widget))
        step_widget.next_button.clicked.connect(lambda: self._on_next_clicked(step_widget))
        
        # Add to layout
        layout = self.steps_container.layout()
        if layout:
            layout.addWidget(step_widget)
        
        # Update step widget text
        if len(self.steps) == 1:
            step_widget.next_button.setText("Finish")
        else:
            step_widget.next_button.setText("Continue")
            
        # Update initial state
        self._update_step_states()
        
        return len(self.steps) - 1
        
    def set_active_step(self, step_index: int):
        """Set the active step."""
        if 0 <= step_index < len(self.steps):
            self.active_step = step_index
            self._update_step_states()
            self.step_changed.emit(step_index)
            
    def get_active_step(self) -> int:
        """Get the current active step."""
        return self.active_step
        
    def update_step_status(self, step_index: int, status: StepStatus, 
                          error_message: str = "", progress_percent: int = 0):
        """Update the status of a specific step."""
        if 0 <= step_index < len(self.step_widgets):
            self.step_widgets[step_index].update_status(status, error_message, progress_percent)
            
            # Emit signals based on status
            if status == StepStatus.COMPLETED:
                self.step_completed.emit(step_index)
            elif status == StepStatus.FAILED:
                self.step_failed.emit(step_index, error_message)
                
    def reset(self):
        """Reset the stepper to initial state."""
        self.active_step = 0
        for step_widget in self.step_widgets:
            step_widget.update_status(StepStatus.PENDING)
        self._update_step_states()
        
    def _update_step_states(self):
        """Update the state of all step widgets."""
        for i, step_widget in enumerate(self.step_widgets):
            # Set expanded state
            is_expanded = i == self.active_step
            step_widget.set_expanded(is_expanded)
            
            # Update status based on position
            if i < self.active_step:
                step_widget.update_status(StepStatus.COMPLETED)
            elif i == self.active_step:
                step_widget.update_status(StepStatus.ACTIVE)
            else:
                step_widget.update_status(StepStatus.PENDING)
                
            # Update controls
            back_enabled = i > 0
            next_enabled = True  # Always enable next for now
            step_widget.set_controls_enabled(back_enabled, next_enabled)
            
    def _on_back_clicked(self, step_widget: StepWidget):
        """Handle back button click."""
        step_index = self.step_widgets.index(step_widget)
        if step_index > 0:
            self.set_active_step(step_index - 1)
            
    def _on_next_clicked(self, step_widget: StepWidget):
        """Handle next button click."""
        step_index = self.step_widgets.index(step_widget)
        if step_index < len(self.steps) - 1:
            self.set_active_step(step_index + 1)
        else:
            # Last step completed
            self.all_steps_completed.emit()
            
    def get_step_content_widget(self, step_index: int) -> Optional[QWidget]:
        """Get the content widget for a specific step."""
        if 0 <= step_index < len(self.steps):
            return self.steps[step_index].content_widget
        return None
        
    def set_step_content_widget(self, step_index: int, content_widget: QWidget):
        """Set the content widget for a specific step."""
        if 0 <= step_index < len(self.steps):
            self.steps[step_index].content_widget = content_widget
            if step_index < len(self.step_widgets):
                # Update the existing step widget
                old_content = self.step_widgets[step_index].content_widget
                if old_content:
                    old_content.deleteLater()
                    
                # Create new content widget
                new_content = self.step_widgets[step_index]._create_content()
                self.step_widgets[step_index].content_widget = new_content
                layout = self.step_widgets[step_index].layout()
                if layout:
                    # Remove old content and add new one
                    layout.removeWidget(old_content)
                    layout.insertWidget(1, new_content)
