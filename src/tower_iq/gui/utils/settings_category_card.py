from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout
from qfluentwidgets import FluentIcon, IconWidget, BodyLabel, CaptionLabel, CardWidget
from typing import Union


class SettingsCategoryCard(CardWidget):
    """A card for displaying settings categories. Styling is handled globally."""
    clicked = pyqtSignal(str)
    
    def __init__(self, title: str, description: str, icon: Union[FluentIcon, str], category: str, parent=None):
        super().__init__(parent)
        self.category = category
        
        # --- UI Setup ---
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(0)

        # Icon
        icon_widget = IconWidget(icon, self)
        icon_widget.setFixedSize(64, 64)
        
        # Content (using theme-aware labels)
        title_label = BodyLabel(title, self)
        description_label = CaptionLabel(description, self)
        description_label.setWordWrap(True)
        
        # Add to layout
        layout.addWidget(icon_widget, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(title_label)
        layout.addWidget(description_label)
        
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
    def mouseReleaseEvent(self, event):
        """Handle mouse release events to emit the clicked signal with category."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.category)
        # Don't call super().mouseReleaseEvent(event) to avoid emitting the base class clicked signal