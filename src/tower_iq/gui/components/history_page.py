"""
TowerIQ v1.0 - History Page

This module defines the HistoryPage widget for viewing past game session data.
"""

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea, 
    QFrame, QPushButton, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

if TYPE_CHECKING:
    from tower_iq.core.main_controller import MainController


class HistoryPage(QWidget):
    """
    A placeholder history page for the TowerIQ application.
    
    This widget will eventually display historical game session data,
    but for now serves as a placeholder in the main window's navigation.
    """
    
    def __init__(self, controller: "MainController") -> None:
        """
        Initialize the history page.
        
        Args:
            controller: The main controller instance
        """
        super().__init__()
        
        self.controller = controller
        self._init_ui()
    
    def _init_ui(self) -> None:
        """Set up the history page UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Page title
        title_label = QLabel("Run History")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #333; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        # Placeholder content
        content_frame = QFrame()
        content_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        content_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 20px;
            }
        """)
        
        content_layout = QVBoxLayout(content_frame)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        placeholder_label = QLabel("Historical Data")
        placeholder_font = QFont()
        placeholder_font.setPointSize(16)
        placeholder_font.setBold(True)
        placeholder_label.setFont(placeholder_font)
        placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_label.setStyleSheet("color: #666; margin-bottom: 10px;")
        
        description_label = QLabel(
            "Game session history will be displayed here.\n"
            "This will include:\n\n"
            "• Past session summaries\n"
            "• Performance analytics\n"
            "• Progress tracking over time\n"
            "• Export and comparison tools\n"
            "• Detailed session reports"
        )
        description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description_label.setStyleSheet("color: #888; line-height: 1.5;")
        description_label.setWordWrap(True)
        
        content_layout.addWidget(placeholder_label)
        content_layout.addWidget(description_label)
        
        layout.addWidget(content_frame)
        layout.addStretch()  # Push content to top 