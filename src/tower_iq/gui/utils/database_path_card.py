"""
TowerIQ Database Path Card Widget

This module provides a specialized card widget for displaying and managing
the database path setting with a modern Windows 11-style design.
"""

import os
import subprocess
from pathlib import Path
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QPushButton
from qfluentwidgets import (SimpleCardWidget, FluentIcon, IconWidget, 
                           BodyLabel, CaptionLabel, PushButton)


class DatabasePathCard(SimpleCardWidget):
    """
    A specialized card widget for displaying and managing the database path.
    
    Features:
    - Download icon on the left
    - Title and current path description
    - "Choose folder" button on the right
    - Click to open database folder in file explorer
    """
    
    # Signal emitted when the choose folder button is clicked
    choose_folder_clicked = pyqtSignal()
    
    def __init__(self, db_path: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self.db_path = db_path
        self._setup_ui()
        self._setup_connections()
        
    def _setup_ui(self):
        """Set up the card's user interface."""
        # Main horizontal layout
        self.main_layout = QHBoxLayout(self)
        self.main_layout.setContentsMargins(15, 12, 15, 12)
        self.main_layout.setSpacing(15)

        # 1. Download icon on the left
        self.icon_widget = IconWidget(FluentIcon.FOLDER, self)
        self.icon_widget.setFixedSize(22, 22)
        
        # 2. Vertical layout for Title and Description
        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(2)
        
        # Title and description labels
        self.title_label = BodyLabel("Database Path", self)
        self.description_label = CaptionLabel(self._get_display_path(), self)
        self.description_label.setWordWrap(True)
        
        text_layout.addWidget(self.title_label)
        text_layout.addWidget(self.description_label)

        # 3. Choose folder button on the right
        self.choose_folder_button = PushButton("Choose folder", self)
        self.choose_folder_button.setFixedHeight(32)
        
        # Add widgets to the main layout
        self.main_layout.addWidget(self.icon_widget, 0, Qt.AlignmentFlag.AlignVCenter)
        self.main_layout.addLayout(text_layout, 1)
        self.main_layout.addWidget(self.choose_folder_button, 0, Qt.AlignmentFlag.AlignVCenter)
        
    def _setup_connections(self):
        """Set up signal connections."""
        self.choose_folder_button.clicked.connect(self.choose_folder_clicked.emit)
        
    def mousePressEvent(self, event):
        """Override mouse press event to make the card clickable."""
        super().mousePressEvent(event)
        # Only respond to left mouse button clicks
        if event.button() == event.button().LeftButton:
            self._on_card_clicked(event)
        
    def _get_display_path(self) -> str:
        """Get the display path for the description."""
        if not self.db_path:
            return "No database path configured"
        
        # Convert to absolute path if it's relative
        path = Path(self.db_path)
        if not path.is_absolute():
            # Get the project root and make the path absolute
            project_root = Path(__file__).parent.parent.parent.parent.parent
            path = project_root / path
            
        return str(path)
        
    def _on_card_clicked(self, event):
        """Handle card click to open database folder in file explorer."""
        if not self.db_path:
            return
            
        try:
            # Get the directory containing the database file
            db_path = Path(self.db_path)
            if not db_path.is_absolute():
                # Get the project root and make the path absolute
                project_root = Path(__file__).parent.parent.parent.parent.parent
                db_path = project_root / db_path
                
            # Get the directory containing the database file
            db_dir = db_path.parent
            
            # Open the directory in file explorer
            if os.name == 'nt':  # Windows
                subprocess.run(['explorer', str(db_dir)])
            elif os.name == 'posix':  # macOS and Linux
                if os.system('which open') == 0:  # macOS
                    subprocess.run(['open', str(db_dir)])
                else:  # Linux
                    subprocess.run(['xdg-open', str(db_dir)])
                    
        except Exception as e:
            # Log error but don't crash the UI
            print(f"Failed to open database folder: {e}")
            
    def update_path(self, new_path: str):
        """Update the database path and refresh the display."""
        self.db_path = new_path
        self.description_label.setText(self._get_display_path())
        
    def get_path(self) -> str:
        """Get the current database path."""
        return self.db_path 