"""
TowerIQ v1.0 - Status Indicator Component

This module defines the StatusIndicator widget that displays the current
connection and service status in the application's status bar.
"""

from typing import Optional

from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel
from PyQt6.QtCore import Qt, pyqtSlot, QTimer
from PyQt6.QtGui import QPixmap, QIcon

from tower_iq.gui.assets import get_status_icon


class StatusIndicator(QWidget):
    """
    A widget that displays the current application status with icon and text.
    
    Shows connection status, service health, and other important system states
    in a compact format suitable for the status bar.
    """
    
    def __init__(self) -> None:
        """Initialize the status indicator widget."""
        super().__init__()
        
        self.current_status = "disconnected"
        self.status_text = "Not Connected"
        
        self._setup_animation_timer()
        self._init_ui()
    
    def _init_ui(self) -> None:
        """Create the UI layout with icon and text labels."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)
        layout.setSpacing(5)
        # Set dark background and white text
        self.setStyleSheet("""
            QWidget {
                background-color: #001219;
                color: #fff;
            }
            QLabel {
                color: #fff;
                background-color: transparent;
            }
        """)
        
        # Status icon
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(16, 16)
        self.icon_label.setScaledContents(True)
        
        # Status text
        self.text_label = QLabel(self.status_text)
        self.text_label.setStyleSheet("color: #666; font-size: 11px;")
        
        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)
        
        # Set initial status
        self.update_status("disconnected", "Not Connected")
    
    def _setup_animation_timer(self) -> None:
        """Set up timer for animating loading status."""
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self._animate_loading)
        self.animation_frame = 0
    
    def _animate_loading(self) -> None:
        """Animate the loading indicator."""
        if self.current_status == "loading":
            # Simple text-based loading animation
            dots = "." * (self.animation_frame % 4)
            self.text_label.setText(f"Connecting{dots}")
            self.animation_frame += 1
    
    @pyqtSlot(str, str)
    def update_status(self, status: str, message: str = "") -> None:
        """
        Update the status indicator.
        
        Args:
            status: The status type ("connected", "disconnected", "loading", "warning", "error")
            message: Optional status message to display
        """
        self.current_status = status
        self.status_text = message or self._get_default_message(status)
        
        # Stop animation timer
        self.animation_timer.stop()
        
        # Update icon
        self._update_icon(status)
        
        # Update text and color
        self._update_text(status, self.status_text)
        
        # Start animation for loading status
        if status == "loading":
            self.animation_frame = 0
            self.animation_timer.start(500)  # 500ms interval
    
    def _update_icon(self, status: str) -> None:
        """
        Update the status icon.
        
        Args:
            status: The status type
        """
        icon_path = get_status_icon(status)
        
        if icon_path:
            try:
                pixmap = QPixmap(icon_path)
                if not pixmap.isNull():
                    self.icon_label.setPixmap(pixmap)
                    return
            except Exception:
                pass
        
        # Fallback to text-based indicators
        status_symbols = {
            "connected": "🟢",
            "disconnected": "🔴", 
            "loading": "🟡",
            "warning": "🟠",
            "error": "🔴"
        }
        
        symbol = status_symbols.get(status, "⚫")
        self.icon_label.setText(symbol)
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    
    def _update_text(self, status: str, message: str) -> None:
        """
        Update the status text with appropriate styling.
        
        Args:
            status: The status type
            message: The message to display
        """
        # Color mapping for different statuses
        status_colors = {
            "connected": "#2a9b8e",      # Jade Current
            "disconnected": "#d72827",   # Crimson Strike
            "loading": "#fee8a8",        # Lemon Cream
            "warning": "#fee8a8",        # Lemon Cream
            "error": "#d72827"           # Crimson Strike
        }
        
        color = status_colors.get(status, "#fff")
        
        self.text_label.setText(message)
        self.text_label.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: bold; background: transparent;")
    
    def _get_default_message(self, status: str) -> str:
        """
        Get the default message for a status type.
        
        Args:
            status: The status type
            
        Returns:
            Default message string
        """
        default_messages = {
            "connected": "Connected",
            "disconnected": "Not Connected",
            "loading": "Connecting...",
            "warning": "Warning",
            "error": "Error"
        }
        
        return default_messages.get(status, "Unknown")
    
    @pyqtSlot()
    def pulse_status(self) -> None:
        """
        Create a visual pulse effect to draw attention to the status.
        
        Useful for highlighting important status changes.
        """
        # Store original stylesheet
        original_style = self.text_label.styleSheet()
        
        # Create highlight effect
        highlight_style = original_style.replace(
            f"color: {self._get_current_color()}", 
            "color: white; background-color: #2196F3"
        )
        
        self.text_label.setStyleSheet(highlight_style)
        
        # Restore original style after a brief delay
        QTimer.singleShot(200, lambda: self.text_label.setStyleSheet(original_style))
    
    def _get_current_color(self) -> str:
        """Get the current text color based on status."""
        status_colors = {
            "connected": "#4CAF50",
            "disconnected": "#F44336",
            "loading": "#FF9800",
            "warning": "#FF9800",
            "error": "#F44336"
        }
        return status_colors.get(self.current_status, "#666")
    
    def get_current_status(self) -> tuple[str, str]:
        """
        Get the current status information.
        
        Returns:
            Tuple of (status_type, status_message)
        """
        return self.current_status, self.status_text
    
    def set_tooltip_info(self, info: str) -> None:
        """
        Set additional tooltip information for the status indicator.
        
        Args:
            info: Detailed information to show in tooltip
        """
        self.setToolTip(info) 