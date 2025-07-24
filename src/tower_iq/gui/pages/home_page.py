"""
TowerIQ Home Page

This module provides the main home page widget for the application.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import TitleLabel

class HomePage(QWidget):
    """
    The main landing page of the application.

    Its style is managed globally by the application's main stylesheet.
    """
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        # --- UI Setup ---
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 36)

        # Use a theme-aware TitleLabel, which is automatically styled
        title = TitleLabel("Home Page", self)

        layout.addWidget(title)
        layout.addStretch()