"""
TowerIQ Modules Page

This module provides the modules page widget for the application.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout
from ..utils.content_page import ContentPage

class ModulesPage(ContentPage):
    """
    The modules page of the application.

    Its style is managed globally by the application's main stylesheet.
    """
    def __init__(self, parent: QWidget | None = None):
        super().__init__(
            title="Modules",
            description="Manage and configure application modules",
            parent=parent
        )
        # Get the content container from the base class and add a stretch
        content_container = self.get_content_container()
        layout = QVBoxLayout(content_container)
        layout.addStretch(1) 