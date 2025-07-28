"""
TowerIQ Health Check Card

This module provides the HealthCheckCard widget for displaying database health check results.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem
from qfluentwidgets import CardWidget, PrimaryPushButton, PushButton, BodyLabel, CaptionLabel, FluentIcon, ProgressRing

from ..stylesheets import get_themed_stylesheet


class HealthCheckCard(CardWidget):
    """Card widget for displaying database health check results."""
    
    # Signals emitted when buttons are clicked
    run_health_check_clicked = pyqtSignal()
    attempt_fixes_clicked = pyqtSignal()
    
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the health check card user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header with title
        title_label = BodyLabel("Database Health Check")
        title_label.setObjectName("card_title")
        layout.addWidget(title_label)
        
        # Instructions
        instructions_label = CaptionLabel(
            "Run a health check to validate database integrity and identify potential issues."
        )
        layout.addWidget(instructions_label)
        
        # Results list widget
        self.results_list = QListWidget()
        self.results_list.setObjectName("health_check_results")
        self.results_list.setMaximumHeight(200)
        layout.addWidget(self.results_list)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(12)
        
        # Run health check button
        self.run_check_button = PrimaryPushButton("Run Health Check", self)
        self.run_check_button.setIcon(FluentIcon.SEARCH)
        self.run_check_button.clicked.connect(self.run_health_check_clicked.emit)
        button_layout.addWidget(self.run_check_button)
        
        # Attempt fixes button (initially hidden)
        self.fix_button = PushButton("Attempt to Fix Issues", self)
        self.fix_button.setIcon(FluentIcon.SETTING)
        self.fix_button.clicked.connect(self.attempt_fixes_clicked.emit)
        self.fix_button.setVisible(False)
        button_layout.addWidget(self.fix_button)
        
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        # Apply styling
        self.setStyleSheet(get_themed_stylesheet())
        
    def update_results(self, results: list):
        """Update the displayed health check results."""
        self.results_list.clear()
        
        if not results:
            item = QListWidgetItem("No health check results available")
            self.results_list.addItem(item)
            return
        
        has_warnings_or_errors = False
        
        for result in results:
            status = result.get('status', 'unknown')
            message = result.get('message', 'No message')
            
            item = QListWidgetItem(message)
            
            # Track warnings and errors for button visibility
            if status in ['warning', 'error']:
                has_warnings_or_errors = True
            
            self.results_list.addItem(item)
        
        # Show/hide fix button based on results
        self.fix_button.setVisible(has_warnings_or_errors)
        
    def set_busy(self, is_busy: bool):
        """Enable or disable buttons during operations."""
        self.run_check_button.setEnabled(not is_busy)
        self.fix_button.setEnabled(not is_busy) 