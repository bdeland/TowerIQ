from PyQt6.QtWidgets import QVBoxLayout, QLabel, QWidget
from ..utils.content_page import ContentPage
from PyQt6.QtCore import pyqtSlot

class DashboardsPage(ContentPage):
    def __init__(self, session_manager, config_manager, parent: QWidget | None = None):
        super().__init__(
            title="Dashboards",
            description="Monitor game metrics and performance data",
            parent=parent
        )
        self.session_manager = session_manager
        self.config_manager = config_manager
        
        # Create status labels
        self.status_label = QLabel("⚫ Disconnected")
        self.round_label = QLabel("No Active Round")
        
        # Get the content container from the base class
        content_container = self.get_content_container()
        layout = QVBoxLayout(content_container)

        # Add widgets directly to the content layout
        layout.addWidget(self.status_label)
        layout.addWidget(self.round_label)
        layout.addStretch(1)
        
        # Connect signals for reactive updates
        self.session_manager.connection_state_changed.connect(self.on_connection_state_changed)
        self.session_manager.round_status_changed.connect(self.on_round_status_changed)
        # Set initial state
        self.on_connection_state_changed(self.session_manager.is_hook_active)
        self.on_round_status_changed(self.session_manager.is_round_active)

    @pyqtSlot(bool)
    def on_connection_state_changed(self, is_active):
        if is_active:
            self.status_label.setText("🟢 Connected")
        else:
            self.status_label.setText("⚫ Disconnected")

    @pyqtSlot(bool)
    def on_round_status_changed(self, is_active):
        if is_active:
            self.round_label.setText("Round Active")
        else:
            self.round_label.setText("No Active Round") 