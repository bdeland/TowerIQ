from PyQt6.QtWidgets import QVBoxLayout, QLabel
from ..utils.utils_gui import ThemeAwareWidget, get_title_font, get_text_color
from PyQt6.QtCore import pyqtSlot

class DashboardsPage(ThemeAwareWidget):
    def __init__(self, session_manager, config_manager, parent=None):
        super().__init__(parent)
        self.session_manager = session_manager
        self.config_manager = config_manager
        self._layout = QVBoxLayout(self)
        self.status_label = QLabel(self)
        self.round_label = QLabel(self)
        self.label = QLabel("Dashboards Page", self)
        self._layout.addWidget(self.label)
        self._layout.addWidget(self.status_label)
        self._layout.addWidget(self.round_label)
        self._layout.addStretch()
        self.update_theme_styles()  # Set initial style

        # Connect signals for reactive updates
        self.session_manager.connection_state_changed.connect(self.on_connection_state_changed)
        self.session_manager.round_status_changed.connect(self.on_round_status_changed)
        # Set initial state
        self.on_connection_state_changed(self.session_manager.is_hook_active)
        self.on_round_status_changed(self.session_manager.is_round_active)

    def update_theme_styles(self):
        self.label.setFont(get_title_font())
        self.label.setStyleSheet(f"color: {get_text_color()};")
        self.status_label.setStyleSheet(f"color: {get_text_color()};")
        self.round_label.setStyleSheet(f"color: {get_text_color()};")

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