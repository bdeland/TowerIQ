from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QFrame, QLabel, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from src.tower_iq.gui.assets import get_icon_path
from src.tower_iq.gui.sidebar import SidebarFrame, SidebarNavButton
from src.tower_iq.ui.widgets.panel_widget import PanelWidget

class DashboardTestPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)

        # Add two PanelWidgets with placeholder content
        panel1 = PanelWidget("Test Panel 1")
        label1 = QLabel("This is the content of Test Panel 1.")
        label1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        panel1.set_content(label1)
        panel1.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        panel2 = PanelWidget("Test Panel 2")
        label2 = QLabel("This is the content of Test Panel 2.")
        label2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        panel2.set_content(label2)
        panel2.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        main_layout.addWidget(panel1)
        main_layout.addWidget(panel2)
        main_layout.addStretch() 