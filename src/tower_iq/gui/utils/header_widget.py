from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget, QPushButton, QSizePolicy
from PyQt6.QtGui import QIcon
from qfluentwidgets import BreadcrumbBar, SearchLineEdit, FluentIcon

class HeaderWidget(QWidget):
    """A Grafana-style header widget with logo toggle, breadcrumbs, and search bar."""

    # Signal emitted when the logo button is clicked (for sidebar toggle)
    sidebar_toggle_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("HeaderWidget")

        self.v_layout = QVBoxLayout(self)
        self.v_layout.setContentsMargins(0, 0, 0, 0)
        self.v_layout.setSpacing(0)

        self.h_layout = QHBoxLayout()
        self.h_layout.setContentsMargins(16, 8, 24, 8)
        self.h_layout.setSpacing(16)

        # 1. Logo button (acts as sidebar toggle)
        self.logo_button = QPushButton(self)
        self.logo_button.setObjectName("logoButton")
        self.logo_button.setFixedSize(32, 32)
        
        # Use TowerIQ logo
        logo_path = "resources/assets/icons/toweriq_icon.svg"
        if QIcon(logo_path).isNull():
            # Fallback to home icon if logo not found
            self.logo_button.setIcon(QIcon(FluentIcon.HOME))
        else:
            self.logo_button.setIcon(QIcon(logo_path))
            
        self.logo_button.setToolTip("Toggle Sidebar")
        self.logo_button.clicked.connect(self.sidebar_toggle_requested.emit)
        self.h_layout.addWidget(self.logo_button, 0, Qt.AlignmentFlag.AlignVCenter)

        # 2. Breadcrumbs
        self.breadcrumb = BreadcrumbBar(self)
        self.breadcrumb.setVisible(True)
        self.h_layout.addWidget(self.breadcrumb, 1, Qt.AlignmentFlag.AlignVCenter)

        # 3. Spacer to push search to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.h_layout.addWidget(spacer)

        # 4. Search bar
        self.search_edit = SearchLineEdit(self)
        self.search_edit.setPlaceholderText("Search...")
        self.search_edit.setFixedWidth(250)
        self.h_layout.addWidget(self.search_edit, 0, Qt.AlignmentFlag.AlignVCenter)

        self.v_layout.addLayout(self.h_layout)

        self.update_theme_styles()  # Set initial style

    def update_theme_styles(self):
        # Header styles are now handled by QFluentWidgets automatically
        # No custom stylesheet needed
        pass