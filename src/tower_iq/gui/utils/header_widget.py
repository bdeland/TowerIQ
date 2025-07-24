from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QVBoxLayout
from qfluentwidgets import BreadcrumbBar, SearchLineEdit, isDarkTheme
from .utils_gui import ThemeAwareWidget, get_border_color
from ..stylesheets import HEADER_WIDGET_LIGHT_QSS, HEADER_WIDGET_DARK_QSS

class HeaderWidget(ThemeAwareWidget):
    """A widget for the header of the main window, containing breadcrumbs and a search bar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("HeaderWidget")

        self.v_layout = QVBoxLayout(self)
        self.v_layout.setContentsMargins(0, 0, 0, 0)
        self.v_layout.setSpacing(0)

        self.h_layout = QHBoxLayout()
        self.h_layout.setContentsMargins(24, 3, 24, 3)
        self.h_layout.setSpacing(16)

        self.breadcrumb = BreadcrumbBar(self)
        self.breadcrumb.setVisible(True)
        self.h_layout.addWidget(self.breadcrumb, 1, Qt.AlignmentFlag.AlignVCenter)

        self.search_edit = SearchLineEdit(self)
        self.search_edit.setPlaceholderText("Search...")
        self.search_edit.setFixedWidth(250)
        self.h_layout.addWidget(self.search_edit, 0, Qt.AlignmentFlag.AlignVCenter)

        self.v_layout.addLayout(self.h_layout)

        # Add horizontal divider
        #self.divider = QFrame(self)
        #self.divider.setFrameShape(QFrame.Shape.HLine)
        #self.divider.setFrameShadow(QFrame.Shadow.Raised)
        #self.v_layout.addWidget(self.divider)

        self.update_theme_styles()  # Set initial style

    def update_theme_styles(self):
        # Apply stylesheet based on theme
        if isDarkTheme():
            self.setStyleSheet(HEADER_WIDGET_DARK_QSS)
        else:
            self.setStyleSheet(HEADER_WIDGET_LIGHT_QSS)