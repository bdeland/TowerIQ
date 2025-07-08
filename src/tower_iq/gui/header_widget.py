from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QWidget
from qfluentwidgets import BreadcrumbBar, SearchLineEdit, isDarkTheme, qconfig


class HeaderWidget(QWidget):
    """A widget for the header of the main window, containing breadcrumbs and a search bar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("HeaderWidget")

        self.h_layout = QHBoxLayout(self)
        self.h_layout.setContentsMargins(24, 8, 24, 8)
        self.h_layout.setSpacing(16)

        self.breadcrumb = BreadcrumbBar(self)
        self.h_layout.addWidget(self.breadcrumb, 0, Qt.AlignmentFlag.AlignVCenter)

        self.h_layout.addStretch(1)

        self.search_edit = SearchLineEdit(self)
        self.search_edit.setPlaceholderText("Search...")
        self.search_edit.setFixedWidth(250)
        self.h_layout.addWidget(self.search_edit, 0, Qt.AlignmentFlag.AlignVCenter)

        self.update_style()

        qconfig.themeChanged.connect(self.update_style)

    def update_style(self):
        if isDarkTheme():
            border_color = "#3e3e3e"
        else:
            border_color = "#dcdcdc"
        
        self.setStyleSheet(f"""
            #HeaderWidget {{
                background-color: transparent;
                border-bottom: 1px solid {border_color};
            }}
        """) 