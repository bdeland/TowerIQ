from PyQt6.QtWidgets import (
    QFrame, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QMenu, QSpacerItem, QSizePolicy
)
from PyQt6.QtGui import QAction, QIcon, QKeySequence
from PyQt6.QtCore import pyqtSignal, QPoint
from tower_iq.gui.assets import get_asset_path

class PanelWidget(QFrame):
    # Action signals for menu actions
    view_requested = pyqtSignal()
    edit_requested = pyqtSignal()
    duplicate_requested = pyqtSignal()
    copy_requested = pyqtSignal()
    remove_requested = pyqtSignal()
    share_requested = pyqtSignal()
    inspect_requested = pyqtSignal()
    get_help_requested = pyqtSignal()

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        # Main layout for the panel
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header section
        header_widget = QWidget(self)
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(8, 8, 8, 8)
        header_layout.setSpacing(4)

        # Title label
        title_label = QLabel(title, header_widget)
        header_layout.addWidget(title_label)

        # Spacer to push options button to the right
        spacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        header_layout.addItem(spacer)

        # Options button
        self.options_button = QPushButton("\u22EE", header_widget)  # Vertical ellipsis
        self.options_button.setFixedSize(24, 24)
        self.options_button.setObjectName("optionsButton")
        header_layout.addWidget(self.options_button)

        # Content area
        self.content_area = QFrame(self)
        self.content_area.setObjectName("contentArea")
        self.content_layout = QVBoxLayout(self.content_area)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(0)

        # Assemble the panel layout
        main_layout.addWidget(header_widget)
        main_layout.addWidget(self.content_area)
        main_layout.setStretch(1, 1)  # Make content area expand

        self.options_button.clicked.connect(self.show_options_menu)

    def set_content(self, widget: QWidget):
        """Replace the content area with the given widget."""
        layout = self.content_layout
        # Remove existing widgets
        while layout.count():
            child = layout.takeAt(0)
            if child is not None:
                w = child.widget()
                if w is not None:
                    w.setParent(None)
        # Add the new widget
        layout.addWidget(widget)

    def show_options_menu(self):
        menu = QMenu(self)

        # Main actions
        view_action = QAction(QIcon(get_asset_path("icons/view.svg")), "View", self)
        view_action.setShortcut(QKeySequence("p, v"))
        view_action.triggered.connect(self.view_requested)

        edit_action = QAction(QIcon(get_asset_path("icons/edit.svg")), "Edit", self)
        edit_action.setShortcut(QKeySequence("p, e"))
        edit_action.triggered.connect(self.edit_requested)

        # Share submenu
        share_action = QAction(QIcon(get_asset_path("icons/share.svg")), "Share", self)
        share_action.setShortcut(QKeySequence("p, s"))
        share_action.triggered.connect(self.share_requested)

        # Inspect submenu
        inspect_action = QAction(QIcon(get_asset_path("icons/inspect.svg")), "Inspect", self)
        inspect_action.setShortcut(QKeySequence("p, i"))
        inspect_action.triggered.connect(self.inspect_requested)

        # More submenu
        more_submenu = QMenu("More...", self)
        more_submenu.setIcon(QIcon(get_asset_path("icons/more.svg")))
        duplicate_action = QAction(QIcon(get_asset_path("icons/duplicate.svg")), "Duplicate", self)
        duplicate_action.setShortcut(QKeySequence("p, d"))
        duplicate_action.triggered.connect(self.duplicate_requested)
        copy_action = QAction(QIcon(get_asset_path("icons/copy.svg")), "Copy", self)
        copy_action.setShortcut(QKeySequence("p, c"))
        copy_action.triggered.connect(self.copy_requested)
        get_help_action = QAction(QIcon(get_asset_path("icons/get_help.svg")), "Get help", self)
        get_help_action.setShortcut(QKeySequence("F1"))
        get_help_action.triggered.connect(self.get_help_requested)
        more_submenu.addAction(duplicate_action)
        more_submenu.addAction(copy_action)
        more_submenu.addAction(get_help_action)

        # Remove action (with separator)
        remove_action = QAction(QIcon(get_asset_path("icons/remove.svg")), "Remove", self)
        remove_action.setShortcut(QKeySequence("Del"))
        remove_action.triggered.connect(self.remove_requested)

        # Assemble menu
        menu.addAction(view_action)
        menu.addAction(edit_action)
        menu.addAction(share_action)
        menu.addAction(inspect_action)
        menu.addMenu(more_submenu)
        menu.addSeparator()
        menu.addAction(remove_action)

        # Placeholder stylesheet (can be refined)
        menu.setStyleSheet("""
            QMenu { background: #23272e; color: #fff; border: 1px solid #444; }
            QMenu::item { padding: 6px 32px 6px 32px; }
            QMenu::icon { padding-left: 8px; }
            QMenu::separator { height: 1px; background: #444; margin: 4px 0; }
        """)

        # Show menu below the options button
        button_pos = self.options_button.mapToGlobal(QPoint(0, self.options_button.height()))
        menu.exec(button_pos) 