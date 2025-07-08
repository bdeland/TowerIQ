from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter, 
                             QTabWidget, QScrollArea, QLabel, QPushButton, QApplication)
from PyQt6.QtCore import Qt
from src.tower_iq.ui.widgets.panel_widget import PanelWidget

class EditPanelPage(QWidget):
    def __init__(self, panel_to_edit: PanelWidget, parent=None):
        super().__init__(parent)
        self.panel_to_edit = panel_to_edit
        self._init_ui()

    def _init_ui(self):
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)

        # Header/toolbar (now above the splitter)
        header_widget = QWidget(self)
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(12, 12, 12, 12)
        header_layout.setSpacing(8)
        # Remove per-page breadcrumb, update main window's breadcrumb instead
        edit_page_path = [
            ("Home", "home_id", "link"),
            ("Dashboards", "dashboard_list_id", "link"),
            ("Tower Dash", "dashboard_view_id", "button"),
            ("Edit panel", None, "text")
        ]
        mw = QApplication.activeWindow()
        try:
            mw.set_breadcrumb_path(edit_page_path)
        except Exception:
            pass
        header_layout.addStretch()
        back_btn = QPushButton("Back to dashboard", header_widget)
        save_btn = QPushButton("Save dashboard", header_widget)
        header_layout.addWidget(back_btn)
        header_layout.addWidget(save_btn)
        page_layout.addWidget(header_widget)

        # Main horizontal splitter (fills the rest)
        main_splitter = QSplitter(Qt.Orientation.Horizontal, self)

        # Left pane (vertical splitter)
        left_pane_widget = QWidget()
        left_pane_layout = QVBoxLayout(left_pane_widget)
        left_pane_layout.setContentsMargins(0, 0, 0, 0)
        left_pane_layout.setSpacing(0)
        left_splitter = QSplitter(Qt.Orientation.Vertical, left_pane_widget)
        left_pane_layout.addWidget(left_splitter)

        # Top: Preview area (PanelWidget)
        preview_frame = QWidget()
        preview_layout = QVBoxLayout(preview_frame)
        preview_layout.setContentsMargins(8, 8, 8, 8)
        preview_layout.addWidget(self.panel_to_edit)
        left_splitter.addWidget(preview_frame)

        # Bottom: Tabs (Queries, Transformations, Alert)
        tabs = QTabWidget()
        queries_tab = QWidget()
        transforms_tab = QWidget()
        alerts_tab = QWidget()
        tabs.addTab(queries_tab, "Queries")
        tabs.addTab(transforms_tab, "Transformations")
        tabs.addTab(alerts_tab, "Alert")
        left_splitter.addWidget(tabs)

        # Add left pane to main splitter
        main_splitter.addWidget(left_pane_widget)

        # Right pane: Scrollable options sidebar
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        options_container = QWidget()
        options_layout = QVBoxLayout(options_container)
        options_layout.setContentsMargins(12, 12, 12, 12)
        options_layout.setSpacing(16)
        # Placeholder options sections
        for section in ["Panel options", "Tooltip", "Legend", "Axes", "Thresholds", "Field overrides"]:
            label = QLabel(section)
            label.setStyleSheet("font-weight: bold; font-size: 15px; margin-bottom: 8px;")
            options_layout.addWidget(label)
        options_layout.addStretch()
        scroll_area.setWidget(options_container)
        main_splitter.addWidget(scroll_area)

        # Set initial splitter sizes (70% left, 30% right)
        main_splitter.setSizes([700, 300])
        page_layout.addWidget(main_splitter) 