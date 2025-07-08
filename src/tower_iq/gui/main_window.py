"""
TowerIQ v1.0 - Main User Interface Window

This module defines the MainWindow class, the primary window for the application
that contains navigation, dashboard panels, and status indicators.
"""

from typing import TYPE_CHECKING
import asyncio
import os
import time

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QFrame, 
    QPushButton, QStackedWidget, QStatusBar, QLabel,
    QMessageBox, QButtonGroup, QHBoxLayout  # Add QHBoxLayout for custom nav button
)
from PyQt6.QtCore import Qt, pyqtSlot, QPropertyAnimation, QEasingCurve, QSize, QObject, pyqtSignal
from PyQt6.QtGui import QIcon, QPixmap, QPalette, QColor
from PyQt6.QtSvgWidgets import QSvgWidget

from tower_iq.gui.components.dashboard_page import DashboardPage
from tower_iq.gui.components.settings_page import SettingsPage
from tower_iq.gui.components.history_page import HistoryPage
from tower_iq.gui.components.status_indicator import StatusIndicator
from tower_iq.gui.assets import get_asset_path
from tower_iq.gui.components.explore_page import ExplorePage
from src.tower_iq.ui.pages.dashboard_test_page import DashboardTestPage
from src.tower_iq.gui.sidebar import SidebarFrame, SidebarNavButton
from src.tower_iq.ui.widgets.q_breadcrumb import QBreadCrumb


class MainWindow(QMainWindow):
    """
    The primary window for the TowerIQ application.
    
    Serves as the main container for the application's UI, including the navigation bar,
    dashboard panels, and status indicators. Uses a QStackedWidget to switch between
    different pages (Dashboard, History, Settings, etc.).
    """
    
    def __init__(self, controller) -> None:
        """
        Initialize the main window.
        
        Args:
            controller: The main controller instance for handling business logic
        """
        super().__init__()
        
        self.controller = controller
        
        # Set window properties
        self.setWindowTitle("TowerIQ")
        self.setMinimumSize(700, 300)  # Allow smaller resizing
        self.resize(1000, 700)
        
        # Set window icon
        try:
            icon_path = get_asset_path("icons/toweriq_icon.png")
            self.setWindowIcon(QIcon(icon_path))
        except Exception:
            # Fallback if icon not found
            pass
        
        # Sidebar state attributes
        self.SIDEBAR_EXPANDED_WIDTH = 200
        self.SIDEBAR_COLLAPSED_WIDTH = 60
        self.is_sidebar_pinned = False
        
        # Initialize UI and connect signals
        self._init_ui()
        self._connect_signals()
        # Collapse sidebar by default
        self.collapse_sidebar()
    
    def _init_ui(self) -> None:
        """
        Create and arrange all the widgets in the main window.
        
        Sets up the navigation panel on the left and the main content area
        on the right using a QStackedWidget for page switching.
        """
        # Set dark theme for the main window and all children
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #001219;
                color: #fff;
            }
            QStatusBar, QLabel {
                background-color: #001219;
                color: #fff;
            }
            QFrame {
                background-color: #001219;
                color: #fff;
            }
            QScrollArea, QAbstractScrollArea {
                background: #001219;
                color: #fff;
            }
            QLineEdit {
                background: #001219;
                color: #fff;
                border: 1px solid #79a2bc;
                border-radius: 5px;
                padding: 2px 8px;
            }
            QPushButton {
                background-color: #001219;
                color: #fff;
                border: 1px solid #2a9b8e;
                border-radius: 5px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #2a9b8e;
                color: #001219;
            }
            QPushButton:pressed, QPushButton:checked {
                background-color: #2a9b8e;
                color: #fff;
            }
            QTableWidget, QHeaderView::section {
                background-color: #001219;
                color: #fff;
                border: 1px solid #79a2bc;
            }
            QTableWidget::item:selected {
                background: #2a9b8e;
                color: #fff;
            }
            QHeaderView::section {
                background-color: #001219;
                color: #fff;
                border: 1px solid #2a9b8e;
            }
            /* --- QBreadCrumb Styles --- */
            QBreadCrumb {
                font-size: 14px;
            }
            QPushButton#breadcrumbLink {
                color: #5794F2;
                background-color: transparent;
                border: none;
                padding: 4px 0;
                margin: 0;
            }
            QPushButton#breadcrumbLink:hover {
                text-decoration: underline;
            }
            QPushButton#breadcrumbButton {
                color: #E0E0E0;
                background-color: #3A3C44;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 4px 8px;
                margin: 0;
            }
            QPushButton#breadcrumbButton:hover {
                background-color: #4a4d55;
                border-color: #666;
            }
            QLabel#currentCrumb {
                color: #FFFFFF;
                font-weight: bold;
                padding: 4px 0;
            }
            QLabel#breadcrumbSeparator {
                color: #8E8F91;
                padding: 4px 0;
            }
        """)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        pal = central_widget.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor('#001219'))
        pal.setColor(QPalette.ColorRole.Base, QColor('#001219'))
        pal.setColor(QPalette.ColorRole.Text, QColor('#ffffff'))
        central_widget.setPalette(pal)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Main horizontal layout for sidebar + content
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        # Left Panel (Navigation)
        self.nav_frame = SidebarFrame()
        self.nav_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        self.nav_frame.setFixedWidth(self.SIDEBAR_COLLAPSED_WIDTH)  # Collapsed by default
        self.nav_frame.setStyleSheet("""
            QFrame {
                background-color: #001219;
                /* border-right: 2px solid #79a2bc; */
            }
            QPushButton {
                background-color: transparent;
                color: #fff;
                text-align: left;
                padding: 12px 16px;
                font-size: 14px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1d3a4a;
            }
            QPushButton:checked {
                background-color: #2a9b8e;
                color: #fff;
                font-weight: bold;
            }
        """)
        
        nav_layout = QVBoxLayout(self.nav_frame)
        nav_layout.setContentsMargins(0, 20, 0, 0)
        nav_layout.setSpacing(5)
        
        # Application logo area (SVG)
        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter)
        self.logo_label.setFixedHeight(70)  # Fixed height to prevent button jumping
        self.logo_label.setStyleSheet("padding: 10px 0 20px 0;")
        nav_layout.addWidget(self.logo_label)
        self._update_sidebar_logo(expanded=False)
        
        # Navigation buttons with icons (now SidebarNavButton)
        self.nav_dashboard_test_button = SidebarNavButton(self._safe_icon("dashboard_icon.svg"), "Dashboard Test", self.nav_frame)
        self.nav_explore_button = SidebarNavButton(self._safe_icon("explore_icon.svg"), "Explore", self.nav_frame)
        self.nav_dashboard_button = SidebarNavButton(self._safe_icon("dashboard_icon.svg"), "Dashboard", self.nav_frame)
        self.nav_history_button = SidebarNavButton(self._safe_icon("history_icon.svg"), "Run History", self.nav_frame)
        self.nav_settings_button = SidebarNavButton(self._safe_icon("settings_icon.svg"), "Settings", self.nav_frame)
        self.nav_buttons = [self.nav_dashboard_test_button, self.nav_dashboard_button, self.nav_explore_button, self.nav_history_button, self.nav_settings_button]
        class NavButtonGroup(QObject):
            buttonClicked = pyqtSignal(object)
            def __init__(self, buttons):
                super().__init__()
                self._buttons = buttons
                for btn in buttons:
                    btn.button_group = self
                    btn.mousePressEvent = self._make_handler(btn)
            def _make_handler(self, btn):
                def handler(event):
                    for b in self._buttons:
                        b.setChecked(False)
                    btn.setChecked(True)
                    self.buttonClicked.emit(btn)
                    QWidget.mousePressEvent(btn, event)
                return handler
            def buttons(self):
                return self._buttons
        self.nav_button_group = NavButtonGroup(self.nav_buttons)
        self.nav_dashboard_test_button.setChecked(True)
        for btn in self.nav_buttons:
            btn.setCollapsed(True)
            nav_layout.addWidget(btn)
        nav_layout.addStretch()
        # Sidebar toggle button at the bottom
        self.sidebar_toggle_button = QPushButton()
        self.sidebar_toggle_button.setIcon(self._safe_icon("sidebar_close.svg"))
        self.sidebar_toggle_button.setIconSize(QSize(24, 24))
        self.sidebar_toggle_button.setToolTip("Close sidebar")
        self.sidebar_toggle_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #2a9b8e;
            }
        """)
        nav_layout.addWidget(self.sidebar_toggle_button, alignment=Qt.AlignmentFlag.AlignHCenter)
        
        content_layout.addWidget(self.nav_frame)

        # --- Begin new content area layout (right of sidebar) ---
        right_content_widget = QWidget()
        right_content_layout = QVBoxLayout(right_content_widget)
        right_content_layout.setContentsMargins(0, 0, 0, 0)
        right_content_layout.setSpacing(0)
        # Breadcrumb at the top of the content area
        self.breadcrumb = QBreadCrumb(separator_type='icon', separator_value='resources/assets/icons/chevron_right.svg')
        self.breadcrumb.setFixedHeight(40)
        right_content_layout.addWidget(self.breadcrumb)
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setFrameShadow(QFrame.Shadow.Sunken)
        divider.setStyleSheet("color: #2a9b8e; background-color: #2a9b8e; min-height: 2px; max-height: 2px;")
        right_content_layout.addWidget(divider)

        # Main content area (QStackedWidget)
        self.content_stack = QStackedWidget()
        self.content_stack.setStyleSheet("""
            QStackedWidget {
                background-color: #001219;
            }
        """)
        # Create page instances
        self.dashboard_test_page = DashboardTestPage(self)
        self.dashboard_page = DashboardPage(self.controller)
        self.explore_page = ExplorePage(self.controller)
        self.history_page = HistoryPage(self.controller)
        self.settings_page = SettingsPage(self.controller)
        # Add pages to stack
        self.content_stack.addWidget(self.dashboard_test_page)
        self.content_stack.addWidget(self.dashboard_page)
        self.content_stack.addWidget(self.explore_page)
        self.content_stack.addWidget(self.history_page)
        self.content_stack.addWidget(self.settings_page)
        # Set dashboard test as default page
        self.content_stack.setCurrentWidget(self.dashboard_test_page)
        self.set_breadcrumb_path([
            ("Home", "home_id", "link"),
            ("Dashboard Test", None, "text")
        ])
        right_content_layout.addWidget(self.content_stack)
        # Add the right content area to the main horizontal layout
        content_layout.addWidget(right_content_widget)
        main_layout.addLayout(content_layout)
        
        # Create status bar with global status indicator
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.status_indicator = StatusIndicator()
        self.status_bar.addPermanentWidget(self.status_indicator)
        
        # Add a label for general status messages
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
    
    def _connect_signals(self) -> None:
        """
        Connect UI widget signals to MainController slots and controller signals to UI update slots.
        
        Sets up the communication between the UI and the business logic layer.
        """
        # Set dashboard reference in controller for connection panel updates
        self.controller.set_dashboard(self.dashboard_page)
        # Navigation button group connection
        self.nav_button_group.buttonClicked.connect(self._on_nav_button_clicked)
        # Sidebar toggle button connection
        self.sidebar_toggle_button.clicked.connect(self.toggle_sidebar)
        # Controller signal connections
        self.controller.new_metric_received.connect(self.dashboard_page.update_metric_display)
        self.controller.new_graph_data.connect(self.dashboard_page.update_graph)
        self.controller.status_changed.connect(self.status_indicator.update_status)
    
    def _on_nav_button_clicked(self, button):
        if button == self.nav_dashboard_test_button:
            self.content_stack.setCurrentWidget(self.dashboard_test_page)
            self.status_label.setText("Viewing: Dashboard Test")
            self.set_breadcrumb_path([
                ("Home", "home_id", "link"),
                ("Dashboard Test", None, "text")
            ])
        elif button == self.nav_dashboard_button:
            self.content_stack.setCurrentWidget(self.dashboard_page)
            self.status_label.setText("Viewing: Dashboard")
            self.set_breadcrumb_path([
                ("Home", "home_id", "link"),
                ("Dashboard", None, "text")
            ])
        elif button == self.nav_explore_button:
            self.content_stack.setCurrentWidget(self.explore_page)
            self.status_label.setText("Viewing: Explore")
            self.set_breadcrumb_path([
                ("Home", "home_id", "link"),
                ("Explore", None, "text")
            ])
        elif button == self.nav_history_button:
            self.content_stack.setCurrentWidget(self.history_page)
            self.status_label.setText("Viewing: Run History")
            self.set_breadcrumb_path([
                ("Home", "home_id", "link"),
                ("Run History", None, "text")
            ])
        elif button == self.nav_settings_button:
            self.content_stack.setCurrentWidget(self.settings_page)
            self.status_label.setText("Viewing: Settings")
            self.set_breadcrumb_path([
                ("Home", "home_id", "link"),
                ("Settings", None, "text")
            ])
    
    def toggle_sidebar(self):
        # Determine current state by width
        expanded = self.nav_frame.width() > (self.SIDEBAR_EXPANDED_WIDTH + self.SIDEBAR_COLLAPSED_WIDTH) // 2
        if expanded:
            self.collapse_sidebar()
            self.sidebar_toggle_button.setIcon(self._safe_icon("sidebar_open.svg"))
            self.sidebar_toggle_button.setToolTip("Open sidebar")
        else:
            self.expand_sidebar()
            self.sidebar_toggle_button.setIcon(self._safe_icon("sidebar_close.svg"))
            self.sidebar_toggle_button.setToolTip("Close sidebar")

    def expand_sidebar(self):
        for btn in self.nav_buttons:
            btn.setCollapsed(False)
        self._update_sidebar_logo(expanded=True)
        self.animation = QPropertyAnimation(self.nav_frame, b"minimumWidth")
        self.animation.setDuration(350)
        self.animation.setStartValue(self.nav_frame.width())
        self.animation.setEndValue(self.SIDEBAR_EXPANDED_WIDTH)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.start()

    def collapse_sidebar(self):
        for btn in self.nav_buttons:
            btn.setCollapsed(True)
        self._update_sidebar_logo(expanded=False)
        self.animation = QPropertyAnimation(self.nav_frame, b"minimumWidth")
        self.animation.setDuration(350)
        self.animation.setStartValue(self.nav_frame.width())
        self.animation.setEndValue(self.SIDEBAR_COLLAPSED_WIDTH)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.start()
    
    def _update_sidebar_logo(self, expanded: bool):
        # Placeholder: swap SVGs when available
        if expanded:
            logo_path = self._safe_icon("sidebar_logo_expanded.svg")
        else:
            logo_path = self._safe_icon("sidebar_logo_collapsed.svg")
        # Use QPixmap for now, can switch to QSvgWidget if needed
        if isinstance(logo_path, QIcon):
            pixmap = logo_path.pixmap(QSize(48, 48))
            self.logo_label.setPixmap(pixmap)
        else:
            self.logo_label.clear()
    
    @pyqtSlot(str)
    def show_status_message(self, message: str) -> None:
        """
        Display a status message in the status bar.
        
        Args:
            message: The message to display
        """
        self.status_label.setText(message)
    
    def closeEvent(self, event) -> None:
        """
        Handle the window close event.
        Ensures robust, unified shutdown when the user closes the main window.
        Blocks until shutdown is complete or a timeout is reached, then force-exits if needed.
        Args:
            event: The close event
        """
        if getattr(self, '_shutdown_in_progress', False):
            event.accept()
            return
        # Check if a round is active and prompt the user
        try:
            if hasattr(self.controller, 'session') and getattr(self.controller.session, 'is_round_active', False):
                if self.controller.session.is_round_active:
                    msg_box = QMessageBox(self)
                    msg_box.setIcon(QMessageBox.Icon.Warning)
                    msg_box.setWindowTitle("Active Round Detected")
                    msg_box.setText("You are currently monitoring an active round. Are you sure that you want to exit?")
                    exit_button = msg_box.addButton("Exit", QMessageBox.ButtonRole.AcceptRole)
                    dont_exit_button = msg_box.addButton("Don't Exit", QMessageBox.ButtonRole.RejectRole)
                    msg_box.setDefaultButton(dont_exit_button)
                    msg_box.exec()
                    if msg_box.clickedButton() == dont_exit_button:
                        event.ignore()
                        return
                    # else, proceed with shutdown
        except Exception as e:
            print(f"Error checking round active state: {e}")
        self._shutdown_in_progress = True
        try:
            # Stop all timers to prevent threading issues during shutdown
            self._cleanup_timers()
            # Set controller shutdown flag to prevent new operations
            if hasattr(self.controller, '_is_shutting_down'):
                self.controller._is_shutting_down = True
            # Stop status indicator animation if running
            if hasattr(self.status_indicator, 'animation_timer'):
                self.status_indicator.animation_timer.stop()
            # Clean up any connection panel timers
            if (hasattr(self.dashboard_page, 'connection_panel') and 
                hasattr(self.dashboard_page.connection_panel, 'animation_timer')):
                self.dashboard_page.connection_panel.animation_timer.stop()
                self.dashboard_page.connection_panel.safety_timer.stop()
            # Await controller shutdown (robust, with timeout)
            loop = None
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                pass
            shutdown_done = False
            start_time = time.time()
            if loop and loop.is_running():
                try:
                    coro = self.controller.stop()
                    fut = asyncio.run_coroutine_threadsafe(coro, loop)
                    fut.result(timeout=3.0)
                    shutdown_done = True
                except Exception as e:
                    print(f"Error during async controller shutdown: {e}")
            else:
                try:
                    # Fallback: call stop synchronously if possible
                    if hasattr(self.controller, 'stop'):
                        self.controller.stop()
                        shutdown_done = True
                except Exception as e:
                    print(f"Error during sync controller shutdown: {e}")
            # Wait up to 3 seconds for shutdown
            while not shutdown_done and (time.time() - start_time) < 3.0:
                time.sleep(0.1)
            if not shutdown_done:
                print("Shutdown did not complete in 3 seconds. Forcing exit.")
                os._exit(0)
        except Exception as e:
            print(f"Error during main window cleanup: {e}")
            os._exit(1)
        event.accept()
    
    def _cleanup_timers(self) -> None:
        """Clean up all QTimer instances to prevent threading issues during shutdown."""
        try:
            from PyQt6.QtCore import QTimer
            
            # Find all QTimer objects in the main window and its children
            timers = self.findChildren(QTimer)
            for timer in timers:
                if timer.isActive():
                    timer.stop()
            
        except Exception as e:
            print(f"Error cleaning up timers: {e}")

    def _safe_icon(self, icon_name):
        try:
            return QIcon(get_asset_path(f"icons/{icon_name}"))
        except Exception as e:
            print(f"Warning: Could not load icon {icon_name}: {e}")
            return QIcon()

    def set_breadcrumb_path(self, path_segments):
        self.breadcrumb.set_path(path_segments) 