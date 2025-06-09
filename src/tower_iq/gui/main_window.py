"""
TowerIQ v1.0 - Main User Interface Window

This module defines the MainWindow class, the primary window for the application
that contains navigation, dashboard panels, and status indicators.
"""

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QFrame, 
    QPushButton, QStackedWidget, QStatusBar, QLabel
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QIcon, QPixmap

from tower_iq.gui.components.dashboard_page import DashboardPage
from tower_iq.gui.components.settings_page import SettingsPage
from tower_iq.gui.components.history_page import HistoryPage
from tower_iq.gui.components.status_indicator import StatusIndicator
from tower_iq.gui.assets import get_asset_path

if TYPE_CHECKING:
    from tower_iq.core.main_controller import MainController


class MainWindow(QMainWindow):
    """
    The primary window for the TowerIQ application.
    
    Serves as the main container for the application's UI, including the navigation bar,
    dashboard panels, and status indicators. Uses a QStackedWidget to switch between
    different pages (Dashboard, History, Settings, etc.).
    """
    
    def __init__(self, controller: "MainController") -> None:
        """
        Initialize the main window.
        
        Args:
            controller: The main controller instance for handling business logic
        """
        super().__init__()
        
        self.controller = controller
        
        # Set window properties
        self.setWindowTitle("TowerIQ")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        
        # Set window icon
        try:
            icon_path = get_asset_path("icons/toweriq_icon.png")
            self.setWindowIcon(QIcon(icon_path))
        except Exception:
            # Fallback if icon not found
            pass
        
        # Initialize UI and connect signals
        self._init_ui()
        self._connect_signals()
    
    def _init_ui(self) -> None:
        """
        Create and arrange all the widgets in the main window.
        
        Sets up the navigation panel on the left and the main content area
        on the right using a QStackedWidget for page switching.
        """
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Left Panel (Navigation)
        self.nav_frame = QFrame()
        self.nav_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        self.nav_frame.setFixedWidth(200)
        self.nav_frame.setStyleSheet("""
            QFrame {
                background-color: #2b2b2b;
                border-right: 1px solid #555;
            }
            QPushButton {
                background-color: transparent;
                border: none;
                color: white;
                text-align: left;
                padding: 12px 16px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #3a3a3a;
            }
            QPushButton:pressed {
                background-color: #4a4a4a;
            }
        """)
        
        nav_layout = QVBoxLayout(self.nav_frame)
        nav_layout.setContentsMargins(0, 20, 0, 0)
        nav_layout.setSpacing(5)
        
        # Application title/logo area
        title_label = QLabel("TowerIQ")
        title_label.setStyleSheet("""
            QLabel {
                color: #4CAF50;
                font-size: 18px;
                font-weight: bold;
                padding: 10px 16px 20px 16px;
            }
        """)
        nav_layout.addWidget(title_label)
        
        # Navigation buttons
        self.nav_dashboard_button = QPushButton("📊 Dashboard")
        self.nav_history_button = QPushButton("📈 Run History")
        self.nav_settings_button = QPushButton("⚙️ Settings")
        
        nav_layout.addWidget(self.nav_dashboard_button)
        nav_layout.addWidget(self.nav_history_button)
        nav_layout.addWidget(self.nav_settings_button)
        nav_layout.addStretch()  # Push buttons to top
        
        main_layout.addWidget(self.nav_frame)
        
        # Right Panel (Main Content)
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setStyleSheet("""
            QStackedWidget {
                background-color: #f5f5f5;
            }
        """)
        
        # Create page instances
        self.dashboard_page = DashboardPage(self.controller)
        self.history_page = HistoryPage(self.controller)
        self.settings_page = SettingsPage(self.controller)
        
        # Add pages to stack
        self.stacked_widget.addWidget(self.dashboard_page)
        self.stacked_widget.addWidget(self.history_page)
        self.stacked_widget.addWidget(self.settings_page)
        
        # Set dashboard as default page
        self.stacked_widget.setCurrentWidget(self.dashboard_page)
        
        main_layout.addWidget(self.stacked_widget, 1)  # Stretch factor 1
        
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
        
        # Navigation button connections
        self.nav_dashboard_button.clicked.connect(
            lambda: self._switch_to_page(self.dashboard_page, "Dashboard")
        )
        self.nav_history_button.clicked.connect(
            lambda: self._switch_to_page(self.history_page, "Run History")
        )
        self.nav_settings_button.clicked.connect(
            lambda: self._switch_to_page(self.settings_page, "Settings")
        )
        
        # Controller signal connections
        self.controller.new_metric_received.connect(self.dashboard_page.update_metric_display)
        self.controller.new_graph_data.connect(self.dashboard_page.update_graph)
        self.controller.status_changed.connect(self.status_indicator.update_status)
        # self.controller.status_message_changed.connect(self.status_label.setText)
    
    def _switch_to_page(self, page_widget: QWidget, page_name: str) -> None:
        """
        Switch to a different page in the main content area.
        
        Args:
            page_widget: The widget to switch to
            page_name: Name of the page for status display
        """
        self.stacked_widget.setCurrentWidget(page_widget)
        self.status_label.setText(f"Viewing: {page_name}")
        
        # Update navigation button styles to show active state
        self._update_nav_button_styles(page_widget)
    
    def _update_nav_button_styles(self, active_page: QWidget) -> None:
        """
        Update navigation button styles to highlight the active page.
        
        Args:
            active_page: The currently active page widget
        """
        # Reset all buttons to default style
        buttons = [self.nav_dashboard_button, self.nav_history_button, self.nav_settings_button]
        for button in buttons:
            button.setStyleSheet(button.styleSheet().replace("background-color: #4CAF50;", ""))
        
        # Highlight active button
        if active_page == self.dashboard_page:
            self._highlight_nav_button(self.nav_dashboard_button)
        elif active_page == self.history_page:
            self._highlight_nav_button(self.nav_history_button)
        elif active_page == self.settings_page:
            self._highlight_nav_button(self.nav_settings_button)
    
    def _highlight_nav_button(self, button: QPushButton) -> None:
        """
        Apply highlighting style to a navigation button.
        
        Args:
            button: The button to highlight
        """
        current_style = button.styleSheet()
        if "background-color: #4CAF50;" not in current_style:
            button.setStyleSheet(current_style + "QPushButton { background-color: #4CAF50; }")
    
    @pyqtSlot(str)
    def show_status_message(self, message: str) -> None:
        """
        Display a status message in the status bar.
        
        Args:
            message: The message to display
        """
        self.status_label.setText(message)
        
    @pyqtSlot()
    def show_setup_wizard(self) -> None:
        """
        Show the setup wizard dialog.
        
        This slot can be connected to controller signals that indicate
        setup is needed (e.g., on first run).
        """
        from tower_iq.gui.setup_wizard_dialog import SetupWizardDialog
        
        wizard = SetupWizardDialog(self.controller)
        wizard.exec()
    
    def closeEvent(self, event) -> None:
        """
        Handle the window close event.
        
        Ensures proper cleanup when the user closes the main window.
        
        Args:
            event: The close event
        """
        # Could add confirmation dialog here if needed
        # For now, just accept the close event
        event.accept() 