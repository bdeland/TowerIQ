"""
TowerIQ Database Settings Page

This module provides the database and storage settings content.
"""

from pathlib import Path
import structlog
from PyQt6.QtCore import Qt, pyqtSlot, QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QScrollArea, QFileDialog
from qfluentwidgets import FluentIcon, LineEdit, InfoBar

from ..utils.settings_item_card import SettingsItemCard
from ..utils.database_path_card import DatabasePathCard
from ..utils.database_info_card import DatabaseInfoCard
from ..utils.health_check_card import HealthCheckCard


class DatabaseWorker(QObject):
    """Worker thread for database operations."""
    
    # Signals
    stats_ready = pyqtSignal(dict)  # Emits database statistics
    health_check_ready = pyqtSignal(list)  # Emits health check results
    error_occurred = pyqtSignal(str)  # Emits error message
    
    def __init__(self, controller, logger):
        super().__init__()
        self.controller = controller
        self.logger = logger
    
    @pyqtSlot()
    def get_database_stats(self):
        """Get database statistics in worker thread."""
        try:
            self.logger.info("Getting database statistics")
            stats = self.controller.get_database_stats()
            self.stats_ready.emit(stats)
            self.logger.info("Database statistics retrieved successfully")
        except Exception as e:
            self.logger.error("Error getting database statistics", error=str(e))
            self.error_occurred.emit(f"Failed to get database statistics: {str(e)}")
    
    @pyqtSlot(bool)
    def run_health_check(self, perform_fixes: bool):
        """Run database health check in worker thread."""
        try:
            self.logger.info("Running database health check", perform_fixes=perform_fixes)
            results = self.controller.validate_database_health(perform_fixes=perform_fixes)
            self.health_check_ready.emit(results)
            self.logger.info("Database health check completed")
        except Exception as e:
            self.logger.error("Error running database health check", error=str(e))
            self.error_occurred.emit(f"Health check failed: {str(e)}")


class DatabaseSettingsPage(QWidget):
    """Database & Storage settings content page."""
    
    def __init__(self, config_manager=None, controller=None, parent: QWidget | None = None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.controller = controller
        
        # Set up worker thread for database operations
        self._setup_worker_thread()
        
        self.setup_ui()
    
    def _setup_worker_thread(self):
        """Set up worker thread for database operations."""
        if not self.controller:
            return
            
        # Create worker thread
        self.database_thread = QThread()
        
        # Get logger from controller if available, otherwise create a simple one
        logger = None
        if hasattr(self.controller, 'logger'):
            logger = self.controller.logger
        else:
            # Create a simple logger that doesn't fail
            logger = structlog.get_logger().bind(source="DatabaseSettingsPage")
        
        self.database_worker = DatabaseWorker(self.controller, logger)
        self.database_worker.moveToThread(self.database_thread)
        
        # Connect signals
        self.database_worker.stats_ready.connect(self._on_stats_ready)
        self.database_worker.health_check_ready.connect(self._on_health_check_ready)
        self.database_worker.error_occurred.connect(self._on_database_error)
        
        # Start thread
        self.database_thread.start()
        
    def setup_ui(self):
        """Set up the database settings user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Create scrollable content area
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("border: 0px transparent;")

        content_widget = QWidget()
        content_widget.setObjectName("content_widget")
        content_widget.setStyleSheet("border: 0px transparent; background-color: transparent;")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        # Add settings content
        self.setup_content(content_layout)
        
        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)
        
    def setup_content(self, content_layout: QVBoxLayout):
        """Set up the database settings content."""
        # Create the database info card
        self.info_card = DatabaseInfoCard(self)
        self.info_card.refresh_clicked.connect(self._on_refresh_info_clicked)
        content_layout.addWidget(self.info_card)
        
        # Create the health check card
        self.health_check_card = HealthCheckCard(self)
        self.health_check_card.run_health_check_clicked.connect(self._on_run_health_check_clicked)
        self.health_check_card.attempt_fixes_clicked.connect(self._on_attempt_fixes_clicked)
        content_layout.addWidget(self.health_check_card)
        
        # Get current database path
        db_path = 'data/toweriq.sqlite'  # Default path
        if self.config_manager:
            db_path = self.config_manager.get('database.sqlite_path', db_path)
        
        # Create the database path card
        self.db_path_card = DatabasePathCard(db_path, self)
        self.db_path_card.choose_folder_clicked.connect(self._on_choose_folder)
        
        content_layout.addWidget(self.db_path_card)
        
        # Note: Database info will be loaded when the page is first accessed
        # to avoid async operations during initialization
        self._info_loaded = False
        
    def showEvent(self, event):
        """Override showEvent to load database info when page is shown."""
        super().showEvent(event)
        if not self._info_loaded:
            self._info_loaded = True
            # Use worker thread to get database stats
            if hasattr(self, 'database_worker') and self.database_worker:
                self.database_worker.get_database_stats()
    
    @pyqtSlot(dict)
    def _on_stats_ready(self, stats):
        """Handle database statistics from worker thread."""
        self.info_card.update_info(stats)
    
    @pyqtSlot(list)
    def _on_health_check_ready(self, results):
        """Handle health check results from worker thread."""
        self.health_check_card.update_results(results)
        self.health_check_card.set_busy(False)
        
        # Show success message if fixes were attempted
        if any('fixes' in str(result).lower() for result in results):
            InfoBar.success(
                title='Fixes Attempted',
                content='Database health check and fix process completed.',
                duration=3000,
                parent=self
            )
    
    @pyqtSlot(str)
    def _on_database_error(self, error_message):
        """Handle database errors from worker thread."""
        InfoBar.error(
            title='Error',
            content=error_message,
            duration=3000,
            parent=self
        )
        self.health_check_card.set_busy(False)
        
    def _on_choose_folder(self):
        """Handle choose folder button click."""
        current_path = self.db_path_card.get_path()
        
        # Convert to absolute path for the file dialog
        if current_path:
            path = Path(current_path)
            if not path.is_absolute():
                # Get the project root and make the path absolute
                project_root = Path(__file__).parent.parent.parent.parent.parent
                path = project_root / path
            initial_dir = str(path.parent)
        else:
            initial_dir = str(Path.cwd())
        
        # Open folder selection dialog
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Choose Database Directory",
            initial_dir,
            QFileDialog.Option.ShowDirsOnly
        )
        
        if folder_path:
            # Create the new database path (folder + filename)
            new_db_path = Path(folder_path) / "toweriq.sqlite"
            
            # Update the card
            self.db_path_card.update_path(str(new_db_path))
            
            # Update the configuration if config manager is available
            if self.config_manager:
                self.config_manager.set('database.sqlite_path', str(new_db_path))
    
    @pyqtSlot()
    def _on_refresh_info_clicked(self):
        """Handle refresh info button click."""
        if hasattr(self, 'database_worker') and self.database_worker:
            self.database_worker.get_database_stats()
    
    @pyqtSlot()
    def _on_run_health_check_clicked(self):
        """Handle run health check button click."""
        if hasattr(self, 'database_worker') and self.database_worker:
            self.health_check_card.set_busy(True)
            self.database_worker.run_health_check(perform_fixes=False)
    
    @pyqtSlot()
    def _on_attempt_fixes_clicked(self):
        """Handle attempt fixes button click."""
        if hasattr(self, 'database_worker') and self.database_worker:
            self.health_check_card.set_busy(True)
            self.database_worker.run_health_check(perform_fixes=True)
    
    def cleanup(self):
        """Clean up worker thread before destruction."""
        if hasattr(self, 'database_thread') and self.database_thread and self.database_thread.isRunning():
            # Disconnect signals to prevent callbacks after thread stops
            if hasattr(self, 'database_worker') and self.database_worker:
                try:
                    self.database_worker.stats_ready.disconnect()
                    self.database_worker.health_check_ready.disconnect()
                    self.database_worker.error_occurred.disconnect()
                except Exception:
                    # Signals might already be disconnected
                    pass
            
            # Stop the thread
            self.database_thread.quit()
            if not self.database_thread.wait(2000):  # Wait up to 2 seconds
                self.database_thread.terminate()  # Force terminate if it doesn't stop
            
            # Clean up references
            self.database_worker = None
            self.database_thread = None
    
    def closeEvent(self, event):
        """Override closeEvent to ensure proper cleanup."""
        self.cleanup()
        super().closeEvent(event)
    
    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup()