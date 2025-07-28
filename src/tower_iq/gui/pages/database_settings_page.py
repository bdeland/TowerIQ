"""
TowerIQ Database Settings Page

This module provides the database and storage settings content.
"""

import asyncio
from pathlib import Path
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QScrollArea, QFileDialog
from qfluentwidgets import FluentIcon, LineEdit, InfoBar

from ..utils.settings_item_card import SettingsItemCard
from ..utils.database_path_card import DatabasePathCard
from ..utils.database_info_card import DatabaseInfoCard
from ..utils.health_check_card import HealthCheckCard


class DatabaseSettingsPage(QWidget):
    """Database & Storage settings content page."""
    
    def __init__(self, config_manager=None, controller=None, parent: QWidget | None = None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.controller = controller
        self.setup_ui()
        
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
        """Override showEvent to load database info when page is first shown."""
        super().showEvent(event)
        if not self._info_loaded:
            self._info_loaded = True
            # Use QTimer to schedule the async call after the event loop is ready
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(0, lambda: asyncio.create_task(self._refresh_database_info()) if asyncio.get_event_loop().is_running() else None)
        
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
        asyncio.create_task(self._refresh_database_info())
    
    @pyqtSlot()
    def _on_run_health_check_clicked(self):
        """Handle run health check button click."""
        asyncio.create_task(self._run_health_check(perform_fixes=False))
    
    @pyqtSlot()
    def _on_attempt_fixes_clicked(self):
        """Handle attempt fixes button click."""
        asyncio.create_task(self._run_health_check(perform_fixes=True))
    
    async def _refresh_database_info(self):
        """Refresh database information from the controller."""
        if not self.controller:
            return
        
        try:
            stats = await self.controller.get_database_stats()
            self.info_card.update_info(stats)
        except Exception as e:
            InfoBar.error(
                title='Error',
                content=f'Failed to refresh database info: {str(e)}',
                duration=3000,
                parent=self
            )
    
    async def _run_health_check(self, perform_fixes: bool):
        """Run database health check."""
        if not self.controller:
            return
        
        self.health_check_card.set_busy(True)
        
        try:
            results = await self.controller.validate_database_health(perform_fixes=perform_fixes)
            self.health_check_card.update_results(results)
            
            # Show success message if fixes were attempted
            if perform_fixes:
                InfoBar.success(
                    title='Fixes Attempted',
                    content='Database health check and fix process completed.',
                    duration=3000,
                    parent=self
                )
        except Exception as e:
            InfoBar.error(
                title='Error',
                content=f'Health check failed: {str(e)}',
                duration=3000,
                parent=self
            )
        finally:
            self.health_check_card.set_busy(False) 