"""
TowerIQ Main Controller

This module provides the main controller that uses QThread instead of asyncio
to eliminate qasync timer conflicts completely.
"""

import time
import os
from typing import Any, Optional

from PyQt6.QtCore import QObject, QThread, pyqtSignal, pyqtSlot, QTimer

from .core.config import ConfigurationManager
from .core.session import SessionManager
from .services.database_service import DatabaseService
from .services.emulator_service import EmulatorService
from .services.connection_flow_controller import ConnectionFlowController
from .services.connection_stage_manager import ConnectionStageManager


class DeviceScanWorker(QObject):
    """Worker thread for device scanning operations."""
    
    # Signals
    scan_completed = pyqtSignal(list)  # Emits list of devices
    scan_failed = pyqtSignal(str)      # Emits error message
    
    def __init__(self, emulator_service, logger):
        super().__init__()
        self.emulator_service = emulator_service
        self.logger = logger
        self._should_stop = False
    
    @pyqtSlot()
    def scan_devices(self):
        """Perform device scan."""
        try:
            self.logger.info("DeviceScanWorker: scan_devices slot called")
            self.logger.info("Starting device scan")
            # Use sync version for Qt threading
            devices = self.emulator_service.find_connected_devices_sync()
            self.logger.info("DeviceScanWorker: About to emit scan_completed signal", device_count=len(devices))
            self.scan_completed.emit(devices)
            self.logger.info("Device scan completed", device_count=len(devices))
            self.logger.info("DeviceScanWorker: scan_completed signal emitted successfully")
        except Exception as e:
            self.logger.error("Device scan failed", error=str(e))
            self.logger.info("DeviceScanWorker: About to emit scan_failed signal")
            self.scan_failed.emit(str(e))
            self.logger.info("DeviceScanWorker: scan_failed signal emitted")
    
    def stop(self):
        """Stop the worker."""
        self._should_stop = True


class DatabaseWorker(QObject):
    """Worker thread for database operations."""
    
    # Signals
    database_connected = pyqtSignal()
    database_error = pyqtSignal(str)
    
    def __init__(self, db_service, logger):
        super().__init__()
        self.db_service = db_service
        self.logger = logger
    
    @pyqtSlot()
    def connect_database(self):
        """Connect to database."""
        try:
            self.logger.info("Connecting to database")
            self.db_service.connect()
            self.database_connected.emit()
            self.logger.info("Database connected successfully")
        except Exception as e:
            self.logger.error("Database connection failed", error=str(e))
            self.database_error.emit(str(e))


class MainController(QObject):
    """
    Main Controller that uses QThread instead of asyncio.
    This eliminates qasync timer conflicts completely.
    """
    
    # Signals
    setup_finished = pyqtSignal(bool)
    device_scan_requested = pyqtSignal()
    
    def __init__(self, config: ConfigurationManager, logger: Any, db_path: str = '', db_service=None) -> None:
        super().__init__()
        self.config = config
        self.logger = logger
        
        # Initialize services
        if db_service is not None:
            # Use pre-connected database service
            self.db_service = db_service
            self.logger.info("Using pre-connected database service")
        else:
            # Create new database service
            self.db_service = DatabaseService(config, logger, db_path=db_path)
        
        self.emulator_service = EmulatorService(config, logger)
        
        # Initialize session manager
        self.session = SessionManager()
        
        # Link services (only if not already linked)
        if not hasattr(config, '_db_service') or config._db_service is None:
            self.config.link_database_service(self.db_service)
        
        # Application state
        self._is_running = False
        self._is_shutting_down = False
        
        # Qt Threading
        self._setup_worker_threads()
        
        # Test mode flags
        self._test_mode = False
        self._test_mode_replay = False
        self._test_mode_generate = False
        
        # Debouncing for device scans
        self._last_scan_request_time = 0.0
        self._scan_debounce_delay = 0.5  # 500ms debounce
        
        # Initialize timer properly in main thread
        self.monitor_timer = None
    
    def _setup_worker_threads(self):
        """Set up worker threads for background operations."""
        # Device scan thread
        self.device_scan_thread = QThread()
        self.device_scan_worker = DeviceScanWorker(self.emulator_service, self.logger)
        self.device_scan_worker.moveToThread(self.device_scan_thread)
        
        # Connect signals
        self.device_scan_requested.connect(self.device_scan_worker.scan_devices)
        self.device_scan_worker.scan_completed.connect(self._on_device_scan_completed)
        self.device_scan_worker.scan_failed.connect(self._on_device_scan_failed)
        
        # Database thread (only if needed)
        if self.db_service.sqlite_conn is None:
            self.database_thread = QThread()
            self.database_worker = DatabaseWorker(self.db_service, self.logger)
            self.database_worker.moveToThread(self.database_thread)
            
            # Connect database signals
            self.database_worker.database_connected.connect(self._on_database_connected)
            self.database_worker.database_error.connect(self._on_database_error)
            
            # Start database thread
            self.database_thread.start()
        
        # Start device scan thread
        self.device_scan_thread.start()
    
    def start_background_operations(self):
        """Start background operations using Qt threads."""
        self.logger.info("Starting background operations")
        self._is_running = True
        
        # Connect to database in background thread if needed
        if hasattr(self, 'database_worker'):
            self.database_worker.connect_database()
        
        # Defer timer creation until after Qt event loop is running
        # This ensures proper thread context for QTimer
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(500, self._setup_monitoring_timer)
        
        self.logger.info("Background operations started successfully")
    
    def _setup_monitoring_timer(self):
        """Set up the monitoring timer after Qt event loop is established."""
        try:
            self.logger.info("Setting up health monitoring timer")
            self.monitor_timer = QTimer(self)
            self.monitor_timer.timeout.connect(self._monitor_system_health)
            self.monitor_timer.start(5000)  # Every 5 seconds
            self.logger.info("Health monitoring timer started successfully")
        except Exception as e:
            self.logger.error("Failed to setup monitoring timer", error=str(e))
    
    @pyqtSlot(list)
    def _on_device_scan_completed(self, devices):
        """Handle device scan completion."""
        self.logger.info("Device scan completed", device_count=len(devices))
        
        current_devices = len(self.session.available_emulators)
        self.logger.info("Current devices in session before update", current_count=current_devices)
        
        # Update session state - this should trigger GUI updates via signals
        self.session.available_emulators = devices
        
        updated_devices = len(self.session.available_emulators)
        self.logger.info("Updated devices in session after update", new_count=updated_devices)
        
        self.logger.info("Session state updated with device scan results")
    
    @pyqtSlot(str)
    def _on_device_scan_failed(self, error):
        """Handle device scan failure."""
        self.session.available_emulators = []
        self.logger.error("Device scan failed", error=error)
    
    @pyqtSlot()
    def _on_database_connected(self):
        """Handle database connection success."""
        self.logger.info("Database connected in background thread")
        self.setup_finished.emit(True)
    
    @pyqtSlot(str)
    def _on_database_error(self, error):
        """Handle database connection error."""
        self.logger.error("Database connection error", error=error)
        self.setup_finished.emit(False)
    
    @pyqtSlot()
    def _monitor_system_health(self):
        """Monitor system health (Qt Timer based)."""
        try:
            # Basic health monitoring
            if not self._is_shutting_down:
                self.logger.debug("System health check")
        except Exception as e:
            self.logger.error("Error in system health monitoring", error=str(e))
    
    @pyqtSlot()
    def on_scan_devices_requested(self):
        """Handle device scan requests from the GUI."""
        current_time = time.time()
        
        # Debounce rapid requests
        if current_time - self._last_scan_request_time < self._scan_debounce_delay:
            self.logger.debug("Device scan request debounced - too soon after last request")
            return
            
        self._last_scan_request_time = current_time
        self.logger.info("MainController: Device scan requested from GUI")
        
        # Emit signal to worker thread
        self.logger.info("MainController: About to emit device_scan_requested signal to worker")
        self.device_scan_requested.emit()
        self.logger.info("MainController: device_scan_requested signal emitted to worker thread")
    
    @pyqtSlot(str)
    def on_connect_device_requested(self, device_serial: str):
        """Handle device connection requests from the GUI."""
        self.logger.info("Device connection requested from GUI", device_serial=device_serial)
        
        # Update session state to reflect connection
        self.session.connected_emulator_serial = device_serial
        self.session.is_emulator_connected = True
        
        # Find the device in available emulators
        device_found = False
        for device in self.session.available_emulators:
            if device.get('serial') == device_serial:
                device_found = True
                self.logger.info("Device found in available emulators", device_info=device)
                break
        
        if device_found:
            # TODO: Get real processes from the connected device
            # For now, clear processes until real implementation
            self.session.available_processes = []
            self.logger.info("Device connected, processes will be loaded when implemented")
        else:
            self.logger.warning("Device not found in available emulators", device_serial=device_serial)
            self.session.available_processes = []
        
        self.logger.info("Device connection handled", device_serial=device_serial)
    
    @pyqtSlot(str)
    def on_select_process_requested(self, package_name: str):
        """Handle process selection requests from the GUI."""
        self.logger.info("Process selection requested from GUI", package_name=package_name)
        
        # Update session state
        self.session.selected_target_package = package_name
        
        # TODO: Implement real hook compatibility check
        self.session.is_hook_compatible = False  # Conservative default
        
        self.logger.info("Process selection handled", package_name=package_name)
    
    @pyqtSlot(str)
    def on_activate_hook_requested(self, package_name: str):
        """Handle hook activation requests from the GUI."""
        self.logger.info("Hook activation requested from GUI", package_name=package_name)
        
        # TODO: Implement real hook activation
        self.session.is_hook_active = False  # Conservative default
        self.session.selected_target_package = package_name
        
        self.logger.info("Hook activation handled (not yet implemented)", package_name=package_name)
        
    def get_session_state(self) -> dict:
        """Get current session state for debugging."""
        return {
            'is_emulator_connected': self.session.is_emulator_connected,
            'connected_emulator_serial': self.session.connected_emulator_serial,
            'is_hook_active': self.session.is_hook_active,
            'selected_target_package': self.session.selected_target_package,
            'available_emulators_count': len(self.session.available_emulators),
            'available_processes_count': len(self.session.available_processes)
        }
    
    def shutdown(self):
        """Shutdown the controller."""
        if self._is_shutting_down:
            return
            
        self.logger.info("Starting controller shutdown")
        self._is_shutting_down = True
        self._is_running = False
        
        try:
            # Stop timer
            if self.monitor_timer:
                self.monitor_timer.stop()
                self.monitor_timer = None
            
            # Stop worker threads
            if hasattr(self, 'device_scan_worker'):
                self.device_scan_worker.stop()
            
            # Quit and wait for threads
            if hasattr(self, 'device_scan_thread'):
                self.device_scan_thread.quit()
                self.device_scan_thread.wait(2000)  # Wait up to 2 seconds
            
            if hasattr(self, 'database_thread'):
                self.database_thread.quit()
                self.database_thread.wait(2000)  # Wait up to 2 seconds
            
            # Close database
            if hasattr(self, 'db_service'):
                self.db_service.close()
            
            self.logger.info("Controller shutdown completed")
            
        except Exception as e:
            self.logger.error("Error during shutdown", error=str(e))
    
    # Compatibility methods for GUI integration
    def set_dashboard(self, dashboard) -> None:
        """Compatibility method - not needed in Qt-native version."""
        pass