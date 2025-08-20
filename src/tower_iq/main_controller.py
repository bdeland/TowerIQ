"""
TowerIQ Main Controller

This module provides the main controller that uses standard Python threading
instead of Qt components for compatibility with FastAPI server.
"""

import os
import time
import threading
from typing import Any, Optional, Callable, Dict, List
from datetime import datetime

from .core.config import ConfigurationManager
from .core.session import SessionManager, ConnectionState, ConnectionSubState, ErrorInfo, ErrorType
from .services.database_service import DatabaseService
from .services.emulator_service import EmulatorService
from .services.connection_flow_controller import ConnectionFlowController
from .services.connection_stage_manager import ConnectionStageManager
from .services.hook_script_manager import HookScriptManager
from .services.frida_service import FridaService


class DeviceScanWorker:
    """Worker thread for device scanning operations."""
    
    def __init__(self, emulator_service, logger, on_complete: Callable[[List], None] = lambda _: None, on_error: Callable[[str], None] = lambda _: None):
        self.emulator_service = emulator_service
        self.logger = logger
        self.on_complete = on_complete
        self.on_error = on_error
        self._should_stop = False
        self._thread = None
    
    def scan_devices(self):
        """Perform device scan using the new two-phase API."""
        try:
            self.logger.info("DeviceScanWorker: scan_devices called")
            self.logger.info("Starting device scan with new API")
            
            # Use the new list_devices_with_details method
            # Since this is a thread, we need to run the async method in a new event loop
            import asyncio
            import concurrent.futures
            
            # Create a new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Run the async method
                devices = loop.run_until_complete(self.emulator_service.list_devices_with_details())
                self.logger.info("DeviceScanWorker: About to call on_complete callback", device_count=len(devices))
                if self.on_complete:
                    self.on_complete(devices)
                self.logger.info("Device scan completed", device_count=len(devices))
                self.logger.info("DeviceScanWorker: on_complete callback called successfully")
            finally:
                loop.close()
                
        except Exception as e:
            self.logger.error("Device scan failed", error=str(e))
            self.logger.info("DeviceScanWorker: About to call on_error callback")
            if self.on_error:
                self.on_error(str(e))
            self.logger.info("DeviceScanWorker: on_error callback called")
    
    def start_scan(self):
        """Start device scan in a separate thread."""
        self._thread = threading.Thread(target=self.scan_devices)
        self._thread.daemon = True
        self._thread.start()
    
    def stop(self):
        """Stop the worker."""
        self._should_stop = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)


class DatabaseWorker:
    """Worker thread for database operations."""
    
    def __init__(self, db_service, logger, on_connected: Callable[[], None] = lambda: None, on_error: Callable[[str], None] = lambda _: None):
        self.db_service = db_service
        self.logger = logger
        self.on_connected = on_connected
        self.on_error = on_error
        self._thread = None
    
    def connect_database(self):
        """Connect to database."""
        try:
            self.logger.info("Connecting to database")
            self.db_service.connect()
            if self.on_connected:
                self.on_connected()
            self.logger.info("Database connected successfully")
        except Exception as e:
            self.logger.error("Database connection failed", error=str(e))
            if self.on_error:
                self.on_error(str(e))
    
    def start_connect(self):
        """Start database connection in a separate thread."""
        self._thread = threading.Thread(target=self.connect_database)
        self._thread.daemon = True
        self._thread.start()


class MainController:
    """
    Main controller for TowerIQ application.
    
    This version uses standard Python threading instead of Qt components
    for compatibility with FastAPI server.
    """
    
    def __init__(self, config: ConfigurationManager, logger, db_service: Optional[DatabaseService] = None):
        """
        Initialize the main controller.
        
        Args:
            config: Configuration manager instance
            logger: Logger instance
            db_service: Database service instance (optional)
        """
        self.config = config
        self.logger = logger
        self.db_service = db_service
        
        # Initialize services (simplified for API mode)
        self.session = SessionManager()
        self.emulator_service = EmulatorService(config, logger)
        
        # Initialize FridaService with event loop and session manager
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self.frida_service = FridaService(config, logger, loop, self.session)
        
        # For API mode, we'll skip the Qt-dependent services for now
        # self.connection_flow_controller = ConnectionFlowController(config, logger)
        # self.connection_stage_manager = ConnectionStageManager(config, logger)
        # self.hook_script_manager = HookScriptManager(config, logger)
        
        # Initialize hooks directory
        project_root = self.config.get_project_root()
        hooks_dir = os.path.join(project_root, 'src', 'tower_iq', 'scripts')
        self.hook_script_manager = HookScriptManager(hooks_dir)
        try:
            self.hook_script_manager.discover_scripts()
        except Exception:
            pass
        
        # Test mode flags
        self._test_mode = False
        self._test_mode_replay = False
        self._test_mode_generate = False
        
        # Callback handlers for API mode
        self._device_scan_callbacks = []
        self._connection_callbacks = []
        self._status_callbacks = []
        
        # Background operations
        self._background_threads = []
        self._running = False
        
        self.logger.info("MainController initialized")
    
    def add_device_scan_callback(self, callback: Callable[[List], None]):
        """Add callback for device scan completion."""
        self._device_scan_callbacks.append(callback)
    
    def add_connection_callback(self, callback: Callable[[Dict], None]):
        """Add callback for connection state changes."""
        self._connection_callbacks.append(callback)
    
    def add_status_callback(self, callback: Callable[[Dict], None]):
        """Add callback for status updates."""
        self._status_callbacks.append(callback)
    
    def _notify_device_scan_complete(self, devices: List):
        """Notify all device scan callbacks."""
        for callback in self._device_scan_callbacks:
            try:
                callback(devices)
            except Exception as e:
                self.logger.error("Error in device scan callback", error=str(e))
    
    def _notify_connection_change(self, connection_info: Dict):
        """Notify all connection callbacks."""
        for callback in self._connection_callbacks:
            try:
                callback(connection_info)
            except Exception as e:
                self.logger.error("Error in connection callback", error=str(e))
    
    def _notify_status_change(self, status_info: Dict):
        """Notify all status callbacks."""
        for callback in self._status_callbacks:
            try:
                callback(status_info)
            except Exception as e:
                self.logger.error("Error in status callback", error=str(e))
    
    def start_background_operations(self):
        """Start background operations."""
        if self._running:
            return
        
        self._running = True
        self.logger.info("Starting background operations")
        
        # Start any background threads here if needed
        # For now, we'll just mark as running
    
    def scan_devices(self):
        """Scan for available devices."""
        self.logger.info("Starting device scan")
        
        worker = DeviceScanWorker(
            self.emulator_service, 
            self.logger,
            on_complete=self._notify_device_scan_complete,
            on_error=lambda error: self.logger.error("Device scan error", error=error)
        )
        worker.start_scan()
        
        # Store the worker to prevent garbage collection
        self._background_threads.append(worker)
    
    def connect_to_device(self, device_serial: str):
        """Connect to a specific device."""
        self.logger.info("Connecting to device", device_serial=device_serial)
        
        # Update session state
        self.session.transition_to_state(ConnectionState.CONNECTING)
        
        # For now, just simulate connection
        # In a real implementation, this would use the emulator service
        time.sleep(1)  # Simulate connection time
        
        self.session.transition_to_state(ConnectionState.CONNECTED)
        # Store device info in session (using available properties)
        self.session.connected_emulator_serial = device_serial
        
        # Notify callbacks
        self._notify_connection_change({
            "state": "connected",
            "device_serial": device_serial
        })
        
        self.logger.info("Device connected", device_serial=device_serial)
    
    def disconnect_from_device(self):
        """Disconnect from the currently connected device."""
        self.logger.info("Disconnecting from device")
        
        # Update session state
        self.session.transition_to_state(ConnectionState.DISCONNECTING)
        
        # Clear device info from session
        self.session.connected_emulator_serial = None
        
        # Transition to disconnected state
        self.session.transition_to_state(ConnectionState.DISCONNECTED)
        
        # Notify callbacks
        self._notify_connection_change({
            "state": "disconnected",
            "device_serial": None
        })
        
        self.logger.info("Device disconnected")
    
    def get_session_state(self) -> Dict[str, Any]:
        """Get current session state."""
        return {
            "is_connected": self.session.connection_main_state in [ConnectionState.CONNECTED, ConnectionState.ACTIVE],
            "current_device": getattr(self.session, 'connected_emulator_serial', None),
            "current_process": {
                "package": getattr(self.session, 'selected_target_package', None),
                "pid": getattr(self.session, 'selected_target_pid', None),
                "version": getattr(self.session, 'selected_target_version', None)
            },
            "connection_state": self.session.connection_main_state.value,
            "connection_sub_state": self.session.connection_sub_state.value if self.session.connection_sub_state else None
        }

    def get_script_status(self) -> Dict[str, Any]:
        """Get current script status for API."""
        script_status = self.session.script_status
        
        status_data = {
            "is_active": script_status.is_active,
            "heartbeat_interval_seconds": script_status.heartbeat_interval_seconds,
            "is_game_reachable": script_status.is_game_reachable,
            "error_count": script_status.error_count,
        }
        
        # Add optional fields if they exist
        if script_status.last_heartbeat:
            status_data["last_heartbeat"] = script_status.last_heartbeat.isoformat()
        if script_status.script_name:
            status_data["script_name"] = script_status.script_name
        if script_status.injection_time:
            status_data["injection_time"] = script_status.injection_time.isoformat()
        if script_status.last_error:
            status_data["last_error"] = script_status.last_error
        
        return status_data

    def handle_heartbeat_message(self, message_data: Dict[str, Any]) -> None:
        """Handle incoming heartbeat message from hook script."""
        self.session.handle_heartbeat_message(message_data)
    
    def get_status(self) -> Dict[str, Any]:
        """Get overall system status."""
        session_state = self.get_session_state()
        
        status_info = {
            "status": "running",
            "session": session_state,
            "test_mode": self._test_mode,
            "test_mode_replay": self._test_mode_replay,
            "test_mode_generate": self._test_mode_generate
        }
        
        # Notify status callbacks
        self._notify_status_change(status_info)
        
        return status_info
    
    def set_test_mode(self, test_mode: bool, test_mode_replay: bool = False, test_mode_generate: bool = False):
        """Set test mode configuration."""
        self._test_mode = test_mode
        self._test_mode_replay = test_mode_replay
        self._test_mode_generate = test_mode_generate
        
        self.logger.info("Test mode updated", 
                        test_mode=test_mode, 
                        test_mode_replay=test_mode_replay, 
                        test_mode_generate=test_mode_generate)
    
    def shutdown(self):
        """Shutdown the controller and cleanup resources."""
        if not self._running:
            return
        
        self.logger.info("Shutting down MainController")
        self._running = False
        
        # Stop all background threads
        for thread in self._background_threads:
            if hasattr(thread, 'stop'):
                thread.stop()
        
        self._background_threads.clear()
        
        # Cleanup services
        if hasattr(self, 'emulator_service'):
            self.emulator_service = None
        
        self.logger.info("MainController shutdown complete")