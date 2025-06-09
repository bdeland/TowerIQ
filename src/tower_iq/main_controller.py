"""
TowerIQ Main Controller

This module provides the MainController class that orchestrates all
application components and manages the overall application lifecycle.
"""

import asyncio
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from .core.config import ConfigurationManager
from .core.session import SessionManager
from .services.database_service import DatabaseService
from .services.emulator_service import EmulatorService
from .services.frida_service import FridaService


class MainController(QObject):
    """
    Main controller that orchestrates all application components.
    Manages the overall application lifecycle and coordinates between services.
    """
    
    # PyQt Signals for UI communication
    log_received = pyqtSignal(dict)
    status_changed = pyqtSignal(str, str)
    new_metric_received = pyqtSignal(str, object)
    new_graph_data = pyqtSignal(str, object)  # New signal for graph data
    setup_finished = pyqtSignal(bool)
    connection_state_changed = pyqtSignal(bool)  # New signal for connection state
    
    def __init__(self, config: ConfigurationManager, logger: Any) -> None:
        """
        Initialize the main controller.
        
        Args:
            config: Configuration manager instance
            logger: Logger instance
        """
        super().__init__()
        
        self.logger = logger.bind(source="MainController")
        self.config = config
        
        # Initialize core services
        self.session = SessionManager()
        self.db_service = DatabaseService(config, logger)
        self.emulator_service = EmulatorService(config, logger)
        self.frida_service = FridaService(config, logger)
        
        # Message dispatch pattern
        self._message_handlers: dict = {}
        self._register_handlers()
        
        # Application state
        self._is_running = False
        
        # Reference to dashboard for connection panel updates
        self.dashboard = None
    
    def set_dashboard(self, dashboard) -> None:
        """Set the dashboard reference for connection panel updates."""
        self.dashboard = dashboard
        
        # Connect the connection panel signals
        if hasattr(dashboard, 'connection_panel'):
            dashboard.connection_panel.scan_devices_requested.connect(self.on_scan_devices_requested)
            dashboard.connection_panel.connect_device_requested.connect(self.on_connect_device_requested)
            dashboard.connection_panel.refresh_processes_requested.connect(self.on_refresh_processes_requested)
            dashboard.connection_panel.select_process_requested.connect(self.on_select_process_requested)
            dashboard.connection_panel.activate_hook_requested.connect(self.on_activate_hook_requested)
            dashboard.connection_panel.back_to_stage_requested.connect(self.on_back_to_stage_requested)

    async def run(self) -> None:
        """
        The main entry point for the controller's lifecycle.
        This method is started in the background by main_app_entry.py.
        """
        self._is_running = True
        
        # Connect to database and run migrations
        try:
            await asyncio.to_thread(self.db_service.connect)
            self.logger.info("Database connection established successfully")
            self.setup_finished.emit(True)
        except Exception as e:
            self.logger.error("Failed to connect to database", error=str(e))
            self.setup_finished.emit(False)
            return
        
        # Check if automatic connection is enabled in config
        auto_connect_enabled = self.config.get('gui.auto_connect_emulator', False)
        
        if auto_connect_enabled:
            # Try automatic connection first
            connection_successful = await self._run_automatic_connection()
            
            if connection_successful:
                # Emit signal to dashboard to go into "active" mode
                self.connection_state_changed.emit(True)
                if self.dashboard:
                    self.dashboard.set_connection_active(True)
            else:
                # Reset connection state and show manual connection panel
                self.session.reset_connection_state()
                self.connection_state_changed.emit(False)
                if self.dashboard:
                    self.dashboard.set_connection_active(False)
                    self.dashboard.connection_panel.update_state(self.session)
        else:
            # Automatic connection disabled, always show manual connection panel
            self.session.reset_connection_state()
            self.connection_state_changed.emit(False)
            if self.dashboard:
                self.dashboard.set_connection_active(False)
                self.dashboard.connection_panel.update_state(self.session)
        
        # Start main monitoring tasks with proper exception handling
        try:
            await asyncio.gather(
                self._listen_for_frida_messages(),
                self._monitor_system_health(),
                return_exceptions=True  # Don't fail if one task has an exception
            )
        except Exception as e:
            self.logger.error("Error in main monitoring tasks", error=str(e))
        finally:
            self.logger.info("Main controller tasks completed")

    async def _run_automatic_connection(self) -> bool:
        """
        Attempt automatic connection flow.
        
        Returns:
            True if automatic connection was successful, False otherwise
        """
        self.logger.info("Attempting automatic connection")
        
        try:
            # Try to find and connect to a device automatically
            device_id = await self.emulator_service.find_and_connect_device()
            if not device_id:
                self.logger.info("No device found for automatic connection")
                return False
            
            self.session.connected_emulator_serial = device_id
            self.session.is_emulator_connected = True
            
            # Try to find the target game package
            target_package = self.config.get('emulator.package_name', 'com.techtreegames.thetower')
            
            # Get the game PID
            pid = await self.emulator_service.get_game_pid(device_id, target_package)
            if not pid:
                self.logger.info("Target game not running for automatic connection")
                return False
            
            # Set up session with found process
            self.session.selected_target_package = target_package
            self.session.selected_target_pid = pid
            
            # Try to get game version (simplified for automatic mode)
            self.session.selected_target_version = "auto-detected"
            
            # Check hook compatibility
            is_compatible = await self.frida_service.check_hook_compatibility(self.session.selected_target_version)
            self.session.is_hook_compatible = is_compatible
            
            if not is_compatible:
                self.logger.warning("Hook not compatible for automatic connection")
                return False
            
            # Try to inject and run the script
            success = await self.frida_service.inject_and_run_script(
                device_id, pid, self.session.selected_target_version
            )
            
            if success:
                self.session.is_hook_active = True
                self.logger.info("Automatic connection successful")
                return True
            else:
                self.logger.warning("Failed to inject script in automatic connection")
                return False
                
        except Exception as e:
            self.logger.error("Error in automatic connection", error=str(e))
            return False

    # Connection panel slot implementations
    @pyqtSlot()
    def on_scan_devices_requested(self) -> None:
        """Handle scan devices request from connection panel."""
        asyncio.create_task(self._handle_scan_devices())
    
    async def _handle_scan_devices(self) -> None:
        """Handle the actual device scanning."""
        try:
            devices = await self.emulator_service.find_connected_devices()
            self.session.available_emulators = devices
            
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.update_state(self.session)
                
        except Exception as e:
            self.logger.error("Error scanning devices", error=str(e))
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.show_error(f"Failed to scan devices: {str(e)}")

    @pyqtSlot(str)
    def on_connect_device_requested(self, device_id: str) -> None:
        """Handle connect device request from connection panel."""
        asyncio.create_task(self._handle_connect_device(device_id))
    
    async def _handle_connect_device(self, device_id: str) -> None:
        """Handle the actual device connection."""
        try:
            self.session.connected_emulator_serial = device_id
            self.session.is_emulator_connected = True
            
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.update_state(self.session)
            
            # Automatically trigger process refresh
            await self._handle_refresh_processes()
                
        except Exception as e:
            self.logger.error("Error connecting to device", device_id=device_id, error=str(e))
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.show_error(f"Failed to connect to device: {str(e)}")

    @pyqtSlot()
    def on_refresh_processes_requested(self) -> None:
        """Handle refresh processes request from connection panel."""
        asyncio.create_task(self._handle_refresh_processes())
    
    async def _handle_refresh_processes(self) -> None:
        """Handle the actual process refresh."""
        try:
            if not self.session.connected_emulator_serial:
                raise ValueError("No device connected")
            
            processes = await self.emulator_service.get_installed_third_party_packages(
                self.session.connected_emulator_serial
            )
            self.session.available_processes = processes
            
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.update_state(self.session)
                
        except Exception as e:
            self.logger.error("Error refreshing processes", error=str(e))
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.show_error(f"Failed to refresh processes: {str(e)}")

    @pyqtSlot(dict)
    def on_select_process_requested(self, process_info: dict) -> None:
        """Handle process selection request from connection panel."""
        asyncio.create_task(self._handle_select_process(process_info))
    
    async def _handle_select_process(self, process_info: dict) -> None:
        """Handle the actual process selection."""
        try:
            # Update session with selected process info
            self.session.selected_target_package = process_info.get('package')
            self.session.selected_target_pid = process_info.get('pid')
            self.session.selected_target_version = process_info.get('version')
            
            # Check hook compatibility
            is_compatible = await self.frida_service.check_hook_compatibility(
                self.session.selected_target_version
            )
            self.session.is_hook_compatible = is_compatible
            
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.update_state(self.session)
                
        except Exception as e:
            self.logger.error("Error selecting process", error=str(e))
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.show_error(f"Failed to select process: {str(e)}")

    @pyqtSlot()
    def on_activate_hook_requested(self) -> None:
        """Handle hook activation request from connection panel."""
        asyncio.create_task(self._handle_activate_hook())
    
    async def _handle_activate_hook(self) -> None:
        """Handle the actual hook activation."""
        try:
            if not all([
                self.session.connected_emulator_serial,
                self.session.selected_target_pid,
                self.session.selected_target_version
            ]):
                raise ValueError("Missing required connection information")
            
            success = await self.frida_service.inject_and_run_script(
                self.session.connected_emulator_serial,
                self.session.selected_target_pid,
                self.session.selected_target_version
            )
            
            if success:
                self.session.is_hook_active = True
                self.connection_state_changed.emit(True)
                
                if self.dashboard:
                    self.dashboard.set_connection_active(True)
                    if hasattr(self.dashboard, 'connection_panel'):
                        self.dashboard.connection_panel.show_success("Hook activated successfully!")
                
                self.logger.info("Hook activation successful")
            else:
                if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                    self.dashboard.connection_panel.show_error("Failed to activate hook")
                    self.dashboard.connection_panel.update_state(self.session)
                
        except Exception as e:
            self.logger.error("Error activating hook", error=str(e))
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.show_error(f"Failed to activate hook: {str(e)}")

    @pyqtSlot(int)
    def on_back_to_stage_requested(self, target_stage: int) -> None:
        """Handle back to stage request from connection panel."""
        asyncio.create_task(self._handle_back_to_stage(target_stage))
    
    async def _handle_back_to_stage(self, target_stage: int) -> None:
        """Handle the actual back to stage."""
        try:
            # Reset session state based on target stage
            if target_stage == 1:
                # Going back to stage 1, reset all connection state
                self.session.reset_connection_state()
            elif target_stage == 2:
                # Going back to stage 2, keep device but reset process selection
                self.session.available_processes = []
                self.session.selected_target_package = None
                self.session.selected_target_pid = None
                self.session.selected_target_version = None
                self.session.is_hook_compatible = False
            
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.update_state(self.session)
                
        except Exception as e:
            self.logger.error("Error handling back to stage", error=str(e))
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.show_error(f"Failed to go back: {str(e)}")

    async def stop(self) -> None:
        """
        Gracefully shuts down all services.
        """
        self._is_running = False
        
        # Only detach from Frida if there's an active hook
        if self.session.is_hook_active:
            await self.frida_service.detach()
        
        await asyncio.to_thread(self.db_service.close)
    
    def _register_handlers(self) -> None:
        """
        Implements the Dispatch Pattern. Maps incoming message types from Frida 
        to handler methods within this class.
        """
        self._message_handlers = {
            "game_metric": self._handle_game_metric,
            "game_event": self._handle_game_event,
            "hook_log": self._handle_hook_log,
        }
    
    async def _listen_for_frida_messages(self) -> None:
        """
        A long-running task that continuously waits for messages from the FridaService queue.
        """
        while self._is_running:
            try:
                # Add a timeout to prevent indefinite blocking
                message = await asyncio.wait_for(
                    self.frida_service.get_message(), 
                    timeout=1.0
                )
                handler = self._message_handlers.get(message.get("type"))
                if handler:
                    await handler(message)
                else:
                    self.logger.warn("unhandled_message", message_type=message.get("type"))
            except asyncio.TimeoutError:
                # This is normal - no messages available
                continue
            except Exception as e:
                self.logger.error("Error in frida message listener", error=str(e))
                await asyncio.sleep(1)  # Prevent tight loop on errors
    
    async def _handle_game_metric(self, message: dict) -> None:
        """
        Processes metric data.
        """
        try:
            payload = message.get("payload", {})
            run_id = self.session.current_runId or "default"
            timestamp = int(payload.get("timestamp", asyncio.get_event_loop().time()))
            name = payload.get("name", "unknown_metric")
            value = float(payload.get("value", 0))
            
            # Write to database using synchronous call wrapped in thread
            await asyncio.to_thread(self.db_service.write_metric, run_id, timestamp, name, value)
            
            # Emit signal for UI metric display
            self.new_metric_received.emit(name, value)
            
            # Fetch recent data and update graph
            df = await asyncio.to_thread(self.db_service.get_run_metrics, run_id, name)
            self.new_graph_data.emit(f"{name}_graph", df)
                
        except Exception as e:
            self.logger.error("Error handling game metric", error=str(e))
    
    async def _handle_game_event(self, message: dict) -> None:
        """
        Processes discrete game events (e.g., round start, perk chosen).
        """
        try:
            payload = message.get("payload", {})
            run_id = self.session.current_runId or "default"
            timestamp = int(payload.get("timestamp", asyncio.get_event_loop().time()))
            name = payload.get("name", "unknown_event")
            data = payload.get("data", {})
            
            # Write to database using synchronous call wrapped in thread
            await asyncio.to_thread(self.db_service.write_event, run_id, timestamp, name, data)
            
            # Manage session state
            if name == "run_started":
                self.session.start_new_run()
            elif name == "run_ended":
                self.session.end_run()
                
        except Exception as e:
            self.logger.error("Error handling game event", error=str(e))
    
    async def _handle_hook_log(self, message: dict) -> None:
        """
        Processes log messages originating from the Frida script.
        """
        try:
            payload = message.get("payload", {})
            event = payload.get("event", "frida_log")
            
            # Forward to structlog system
            self.logger.info(event, **payload)
            
            # Emit signal for UI log viewer
            self.log_received.emit(payload)
            
        except Exception as e:
            self.logger.error("Error handling hook log", error=str(e))
    
    async def _monitor_system_health(self) -> None:
        """
        A simplified health monitoring task that checks emulator connection.
        """
        while self._is_running:
            try:
                # Check emulator connection
                emulator_connected = await self.emulator_service.is_connected()
                self.status_changed.emit("emulator", "connected" if emulator_connected else "disconnected")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error("Error in system health monitor", error=str(e))
                await asyncio.sleep(10)  # Wait before retrying
    
 