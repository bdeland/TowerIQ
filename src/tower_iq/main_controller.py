"""
TowerIQ Main Controller

This module provides the MainController class that orchestrates all
application components and manages the overall application lifecycle.
"""

import asyncio
from typing import Any, Optional

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from .core.config import ConfigurationManager
from .core.session import SessionManager
from .services.database_service import DatabaseService
from .services.emulator_service import EmulatorService, FridaServerSetupError
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
        self._is_shutting_down = False  # Flag to prevent operations during shutdown
        
        # Frida message listener task management
        self._frida_listener_task: Optional[asyncio.Task] = None
        
        # Reference to dashboard for connection panel updates
        self.dashboard = None
    
    def _emit_signal_safely(self, signal, *args) -> None:
        """
        Emit a Qt signal in a thread-safe manner.
        
        This method ensures Qt signals are emitted from the Qt main thread,
        even when called from asyncio tasks.
        """
        # Skip signal emission during shutdown to prevent threading issues
        if self._is_shutting_down:
            self.logger.debug("Skipping signal emission during shutdown")
            return
            
        try:
            # Use QTimer.singleShot to schedule signal emission on the Qt main thread
            from PyQt6.QtCore import QTimer
            from PyQt6.QtWidgets import QApplication
            
            # Check if QApplication still exists and is not closing
            app = QApplication.instance()
            if app is None or app.closingDown():
                self.logger.debug("QApplication is shutting down, skipping signal emission")
                return
            
            def emit_signal():
                try:
                    # Double-check we're not shutting down before emitting
                    if not self._is_shutting_down:
                        signal.emit(*args)
                except Exception as e:
                    self.logger.debug("Error emitting signal", error=str(e))
            
            # Schedule the emission on the Qt main thread using QTimer
            try:
                QTimer.singleShot(0, emit_signal)
            except RuntimeError as e:
                # This can happen if Qt is shutting down
                self.logger.debug("Could not schedule signal emission", error=str(e))
            
        except Exception as e:
            self.logger.debug("Error scheduling signal emission", error=str(e))
            # Don't use fallback during shutdown to prevent more threading issues
    
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
                # First deactivate hook if active (this stops the listener)
                if self.session.is_hook_active:
                    self.set_hook_active(False)
                self.session.reset_connection_state()
                self.connection_state_changed.emit(False)
                if self.dashboard:
                    self.dashboard.set_connection_active(False)
                    self.dashboard.connection_panel.update_state(self.session)
        else:
            # Automatic connection disabled, always show manual connection panel
            # First deactivate hook if active (this stops the listener)
            if self.session.is_hook_active:
                self.set_hook_active(False)
            self.session.reset_connection_state()
            self.connection_state_changed.emit(False)
            if self.dashboard:
                self.dashboard.set_connection_active(False)
                self.dashboard.connection_panel.update_state(self.session)
        
        # Start main monitoring tasks with proper exception handling
        try:
            await asyncio.gather(
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
            # Try to find and connect to a device automatically with timeout
            device_id = await asyncio.wait_for(
                self.emulator_service.find_and_connect_device(),
                timeout=30.0  # 30 second timeout for automatic connection
            )
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
            is_compatible = self.frida_service.check_local_hook_compatibility(
                target_package, 
                self.session.selected_target_version
            )
            self.session.is_hook_compatible = is_compatible
            
            if not is_compatible:
                self.logger.warning("Hook not compatible for automatic connection")
                return False
            
            # Ensure frida-server is running with the latest version
            await self.emulator_service.ensure_frida_server_is_running(device_id)
            
            # Try to inject and run the script
            success = await self.frida_service.inject_and_run_script(
                device_id, pid, self.session.selected_target_version
            )
            
            if success:
                self.set_hook_active(True)
                self.logger.info("Automatic connection successful")
                return True
            else:
                self.logger.warning("Failed to inject script in automatic connection")
                return False
                
        except asyncio.TimeoutError:
            self.logger.warning("Automatic connection timed out after 30 seconds")
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
            
            # Immediately stop scanning animation and update UI
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.stop_scanning()  # Stop animation immediately
                self.dashboard.connection_panel.update_state(self.session)
                
        except Exception as e:
            self.logger.error("Error scanning devices", error=str(e))
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                if "timed out" in str(e).lower() or "timeout" in str(e).lower():
                    self.dashboard.connection_panel.show_error(
                        "Device scan timed out. ADB may be unresponsive. Try again or restart ADB."
                    )
                else:
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
            package = self.session.selected_target_package
            version = self.session.selected_target_version
            
            if package is not None and version is not None:
                is_compatible = self.frida_service.check_local_hook_compatibility(
                    package,
                    version
                )
                self.session.is_hook_compatible = is_compatible
            else:
                self.session.is_hook_compatible = False
                self.logger.warning("Invalid package or version selected")
            
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
            # Validate all required fields are present and not None
            if not all([
                self.session.connected_emulator_serial,
                self.session.selected_target_pid is not None,
                self.session.selected_target_version
            ]):
                raise ValueError("Missing required connection information")
            
            # Additional type validation
            device_id = self.session.connected_emulator_serial
            pid = self.session.selected_target_pid
            version = self.session.selected_target_version
            
            if device_id is None or pid is None or version is None:
                raise ValueError("Invalid connection parameters")

            # Step 1: Ensure frida-server is running with the latest version
            self.logger.info("Setting up frida-server on device...")
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.status_text.setText("Setting up frida-server on device...")
            
            await self.emulator_service.ensure_frida_server_is_running(device_id)
            
            # Step 2: Set up the event loop on FridaService before injection
            self.logger.info("Setting up Frida service event loop...")
            self.frida_service.set_event_loop(asyncio.get_running_loop())
            
            # Step 3: Inject and run the script
            self.logger.info("Injecting and running Frida script...")
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.status_text.setText("Injecting and running Frida script...")
            
            success = await self.frida_service.inject_and_run_script(
                device_id,
                pid,
                version
            )
            
            if success:
                self.set_hook_active(True)
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
                
        except FridaServerSetupError as e:
            self.logger.error("Frida-server setup failed", error=str(e))
            if self.dashboard and hasattr(self.dashboard, 'connection_panel'):
                self.dashboard.connection_panel.show_error(f"Frida-server setup failed: {str(e)}")
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
                # First deactivate hook if active (this stops the listener)
                if self.session.is_hook_active:
                    self.set_hook_active(False)
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
        self.logger.info("Starting controller shutdown")
        
        # Set shutdown flags early to prevent new operations
        self._is_shutting_down = True
        self._is_running = False
        
        # Stop the Frida message listener if running
        self._stop_frida_listener()
        
        # Only detach from Frida if there's an active hook
        if self.session.is_hook_active:
            try:
                self.logger.info("Detaching from Frida service")
                # Add timeout to prevent hanging on Frida detachment
                await asyncio.wait_for(self.frida_service.detach(), timeout=3.0)
                self.logger.info("Frida detachment completed")
            except asyncio.TimeoutError:
                self.logger.warning("Frida detachment timed out after 3 seconds")
            except Exception as e:
                self.logger.error("Error during Frida detachment", error=str(e))
        
        # Clean up frida-server on connected device
        if self.emulator_service.connected_device:
            try:
                self.logger.info("Cleaning up frida-server on device", device=self.emulator_service.connected_device)
                await asyncio.wait_for(
                    self.emulator_service._kill_frida_server(self.emulator_service.connected_device), 
                    timeout=5.0
                )
                self.logger.info("Frida-server cleanup completed")
            except asyncio.TimeoutError:
                self.logger.warning("Frida-server cleanup timed out after 5 seconds")
            except Exception as e:
                self.logger.error("Error during frida-server cleanup", error=str(e))
        
        # Close database connection
        try:
            self.logger.info("Closing database connection")
            await asyncio.to_thread(self.db_service.close)
            self.logger.info("Database connection closed")
        except Exception as e:
            self.logger.error("Error closing database", error=str(e))
        
        self.logger.info("Controller shutdown completed")
    
    def _start_frida_listener(self) -> None:
        """Start the Frida message listener task."""
        if self._frida_listener_task is None or self._frida_listener_task.done():
            self.logger.info("Starting Frida message listener task")
            self._frida_listener_task = asyncio.create_task(self._listen_for_frida_messages())
        else:
            self.logger.debug("Frida message listener task already running")
    
    def _stop_frida_listener(self) -> None:
        """Stop the Frida message listener task."""
        if self._frida_listener_task and not self._frida_listener_task.done():
            self.logger.info("Stopping Frida message listener task")
            self._frida_listener_task.cancel()
            self._frida_listener_task = None
        else:
            self.logger.debug("Frida message listener task not running or already stopped")
    
    def set_hook_active(self, active: bool) -> None:
        """
        Set the hook active status and manage the message listener accordingly.
        Use this method instead of directly setting session.is_hook_active.
        """
        was_active = self.session.is_hook_active
        self.session.is_hook_active = active
        
        if active and not was_active:
            # Hook became active - start listener
            self._start_frida_listener()
            self.logger.info("Hook activated - message listener started")
        elif not active and was_active:
            # Hook became inactive - stop listener
            self._stop_frida_listener()
            self.logger.info("Hook deactivated - message listener stopped")
    
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
        This listener is only started when the hook is active.
        """
        self.logger.info("Frida message listener started")
        
        try:
            message_count = 0
            while self._is_running and self.session.is_hook_active:
                try:
                    # Add a timeout to prevent indefinite blocking
                    message = await asyncio.wait_for(
                        self.frida_service.get_message(), 
                        timeout=1.0
                    )
                    
                    message_count += 1
                    self.logger.debug("Received message from Frida", 
                                   message_type=message.get("type"), 
                                   payload_keys=list(message.get("payload", {}).keys()),
                                   message_count=message_count,
                                   queue_size=self.frida_service.message_queue.qsize())
                    
                    handler = self._message_handlers.get(message.get("type"))
                    if handler:
                        self.logger.debug("Processing message with handler", 
                                       message_type=message.get("type"),
                                       handler=handler.__name__)
                        await handler(message)
                        self.logger.debug("Handler completed successfully")
                    else:
                        self.logger.warn("unhandled_message", message_type=message.get("type"))
                except asyncio.TimeoutError:
                    # This is normal - no messages available
                    # Only log if there are messages in queue but we're not getting them
                    queue_size = self.frida_service.message_queue.qsize() if hasattr(self.frida_service, '_message_queue') and self.frida_service._message_queue else 0
                    if queue_size > 0:
                        self.logger.warning("Message listener timeout but queue has messages", queue_size=queue_size)
                    continue
                except Exception as e:
                    self.logger.error("Error in frida message listener", error=str(e))
                    await asyncio.sleep(1)  # Prevent tight loop on errors
        except asyncio.CancelledError:
            self.logger.info("Frida message listener cancelled")
            raise
        finally:
            self.logger.info("Frida message listener stopped", total_messages_processed=message_count)
    
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
            
            self.logger.debug("Processing game metric", 
                           metric_name=name, 
                           value=value, 
                           run_id=run_id)
            
            # Write to database using synchronous call wrapped in thread
            await asyncio.to_thread(self.db_service.write_metric, run_id, timestamp, name, value)
            self.logger.debug("Wrote metric to database", metric_name=name, value=value)
            
            # Emit signal for UI metric display - use thread-safe emission
            self._emit_signal_safely(self.new_metric_received, name, value)
            self.logger.debug("Emitted metric signal to UI", metric_name=name, value=value)
            
            # Fetch recent data and update graph with proper graph names
            df = await asyncio.to_thread(self.db_service.get_run_metrics, run_id, name)
            
            # Map metric names to graph names
            graph_name_mapping = {
                "coins": "coins_timeline",
                "total_coins": "coins_timeline",
                "efficiency": "efficiency_timeline"
            }
            
            graph_name = graph_name_mapping.get(name, f"{name}_graph")
            self._emit_signal_safely(self.new_graph_data, graph_name, df)
            self.logger.debug("Emitted graph data signal", 
                            graph_name=graph_name, 
                            data_points=len(df))
                
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
            
            # Create a copy of payload without the 'event' key to avoid conflicts
            log_data = {k: v for k, v in payload.items() if k != "event"}
            
            # Forward to structlog system
            self.logger.info(event, **log_data)
            
            # Emit signal for UI log viewer - use thread-safe emission
            self._emit_signal_safely(self.log_received, payload)
            
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
    
 