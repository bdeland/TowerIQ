"""
TowerIQ Main Controller

This module provides the main controller that uses standard Python threading
instead of Qt components for compatibility with FastAPI server.
"""

import os
import time
import threading
import asyncio
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


class LoadingManager:
    """Manages the application startup loading sequence."""
    
    def __init__(self, logger):
        self.logger = logger
        self._loading_steps = {
            'database': False,
            'emulator_service': False,
            'frida_service': False,
            'hook_scripts': False,
            'api_server': False
        }
        self._callbacks = []
        self._start_time = None
    
    def start_loading(self):
        """Start the loading sequence."""
        self._start_time = time.time()
        self.logger.info("Starting application loading sequence")
    
    def mark_step_complete(self, step_name: str):
        """Mark a loading step as complete."""
        if step_name in self._loading_steps:
            self._loading_steps[step_name] = True
            self.logger.info(f"Loading step completed: {step_name}")
            self._check_completion()
    
    def add_completion_callback(self, callback):
        """Add a callback to be called when loading is complete."""
        self._callbacks.append(callback)
    
    def is_loading_complete(self) -> bool:
        """Check if all loading steps are complete."""
        return all(self._loading_steps.values())
    
    def _check_completion(self):
        """Check if all loading steps are complete."""
        if all(self._loading_steps.values()) and self._start_time is not None:
            elapsed_time = time.time() - self._start_time
            self.logger.info(f"All loading steps completed in {elapsed_time:.2f} seconds")
            
            # Ensure minimum display time of 3 seconds
            min_display_time = 3.0
            if elapsed_time < min_display_time:
                remaining_time = min_display_time - elapsed_time
                self.logger.info(f"Waiting {remaining_time:.2f} seconds to meet minimum splash screen time")
                time.sleep(remaining_time)
            
            # Notify all callbacks
            for callback in self._callbacks:
                try:
                    callback()
                except Exception as e:
                    self.logger.error(f"Error in loading completion callback: {e}")


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
        
        # Initialize loading manager
        self.loading_manager = LoadingManager(logger)
        
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
    
    async def _load_script_by_id(self, script_id: str) -> Optional[str]:
        """Load script content by script ID."""
        if not self.hook_script_manager:
            self.logger.error("Hook script manager not available")
            return None
        
        try:
            # Get all available scripts
            available_scripts = self.hook_script_manager.get_available_scripts()
            
            # Find script by ID
            for script in available_scripts:
                if script.get('id') == script_id:
                    script_content = script.get('content', '')
                    if script_content:
                        self.logger.info("Script loaded by ID", script_id=script_id, 
                                       script_name=script.get('name', 'Unknown'),
                                       content_length=len(script_content))
                        return script_content
                    else:
                        self.logger.error("Script found but content is empty", script_id=script_id)
                        return None
            
            self.logger.error("Script not found by ID", script_id=script_id)
            return None
            
        except Exception as e:
            self.logger.error("Error loading script by ID", script_id=script_id, error=str(e))
            return None
    
    async def _load_script_by_name(self, script_name: str, package_name: str, version: str) -> Optional[str]:
        """Load script content by script name, filtering by package and version compatibility."""
        if not self.hook_script_manager:
            self.logger.error("Hook script manager not available")
            return None
        
        try:
            # Get compatible scripts first
            compatible_scripts = self.hook_script_manager.get_compatible_scripts(package_name, version)
            
            # Find script by name among compatible scripts
            for script in compatible_scripts:
                if script.get('scriptName', '') == script_name:
                    script_file_name = script.get('fileName', '')
                    if script_file_name:
                        script_content = self.hook_script_manager.get_script_content(script_file_name)
                        if script_content:
                            self.logger.info("Script loaded by name", script_name=script_name,
                                           package_name=package_name, version=version,
                                           content_length=len(script_content))
                            return script_content
                        else:
                            self.logger.error("Script found but content is empty", script_name=script_name)
                            return None
            
            self.logger.error("Script not found by name among compatible scripts", 
                            script_name=script_name, package_name=package_name, version=version)
            return None
            
        except Exception as e:
            self.logger.error("Error loading script by name", script_name=script_name, error=str(e))
            return None
    
    async def _load_compatible_script(self, package_name: str, version: str) -> Optional[str]:
        """Load the first compatible script for the given package and version."""
        if not self.hook_script_manager:
            self.logger.error("Hook script manager not available")
            return None
        
        try:
            # Log when version is unknown for debugging
            if version == "Unknown":
                self.logger.info("Attempting to load compatible script with unknown version", 
                               package_name=package_name, version=version)
            
            # Get compatible scripts
            compatible_scripts = self.hook_script_manager.get_compatible_scripts(package_name, version)
            
            if not compatible_scripts:
                self.logger.error("No compatible scripts found", package_name=package_name, version=version)
                return None
            
            # Use the first compatible script
            selected_script = compatible_scripts[0]
            script_file_name = selected_script.get('fileName', '')
            
            if not script_file_name:
                self.logger.error("Script file name not found in metadata")
                return None
            
            # Load the script content
            script_content = self.hook_script_manager.get_script_content(script_file_name)
            
            if not script_content:
                self.logger.error("Failed to load script content", script_file_name=script_file_name)
                return None
            
            self.logger.info("Compatible script loaded", 
                           script_name=selected_script.get('scriptName', script_file_name),
                           package_name=package_name, version=version,
                           content_length=len(script_content))
            
            return script_content
            
        except Exception as e:
            self.logger.error("Error loading compatible script", package_name=package_name, version=version, error=str(e))
            return None
    
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
        
        # Start the Frida message processing loop
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            # Start the message processing loop as a task
            loop.create_task(self.run())
            self.logger.info("Frida message processing loop started")
        except RuntimeError:
            # If no event loop is running, we'll need to be started later
            self.logger.info("No event loop running - message processing will be started when loop is available")
        except Exception as e:
            self.logger.error("Error starting Frida message processing loop", error=str(e))
    
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

    async def run(self):
        """
        Main async run loop for processing messages from Frida.
        
        This method continuously polls for messages from the FridaService queue
        and processes them (storing game data in database, handling events, etc.).
        """
        self.logger.info("Starting MainController message processing loop")
        
        while self._running:
            try:
                # Get message from Frida service with timeout
                self.logger.debug("Waiting for message from Frida service...")
                message = await self.frida_service.get_message()
                
                if message:
                    self.logger.info("Received message from Frida", message_type=message.get('type'), payload_keys=list(message.get('payload', {}).keys()) if isinstance(message.get('payload'), dict) else 'not_dict')
                    await self._process_frida_message(message)
                else:
                    self.logger.debug("No message received from Frida service")
                    
            except asyncio.TimeoutError:
                # Timeout is normal - just continue the loop
                self.logger.debug("Timeout waiting for message from Frida service - continuing loop")
                continue
            except RuntimeError as e:
                if "shutdown" in str(e).lower():
                    self.logger.info("Shutdown signal received, stopping message processing")
                    break
                else:
                    self.logger.error("Runtime error in message processing", error=str(e))
                    break
            except Exception as e:
                self.logger.error("Error processing message from Frida", error=str(e))
                # Continue processing other messages
                await asyncio.sleep(0.1)
        
        self.logger.info("MainController message processing loop stopped")

    async def _process_frida_message(self, message: Dict[str, Any]) -> None:
        """
        Process a message received from the Frida script.
        
        Args:
            message: The message dictionary from Frida
        """
        try:
            message_type = message.get('type', 'unknown')
            payload = message.get('payload', {})
            timestamp = message.get('timestamp')
            
            self.logger.debug("Processing Frida message", 
                            message_type=message_type, 
                            payload_keys=list(payload.keys()) if isinstance(payload, dict) else 'not_dict')
            
            # Handle different message types
            if message_type == 'hook_log':
                await self._handle_hook_log_message(payload, timestamp)
            elif message_type == 'game_data' or message_type == 'game_metric':
                await self._handle_game_data_message(payload, timestamp)
            elif message_type == 'game_event':
                await self._handle_game_event_message(payload, timestamp)
            elif message_type == 'script_error':
                await self._handle_script_error_message(payload, timestamp)
            elif message_type == 'test_message':
                await self._handle_test_message(payload, timestamp)
            else:
                self.logger.warning("Unknown message type received from Frida", 
                                  message_type=message_type, 
                                  payload=payload)
                
        except Exception as e:
            self.logger.error("Error processing Frida message", 
                            message=message, 
                            error=str(e))

    async def _handle_hook_log_message(self, payload: Dict[str, Any], timestamp: Any) -> None:
        """Handle hook log messages (heartbeats, debug info, etc.)."""
        try:
            event = payload.get('event', 'unknown')
            
            if event == 'frida_heartbeat':
                # Heartbeat is already handled by the Frida service
                self.logger.debug("Heartbeat message processed")
            else:
                self.logger.debug("Hook log event", event=event, payload=payload)
                
        except Exception as e:
            self.logger.error("Error handling hook log message", error=str(e))

    async def _handle_game_data_message(self, payload: Dict[str, Any], timestamp: Any) -> None:
        """Handle game data messages and store them in the database."""
        try:
            if not self.db_service:
                self.logger.warning("Cannot store game data: database service not available")
                return
            
            # Extract relevant data from payload
            run_id = payload.get('roundSeed') or payload.get('run_id')
            wave = payload.get('currentWave')
            
            # Handle both direct field format and metrics object format
            metrics = {}
            if 'metrics' in payload:
                # New format: metrics are in a 'metrics' object
                for key, value in payload['metrics'].items():
                    if value is not None:
                        metrics[key] = float(value)
            else:
                # Old format: metrics are direct fields
                coins = payload.get('coins')
                if coins is not None:
                    metrics['coins'] = float(coins)
                if wave is not None:
                    metrics['wave'] = float(wave)
            
            self.logger.info("Storing game data in database", 
                           payload_keys=list(payload.keys()) if isinstance(payload, dict) else 'not_dict',
                           metrics_count=len(metrics),
                           run_id=run_id)
            
            # Store the game data in the database
            if run_id and metrics:
                self.db_service.write_metric(
                    run_id=str(run_id),
                    real_timestamp=timestamp or int(time.time() * 1000),
                    game_timestamp=payload.get('gameTimestamp', float(timestamp or time.time())),
                    current_wave=wave or 0,
                    metrics=metrics
                )
                
                self.logger.info("Game data stored successfully", 
                               run_id=run_id, 
                               metrics_count=len(metrics),
                               wave=wave)
            else:
                self.logger.warning("Incomplete game data received", 
                                  run_id=run_id, 
                                  available_keys=list(payload.keys()))
                
        except Exception as e:
            self.logger.error("Error storing game data", 
                            payload=payload, 
                            error=str(e))

    async def _handle_game_event_message(self, payload: Dict[str, Any], timestamp: Any) -> None:
        """Handle game event messages."""
        try:
            if not self.db_service:
                self.logger.warning("Cannot store game event: database service not available")
                return
            
            event_type = payload.get('event', 'unknown')
            
            self.logger.info("Storing game event in database", 
                           event_type=event_type, 
                           payload=payload)
            
            # Store as an event in the database using write_event method
            run_id = payload.get('roundSeed', 'unknown')
            self.db_service.write_event(
                run_id=str(run_id),
                timestamp=timestamp or int(time.time() * 1000),
                event_name=event_type,
                data=payload
            )
            
        except Exception as e:
            self.logger.error("Error storing game event", 
                            payload=payload, 
                            error=str(e))

    async def _handle_script_error_message(self, payload: Dict[str, Any], timestamp: Any) -> None:
        """Handle script error messages."""
        try:
            error_msg = payload.get('error', 'Unknown script error')
            stack = payload.get('stack', '')
            
            self.logger.error("Script error received", 
                            error=error_msg, 
                            stack=stack, 
                            timestamp=timestamp)
            
            # Log error for now - TODO: Create proper ErrorInfo object
            # Note: Need to check ErrorType enum values for proper error handling
            self.logger.error("Script error details logged", 
                            error_message=error_msg, 
                            stack_trace=stack)
                
        except Exception as e:
            self.logger.error("Error handling script error message", 
                            payload=payload, 
                            error=str(e))

    async def _handle_test_message(self, payload: Dict[str, Any], timestamp: Any) -> None:
        """Handle test messages from the script."""
        try:
            message = payload.get('message', 'No message')
            self.logger.info("Test message received from Frida", 
                           message=message, 
                           timestamp=timestamp)
            
            # Log test message for debugging purposes
            if self.db_service:
                self.db_service.write_event(
                    run_id="test_run",
                    timestamp=timestamp or int(time.time() * 1000),
                    event_name="test_message",
                    data=payload
                )
                
        except Exception as e:
            self.logger.error("Error handling test message", 
                            payload=payload, 
                            error=str(e))
    
    def get_status(self) -> Dict[str, Any]:
        """Get overall system status."""
        session_state = self.get_session_state()
        
        status_info = {
            "status": "running",
            "session": session_state,
            "test_mode": self._test_mode,
            "test_mode_replay": self._test_mode_replay,
            "test_mode_generate": self._test_mode_generate,
            "loading_complete": self.loading_manager.is_loading_complete()
        }
        
        # Notify status callbacks
        self._notify_status_change(status_info)
        
        return status_info
    
    def signal_loading_complete(self):
        """Signal that the application loading is complete."""
        self.logger.info("Signaling loading complete to frontend")
        # This will be called by the API server when it's ready
        self.loading_manager.mark_step_complete('api_server')
    
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