"""
TowerIQ Main Controller

This module provides the MainController class that orchestrates all
application components and manages the overall application lifecycle.
"""

import asyncio
from typing import Any, Optional
import os
import time
import random
import math
import cProfile
import pstats

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
    
    def __init__(self, config: ConfigurationManager, logger: Any, db_path: str = '') -> None:
        """
        Initialize the main controller.
        Args:
            config: Configuration manager instance
            logger: Logger instance
            db_path: Optional override for the database file path
        """
        super().__init__()
        
        self.logger = logger.bind(source="MainController")
        self.config = config
        
        # Initialize core services
        self.session = SessionManager()
        self.db_service = DatabaseService(config, logger, db_path=db_path)
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
        
        self._test_mode = getattr(config, '_test_mode', False)
        self._test_mode_replay = getattr(config, '_test_mode_replay', False)
        self._test_mode_generate = getattr(config, '_test_mode_generate', False)
        self._test_mode_task = None
    
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
            from PyQt6.QtCore import QTimer, QThread
            from PyQt6.QtWidgets import QApplication
            
            # Check if QApplication still exists and is not closing
            app = QApplication.instance()
            if app is None or app.closingDown():
                self.logger.debug("QApplication is shutting down, skipping signal emission")
                return
            
            # Additional shutdown safety checks
            try:
                # Check if we're in the main thread - if so, emit directly
                if QThread.currentThread() == app.thread():
                    # We're already on the main thread, emit directly
                    if not self._is_shutting_down and app and not app.closingDown():
                        signal.emit(*args)
                    return
            except (RuntimeError, AttributeError):
                self.logger.debug("Qt threading system unavailable, skipping signal emission")
                return
            
            # Only use QTimer if we're not shutting down and not already on main thread
            if not self._is_shutting_down and app and not app.closingDown():
                def emit_signal():
                    try:
                        # Final check before emitting
                        if not self._is_shutting_down and app and not app.closingDown():
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
        
        if self._test_mode:
            await asyncio.to_thread(self.db_service.connect)
            self.logger.info("Test mode: database connected. Starting simulation.")
            self._emit_signal_safely(self.setup_finished, True)
            if self._test_mode_replay:
                self._test_mode_task = asyncio.create_task(self._run_test_mode_replay())
            else:
                self._test_mode_task = asyncio.create_task(self._run_test_mode_simulation())
            await self._test_mode_task
            return
        
        # Connect to database and run migrations
        try:
            await asyncio.to_thread(self.db_service.connect)
            self.logger.info("Database connection established successfully")
            self._emit_signal_safely(self.setup_finished, True)
        except Exception as e:
            self.logger.error("Failed to connect to database", error=str(e))
            self._emit_signal_safely(self.setup_finished, False)
            return
        
        # Check if automatic connection is enabled in config
        auto_connect_enabled = self.config.get('gui.auto_connect_emulator', False)
        
        if auto_connect_enabled:
            # Try automatic connection first
            connection_successful = await self._run_automatic_connection()
            
            if connection_successful:
                # Emit signal to dashboard to go into "active" mode
                self._emit_signal_safely(self.connection_state_changed, True)
                if self.dashboard:
                    self.dashboard.set_connection_active(True)
            else:
                # Reset connection state and show manual connection panel
                # First deactivate hook if active (this stops the listener)
                if self.session.is_hook_active:
                    self.set_hook_active(False)
                self.session.reset_connection_state()
                self._emit_signal_safely(self.connection_state_changed, False)
                if self.dashboard:
                    self.dashboard.set_connection_active(False)
                    self.dashboard.connection_panel.update_state(self.session)
        else:
            # Automatic connection disabled, always show manual connection panel
            # First deactivate hook if active (this stops the listener)
            if self.session.is_hook_active:
                self.set_hook_active(False)
            self.session.reset_connection_state()
            self._emit_signal_safely(self.connection_state_changed, False)
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
                self._emit_signal_safely(self.connection_state_changed, True)
                
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

    async def shutdown(self, force_exit_timeout: float = 3.0) -> None:
        """
        Robust, unified shutdown for the entire application.
        - Sets shutdown flag immediately.
        - Cancels all background tasks and timers.
        - Detaches from Frida with timeout and force cleanup.
        - Closes the database with timeout and error handling.
        - Force-exits if shutdown takes too long.
        This method is idempotent and safe to call from any context.
        Args:
            force_exit_timeout: Maximum seconds to wait before force exit (default 3.0)
        """
        if getattr(self, '_shutdown_in_progress', False):
            return
        self._shutdown_in_progress = True
        self._is_shutting_down = True
        self._is_running = False
        start_time = time.time()
        try:
            # Cancel all background asyncio tasks except this one
            loop = None
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                pass
            if loop and loop.is_running():
                current_task = asyncio.current_task(loop=loop)
                tasks = [t for t in asyncio.all_tasks(loop) if t is not current_task and not t.done()]
                for t in tasks:
                    t.cancel()
                await asyncio.sleep(0.05)
            # Stop all QTimers and UI timers (if any)
            try:
                from PyQt6.QtCore import QTimer
                timers = []
                if hasattr(self, 'dashboard') and self.dashboard:
                    timers += self.dashboard.findChildren(QTimer)
                for timer in timers:
                    if timer.isActive():
                        timer.stop()
            except Exception:
                pass
            # Detach from Frida with timeout
            try:
                if self.session.is_hook_active:
                    await asyncio.wait_for(self.frida_service.detach(), timeout=1.0)
            except Exception:
                pass
            # Close database with timeout
            try:
                await asyncio.wait_for(asyncio.to_thread(self.db_service.close), timeout=1.0)
            except Exception:
                pass
            # Wait for all tasks to finish or timeout
            while (time.time() - start_time) < force_exit_timeout:
                pending = [t for t in asyncio.all_tasks() if not t.done()]
                if not pending:
                    break
                await asyncio.sleep(0.05)
            if (time.time() - start_time) >= force_exit_timeout:
                print("Shutdown did not complete in time. Forcing exit.")
                os._exit(0)
        except Exception as e:
            print(f"Error during robust shutdown: {e}")
            os._exit(1)
    
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
            while self._is_running and self.session.is_hook_active and not self._is_shutting_down:
                try:
                    # The FridaService.get_message() now has internal timeout and shutdown handling
                    message = await self.frida_service.get_message()
                    
                    message_count += 1
                    self.logger.debug("Received message from Frida", 
                                   message_type=message.get("type"), 
                                   payload_keys=list(message.get("payload", {}).keys()),
                                   message_count=message_count,
                                   queue_size=self.frida_service.queue_size)
                    
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
                    # This is normal - no messages available, continue checking shutdown flags
                    continue
                except RuntimeError as e:
                    # This is expected during shutdown when FridaService signals completion
                    if "shutdown" in str(e).lower():
                        self.logger.info("Frida message listener received shutdown signal")
                        break
                    else:
                        self.logger.error("Runtime error in frida message listener", error=str(e))
                        break
                except Exception as e:
                    self.logger.error("Error in frida message listener", error=str(e))
                    # Check if we should continue or break
                    if self._is_shutting_down:
                        self.logger.info("Shutting down, exiting message listener")
                        break
                    await asyncio.sleep(1)  # Prevent tight loop on errors
        except asyncio.CancelledError:
            self.logger.info("Frida message listener cancelled")
            raise
        finally:
            self.logger.info("Frida message listener stopped", total_messages_processed=message_count)
    
    async def _handle_game_metric(self, message: dict) -> None:
        """
        Processes metric data in wide format. Handles both single and bulk metrics.
        Uses roundSeed from the game as the run identifier for all database writes.
        """
        try:
            payload = message.get("payload", {})
            round_seed = payload.get("roundSeed")
            if round_seed is not None:
                self.session.current_round_seed = round_seed
            run_id = self.session.current_round_seed
            if run_id is None:
                self.logger.warning("No roundSeed available for metric, skipping database write.")
                return
            run_id_str = str(run_id)
            real_timestamp = int(payload.get("timestamp", asyncio.get_event_loop().time()))
            game_timestamp = float(payload.get("gameTimestamp", 0))
            game_speed = float(payload.get("gameSpeed", 1.0))
            current_wave = int(payload.get("currentWave", 0))
            metrics = payload.get("metrics", {})
            # Insert wide metric row
            await asyncio.to_thread(
                self.db_service.write_metric,
                run_id_str, real_timestamp, game_timestamp, current_wave, metrics
            )
            self.logger.debug("Inserted wide metric row", run_id=run_id_str, real_timestamp=real_timestamp)
            # Optionally emit signals for UI updates (can be customized)
            for name, value in metrics.items():
                self._emit_signal_safely(self.new_metric_received, name, value)
            # Optionally update graph data (can be customized)
            for name in metrics.keys():
                await self._get_run_metrics_for_graph(run_id_str, name)
        except Exception as e:
            self.logger.error("Error handling wide game metric(s)", error=str(e))
    
    async def _handle_game_event(self, message: dict) -> None:
        """
        Processes discrete game events in wide format. Handles startNewRound, gameOver, gamePaused, gameResumed.
        """
        try:
            payload = message.get("payload", {})
            round_seed = payload.get("roundSeed")
            if round_seed is not None:
                self.session.current_round_seed = round_seed
            run_id = self.session.current_round_seed
            if run_id is None:
                self.logger.warning("No roundSeed available for event, skipping database write.")
                return
            run_id_str = str(run_id)
            timestamp = int(payload.get("timestamp", asyncio.get_event_loop().time()))
            event_name = payload.get("event") or payload.get("name") or "unknown_event"
            data = payload.get("data", {}).copy() if isinstance(payload.get("data"), dict) else {}
            # Always include gameplayTime if present
            if "gameplayTime" in payload:
                data["gameplayTime"] = payload["gameplayTime"]
            if event_name == "startNewRound":
                # Use roundStartTime for accurate start time
                run_id = payload.get("roundSeed")
                start_time_ms = payload.get("roundStartTime")
                tier = payload.get("tier")
                game_version = payload.get("gameVersion")
                await asyncio.to_thread(
                    self.db_service.insert_run_start,
                    str(run_id), start_time_ms, game_version, tier
                )
                await asyncio.to_thread(
                    self.db_service.write_event,
                    str(run_id), start_time_ms, event_name, data
                )
                self.session.is_round_active = True
                self.logger.info("Start of new round detected (game_event)", round_seed=round_seed)
            elif event_name == "gameOver":
                # Use roundStartTime for accurate duration calculation
                run_id = payload.get("roundSeed")
                end_time_ms = payload.get("timestamp")
                start_time_ms = payload.get("roundStartTime")
                duration_ms = end_time_ms - start_time_ms if end_time_ms is not None and start_time_ms is not None else None
                metrics = payload.get("metrics", {})
                await asyncio.to_thread(
                    self.db_service.update_run_end,
                    str(run_id),
                    end_time_ms,
                    payload.get("currentWave"),
                    payload.get("coinsEarned"),
                    duration_ms,
                    payload.get("gameTimestamp"),
                    metrics.get("round_cells"),
                    metrics.get("round_gems"),
                    metrics.get("round_cash")
                )
                self.session.is_round_active = False
                self.logger.info("Game over event received (game_event)", payload=payload)
            elif event_name in ("gamePaused", "gameResumed"):
                await asyncio.to_thread(
                    self.db_service.write_event,
                    run_id_str, timestamp, event_name, data
                )
                self.logger.info(f"{event_name} event received (game_event)", payload=payload)
            else:
                # For all other events, just insert as wide event
                await asyncio.to_thread(
                    self.db_service.write_event,
                    run_id_str, timestamp, event_name, data
                )
        except Exception as e:
            self.logger.error("Error handling wide game event", error=str(e))
    
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
        while self._is_running and not self._is_shutting_down:
            try:
                # Check emulator connection
                emulator_connected = await self.emulator_service.is_connected()
                self._emit_signal_safely(self.status_changed, "emulator", "connected" if emulator_connected else "disconnected")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error("Error in system health monitor", error=str(e))
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _get_run_metrics_for_graph(self, run_id: str, name: str) -> None:
        """Fetch metrics and emit graph data with proper graph name mapping."""
        # Don't fetch from database during shutdown
        if self._is_shutting_down:
            return
            
        try:
            if name == "round_gems":
                df = await asyncio.to_thread(self.db_service.get_total_gems_over_time, run_id)
            else:
                df = await asyncio.to_thread(self.db_service.get_run_metrics, run_id, name)
            
            # Map metric names to graph names
            graph_name_mapping = {
                "coins": "coins_timeline",
                "total_coins": "coins_timeline",
                "round_gems": "gems_timeline",
                "round_cells": "cells_timeline",
                "round_cash": "cash_timeline",
                "efficiency": "efficiency_timeline",
                "wave_coins": "wave_coins_timeline"
            }
            
            graph_name = graph_name_mapping.get(name, f"{name}_graph")
            self._emit_signal_safely(self.new_graph_data, graph_name, df)
            self.logger.debug("Emitted graph data signal", 
                            graph_name=graph_name, 
                            data_points=len(df))
        except Exception as e:
            self.logger.error("Failed to get run metrics for graph", error=str(e), run_id=run_id, name=name)
    
    async def stop(self) -> None:
        """
        Backward-compatible alias for shutdown().
        Calls the robust, unified shutdown logic.
        """
        await self.shutdown()

    async def _run_test_mode_simulation(self):
        """
        Simulate fake game runs and write metrics to the database for chart testing.
        Profile the entire simulation using cProfile and dump stats to a file.
        """
        profile = cProfile.Profile()
        profile_output_path = os.path.abspath("test_mode_profile.prof")
        profile.enable()
        try:
            while self._is_running:
                # Randomize parameters for each run
                a = round(random.uniform(4, 5) / 0.1) * 0.1
                n = random.choice([0.65, 0.75])
                k = round(random.uniform(0.001, 0.009) / 0.0001) * 0.0001
                b = random.randint(500, 1500)

                # --- Set session state for dashboard/stat panels ---
                # Use an int for current_round_seed (DB run_id is str, but session expects int)
                run_id_num = int(time.time() * 1000) + random.randint(0, 999)
                run_id = f"testrun_{run_id_num}"
                start_time = int(time.time())
                tier = random.randint(3, 9)
                self.db_service.insert_run_start(run_id, start_time, tier=tier)
                self.logger.info(f"Test mode: started new run {run_id} with a={a}, n={n}, k={k}, b={b}, tier={tier}")

                self.session.current_round_seed = run_id
                self.session.is_round_active = True
                self.session.is_emulator_connected = True
                self.session.is_hook_active = True
                if self.dashboard:
                    self.dashboard.set_connection_active(True)

                # Initialize gem and cell values and next increment times
                gems_blocks = 0
                gems_ads = 0
                cells = 0
                next_gems_blocks = random.randint(180, 600)  # 3-10 min
                next_gems_ads = random.randint(180, 600)     # 3-10 min
                next_cells = random.randint(60, 300)         # 1-5 min

                # --- For wave coins ---
                current_wave = 1
                last_wave = 1
                coins_at_wave_start = 0.0
                last_coins = 0.0

                # Simulate 1800 seconds (30 minutes) of game time, 1s per step
                for x in range(1800):
                    if not self._is_running:
                        break
                    # f(x) = a * (x^n) / (1 + exp(-k * (x - b)))
                    coins = a * (x ** n) / (1 + math.exp(-k * (x - b)))

                    # Gems from blocks
                    if x == next_gems_blocks:
                        gems_blocks += 2
                        next_gems_blocks += random.randint(180, 600)
                    # Gems from ads
                    if x == next_gems_ads:
                        gems_ads += 5
                        next_gems_ads += random.randint(180, 600)
                    # Cells
                    if x == next_cells:
                        add_cells = random.randint(5, 20)
                        cells += add_cells
                        next_cells += random.randint(60, 300)

                    real_timestamp = start_time + x
                    game_timestamp = x
                    # current_wave increments every 12 seconds
                    wave_incremented = False
                    if x > 0 and x % 12 == 0:
                        current_wave += 1
                        wave_incremented = True

                    # --- Calculate wave_coins when wave increments ---
                    wave_coins = None
                    if wave_incremented:
                        wave_coins = coins - coins_at_wave_start
                        coins_at_wave_start = coins
                        last_wave = current_wave
                    # For the very first wave, set coins_at_wave_start
                    if x == 0:
                        coins_at_wave_start = coins

                    # --- Main metrics dict (no round_gems) ---
                    metrics = {
                        "round_coins": coins,
                        "round_gems_from_blocks_value": gems_blocks,
                        "round_gems_from_ads_value": gems_ads,
                        "round_cells": cells,
                        "current_wave": current_wave
                    }
                    self.db_service.write_metric(run_id, real_timestamp, game_timestamp, current_wave, metrics)

                    # If wave incremented, write a separate wave_coins metric row
                    if wave_incremented and wave_coins is not None:
                        self.db_service.write_metric(run_id, real_timestamp, game_timestamp, current_wave, {"wave_coins": wave_coins})

                    # Emit signals to update UI (metrics)
                    self._emit_signal_safely(self.new_metric_received, "round_coins", coins)
                    self._emit_signal_safely(self.new_metric_received, "round_gems_from_blocks_value", gems_blocks)
                    self._emit_signal_safely(self.new_metric_received, "round_gems_from_ads_value", gems_ads)
                    self._emit_signal_safely(self.new_metric_received, "round_cells", cells)
                    self._emit_signal_safely(self.new_metric_received, "current_wave", current_wave)
                    if wave_coins is not None:
                        self._emit_signal_safely(self.new_metric_received, "wave_coins", wave_coins)

                    # Optionally emit new_graph_data for all relevant charts
                    # (simulate real handler)
                    await self._get_run_metrics_for_graph(run_id, "round_coins")
                    await self._get_run_metrics_for_graph(run_id, "round_gems")
                    await self._get_run_metrics_for_graph(run_id, "round_cells")
                    await self._get_run_metrics_for_graph(run_id, "wave_coins")

                    await asyncio.sleep(0.01)  # Fast-forward: 20x real time

                # End the run
                end_time = start_time + 1800
                self.db_service.update_run_end(run_id, end_time, final_wave=current_wave, coins_earned=coins, duration_realtime=1800)
                self.logger.info(f"Test mode: ended run {run_id}")
                # Mark round as inactive in session
                self.session.is_round_active = False
                self.session.is_hook_active = False
                if self.dashboard:
                    self.dashboard.set_connection_active(False)
                await asyncio.sleep(5)  # Wait before starting next run
        finally:
            profile.disable()
            profile.dump_stats(profile_output_path)
            self.logger.info(f"cProfile stats for test mode simulation written to {profile_output_path}")
            print(f"[Test Mode] cProfile stats written to: {profile_output_path}")
            # Print top 20 functions by cumulative time
            try:
                stats = pstats.Stats(profile_output_path)
                print("\n[Test Mode] Top 20 functions by cumulative time:")
                stats.sort_stats("cumulative").print_stats(20)
            except Exception as e:
                print(f"[Test Mode] Failed to print cProfile stats summary: {e}")
            self.logger.info(f"cProfile stats summary printed to console (if available)")

    async def _run_test_mode_replay(self):
        """
        Replay existing data from the test_mode.sqlite database, emitting signals as if it were a real run.
        """
        import pandas as pd
        # Get all run_ids
        run_ids = await asyncio.to_thread(self.db_service.get_all_run_ids)
        if not run_ids:
            self.logger.error("No test runs found in test database!")
            return
        run_id = run_ids[-1]  # Use the latest run
        self.logger.info(f"Test mode replay: using run_id {run_id}")
        # Get all metrics for that run, ordered by game_timestamp or real_timestamp
        metrics_df = await asyncio.to_thread(self.db_service.get_all_metrics_for_run, run_id)
        # Optionally, get events as well if needed
        # events_df = await asyncio.to_thread(self.db_service.get_all_events_for_run, run_id)
        self.session.current_round_seed = run_id
        self.session.is_round_active = True
        self.session.is_emulator_connected = True
        self.session.is_hook_active = True
        if self.dashboard:
            self.dashboard.set_connection_active(True)
        # Replay metrics
        for idx, row in metrics_df.iterrows():
            if not self._is_running:
                break
            # Emit signals to update UI (metrics)
            for col in ["round_coins", "round_gems_from_blocks_value", "round_gems_from_ads_value", "round_cells", "current_wave", "wave_coins"]:
                if col in row and row[col] is not None:
                    self._emit_signal_safely(self.new_metric_received, col, row[col])
            # Optionally emit new_graph_data for all relevant charts
            await self._get_run_metrics_for_graph(run_id, "round_coins")
            await self._get_run_metrics_for_graph(run_id, "round_gems")
            await self._get_run_metrics_for_graph(run_id, "round_cells")
            await self._get_run_metrics_for_graph(run_id, "wave_coins")
            await asyncio.sleep(0.001)  # Fast replay
        self.session.is_round_active = False
        self.session.is_hook_active = False
        if self.dashboard:
            self.dashboard.set_connection_active(False)
        self.logger.info(f"Test mode replay: finished run_id {run_id}")
 