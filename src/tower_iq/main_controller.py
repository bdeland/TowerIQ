"""
TowerIQ Main Controller

This module provides the MainController class that orchestrates all
application components and manages the overall application lifecycle.
"""

import asyncio
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal

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
    
    async def stop(self) -> None:
        """
        Gracefully shuts down all services.
        """
        self._is_running = False
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
    
 