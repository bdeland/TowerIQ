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
from .services.docker_service import DockerService
from .services.database_service import DatabaseService
from .services.setup_service import SetupService
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
        self.docker_service = DockerService(config, logger)
        self.setup_service = SetupService(config, logger, self.docker_service, self.db_service, self)
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
        
        # Run initial setup
        setup_success = await self.setup_service.run_initial_setup()
        self.setup_finished.emit(setup_success)
        
        if setup_success:
            # Start main monitoring tasks
            await asyncio.gather(
                self._listen_for_frida_messages(),
                self._monitor_system_health()
            )
    
    async def stop(self) -> None:
        """
        Gracefully shuts down all services.
        """
        self._is_running = False
        await self.frida_service.detach()
        await self.docker_service.stop_stack()
        await self.db_service.close()
    
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
                message = await self.frida_service.get_message()  # Blocks until message available
                handler = self._message_handlers.get(message.get("type"))
                if handler:
                    await handler(message)
                else:
                    self.logger.warn("unhandled_message", message_type=message.get("type"))
            except Exception as e:
                self.logger.error("Error in frida message listener", error=str(e))
                await asyncio.sleep(1)  # Prevent tight loop on errors
    
    async def _handle_game_metric(self, message: dict) -> None:
        """
        Processes metric data.
        """
        try:
            payload = message.get("payload", {})
            measurement = payload.get("measurement")
            fields = payload.get("fields", {})
            tags = payload.get("tags", {})
            
            await self.db_service.write_metric(measurement, fields, tags)
            
            # Emit signal for UI
            for field_name, field_value in fields.items():
                self.new_metric_received.emit(field_name, field_value)
                
        except Exception as e:
            self.logger.error("Error handling game metric", error=str(e))
    
    async def _handle_game_event(self, message: dict) -> None:
        """
        Processes discrete game events (e.g., round start, perk chosen).
        """
        try:
            payload = message.get("payload", {})
            event_type = payload.get("event_type")
            event_data = payload.get("data", {})
            
            await self.db_service.write_event(event_type, event_data)
            
            # Manage session state
            if event_type == "run_started":
                self.session.start_new_run()
            elif event_type == "run_ended":
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
        A long-running task that periodically checks the health of backend services.
        """
        while self._is_running:
            try:
                # Check Docker health
                docker_healthy = await self.docker_service.is_healthy()
                self.status_changed.emit("docker", "healthy" if docker_healthy else "unhealthy")
                
                # Check emulator connection
                emulator_connected = await self.emulator_service.is_connected()
                self.status_changed.emit("emulator", "connected" if emulator_connected else "disconnected")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error("Error in system health monitor", error=str(e))
                await asyncio.sleep(10)  # Wait before retrying
    
 