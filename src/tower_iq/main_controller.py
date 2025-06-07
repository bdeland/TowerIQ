"""
TowerIQ Main Controller

This module provides the MainController class that orchestrates all
application components and manages the overall application lifecycle.
"""

import asyncio
from typing import Any

from .core.config import ConfigurationManager
from .core.session import SessionManager
from .services.docker_service import DockerService
from .services.database_service import DatabaseService


class MainController:
    """
    Main controller that orchestrates all application components.
    Manages the overall application lifecycle and coordinates between services.
    """
    
    def __init__(
        self,
        config: ConfigurationManager,
        session_manager: SessionManager,
        docker_service: DockerService,
        database_service: DatabaseService,
        logger: Any
    ) -> None:
        """
        Initialize the main controller.
        
        Args:
            config: Configuration manager instance
            session_manager: Session manager instance
            docker_service: Docker service instance
            database_service: Database service instance
            logger: Logger instance
        """
        self.config = config
        self.session_manager = session_manager
        self.docker_service = docker_service
        self.database_service = database_service
        self.logger = logger.bind(source="MainController")
        
        # Application state
        self._is_running = False
        self._startup_complete = False
        
        # Background tasks
        self._background_tasks: set[asyncio.Task] = set()
    
    async def start(self) -> None:
        """
        Start the main application controller.
        Initializes all services and starts background tasks.
        """
        if self._is_running:
            self.logger.warning("Controller is already running")
            return
        
        self.logger.info("Starting TowerIQ main controller")
        
        try:
            # Start Docker stack if auto-start is enabled
            if self.config.get('gui.auto_start_docker', True):
                await self._start_docker_stack()
            
            # Start background monitoring tasks
            await self._start_background_tasks()
            
            # Mark as running
            self._is_running = True
            self._startup_complete = True
            
            self.logger.info("Main controller started successfully")
            
        except Exception as e:
            self.logger.error("Failed to start main controller", error=str(e))
            await self.shutdown()
            raise
    
    async def shutdown(self) -> None:
        """
        Gracefully shutdown the main controller.
        Stops all services and cleans up resources.
        """
        if not self._is_running:
            return
        
        self.logger.info("Shutting down main controller")
        
        try:
            # Mark as not running to stop background tasks
            self._is_running = False
            
            # Cancel all background tasks
            await self._stop_background_tasks()
            
            # End current run if active
            if self.session_manager.current_runId:
                self.session_manager.end_run()
                self.logger.info("Ended active run session")
            
            # Stop Docker stack
            await self._stop_docker_stack()
            
            # Close database connections
            await self.database_service.close()
            
            # Reset session state
            self.session_manager.reset_all_state()
            
            self.logger.info("Main controller shutdown completed")
            
        except Exception as e:
            self.logger.error("Error during controller shutdown", error=str(e))
    
    async def _start_docker_stack(self) -> None:
        """Start the Docker backend stack."""
        self.logger.info("Starting Docker backend stack")
        
        if await self.docker_service.start_stack():
            self.logger.info("Docker stack started successfully")
        else:
            self.logger.error("Failed to start Docker stack")
            # Don't fail startup if Docker fails - allow manual retry
    
    async def _stop_docker_stack(self) -> None:
        """Stop the Docker backend stack."""
        self.logger.info("Stopping Docker backend stack")
        
        if await self.docker_service.stop_stack():
            self.logger.info("Docker stack stopped successfully")
        else:
            self.logger.warning("Failed to stop Docker stack cleanly")
    
    async def _start_background_tasks(self) -> None:
        """Start all background monitoring tasks."""
        self.logger.info("Starting background monitoring tasks")
        
        # Health monitoring task
        health_task = asyncio.create_task(self._health_monitoring_loop())
        self._background_tasks.add(health_task)
        health_task.add_done_callback(self._background_tasks.discard)
        
        # Session monitoring task
        session_task = asyncio.create_task(self._session_monitoring_loop())
        self._background_tasks.add(session_task)
        session_task.add_done_callback(self._background_tasks.discard)
        
        self.logger.info("Background tasks started", task_count=len(self._background_tasks))
    
    async def _stop_background_tasks(self) -> None:
        """Stop all background tasks."""
        if not self._background_tasks:
            return
        
        self.logger.info("Stopping background tasks", task_count=len(self._background_tasks))
        
        # Cancel all tasks
        for task in self._background_tasks:
            task.cancel()
        
        # Wait for all tasks to complete
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        
        self._background_tasks.clear()
        self.logger.info("All background tasks stopped")
    
    async def _health_monitoring_loop(self) -> None:
        """Background task for monitoring system health."""
        self.logger.debug("Starting health monitoring loop")
        
        while self._is_running:
            try:
                # Check Docker stack health
                docker_healthy = await self.docker_service.is_healthy()
                
                # Log health status changes
                if docker_healthy != self.session_manager.get_status_summary().get('docker_healthy'):
                    self.logger.info("Docker health status changed", healthy=docker_healthy)
                
                # Update session state (we'll add this field to session manager later)
                # For now, just log the status
                self.logger.debug("Health check completed", docker_healthy=docker_healthy)
                
                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                self.logger.debug("Health monitoring loop cancelled")
                break
            except Exception as e:
                self.logger.error("Error in health monitoring loop", error=str(e))
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _session_monitoring_loop(self) -> None:
        """Background task for monitoring session state."""
        self.logger.debug("Starting session monitoring loop")
        
        while self._is_running:
            try:
                # Get current session status
                status = self.session_manager.get_status_summary()
                
                # Log session status periodically (every 5 minutes)
                self.logger.debug("Session status", **status)
                
                # Perform any session-related maintenance
                # (This is where we'd add logic for session timeouts, etc.)
                
                # Wait before next check
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except asyncio.CancelledError:
                self.logger.debug("Session monitoring loop cancelled")
                break
            except Exception as e:
                self.logger.error("Error in session monitoring loop", error=str(e))
                await asyncio.sleep(30)  # Wait before retrying
    
    # Public API methods for external components
    
    async def start_new_run(self, game_version: str = None) -> str:
        """
        Start a new monitoring run.
        
        Args:
            game_version: Version of the game being monitored
            
        Returns:
            New run ID
        """
        run_id = self.session_manager.start_new_run()
        
        if game_version:
            self.session_manager.game_version = game_version
        
        self.logger.info("Started new run", run_id=run_id, game_version=game_version)
        
        # Record run start in database
        try:
            await self.database_service.set_setting(f"run_{run_id}_started", "true")
            if game_version:
                await self.database_service.set_setting(f"run_{run_id}_game_version", game_version)
        except Exception as e:
            self.logger.error("Failed to record run start in database", error=str(e))
        
        return run_id
    
    async def end_current_run(self) -> None:
        """End the current monitoring run."""
        current_run = self.session_manager.current_runId
        if not current_run:
            self.logger.warning("No active run to end")
            return
        
        self.logger.info("Ending current run", run_id=current_run)
        
        # Record run end in database
        try:
            await self.database_service.set_setting(f"run_{current_run}_ended", "true")
        except Exception as e:
            self.logger.error("Failed to record run end in database", error=str(e))
        
        self.session_manager.end_run()
    
    async def get_system_status(self) -> dict:
        """
        Get comprehensive system status.
        
        Returns:
            Dictionary containing system status information
        """
        docker_healthy = await self.docker_service.is_healthy()
        session_status = self.session_manager.get_status_summary()
        
        return {
            'controller_running': self._is_running,
            'startup_complete': self._startup_complete,
            'docker_healthy': docker_healthy,
            'session': session_status,
            'background_tasks': len(self._background_tasks)
        }
    
    def is_running(self) -> bool:
        """Check if the controller is running."""
        return self._is_running
    
    def is_startup_complete(self) -> bool:
        """Check if startup is complete."""
        return self._startup_complete 