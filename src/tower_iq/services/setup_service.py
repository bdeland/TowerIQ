"""
TowerIQ Setup Service

This module provides the SetupService class that orchestrates the entire
first-time setup process including WSL installation, Docker setup, and
database initialization.
"""

import asyncio
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject

from ..core.config import ConfigurationManager
from .docker_service import DockerService
from .database_service import DatabaseService


class SetupStepFailedError(Exception):
    """Raised when a setup step fails and cannot be recovered."""
    pass


class SetupService:
    """
    Service for orchestrating the entire first-time setup process.
    
    This service handles WSL installation, Docker setup, and database
    initialization in a coordinated manner.
    """
    
    def __init__(
        self,
        config: ConfigurationManager,
        logger: Any,
        docker_service: DockerService,
        db_service: DatabaseService,
        ui_signal_emitter: QObject
    ) -> None:
        """
        Initialize the setup service.
        
        Args:
            config: Configuration manager instance
            logger: Logger instance
            docker_service: Docker service instance
            db_service: Database service instance
            ui_signal_emitter: QObject that can emit signals for UI updates
        """
        self.logger = logger.bind(source="SetupService")
        self.config = config
        self.docker_service = docker_service
        self.db_service = db_service
        self.ui_signal_emitter = ui_signal_emitter
        
        # Setup state
        self._setup_complete_marker = Path.home() / ".toweriq_setup_complete"
    
    async def run_initial_setup(self) -> bool:
        """
        Run the complete initial setup process.
        
        This is the main entry point for the setup wizard/first-time flow.
        
        Returns:
            True if setup completed successfully, False otherwise
        """
        if self._is_setup_complete():
            self.logger.info("Setup already completed, skipping initial setup")
            return True
        
        self.logger.info("Starting initial setup process")
        
        try:
            # Execute setup steps in order
            await self._check_and_install_wsl()
            await self._import_wsl_distro()
            await self._install_docker_in_wsl()
            await self.docker_service.start_stack()
            await self.db_service.connect()
            await self.db_service.run_migrations()
            await self._mark_setup_as_complete()
            
            self.logger.info("Initial setup completed successfully")
            return True
            
        except SetupStepFailedError as e:
            self.logger.error("Setup step failed", error=str(e))
            return False
        except Exception as e:
            self.logger.error("Unexpected error during setup", error=str(e))
            return False
    
    async def validate_environment(self) -> bool:
        """
        Validate the current environment without attempting installations.
        
        This is a non-interactive check run on every application start
        after the first setup.
        
        Returns:
            True if the environment is healthy, False otherwise
        """
        self.logger.info("Validating environment health")
        
        try:
            # Check WSL
            if not await self._check_wsl_available():
                self.logger.error("WSL is not available")
                return False
            
            # Check WSL distro
            if not await self._check_wsl_distro_exists():
                self.logger.error("TowerIQ WSL distro not found")
                return False
            
            # Check Docker in WSL
            if not await self._check_docker_in_wsl():
                self.logger.error("Docker not available in WSL")
                return False
            
            # Check database connectivity
            if not await self.db_service.test_connection():
                self.logger.error("Database connection failed")
                return False
            
            self.logger.info("Environment validation passed")
            return True
            
        except Exception as e:
            self.logger.error("Error during environment validation", error=str(e))
            return False
    
    def _is_setup_complete(self) -> bool:
        """Check if the setup completion marker exists."""
        return self._setup_complete_marker.exists()
    
    async def _check_and_install_wsl(self) -> None:
        """
        Check if WSL is installed. If not, install it with user permission.
        
        Raises:
            SetupStepFailedError: If WSL installation fails
        """
        self.logger.info("Checking WSL installation")
        
        if await self._check_wsl_available():
            self.logger.info("WSL is already installed")
            return
        
        self.logger.info("WSL not found, attempting installation")
        
        try:
            # Run WSL install command with elevated privileges
            result = await asyncio.create_subprocess_exec(
                "powershell", "-Command", "Start-Process", "wsl", "--install", 
                "-Verb", "RunAs", "-Wait",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                self.logger.info("WSL installation completed successfully")
                # WSL installation requires a reboot
                self.logger.warning("System reboot required to complete WSL setup")
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                raise SetupStepFailedError(f"WSL installation failed: {error_msg}")
                
        except Exception as e:
            raise SetupStepFailedError(f"Failed to install WSL: {str(e)}")
    
    async def _check_wsl_available(self) -> bool:
        """Check if WSL is available and working."""
        try:
            result = await asyncio.create_subprocess_exec(
                "wsl", "--status",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            await result.communicate()
            return result.returncode == 0
            
        except FileNotFoundError:
            return False
        except Exception:
            return False
    
    async def _import_wsl_distro(self) -> None:
        """
        Import the dedicated TowerIQ WSL distribution.
        
        Raises:
            SetupStepFailedError: If distro import fails
        """
        self.logger.info("Checking TowerIQ WSL distribution")
        
        if await self._check_wsl_distro_exists():
            self.logger.info("TowerIQ WSL distribution already exists")
            return
        
        self.logger.info("Importing TowerIQ WSL distribution")
        
        try:
            # Find the bundled distro tar.gz file
            distro_path = self._find_bundled_distro()
            if not distro_path:
                raise SetupStepFailedError("Bundled WSL distribution not found")
            
            # Import the distribution
            install_path = Path.home() / "TowerIQ-WSL"
            install_path.mkdir(exist_ok=True)
            
            result = await asyncio.create_subprocess_exec(
                "wsl", "--import", "TowerIQ-Backend", 
                str(install_path), str(distro_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                self.logger.info("WSL distribution imported successfully")
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                raise SetupStepFailedError(f"WSL distribution import failed: {error_msg}")
                
        except Exception as e:
            raise SetupStepFailedError(f"Failed to import WSL distribution: {str(e)}")
    
    def _find_bundled_distro(self) -> Path | None:
        """Find the bundled WSL distribution file."""
        # Look for the distro in the resources directory
        resources_dir = Path(__file__).parent.parent.parent.parent / "resources"
        docker_dir = resources_dir / "docker"
        
        for tar_file in docker_dir.glob("*.tar.gz"):
            if "toweriq" in tar_file.name.lower():
                return tar_file
        
        return None
    
    async def _check_wsl_distro_exists(self) -> bool:
        """Check if the TowerIQ WSL distribution exists."""
        try:
            result = await asyncio.create_subprocess_exec(
                "wsl", "-l", "-v",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                output = stdout.decode()
                return "TowerIQ-Backend" in output
            
            return False
            
        except Exception:
            return False
    
    async def _install_docker_in_wsl(self) -> None:
        """
        Install Docker in the WSL distribution.
        
        Raises:
            SetupStepFailedError: If Docker installation fails
        """
        self.logger.info("Installing Docker in WSL distribution")
        
        if await self._check_docker_in_wsl():
            self.logger.info("Docker is already installed in WSL")
            return
        
        try:
            # Update package lists
            result = await asyncio.create_subprocess_exec(
                "wsl", "-d", "TowerIQ-Backend", "apt-get", "update",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode != 0:
                raise SetupStepFailedError("Failed to update package lists in WSL")
            
            # Install Docker
            result = await asyncio.create_subprocess_exec(
                "wsl", "-d", "TowerIQ-Backend", "apt-get", "install", "-y",
                "docker.io", "docker-compose",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode != 0:
                raise SetupStepFailedError("Failed to install Docker in WSL")
            
            # Start Docker service
            result = await asyncio.create_subprocess_exec(
                "wsl", "-d", "TowerIQ-Backend", "service", "docker", "start",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0:
                self.logger.info("Docker installed and started successfully in WSL")
            else:
                self.logger.warning("Docker installed but failed to start service")
                
        except Exception as e:
            raise SetupStepFailedError(f"Failed to install Docker in WSL: {str(e)}")
    
    async def _check_docker_in_wsl(self) -> bool:
        """Check if Docker is available in the WSL distribution."""
        try:
            result = await asyncio.create_subprocess_exec(
                "wsl", "-d", "TowerIQ-Backend", "docker", "--version",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            await result.communicate()
            return result.returncode == 0
            
        except Exception:
            return False
    
    async def _mark_setup_as_complete(self) -> None:
        """Create the setup completion marker file."""
        try:
            self._setup_complete_marker.touch()
            self.logger.info("Setup marked as complete")
        except Exception as e:
            self.logger.error("Failed to mark setup as complete", error=str(e))
            raise SetupStepFailedError(f"Failed to create setup marker: {str(e)}") 