"""
TowerIQ Docker Management Service

This module provides the DockerService class for managing the application's
Docker infrastructure including the backend stack and health monitoring.
"""

import asyncio
import subprocess
from typing import Any, Optional
from pathlib import Path

import docker
import aiohttp
from docker.errors import DockerException, NotFound, APIError

from ..core.config import ConfigurationManager


class DockerService:
    """
    Service for managing Docker and Docker Compose operations.
    Provides async interface for starting, stopping, and monitoring containers.
    """
    
    def __init__(self, config: ConfigurationManager, logger: Any) -> None:
        """
        Initialize the Docker service.
        
        Args:
            config: Configuration manager instance
            logger: Logger instance for this service
        """
        self.logger = logger.bind(source="DockerService")
        self.compose_file_path = config.get('docker.compose_file')
        self.health_endpoints = config.get('docker.health_check_endpoints', {})
        self.startup_timeout = config.get('docker.startup_timeout', 60)
        self.shutdown_timeout = config.get('docker.shutdown_timeout', 30)
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
            self.logger.info("Docker client initialized successfully")
        except DockerException as e:
            self.logger.error("Failed to initialize Docker client", error=str(e))
            self.docker_client = None
    
    async def start_stack(self) -> bool:
        """
        Start the backend stack using docker compose up -d.
        
        Returns:
            True on success, False on failure
        """
        if not self.docker_client:
            self.logger.error("Docker client not available")
            return False
        
        if not Path(self.compose_file_path).exists():
            self.logger.error("Docker compose file not found", path=self.compose_file_path)
            return False
        
        self.logger.info("Starting Docker stack", compose_file=self.compose_file_path)
        
        try:
            # Use subprocess to run docker compose command
            cmd = [
                "docker", "compose", 
                "-f", self.compose_file_path,
                "up", "-d"
            ]
            
            # Run command in thread pool to avoid blocking
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=self.startup_timeout
            )
            
            if result.returncode == 0:
                self.logger.info("Docker stack started successfully")
                
                # Wait a bit for services to initialize
                await asyncio.sleep(5)
                
                # Verify services are healthy
                if await self.is_healthy():
                    self.logger.info("Docker stack is healthy")
                    return True
                else:
                    self.logger.warning("Docker stack started but health check failed")
                    return False
            else:
                self.logger.error(
                    "Failed to start Docker stack",
                    returncode=result.returncode,
                    stdout=result.stdout,
                    stderr=result.stderr
                )
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Docker stack startup timed out", timeout=self.startup_timeout)
            return False
        except Exception as e:
            self.logger.error("Unexpected error starting Docker stack", error=str(e))
            return False
    
    async def stop_stack(self) -> bool:
        """
        Stop the backend stack using docker compose down.
        
        Returns:
            True on success, False on failure
        """
        if not Path(self.compose_file_path).exists():
            self.logger.error("Docker compose file not found", path=self.compose_file_path)
            return False
        
        self.logger.info("Stopping Docker stack", compose_file=self.compose_file_path)
        
        try:
            cmd = [
                "docker", "compose",
                "-f", self.compose_file_path,
                "down"
            ]
            
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=self.shutdown_timeout
            )
            
            if result.returncode == 0:
                self.logger.info("Docker stack stopped successfully")
                return True
            else:
                self.logger.error(
                    "Failed to stop Docker stack",
                    returncode=result.returncode,
                    stdout=result.stdout,
                    stderr=result.stderr
                )
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Docker stack shutdown timed out", timeout=self.shutdown_timeout)
            return False
        except Exception as e:
            self.logger.error("Unexpected error stopping Docker stack", error=str(e))
            return False
    
    async def is_healthy(self) -> bool:
        """
        Perform comprehensive health check on the Docker stack.
        
        Returns:
            True if container is running and all services are responsive
        """
        if not self.docker_client:
            self.logger.error("Docker client not available for health check")
            return False
        
        try:
            # Check if the main container is running
            containers = await asyncio.to_thread(
                self.docker_client.containers.list,
                filters={"name": "toweriq-backend"}
            )
            
            if not containers:
                self.logger.debug("TowerIQ backend container not found")
                return False
            
            container = containers[0]
            container_status = await asyncio.to_thread(lambda: container.status)
            
            if container_status != "running":
                self.logger.debug("TowerIQ backend container not running", status=container_status)
                return False
            
            self.logger.debug("Container health check passed")
            
            # Check health endpoints
            if not await self._check_service_endpoints():
                return False
            
            self.logger.debug("All health checks passed")
            return True
            
        except DockerException as e:
            self.logger.error("Docker error during health check", error=str(e))
            return False
        except Exception as e:
            self.logger.error("Unexpected error during health check", error=str(e))
            return False
    
    async def _check_service_endpoints(self) -> bool:
        """
        Check health endpoints of services running inside containers.
        
        Returns:
            True if all configured endpoints are responsive
        """
        if not self.health_endpoints:
            self.logger.debug("No health endpoints configured")
            return True
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10)
        ) as session:
            for service_name, endpoint_url in self.health_endpoints.items():
                try:
                    self.logger.debug("Checking service endpoint", service=service_name, url=endpoint_url)
                    
                    async with session.get(endpoint_url) as response:
                        if response.status == 200:
                            self.logger.debug("Service endpoint healthy", service=service_name)
                        else:
                            self.logger.warning(
                                "Service endpoint unhealthy",
                                service=service_name,
                                status=response.status
                            )
                            return False
                            
                except aiohttp.ClientError as e:
                    self.logger.warning(
                        "Service endpoint unreachable",
                        service=service_name,
                        error=str(e)
                    )
                    return False
                except Exception as e:
                    self.logger.error(
                        "Unexpected error checking service endpoint",
                        service=service_name,
                        error=str(e)
                    )
                    return False
        
        return True
    
    async def get_container_logs(self, container_name: str, tail: int = 100) -> Optional[str]:
        """
        Get logs from a specific container.
        
        Args:
            container_name: Name of the container
            tail: Number of lines to retrieve from the end
            
        Returns:
            Container logs as string, or None if container not found
        """
        if not self.docker_client:
            return None
        
        try:
            container = await asyncio.to_thread(
                self.docker_client.containers.get,
                container_name
            )
            
            logs = await asyncio.to_thread(
                container.logs,
                tail=tail,
                timestamps=True
            )
            
            return logs.decode('utf-8', errors='replace')
            
        except NotFound:
            self.logger.warning("Container not found", container=container_name)
            return None
        except Exception as e:
            self.logger.error("Error retrieving container logs", container=container_name, error=str(e))
            return None
    
    async def restart_stack(self) -> bool:
        """
        Restart the entire Docker stack.
        
        Returns:
            True on success, False on failure
        """
        self.logger.info("Restarting Docker stack")
        
        if not await self.stop_stack():
            self.logger.error("Failed to stop stack during restart")
            return False
        
        # Wait a moment before starting
        await asyncio.sleep(2)
        
        if not await self.start_stack():
            self.logger.error("Failed to start stack during restart")
            return False
        
        self.logger.info("Docker stack restarted successfully")
        return True
    
    def __del__(self) -> None:
        """Cleanup Docker client on destruction."""
        if self.docker_client:
            try:
                self.docker_client.close()
            except Exception:
                pass  # Ignore cleanup errors 