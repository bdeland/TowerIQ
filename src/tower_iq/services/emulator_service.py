"""
TowerIQ Emulator Service

This module provides the EmulatorService class for managing Android emulator
connections, ADB communication, and frida-server installation/management.
"""

import asyncio
import subprocess
from pathlib import Path
from typing import Any, Optional

from ..core.config import ConfigurationManager


class EmulatorService:
    """
    Service for managing Android emulator and ADB communication.
    
    This service handles device discovery, connection, and frida-server
    installation and management on Android devices/emulators.
    """
    
    def __init__(self, config: ConfigurationManager, logger: Any) -> None:
        """
        Initialize the emulator service.
        
        Args:
            config: Configuration manager instance
            logger: Logger instance
        """
        self.logger = logger.bind(source="EmulatorService")
        self.config = config
        
        # Connection state
        self.connected_device: Optional[str] = None
        self.device_architecture: Optional[str] = None
        self.frida_server_running = False
    
    async def find_and_connect_device(self, device_id: Optional[str] = None) -> Optional[str]:
        """
        Scan for ADB devices and connect to one.
        
        Args:
            device_id: Specific device ID to connect to. If None, will connect
                      to the first available device.
        
        Returns:
            The serial ID of the connected device, or None if no device found
        """
        self.logger.info("Scanning for ADB devices", target_device=device_id)
        
        try:
            devices = await self._get_connected_devices()
            
            if not devices:
                self.logger.info("No ADB devices found")
                return None
            
            if len(devices) == 1 and device_id is None:
                target_device = devices[0]
                self.logger.info("Single device found, connecting", device=target_device)
            elif device_id in devices:
                target_device = device_id
                self.logger.info("Target device found, connecting", device=target_device)
            elif device_id is None:
                self.logger.info("Multiple devices found", devices=devices)
                return None
            else:
                self.logger.error("Target device not found", device=device_id, available=devices)
                return None
            
            if await self._test_device_connection(target_device):
                self.connected_device = target_device
                self.logger.info("Successfully connected to device", device=target_device)
                return target_device
            else:
                self.logger.error("Failed to establish connection to device", device=target_device)
                return None
                
        except Exception as e:
            self.logger.error("Error during device discovery", error=str(e))
            return None
    
    async def get_device_architecture(self, device_id: str) -> str:
        """Get the CPU architecture of the specified device."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "getprop", "ro.product.cpu.abi",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                architecture = stdout.decode().strip()
                self.logger.info("Device architecture detected", device=device_id, arch=architecture)
                self.device_architecture = architecture
                return architecture
            else:
                error_msg = stderr.decode().strip()
                raise RuntimeError(f"Failed to get device architecture: {error_msg}")
                
        except Exception as e:
            self.logger.error("Error getting device architecture", device=device_id, error=str(e))
            raise
    
    async def install_frida_server(self, device_id: str) -> bool:
        """Install frida-server on the specified device."""
        self.logger.info("Installing frida-server", device=device_id)
        
        try:
            architecture = await self.get_device_architecture(device_id)
            frida_binary_path = await self._download_frida_server(architecture)
            if not frida_binary_path:
                return False
            
            target_path = "/data/local/tmp/frida-server"
            if not await self._push_file_to_device(device_id, frida_binary_path, target_path):
                return False
            
            if not await self._set_executable_permissions(device_id, target_path):
                return False
            
            self.logger.info("frida-server installed successfully", device=device_id)
            return True
            
        except Exception as e:
            self.logger.error("Error installing frida-server", device=device_id, error=str(e))
            return False
    
    async def start_frida_server(self, device_id: str) -> bool:
        """Start the frida-server process on the device."""
        self.logger.info("Starting frida-server", device=device_id)
        
        try:
            if await self.is_frida_server_running(device_id):
                self.logger.info("frida-server is already running", device=device_id)
                self.frida_server_running = True
                return True
            
            await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "su", "-c", 
                "/data/local/tmp/frida-server &",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            await asyncio.sleep(2)
            
            if await self.is_frida_server_running(device_id):
                self.logger.info("frida-server started successfully", device=device_id)
                self.frida_server_running = True
                return True
            else:
                self.logger.error("frida-server failed to start", device=device_id)
                return False
                
        except Exception as e:
            self.logger.error("Error starting frida-server", device=device_id, error=str(e))
            return False
    
    async def is_frida_server_running(self, device_id: str) -> bool:
        """Check if frida-server is running on the device."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "ps", "-A",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                output = stdout.decode()
                is_running = "frida-server" in output
                self.frida_server_running = is_running
                return is_running
            else:
                return False
                
        except Exception as e:
            self.logger.error("Error checking frida-server status", device=device_id, error=str(e))
            return False
    
    async def get_game_pid(self, device_id: str, package_name: str) -> Optional[int]:
        """Find the Process ID for the running game package."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "pidof", package_name,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                pid_str = stdout.decode().strip()
                if pid_str:
                    pid = int(pid_str)
                    self.logger.info("Game process found", device=device_id, package=package_name, pid=pid)
                    return pid
            
            return None
            
        except Exception as e:
            self.logger.error("Error finding game PID", device=device_id, package=package_name, error=str(e))
            return None
    
    async def is_connected(self) -> bool:
        """Check if there's an active device connection."""
        if not self.connected_device:
            return False
        
        return await self._test_device_connection(self.connected_device)
    
    async def _get_connected_devices(self) -> list[str]:
        """Get list of connected ADB devices."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "devices",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                output = stdout.decode()
                devices = []
                
                for line in output.split('\n')[1:]:
                    if '\tdevice' in line:
                        device_id = line.split('\t')[0].strip()
                        if device_id:
                            devices.append(device_id)
                
                return devices
            else:
                return []
                
        except Exception as e:
            self.logger.error("Error getting device list", error=str(e))
            return []
    
    async def _test_device_connection(self, device_id: str) -> bool:
        """Test if we can communicate with the specified device."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "echo", "test",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            return result.returncode == 0 and b"test" in stdout
            
        except Exception:
            return False
    
    async def _download_frida_server(self, architecture: str) -> Optional[Path]:
        """Download the appropriate frida-server binary for the architecture."""
        self.logger.info("Downloading frida-server", architecture=architecture)
        
        resources_dir = Path(__file__).parent.parent.parent.parent / "resources"
        frida_dir = resources_dir / "frida"
        frida_dir.mkdir(exist_ok=True)
        
        binary_name = f"frida-server-{architecture}"
        binary_path = frida_dir / binary_name
        
        if binary_path.exists():
            self.logger.info("Using existing frida-server binary", path=binary_path)
            return binary_path
        
        self.logger.error("frida-server binary not found", architecture=architecture)
        return None
    
    async def _push_file_to_device(self, device_id: str, local_path: Path, remote_path: str) -> bool:
        """Push a file from local filesystem to the Android device."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "push", str(local_path), remote_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            return result.returncode == 0
                
        except Exception as e:
            self.logger.error("Error pushing file", local=local_path, remote=remote_path, error=str(e))
            return False
    
    async def _set_executable_permissions(self, device_id: str, remote_path: str) -> bool:
        """Set executable permissions on a file on the Android device."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "chmod", "755", remote_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            return result.returncode == 0
                
        except Exception as e:
            self.logger.error("Error setting permissions", path=remote_path, error=str(e))
            return False 