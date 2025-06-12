"""
TowerIQ Frida Service

This module provides the FridaService class for managing Frida injection,
script loading, and secure communication with injected scripts.
"""

import asyncio
import hashlib
import json
import yaml
from pathlib import Path
from typing import Any, Dict, Optional

import aiohttp
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES

try:
    import frida
except ImportError:
    frida = None

from ..core.config import ConfigurationManager


class SecurityException(Exception):
    """Raised when security validation fails."""
    pass


class FridaService:
    """
    Service for managing Frida injection and script communication.
    
    This service handles secure script downloading, injection, and
    message handling between the host application and injected scripts.
    """
    
    def __init__(self, config: ConfigurationManager, logger: Any) -> None:
        """
        Initialize the Frida service.
        
        Args:
            config: Configuration manager instance
            logger: Logger instance
        """
        self.logger = logger.bind(source="FridaService")
        self.config = config
        
        # Check if Frida is available
        if frida is None:
            self.logger.warning("Frida not available - install 'frida-tools' package")
        
        # Frida state
        self.device = None
        self.session = None
        self.script = None
        self.attached_pid: Optional[int] = None
        
        # Message handling - create queue lazily to ensure it's in the right event loop
        self._message_queue: Optional[asyncio.Queue] = None
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None
        
        # Security settings
        self.script_cache_dir = Path.home() / ".toweriq" / "scripts"
        self.script_cache_dir.mkdir(parents=True, exist_ok=True)
    
    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """
        Set the event loop for message handling.
        Should be called from the main thread before injecting scripts.
        """
        self._event_loop = loop
        self.logger.info("Event loop set for Frida message handling")
    
    @property
    def message_queue(self) -> asyncio.Queue:
        """Get or create the message queue in the current event loop."""
        if self._message_queue is None:
            try:
                # Try to get the running event loop
                current_loop = asyncio.get_running_loop()
                
                # If we have a stored loop and it's the same as current, use it
                if self._event_loop is None or self._event_loop == current_loop:
                    self._event_loop = current_loop
                    self._message_queue = asyncio.Queue()
                    self.logger.debug("Created message queue in current event loop")
                else:
                    # Create queue in the stored event loop
                    self._message_queue = asyncio.Queue()
                    self.logger.debug("Created message queue for stored event loop")
                    
            except RuntimeError:
                # No event loop running - create without loop reference
                self._message_queue = asyncio.Queue()
                self.logger.debug("Created message queue as fallback (no running loop)")
                
        return self._message_queue
    
    async def get_message(self) -> dict:
        """
        Get the next message from the Frida script queue.
        
        This method blocks until a message is available.
        
        Returns:
            Message dictionary from the injected script
        """
        return await self.message_queue.get()
    
    async def attach(self, pid: int, device_id: Optional[str] = None) -> bool:
        """
        Attach Frida to the specified process.
        
        Args:
            pid: Process ID to attach to
            device_id: Device serial ID (for remote devices)
            
        Returns:
            True if attachment was successful, False otherwise
        """
        if frida is None:
            self.logger.error("Frida not available")
            return False
            
        self.logger.info("Attaching to process", pid=pid, device_id=device_id)
        
        try:
            # Get the device
            if device_id:
                self.device = frida.get_device(device_id)
            else:
                self.device = frida.get_local_device()
            
            # Attach to the process
            self.session = self.device.attach(pid)
            self.attached_pid = pid
            
            self.logger.info("Successfully attached to process", pid=pid)
            return True
            
        except Exception as e:
            self.logger.error("Error attaching to process", pid=pid, error=str(e))
            return False
    
    async def detach(self) -> None:
        """Detach from the current process and clean up resources."""
        self.logger.info("Detaching from process")
        
        try:
            if self.script:
                self.script.unload()
                self.script = None
            
            if self.session:
                self.session.detach()
                self.session = None
            
            self.device = None
            self.attached_pid = None
            
            # Clear any remaining messages
            if self._message_queue is not None:
                while not self._message_queue.empty():
                    try:
                        self._message_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
            
            self.logger.info("Successfully detached from process")
            
        except Exception as e:
            self.logger.error("Error during detachment", error=str(e))
    
    async def inject_script(self, game_version: str) -> bool:
        """
        Inject the local script for the specified game version.
        
        This method loads the bundled local script from the path specified
        in the hook contract file. Compatibility checking should be done
        before calling this method.
        
        Args:
            game_version: Version of the game to inject script for (for logging)
            
        Returns:
            True if injection was successful, False otherwise
        """
        if not self.session:
            self.logger.error("No active session - cannot inject script")
            return False
        
        self.logger.info("Injecting local script", game_version=game_version)
        
        try:
            # Get the path to the hook contract from configuration
            contract_path = self.config.get("frida.hook_contract_path")
            if not contract_path:
                self.logger.error("Hook contract path not configured")
                return False
            
            # Build full path relative to project root
            project_root = self.config.get_project_root()
            full_contract_path = Path(project_root) / contract_path
            
            # Load and parse the contract YAML file
            with open(full_contract_path, 'r', encoding='utf-8') as f:
                contract = yaml.safe_load(f)
            
            # Get the script path from the contract
            script_info = contract.get('script_info', {})
            script_path = script_info.get('path')
            if not script_path:
                self.logger.error("Script path not specified in hook contract")
                return False
            
            # Resolve script path relative to the project root
            full_script_path = Path(project_root) / script_path
            
            if not full_script_path.exists():
                self.logger.error("Script file not found", path=str(full_script_path))
                return False
            
            # Read the script content
            with open(full_script_path, 'r', encoding='utf-8') as f:
                script_content = f.read()
            
            # Create and load the script
            self.script = self.session.create_script(script_content)
            self.script.on('message', self._on_message)
            self.script.load()
            
            self.logger.info("Local script injected successfully", 
                           game_version=game_version,
                           script_path=str(full_script_path))
            return True
            
        except FileNotFoundError as e:
            self.logger.error("File not found during script injection", error=str(e))
            return False
        except yaml.YAMLError as e:
            self.logger.error("Error parsing hook contract YAML during injection", error=str(e))
            return False
        except Exception as e:
            self.logger.error("Error injecting local script", 
                            game_version=game_version, 
                            error=str(e))
            return False
    
    def check_local_hook_compatibility(self, package_name: str, game_version: str) -> bool:
        """
        Check if the local hook script is compatible with the selected package and game version.
        
        This method reads the local hook_contract.yaml file and checks if both the
        package name matches the target_package AND the game_version is in the supported_versions list.
        
        Args:
            package_name: Package name of the game to check compatibility for
            game_version: Version of the game to check compatibility for
            
        Returns:
            True if the local hook is compatible, False otherwise
        """
        self.logger.info("Checking local hook compatibility", 
                        package_name=package_name, 
                        game_version=game_version)
        
        try:
            # Get the path to the hook contract from configuration
            contract_path = self.config.get("frida.hook_contract_path")
            if not contract_path:
                self.logger.error("Hook contract path not configured")
                return False
            
            # Build full path relative to project root
            project_root = self.config.get_project_root()
            full_contract_path = Path(project_root) / contract_path
            
            # Load and parse the YAML file
            with open(full_contract_path, 'r', encoding='utf-8') as f:
                contract = yaml.safe_load(f)
            
            # Safely access the script info
            script_info = contract.get('script_info', {})
            target_package = script_info.get('target_package')
            supported_versions = script_info.get('supported_versions', [])
            
            # Check package name compatibility
            if not target_package:
                self.logger.error("Target package not specified in hook contract")
                return False
            
            if package_name != target_package:
                self.logger.warning("Package name does not match hook target", 
                                  detected_package=package_name,
                                  target_package=target_package)
                return False
            
            # Check version compatibility
            version_compatible = game_version in supported_versions
            
            if not version_compatible:
                self.logger.warning("Game version not supported by local hook", 
                                  game_version=game_version,
                                  supported_versions=supported_versions)
                return False
            
            # Both package and version are compatible
            self.logger.info("Local hook compatibility confirmed", 
                           package_name=package_name,
                           game_version=game_version)
            return True
            
        except FileNotFoundError:
            self.logger.error("Hook contract file not found", path=contract_path)
            return False
        except yaml.YAMLError as e:
            self.logger.error("Error parsing hook contract YAML", error=str(e))
            return False
        except Exception as e:
            self.logger.error("Error checking local hook compatibility", 
                            package_name=package_name,
                            game_version=game_version, 
                            error=str(e))
            return False

    async def inject_and_run_script(self, device_id: str, pid: int, game_version: str) -> bool:
        """
        Complete workflow to attach to process and inject script.
        
        Args:
            device_id: Device serial ID
            pid: Process ID to attach to
            game_version: Game version for script selection
            
        Returns:
            True if successful, False otherwise
        """
        self.logger.info("Starting inject and run workflow", 
                        device_id=device_id, 
                        pid=pid, 
                        game_version=game_version)
        
        try:
            # First attach to the process
            if not await self.attach(pid, device_id):
                self.logger.error("Failed to attach to process")
                return False
            
            # Then inject the script
            if not await self.inject_script(game_version):
                self.logger.error("Failed to inject script")
                await self.detach()  # Clean up
                return False
            
            self.logger.info("Inject and run workflow completed successfully")
            return True
            
        except Exception as e:
            self.logger.error("Error in inject and run workflow", error=str(e))
            await self.detach()  # Ensure cleanup
            return False
    
    def _on_message(self, message: dict, data: Any) -> None:
        """
        Handle messages from the injected Frida script.
        
        This is the synchronous callback that Frida requires. It bridges
        the message to the async world via the message queue.
        
        Args:
            message: Message dictionary from Frida
            data: Optional binary data from Frida
        """
        try:
            self.logger.debug(f"_on_message received: {message}")
            
            # Parse the message type
            if message['type'] == 'send':
                payload = message['payload']
                self.logger.debug(f"Processing 'send' message with payload: {payload}")
                
                # Add metadata
                parsed_message = {
                    'type': payload.get('type', 'unknown'),
                    'payload': payload.get('payload', {}),
                    'timestamp': payload.get('timestamp'),
                    'pid': self.attached_pid
                }
                
                self.logger.debug(f"Parsed message: {parsed_message}")
                
                # Put message on async queue - use thread-safe approach
                self._queue_message_safely(parsed_message)
                
                self.logger.debug("Message received from script", message_type=parsed_message['type'])
                
            elif message['type'] == 'error':
                self.logger.debug(f"Processing 'error' message: {message}")
                # Handle script errors
                error_message = {
                    'type': 'script_error',
                    'payload': {
                        'error': message.get('description', 'Unknown script error'),
                        'stack': message.get('stack'),
                        'fileName': message.get('fileName'),
                        'lineNumber': message.get('lineNumber')
                    },
                    'timestamp': None,
                    'pid': self.attached_pid
                }
                
                # Put error message on async queue
                self._queue_message_safely(error_message)
                
                self.logger.error("Script error", error=message.get('description'))
                
        except Exception as e:
            self.logger.error("Error processing message from script", error=str(e))
    
    def _queue_message_safely(self, message: dict) -> None:
        """
        Safely queue a message for async processing.
        
        This method handles the thread-safe queuing of messages from Frida's thread
        to the main asyncio event loop.
        """
        try:
            if self._event_loop is not None and not self._event_loop.is_closed():
                # Schedule the put operation on the correct event loop from this thread
                if self._event_loop.is_running():
                    self._event_loop.call_soon_threadsafe(
                        lambda: asyncio.create_task(self._async_queue_message(message))
                    )
                    self.logger.debug("Message scheduled via call_soon_threadsafe")
                else:
                    self.logger.debug("Event loop not running, queuing directly")
                    self.message_queue.put_nowait(message)
            else:
                self.logger.debug("No event loop available, attempting direct queue")
                # Fallback to direct queuing
                self.message_queue.put_nowait(message)
                
            self.logger.debug(f"Message queue size: {self.message_queue.qsize()}")
                
        except Exception as e:
            self.logger.error("Failed to queue message", error=str(e))
    
    async def _async_queue_message(self, message: dict) -> None:
        """
        Async helper to put message in queue.
        """
        try:
            await self.message_queue.put(message)
            self.logger.debug(f"Message queued successfully, queue size: {self.message_queue.qsize()}")
        except Exception as e:
            self.logger.error("Failed to queue message async", error=str(e))
    
    def is_attached(self) -> bool:
        """Check if Frida is currently attached to a process."""
        return self.session is not None and self.attached_pid is not None
    
    def get_attached_pid(self) -> Optional[int]:
        """Get the PID of the currently attached process."""
        return self.attached_pid 