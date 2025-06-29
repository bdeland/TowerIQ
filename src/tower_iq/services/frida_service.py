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
        
        # Message handling
        self._message_queue: Optional[asyncio.Queue] = None
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None
        self._shutdown_requested = False  # Flag to signal shutdown to message handling
        
        # Security settings
        self.script_cache_dir = Path.home() / ".toweriq" / "scripts"
        self.script_cache_dir.mkdir(parents=True, exist_ok=True)
    
    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """
        Set the event loop for message handling and create the message queue.
        Should be called from the main thread before injecting scripts.
        """
        self._event_loop = loop
        # Create the message queue here to ensure it's bound to the correct loop
        if self._message_queue is None:
            self._message_queue = asyncio.Queue()
            self.logger.info("Frida message queue created in the correct event loop")
        self.logger.info("Event loop set for Frida message handling")
    
    @property
    def queue_size(self) -> int:
        """Get the current size of the message queue."""
        if self._message_queue:
            return self._message_queue.qsize()
        return 0
    
    async def get_message(self) -> dict:
        """
        Get the next message from the Frida script queue.
        
        This method blocks until a message is available or shutdown is requested.
        
        Returns:
            Message dictionary from the injected script
            
        Raises:
            RuntimeError: If shutdown was requested or queue not initialized
        """
        if self._message_queue is None:
            self.logger.error("Message queue not initialized.")
            raise RuntimeError("Message queue not initialized.")
        
        # Check for shutdown before blocking
        if self._shutdown_requested:
            raise RuntimeError("Shutdown requested - no more messages will be processed")
            
        # Add debugging to understand queue state
        queue = self._message_queue
        queue_size = queue.qsize()
        self.logger.debug(f"get_message called, queue size: {queue_size}, queue id: {id(queue)}")
        
        try:
            # Use asyncio.wait_for with a shorter timeout to check shutdown flag more frequently
            message = await asyncio.wait_for(queue.get(), timeout=2.0)
            
            # Check for poison pill (shutdown signal)
            if isinstance(message, dict) and message.get('type') == '_shutdown_signal':
                self.logger.debug("Received shutdown signal in message queue")
                raise RuntimeError("Shutdown requested via poison pill")
            
            self.logger.debug(f"Successfully got message from queue, new size: {queue.qsize()}")
            return message
        except asyncio.TimeoutError:
            # Check shutdown flag on timeout
            if self._shutdown_requested:
                raise RuntimeError("Shutdown requested during message wait")
            # Re-raise timeout for the caller to handle
            raise
        except Exception as e:
            self.logger.debug(f"Error getting message from queue: {e}, queue size: {queue.qsize()}")
            raise
    
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
            self.session = self.device.attach(pid, realm='emulated')
            self.attached_pid = pid
            
            self.logger.info("Successfully attached to process with emulated realm", pid=pid)
            return True
            
        except Exception as e:
            self.logger.error("Error attaching to process", pid=pid, error=str(e))
            return False
    
    async def detach(self) -> None:
        """Detach from the current process and clean up resources."""
        self.logger.info("Detaching from process")
        
        # Set shutdown flag to prevent new message processing
        self._shutdown_requested = True
        
        # Send poison pill to unblock any waiting get_message() calls
        if self._message_queue is not None:
            try:
                self._message_queue.put_nowait({'type': '_shutdown_signal'})
                self.logger.debug("Sent shutdown signal to message queue")
            except asyncio.QueueFull:
                # If queue is full, that's fine - the poison pill will be processed eventually
                self.logger.debug("Message queue full, poison pill may be delayed")
        
        try:
            # Forcefully unload script first - this stops message generation
            if self.script:
                try:
                    # Give the script a moment to clean up gracefully
                    await asyncio.wait_for(
                        asyncio.to_thread(self.script.unload), 
                        timeout=0.5
                    )
                    self.logger.debug("Script unloaded gracefully")
                except asyncio.TimeoutError:
                    self.logger.warning("Script unload timed out - forcing cleanup")
                    # Force cleanup without waiting
                    try:
                        self.script.unload()
                    except Exception as e:
                        self.logger.debug(f"Error during forced script unload: {e}")
                except Exception as e:
                    self.logger.warning(f"Error during script unload: {e}")
                finally:
                    self.script = None
            
            # Detach from session
            if self.session:
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(self.session.detach), 
                        timeout=1.0
                    )
                    self.logger.debug("Session detached gracefully")
                except asyncio.TimeoutError:
                    self.logger.warning("Session detach timed out - forcing cleanup")
                    # Force cleanup without waiting
                    try:
                        self.session.detach()
                    except Exception as e:
                        self.logger.debug(f"Error during forced session detach: {e}")
                except Exception as e:
                    self.logger.warning(f"Error during session detach: {e}")
                finally:
                    self.session = None
            
            self.device = None
            self.attached_pid = None
            
            # Clear any remaining messages
            if self._message_queue is not None:
                cleared_count = 0
                while not self._message_queue.empty():
                    try:
                        self._message_queue.get_nowait()
                        cleared_count += 1
                    except asyncio.QueueEmpty:
                        break
                if cleared_count > 0:
                    self.logger.debug(f"Cleared {cleared_count} remaining messages from queue")
            
            self.logger.info("Successfully detached from process")
            
        except Exception as e:
            self.logger.error("Error during detachment", error=str(e))
            # Ensure cleanup even if there were errors
            self.script = None
            self.session = None
            self.device = None
            self.attached_pid = None
    
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
        
        This method orchestrates the compatibility checking process by:
        1. Loading the hook contract configuration
        2. Checking package name compatibility
        3. Checking version compatibility
        4. Verifying the script file exists
        
        Args:
            package_name: Package name of the game to check compatibility for
            game_version: Version of the game to check compatibility for
            
        Returns:
            True if the local hook is compatible and the script file exists, False otherwise
        """
        self.logger.info("Validating hook script compatibility with selected package and version", 
                        selected_package_name=package_name, 
                        selected_package_version=game_version)
        
        try:
            # Load the hook contract
            contract = self._load_hook_contract()
            if not contract:
                return False
            
            # Check all compatibility requirements
            if not self._check_script_file_exists(contract):
                return False
            
            if not self._check_package_and_version_compatibility(package_name, game_version, contract):
                return False
            
            # All checks passed - log with script path for confirmation
            script_info = contract.get('script_info', {})
            script_path = script_info.get('path', '')
            project_root = self.config.get_project_root()
            full_script_path = Path(project_root) / script_path
            
            self.logger.info("Local hook compatibility confirmed", 
                           package_name=package_name,
                           game_version=game_version,
                           script_path=str(full_script_path))
            return True
            
        except Exception as e:
            self.logger.error("Error checking local hook compatibility", 
                            package_name=package_name,
                            game_version=game_version, 
                            error=str(e))
            return False

    def _load_hook_contract(self) -> Optional[dict]:
        """
        Load and parse the hook contract YAML file.
        
        Returns:
            Parsed contract dictionary, or None if loading failed
        """
        self.logger.debug("Loading hook contract")
        try:
            # Get the path to the hook contract from configuration
            contract_path = self.config.get("frida.hook_contract_path")
            if not contract_path:
                self.logger.error("Hook contract path not configured", contract_path=contract_path)
                return None
            else:
                self.logger.debug("Hook contract path configured", contract_path=contract_path)
            
            # Build full path relative to project root
            project_root = self.config.get_project_root()
            self.logger.debug("Project root", project_root=project_root)
            full_contract_path = Path(project_root) / contract_path
            self.logger.debug("Full hook contract path", full_contract_path=full_contract_path)
            # Load and parse the YAML file
            with open(full_contract_path, 'r', encoding='utf-8') as f:
                contract = yaml.safe_load(f)
            self.logger.debug("Hook contract loaded", contract=contract)
            return contract
            
        except FileNotFoundError:
            self.logger.error("Hook contract file not found", path=contract_path, full_contract_path=full_contract_path)
            return None
        except yaml.YAMLError as e:
            self.logger.error("Error parsing hook contract YAML", error=str(e), full_contract_path=full_contract_path)
            return None

    def _check_package_and_version_compatibility(self, package_name: str, package_version: str, contract: dict) -> bool:
        """
        Check if the package name and version are compatible with the hook contract.
        
        This method validates all compatibility requirements in one block:
        - Hook contract must define target_package
        - Hook contract must define supported_versions
        - Package name must match target_package
        - Package version must be in supported_versions list
        
        Args:
            package_name: Package name to check
            package_version: Package version to check
            contract: Full hook contract dictionary
            
        Returns:
            True if both package and version are compatible, False otherwise
        """
        self.logger.debug("Checking package and version compatibility", 
                         package_name=package_name, 
                         package_version=package_version, 
                         contract_keys=list(contract.keys()) if isinstance(contract, dict) else None)
        
        try:
            # Validate input parameters
            if not isinstance(contract, dict):
                self.logger.error("Invalid contract parameter: must be a dictionary",
                                current_type=type(contract).__name__,
                                expected_type="dict")
                return False
            
            if not package_name or not isinstance(package_name, str):
                self.logger.error("Invalid package_name parameter: must be a non-empty string",
                                current_value=package_name,
                                current_type=type(package_name).__name__)
                return False
            
            if not package_version or not isinstance(package_version, str):
                self.logger.error("Invalid package_version parameter: must be a non-empty string",
                                current_value=package_version,
                                current_type=type(package_version).__name__)
                return False
            
            # Extract script info from contract
            script_info = contract.get('script_info', {})
            if not isinstance(script_info, dict):
                self.logger.error("script_info section missing or invalid in hook contract",
                                current_type=type(script_info).__name__,
                                expected_type="dict")
                return False
            
            # Extract contract requirements
            target_package = script_info.get('target_package')
            supported_versions = script_info.get('supported_versions')
            
            # Validate all compatibility requirements in one block
            # Check if target_package is defined in the contract
            if not target_package:
                self.logger.error("Target package not defined in hook contract",
                                contract_section="script_info",
                                missing_field="target_package",
                                action_required="Update hook contract to specify target_package")
                return False
            
            # Check if supported_versions is defined in the contract
            if not supported_versions:
                self.logger.error("Supported package versions not defined in hook contract",
                                contract_section="script_info", 
                                missing_field="supported_versions",
                                action_required="Update hook contract to specify supported_versions list")
                return False
            
            # Check if supported_versions is a list
            if not isinstance(supported_versions, list):
                self.logger.error("supported_versions in hook contractmust be a list",
                                contract_section="script_info",
                                current_type=type(supported_versions).__name__,
                                expected_type="list",
                                action_required="Update hook contract to make supported_versions a list")
                return False
            
            # Check if package name matches target_package
            if package_name != target_package:
                self.logger.error("Package mismatch: wrong package targeted for hook contract",
                                detected_package=package_name,
                                target_package=target_package,
                                action_required="Either select correct package or update hook contract target_package")
                return False
            
            # Check if package version is in supported_versions
            if package_version not in supported_versions:
                self.logger.error("Version mismatch: package version not supported by hook contract",
                                detected_version=package_version,
                                supported_versions=supported_versions,
                                action_required="Either select supported version or update hook contract supported_versions")
                return False
            
            # All compatibility checks passed
            self.logger.debug("Package and version compatibility confirmed", 
                             package_name=package_name,
                             package_version=package_version,
                             target_package=target_package,
                             supported_versions=supported_versions)
            return True
            
        except TypeError as e:
            self.logger.error("Type error during compatibility check",
                            error=str(e),
                            package_name=package_name,
                            package_version=package_version,
                            script_info_type=type(script_info).__name__)
            return False
        except AttributeError as e:
            self.logger.error("Attribute error during compatibility check",
                            error=str(e),
                            package_name=package_name,
                            package_version=package_version)
            return False
        except Exception as e:
            self.logger.error("Unexpected error during compatibility check",
                            error=str(e),
                            error_type=type(e).__name__,
                            package_name=package_name,
                            package_version=package_version)
            return False

    def _check_script_file_exists(self, contract: dict) -> bool:
        """
        Check if the hook script file actually exists at the specified path.
        
        Args:
            contract: Full hook contract dictionary
            
        Returns:
            True if script file exists, False otherwise
        """
        try:
            # Validate contract parameter
            if not isinstance(contract, dict):
                self.logger.error("Invalid contract parameter: must be a dictionary",
                                current_type=type(contract).__name__,
                                expected_type="dict")
                return False
            
            # Extract script info from contract
            script_info = contract.get('script_info', {})
            if not isinstance(script_info, dict):
                self.logger.error("script_info section missing or invalid in hook contract",
                                current_type=type(script_info).__name__,
                                expected_type="dict")
                return False
            
            script_path = script_info.get('path')
            if not script_path:
                self.logger.error("Script path not specified in hook contract",
                                contract_section="script_info",
                                missing_field="path")
                return False
            
            # Resolve script path relative to the project root
            project_root = self.config.get_project_root()
            full_script_path = Path(project_root) / script_path
            
            if not full_script_path.exists():
                self.logger.error("Hook script file not found", 
                                path=str(full_script_path),
                                action_required="Ensure hook script file exists at specified path")
                return False
            
            self.logger.debug("Hook script file exists", path=str(full_script_path))
            return True
            
        except Exception as e:
            self.logger.error("Error checking script file existence",
                            error=str(e),
                            error_type=type(e).__name__)
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
                
                # Support for bulk messages: if payload is a list, queue each one
                if isinstance(payload, list):
                    for item in payload:
                        parsed_message = {
                            'type': item.get('type', 'unknown'),
                            'payload': item.get('payload', {}),
                            'timestamp': item.get('timestamp'),
                            'pid': self.attached_pid
                        }
                        self.logger.debug(f"Parsed bulk message: {parsed_message}")
                        self._queue_message_safely(parsed_message)
                        self.logger.debug("Bulk message received from script", message_type=parsed_message['type'])
                else:
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
        if self._message_queue is None:
            self.logger.error("Cannot queue message: queue not initialized.")
            return
            
        try:
            if self._event_loop is not None and not self._event_loop.is_closed():
                # Schedule the put operation on the correct event loop from this thread
                if self._event_loop.is_running():
                    # Use call_soon_threadsafe to directly schedule put_nowait
                    # This avoids the overhead and race condition of creating async tasks
                    self._event_loop.call_soon_threadsafe(
                        self._message_queue.put_nowait, message
                    )
                    self.logger.debug(f"Message scheduled via call_soon_threadsafe, queue id: {id(self._message_queue)}")
                else:
                    self.logger.debug("Event loop not running, queuing directly")
                    self._message_queue.put_nowait(message)
            else:
                self.logger.debug("No event loop available, attempting direct queue")
                # Fallback to direct queuing
                self._message_queue.put_nowait(message)
                
            self.logger.debug(f"Message queue size: {self._message_queue.qsize()}")
                
        except Exception as e:
            self.logger.error("Failed to queue message", error=str(e))
    

    
    def is_attached(self) -> bool:
        """Check if Frida is currently attached to a process."""
        return self.session is not None and self.attached_pid is not None
    
    def get_attached_pid(self) -> Optional[int]:
        """Get the PID of the currently attached process."""
        return self.attached_pid
    
    def reset_shutdown_state(self) -> None:
        """Reset the shutdown state - useful if the service needs to be reused."""
        self._shutdown_requested = False
        self.logger.debug("Frida service shutdown state reset") 