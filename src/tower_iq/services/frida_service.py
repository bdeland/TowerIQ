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

try:
    import frida
except ImportError:
    frida = None

from ..core.config import ConfigurationManager


class HookContractValidator:
    """
    Validates hook script compatibility with target applications.
    
    This class handles all business logic related to script compatibility
    checking, including loading hook contracts, validating package and
    version compatibility, and verifying script file existence.
    """
    
    def __init__(self, config: ConfigurationManager, logger: Any) -> None:
        """
        Initialize the hook contract validator.
        
        Args:
            config: Configuration manager instance
            logger: Logger instance
        """
        self.logger = logger.bind(source="HookContractValidator")
        self.config = config
    
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


class FridaService:
    """
    Service for managing Frida injection and script communication.
    
    This service handles secure script downloading, injection, and
    message handling between the host application and injected scripts.
    """
    
    def __init__(self, config: ConfigurationManager, logger: Any, loop: asyncio.AbstractEventLoop, session_manager: Optional[Any] = None) -> None:
        """
        Initialize the Frida service.
        
        Args:
            config: Configuration manager instance
            logger: Logger instance
            loop: Asyncio event loop for message handling
            session_manager: Session manager for state tracking (optional)
        """
        self.logger = logger.bind(source="FridaService")
        self.config = config
        self._event_loop = loop
        self._message_queue = asyncio.Queue()
        self._session_manager = session_manager
        
        self.logger.info("FridaService initialized", 
                        event_loop_running=loop.is_running() if loop else False,
                        message_queue_initialized=self._message_queue is not None,
                        session_manager_available=self._session_manager is not None)
        
        # Check if Frida is available
        if frida is None:
            self.logger.warning("Frida not available - install 'frida-tools' package")
        
        # Frida state
        self.device = None
        self.session = None
        self.script = None
        self.attached_pid: Optional[int] = None
        
        # Message handling
        self._shutdown_requested = False  # Flag to signal shutdown to message handling
        
        # Security settings
        self.script_cache_dir = Path.home() / ".toweriq" / "scripts"
        self.script_cache_dir.mkdir(parents=True, exist_ok=True)
    
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
            queue_timeout = self.config.get('frida.timeouts.queue_get', 2.0) if hasattr(self, 'config') else 2.0
            message = await asyncio.wait_for(queue.get(), timeout=queue_timeout)
            
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
    
    async def detach(self, timeout: Optional[float] = None, force_cleanup: bool = False) -> None:
        """
        Detach from the current process and clean up resources with improved timeout handling.
        
        Args:
            timeout: Maximum time to wait for graceful cleanup (default: from config or 3.0 seconds)
            force_cleanup: If True, skip graceful cleanup and force immediate cleanup
        """
        # Use config timeout if not provided
        if timeout is None:
            timeout = self.config.get('frida.timeouts.detach', 3.0) if hasattr(self, 'config') else 3.0
        
        self.logger.info("Detaching from process", timeout=timeout, force_cleanup=force_cleanup)
        
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
        
        cleanup_start_time = asyncio.get_event_loop().time()
        
        try:
            if force_cleanup:
                self.logger.info("Force cleanup requested - skipping graceful shutdown")
                await self._force_cleanup_all_resources()
            else:
                # Try graceful cleanup with timeout
                try:
                    await asyncio.wait_for(
                        self._graceful_cleanup_sequence(),
                        timeout=timeout
                    )
                    self.logger.debug("Graceful cleanup completed successfully")
                except asyncio.TimeoutError:
                    cleanup_elapsed = asyncio.get_event_loop().time() - cleanup_start_time
                    self.logger.warning(f"Graceful cleanup timed out after {cleanup_elapsed:.2f}s - forcing cleanup")
                    await self._force_cleanup_all_resources()
            
            # Final state cleanup regardless of cleanup method
            self._cleanup_internal_state()
            
            cleanup_total_time = asyncio.get_event_loop().time() - cleanup_start_time
            self.logger.info(f"Successfully detached from process in {cleanup_total_time:.2f}s")
            
        except Exception as e:
            cleanup_elapsed = asyncio.get_event_loop().time() - cleanup_start_time
            self.logger.error(f"Error during detachment after {cleanup_elapsed:.2f}s", error=str(e))
            # Ensure cleanup even if there were errors
            await self._force_cleanup_all_resources()
            self._cleanup_internal_state()
    
    async def _graceful_cleanup_sequence(self) -> None:
        """Perform graceful cleanup sequence with proper ordering."""
        # Step 1: Unload script gracefully (stops message generation)
        if self.script:
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self.script.unload), 
                    timeout=1.0
                )
                self.logger.debug("Script unloaded gracefully")
            except asyncio.TimeoutError:
                self.logger.warning("Script unload timed out")
                raise  # Let the outer timeout handler deal with this
            except Exception as e:
                self.logger.warning(f"Error during graceful script unload: {e}")
                raise
            finally:
                self.script = None
        
        # Step 2: Detach from session gracefully
        if self.session:
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self.session.detach), 
                    timeout=1.5
                )
                self.logger.debug("Session detached gracefully")
            except asyncio.TimeoutError:
                self.logger.warning("Session detach timed out")
                raise
            except Exception as e:
                self.logger.warning(f"Error during graceful session detach: {e}")
                raise
            finally:
                self.session = None
    
    async def _force_cleanup_all_resources(self) -> None:
        """Force cleanup of all resources without waiting."""
        self.logger.debug("Starting forced cleanup of all resources")
        
        # Force script cleanup
        if self.script:
            try:
                # Try to unload without timeout
                await asyncio.to_thread(self.script.unload)
                self.logger.debug("Script force-unloaded successfully")
            except Exception as e:
                self.logger.debug(f"Error during forced script cleanup: {e}")
            finally:
                self.script = None
        
        # Update session manager with script deactivation
        if self._session_manager:
            try:
                self._session_manager.set_script_inactive()
                self.logger.debug("Updated session manager with script deactivation")
            except Exception as e:
                self.logger.error("Failed to update session manager with script deactivation", error=str(e))
        
        # Force session cleanup
        if self.session:
            try:
                # Try to detach without timeout
                await asyncio.to_thread(self.session.detach)
                self.logger.debug("Session force-detached successfully")
            except Exception as e:
                self.logger.debug(f"Error during forced session cleanup: {e}")
            finally:
                self.session = None
        
        self.logger.debug("Forced cleanup completed")
    
    def _cleanup_internal_state(self) -> None:
        """Clean up internal state variables."""
        self.device = None
        self.session = None
        self.script = None
        self.attached_pid = None
        
        # Clear any remaining messages from queue
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
        
        self.logger.debug("Internal state cleanup completed")
    
    async def inject_script(self, script_content: str) -> bool:
        """
        Inject the provided script content into the attached process.
        
        This method takes script content directly and creates a script
        from it. All file reading and YAML parsing should be done before
        calling this method.
        
        Args:
            script_content: The script content to inject
            
        Returns:
            True if injection was successful, False otherwise
        """
        if not self.session:
            self.logger.error("No active session - cannot inject script")
            return False
        
        self.logger.info("Injecting script content")
        
        try:
            # Create and load the script
            self.script = self.session.create_script(script_content)
            self.script.on('message', self._on_message)
            self.script.load()
            
            self.logger.info("Script injected successfully")
            
            # Add a small delay to allow script to initialize
            await asyncio.sleep(0.5)
            
            # Log script details for debugging
            script_lines = script_content.split('\n')
            script_name = "Unknown"
            if "TOWERIQ_HOOK_METADATA" in script_content:
                for line in script_lines:
                    if '"scriptName"' in line:
                        try:
                            script_name = line.split('"scriptName"')[1].split('"')[1]
                            break
                        except (IndexError, ValueError):
                            pass
            
            self.logger.info("Script injection details", 
                           script_name=script_name,
                           script_lines=len(script_lines),
                           attached_pid=self.attached_pid)
            
            # Update session manager with script activation
            if self._session_manager:
                try:
                    # Try to extract script name from content (look for TOWERIQ_HOOK_METADATA)
                    script_name = "Unknown Script"
                    if "TOWERIQ_HOOK_METADATA" in script_content:
                        # Simple extraction of script name from metadata
                        lines = script_content.split('\n')
                        for i, line in enumerate(lines):
                            if '"scriptName"' in line:
                                # Extract the script name from the JSON-like structure
                                try:
                                    script_name = line.split('"scriptName"')[1].split('"')[1]
                                    break
                                except (IndexError, ValueError):
                                    pass
                    
                    self._session_manager.set_script_active(script_name)
                    self.logger.debug("Updated session manager with script activation", script_name=script_name)
                except Exception as e:
                    self.logger.error("Failed to update session manager with script activation", error=str(e))
            
            return True
            
        except Exception as e:
            self.logger.error("Error injecting script", error=str(e))
            return False
    
    async def inject_and_run_script(self, device_id: str, pid: int, script_content: str) -> bool:
        """
        Complete workflow to attach to process and inject script.
        
        Args:
            device_id: Device serial ID
            pid: Process ID to attach to
            script_content: Script content to inject
            
        Returns:
            True if successful, False otherwise
        """
        self.logger.info("Starting inject and run workflow", 
                        device_id=device_id, 
                        pid=pid)
        
        try:
            # First attach to the process
            if not await self.attach(pid, device_id):
                self.logger.error("Failed to attach to process")
                return False
            
            # Then inject the script
            if not await self.inject_script(script_content):
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
            self.logger.info(f"_on_message received: {message}")
            self.logger.info(f"Message type: {message.get('type')}, Payload keys: {list(message.get('payload', {}).keys()) if isinstance(message.get('payload'), dict) else 'not_dict'}")
            
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
                    # Extract timestamp from nested payload if available
                    inner_payload = payload.get('payload', {})
                    timestamp = inner_payload.get('timestamp') if isinstance(inner_payload, dict) else payload.get('timestamp')
                    
                    parsed_message = {
                        'type': payload.get('type', 'unknown'),
                        'payload': payload.get('payload', {}),
                        'timestamp': timestamp,
                        'pid': self.attached_pid
                    }
                    
                    self.logger.debug(f"Parsed message: {parsed_message}")
                    
                    # Handle heartbeat messages immediately if session manager is available
                    if (self._session_manager and 
                        parsed_message.get('type') == 'hook_log' and 
                        parsed_message.get('payload', {}).get('event') == 'frida_heartbeat'):
                        
                        payload = parsed_message.get('payload', {})
                        is_game_reachable = payload.get('isGameReachable', False)
                        
                        # Update session manager with heartbeat
                        try:
                            self._session_manager.update_script_heartbeat(is_game_reachable)
                            self.logger.debug("Updated script heartbeat", is_game_reachable=is_game_reachable)
                        except Exception as e:
                            self.logger.error("Failed to update script heartbeat", error=str(e))
                    
                    # Put message on async queue - use thread-safe approach
                    self.logger.info("Queueing message for async processing", message_type=parsed_message['type'])
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
            self.logger.error("Failed to queue message", error=str(e), message_type=message.get('type') if isinstance(message, dict) else 'unknown')
    

    
    def is_attached(self) -> bool:
        """Check if Frida is currently attached to a process."""
        return self.session is not None and self.attached_pid is not None
    
    def get_attached_pid(self) -> Optional[int]:
        """Get the PID of the currently attached process."""
        return self.attached_pid
    
    def is_ready_for_connection(self) -> bool:
        """
        Check if the service is ready for a new connection.
        
        Returns:
            True if the service is ready for connection, False otherwise
        """
        # Check if Frida is available
        if frida is None:
            self.logger.error("Frida not available - cannot establish connection")
            return False
        
        # Check if service is in clean state (not attached)
        if self.is_attached():
            self.logger.error("Service already attached to a process - not ready for new connection")
            return False
        
        # Check if shutdown is not requested
        if self._shutdown_requested:
            self.logger.error("Service shutdown requested - not ready for new connection")
            return False
        
        # Check if event loop is set (required for message handling)
        if self._event_loop is None:
            self.logger.error("Event loop not set - not ready for connection")
            return False
        
        # Check if message queue is available
        if self._message_queue is None:
            self.logger.error("Message queue not initialized - not ready for connection")
            return False
        
        self.logger.debug("FridaService is ready for connection")
        return True
    
    def get_service_state(self) -> dict:
        """
        Get detailed service state information for diagnostics.
        
        Returns:
            Dictionary containing service state information
        """
        return {
            "frida_available": frida is not None,
            "is_attached": self.is_attached(),
            "attached_pid": self.attached_pid,
            "shutdown_requested": self._shutdown_requested,
            "event_loop_set": self._event_loop is not None,
            "message_queue_initialized": self._message_queue is not None,
            "message_queue_size": self.queue_size,
            "device_connected": self.device is not None,
            "session_active": self.session is not None,
            "script_loaded": self.script is not None
        }
    
    def validate_service_health(self) -> tuple[bool, list[str]]:
        """
        Validate the health of the Frida service.
        
        Returns:
            Tuple of (is_healthy, list_of_issues)
        """
        issues = []
        
        # Check if Frida is available
        if frida is None:
            issues.append("Frida library not available")
        
        # Check if we have a valid session
        if self.session is None:
            issues.append("No active Frida session")
        
        # Check if we have a valid script
        if self.script is None:
            issues.append("No active Frida script")
        
        # Check if we have a valid device
        if self.device is None:
            issues.append("No active Frida device")
        
        return len(issues) == 0, issues

    def check_local_hook_compatibility(self, package_name: str, game_version: str) -> bool:
        """
        Check if the local hook script is compatible with the selected package and game version.
        
        This method delegates to HookContractValidator to check compatibility.
        
        Args:
            package_name: Package name of the game to check compatibility for
            game_version: Version of the game to check compatibility for
            
        Returns:
            True if the local hook is compatible and the script file exists, False otherwise
        """
        validator = HookContractValidator(self.config, self.logger)
        return validator.check_local_hook_compatibility(package_name, game_version) 