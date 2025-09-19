"""
TowerIQ Frida Service

This module provides the FridaService class for managing Frida injection,
script loading, and secure communication with injected scripts.
"""

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

import aiohttp

try:
    import frida
except ImportError:
    frida = None

from ..core.config import ConfigurationManager
from .hook_script_manager import HookScriptManager


class HookContractValidator:  # Deprecated placeholder for backward compatibility
    """
    Deprecated: The YAML hook contract has been removed in favor of
    metadata embedded in hook scripts. This class remains as a no-op
    to avoid import errors in legacy references.
    """
    def __init__(self, config: ConfigurationManager, logger: Any) -> None:
        self.logger = logger.bind(source="HookContractValidator")
        self.config = config
    def check_local_hook_compatibility(self, package_name: str, game_version: str) -> bool:
        self.logger.warning(
            "HookContractValidator is deprecated; using script metadata for compatibility checks instead"
        )
        project_root = self.config.get_project_root()
        hooks_dir = Path(project_root) / 'src' / 'tower_iq' / 'scripts'
        manager = HookScriptManager(str(hooks_dir))
        manager.discover_scripts()
        compatible = manager.get_compatible_scripts(package_name, game_version)
        for meta in compatible:
            file_name = meta.get('fileName', '')
            if file_name and (hooks_dir / file_name).exists():
                return True
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
        
        # Frida state is maintained in SessionManager
        
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
    
    async def get_message(self) -> Optional[dict]:
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
        except (asyncio.TimeoutError, TimeoutError):
            # Timeout is normal; return None so callers can continue looping calmly
            if self._shutdown_requested:
                raise RuntimeError("Shutdown requested during message wait")
            return None
        except asyncio.CancelledError:
            # Translate cancellation into a controlled shutdown signal
            self.logger.debug("get_message cancelled; treating as shutdown request")
            raise RuntimeError("Shutdown requested via task cancellation")
        except Exception as e:
            self.logger.debug(f"Error getting message from queue: {e}, queue size: {queue.qsize()}")
            raise
        except BaseException as e:
            # As a last resort, treat any base-level cancellation/timeout as non-fatal unless shutting down
            if self._shutdown_requested:
                raise RuntimeError("Shutdown requested during message wait")
            try:
                self.logger.debug(f"BaseException in get_message: {type(e).__name__}: {e}")
            except Exception:
                pass
            return None
    
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
            # Reset shutdown state so message processing can resume after a previous detach
            self._shutdown_requested = False
            # Ensure the message queue is available and clear any leftover messages (including poison pill)
            if self._message_queue is None:
                self._message_queue = asyncio.Queue()
            else:
                try:
                    cleared_count = 0
                    while not self._message_queue.empty():
                        self._message_queue.get_nowait()
                        cleared_count += 1
                    if cleared_count:
                        self.logger.debug(f"Cleared {cleared_count} stale messages from queue before attach")
                except Exception:
                    # Non-fatal; continue
                    pass

            # Get the device
            device = frida.get_device(device_id) if device_id else frida.get_local_device()
            
            # Attach to the process
            session = device.attach(pid, realm='emulated')
            
            # Store in session manager
            if self._session_manager:
                try:
                    self._session_manager.frida_device = device
                    self._session_manager.frida_session = session
                    self._session_manager.frida_script = None
                    self._session_manager.frida_attached_pid = pid
                except Exception as e:
                    self.logger.error("Failed to update SessionManager with frida attach state", error=str(e))
            
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
        script = self._session_manager.frida_script if self._session_manager else None
        if script:
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(script.unload), 
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
                if self._session_manager:
                    self._session_manager.frida_script = None
        
        # Step 2: Detach from session gracefully
        session = self._session_manager.frida_session if self._session_manager else None
        if session:
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(session.detach), 
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
                if self._session_manager:
                    self._session_manager.frida_session = None
    
    async def _force_cleanup_all_resources(self) -> None:
        """Force cleanup of all resources without waiting."""
        self.logger.debug("Starting forced cleanup of all resources")
        
        # Force script cleanup
        script = self._session_manager.frida_script if self._session_manager else None
        if script:
            try:
                # Try to unload without timeout
                await asyncio.to_thread(script.unload)
                self.logger.debug("Script force-unloaded successfully")
            except Exception as e:
                self.logger.debug(f"Error during forced script cleanup: {e}")
            finally:
                if self._session_manager:
                    self._session_manager.frida_script = None
        
        # Update session manager with script deactivation
        if self._session_manager:
            try:
                self._session_manager.set_script_inactive()
                self.logger.debug("Updated session manager with script deactivation")
            except Exception as e:
                self.logger.error("Failed to update session manager with script deactivation", error=str(e))
        
        # Force session cleanup
        session = self._session_manager.frida_session if self._session_manager else None
        if session:
            try:
                # Try to detach without timeout
                await asyncio.to_thread(session.detach)
                self.logger.debug("Session force-detached successfully")
            except Exception as e:
                self.logger.debug(f"Error during forced session cleanup: {e}")
            finally:
                if self._session_manager:
                    self._session_manager.frida_session = None
        
        self.logger.debug("Forced cleanup completed")
    
    def _cleanup_internal_state(self) -> None:
        """Clean up internal state variables."""
        # Frida state is owned by SessionManager; nothing to clear here
        
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
        session = self._session_manager.frida_session if self._session_manager else None
        if not session:
            self.logger.error("No active session - cannot inject script")
            return False
        
        self.logger.info("Injecting script content")
        
        try:
            # Create and load the script via Frida API without any sanitization
            script = session.create_script(script_content)
            script.on('message', self._on_message)
            script.load()
            if self._session_manager:
                try:
                    self._session_manager.frida_script = script
                except Exception as e:
                    self.logger.error("Failed to store script in SessionManager", error=str(e))
            
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
                           attached_pid=(self._session_manager.frida_attached_pid if self._session_manager else None))
            
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
        Attach to the process and inject the script using the Frida API only.
        """
        self.logger.info("Starting inject and run (Frida API only)", device_id=device_id, pid=pid)
        try:
            if not await self.attach(pid, device_id):
                self.logger.error("Attach failed")
                return False
            if not await self.inject_script(script_content):
                self.logger.error("Script injection failed")
                await self.detach()
                return False
            self.logger.info("Inject and run completed successfully")
            return True
        except Exception as e:
            self.logger.error("Error in inject and run", error=str(e))
            try:
                await self.detach()
            except Exception:
                pass
            return False
    
    def _log_clean_message(self, message: dict) -> None:
        """
        Log Frida messages in a clean, readable format.
        
        Args:
            message: Message dictionary from Frida
        """
        if message.get('type') != 'send':
            return
            
        payload = message.get('payload', {})
        msg_type = payload.get('type', 'unknown')
        inner_payload = payload.get('payload', {})
        
        # Handle different message types with clean formatting
        if msg_type == 'hook_log':
            event = inner_payload.get('event', '')
            msg_text = inner_payload.get('message', '')
            level = inner_payload.get('level', 'INFO')
            
            # Skip heartbeats - they're handled by the console renderer
            if 'frida_heartbeat' in event or 'Frida script is alive' in msg_text:
                return
                
            # Clean up common log messages
            if 'Hook on' in msg_text and 'is live' in msg_text:
                hook_name = msg_text.replace('Hook on ', '').replace(' is live.', '')
                self.logger.info(f"🎣 Hook active: {hook_name}")
            elif 'Il2Cpp Bridge is ready' in msg_text:
                self.logger.info("🌉 Il2Cpp Bridge ready")
            elif 'Handshake receiver is active' in msg_text:
                self.logger.info("🤝 Handshake receiver active")
            else:
                self.logger.info(f"📋 {msg_text}")
                
        elif msg_type == 'game_event':
            event_name = inner_payload.get('event', 'unknown')
            if event_name == 'startNewRound':
                run_id = inner_payload.get('runId', 'unknown')[:8]  # Short ID
                seed = inner_payload.get('seed', 'unknown')
                tier = inner_payload.get('tier', 'unknown')
                self.logger.info(f"🎮 New round started (ID: {run_id}, Seed: {seed}, Tier: {tier})")
            elif event_name == 'gameOver':
                coins = inner_payload.get('coinsEarned', 0)
                self.logger.info(f"💀 Game over (Coins earned: {coins})")
            elif event_name == 'gamePaused':
                self.logger.info("⏸️ Game paused")
            elif event_name == 'gameResumed':
                self.logger.info("▶️ Game resumed")
            elif event_name == 'gameSpeedChanged':
                speed = inner_payload.get('value', 'unknown')
                self.logger.info(f"⚡ Game speed: {speed}x")
            else:
                self.logger.info(f"🎯 Game event: {event_name}")
                
        elif msg_type == 'game_metric':
            metrics = inner_payload.get('metrics', {})
            if metrics:
                # Format metrics in a clean, readable way
                metric_lines = []
                for key, value in metrics.items():
                    if isinstance(value, (int, float)) and value != 0:
                        # Clean up metric names
                        clean_key = key.replace('_', ' ').title()
                        metric_lines.append(f"  {clean_key}: {value}")
                
                if metric_lines:
                    self.logger.info("📊 Game metrics:")
                    for line in metric_lines[:8]:  # Limit to 8 most important metrics
                        self.logger.info(line)
                    if len(metric_lines) > 8:
                        self.logger.info(f"  ... and {len(metric_lines) - 8} more")
        else:
            # For unknown message types, just log the type
            self.logger.debug(f"📡 Frida message: {msg_type}")

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
            # Clean message logging - only show what's useful for debugging
            self._log_clean_message(message)
            
            # Parse the message type
            if message['type'] == 'send':
                payload = message['payload']
                
                # Support for bulk messages: if payload is a list, queue each one
                if isinstance(payload, list):
                    for item in payload:
                        parsed_message = {
                            'type': item.get('type', 'unknown'),
                            'payload': item.get('payload', {}),
                            'timestamp': item.get('timestamp'),
                            'pid': (self._session_manager.frida_attached_pid if self._session_manager else None)
                        }
                        self._queue_message_safely(parsed_message)
                else:
                    # Add metadata
                    # Extract timestamp from nested payload if available
                    inner_payload = payload.get('payload', {})
                    timestamp = inner_payload.get('timestamp') if isinstance(inner_payload, dict) else payload.get('timestamp')
                    
                    parsed_message = {
                        'type': payload.get('type', 'unknown'),
                        'payload': payload.get('payload', {}),
                        'timestamp': timestamp,
                        'pid': (self._session_manager.frida_attached_pid if self._session_manager else None)
                    }
                    
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
                    self._queue_message_safely(parsed_message)
                
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
                    'pid': (self._session_manager.frida_attached_pid if self._session_manager else None)
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
        if not self._session_manager:
            return False
        return self._session_manager.frida_session is not None and self._session_manager.frida_attached_pid is not None
    
    def get_attached_pid(self) -> Optional[int]:
        """Get the PID of the currently attached process."""
        if not self._session_manager:
            return None
        return self._session_manager.frida_attached_pid
    
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
            "attached_pid": (self._session_manager.frida_attached_pid if self._session_manager else None),
            "shutdown_requested": self._shutdown_requested,
            "event_loop_set": self._event_loop is not None,
            "message_queue_initialized": self._message_queue is not None,
            "message_queue_size": self.queue_size,
            "device_connected": (self._session_manager.frida_device is not None if self._session_manager else False),
            "session_active": (self._session_manager.frida_session is not None if self._session_manager else False),
            "script_loaded": (self._session_manager.frida_script is not None if self._session_manager else False)
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
        if not self._session_manager or self._session_manager.frida_session is None:
            issues.append("No active Frida session")
        
        # Check if we have a valid script
        if not self._session_manager or self._session_manager.frida_script is None:
            issues.append("No active Frida script")
        
        # Check if we have a valid device
        if not self._session_manager or self._session_manager.frida_device is None:
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