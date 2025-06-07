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
        self.message_queue: asyncio.Queue = asyncio.Queue()
        
        # Security settings
        self.script_cache_dir = Path.home() / ".toweriq" / "scripts"
        self.script_cache_dir.mkdir(parents=True, exist_ok=True)
    
    async def get_message(self) -> dict:
        """
        Get the next message from the Frida script queue.
        
        This method blocks until a message is available.
        
        Returns:
            Message dictionary from the injected script
        """
        return await self.message_queue.get()
    
    async def attach(self, pid: int, device_id: str = None) -> bool:
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
            while not self.message_queue.empty():
                try:
                    self.message_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
            
            self.logger.info("Successfully detached from process")
            
        except Exception as e:
            self.logger.error("Error during detachment", error=str(e))
    
    async def inject_script(self, game_version: str) -> bool:
        """
        Inject the appropriate script for the specified game version.
        
        This method implements the secure script download and verification
        workflow as specified in the security requirements.
        
        Args:
            game_version: Version of the game to inject script for
            
        Returns:
            True if injection was successful, False otherwise
        """
        if not self.session:
            self.logger.error("No active session - cannot inject script")
            return False
        
        self.logger.info("Injecting script", game_version=game_version)
        
        try:
            # Download and verify the script
            script_content = await self._download_and_verify_script(game_version)
            
            # Create and load the script
            self.script = self.session.create_script(script_content)
            self.script.on('message', self._on_message)
            self.script.load()
            
            self.logger.info("Script injected successfully", game_version=game_version)
            return True
            
        except SecurityException as e:
            self.logger.error("Security validation failed", error=str(e))
            return False
        except Exception as e:
            self.logger.error("Error injecting script", game_version=game_version, error=str(e))
            return False
    
    async def _download_and_verify_script(self, game_version: str) -> str:
        """
        Download and verify the script for the specified game version.
        
        This implements the secure hook update workflow:
        1. Fetch remote manifest
        2. Find entry for game version
        3. Download encrypted script
        4. Verify signature of encrypted file
        5. Decrypt file in memory
        6. Verify SHA256 hash of decrypted content
        
        Args:
            game_version: Game version to download script for
            
        Returns:
            Decrypted script content as string
            
        Raises:
            SecurityException: If any security validation fails
        """
        self.logger.info("Downloading and verifying script", game_version=game_version)
        
        try:
            # Step 1: Fetch remote manifest
            manifest = await self._fetch_remote_manifest()
            
            # Step 2: Find entry for game version
            script_info = manifest.get('scripts', {}).get(game_version)
            if not script_info:
                raise SecurityException(f"No script available for game version: {game_version}")
            
            # Step 3: Download encrypted script
            encrypted_content = await self._download_encrypted_script(script_info['url'])
            
            # Step 4: Verify signature of encrypted file
            if not self._verify_signature(encrypted_content, script_info['signature']):
                raise SecurityException("Script signature verification failed")
            
            # Step 5: Decrypt file in memory
            decrypted_content = self._decrypt_script(encrypted_content, script_info['key'])
            
            # Step 6: Verify SHA256 hash of decrypted content
            expected_hash = script_info['hash']
            actual_hash = hashlib.sha256(decrypted_content.encode()).hexdigest()
            
            if actual_hash != expected_hash:
                raise SecurityException(f"Script hash mismatch: expected {expected_hash}, got {actual_hash}")
            
            self.logger.info("Script verification successful", game_version=game_version)
            return decrypted_content
            
        except SecurityException:
            raise
        except Exception as e:
            raise SecurityException(f"Script download/verification failed: {str(e)}")
    
    async def _fetch_remote_manifest(self) -> dict:
        """
        Fetch the remote script manifest.
        
        Note: This is a placeholder implementation. In production,
        this would fetch from a secure CDN or API endpoint.
        """
        # For now, look for a local manifest file
        manifest_path = self.script_cache_dir / "manifest.json"
        
        if not manifest_path.exists():
            # Create a dummy manifest for testing
            dummy_manifest = {
                "version": "1.0",
                "scripts": {
                    "1.0.0": {
                        "url": "https://example.com/scripts/script_1.0.0.enc",
                        "signature": "dummy_signature",
                        "key": "dummy_key",
                        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    }
                }
            }
            
            with open(manifest_path, 'w') as f:
                json.dump(dummy_manifest, f)
        
        with open(manifest_path, 'r') as f:
            return json.load(f)
    
    async def _download_encrypted_script(self, url: str) -> bytes:
        """
        Download the encrypted script from the specified URL.
        
        Note: This is a placeholder implementation.
        """
        # For now, return dummy encrypted content
        return b"dummy_encrypted_content"
    
    def _verify_signature(self, content: bytes, signature: str) -> bool:
        """
        Verify the cryptographic signature of the content.
        
        Note: This is a placeholder implementation.
        """
        # In production, this would use proper cryptographic verification
        return True
    
    def _decrypt_script(self, encrypted_content: bytes, key: str) -> str:
        """
        Decrypt the script content using the provided key.
        
        Note: This is a placeholder implementation.
        """
        # For now, return a basic Frida script
        return """
        console.log("TowerIQ Hook Script Loaded");
        
        // Basic hook example
        Java.perform(function() {
            console.log("Java runtime available");
            
            // Send test message
            send({
                "type": "hook_log",
                "payload": {
                    "event": "script_loaded",
                    "timestamp": Date.now()
                }
            });
        });
        """
    
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
            # Parse the message type
            if message['type'] == 'send':
                payload = message['payload']
                
                # Add metadata
                parsed_message = {
                    'type': payload.get('type', 'unknown'),
                    'payload': payload.get('payload', {}),
                    'timestamp': payload.get('timestamp'),
                    'pid': self.attached_pid
                }
                
                # Put message on async queue (thread-safe)
                self.message_queue.put_nowait(parsed_message)
                
                self.logger.debug("Message received from script", message_type=parsed_message['type'])
                
            elif message['type'] == 'error':
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
                
                self.message_queue.put_nowait(error_message)
                self.logger.error("Script error", error=message.get('description'))
                
        except Exception as e:
            self.logger.error("Error processing message from script", error=str(e))
    
    def is_attached(self) -> bool:
        """Check if Frida is currently attached to a process."""
        return self.session is not None and self.attached_pid is not None
    
    def get_attached_pid(self) -> Optional[int]:
        """Get the PID of the currently attached process."""
        return self.attached_pid 