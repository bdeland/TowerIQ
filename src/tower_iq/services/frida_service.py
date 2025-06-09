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
    
    async def check_hook_compatibility(self, game_version: str) -> bool:
        """
        Check if a valid, signed hook script exists for the selected game version.
        
        This method fetches the remote manifest and checks if an entry exists
        for the provided game version. It does not download anything, just confirms
        if a known hook is available.
        
        Args:
            game_version: Version of the game to check compatibility for
            
        Returns:
            True if a compatible hook exists, False otherwise
        """
        self.logger.info("Checking hook compatibility", game_version=game_version)
        
        try:
            # Call remote manifest fetch
            manifest = await self._fetch_remote_manifest()
            
            # Check if the manifest dictionary and the manifest['hooks'] list exist
            if not isinstance(manifest, dict):
                self.logger.error("Invalid manifest format")
                return False
            
            hooks = manifest.get('hooks')
            if not isinstance(hooks, list):
                self.logger.error("Invalid hooks section in manifest")
                return False
            
            # Iterate through the hooks list and check if any dictionary has a 'game_version' key that matches
            for hook in hooks:
                if isinstance(hook, dict) and hook.get('game_version') == game_version:
                    self.logger.info("Hook compatibility confirmed", 
                                   game_version=game_version)
                    return True
            
            self.logger.warning("No compatible hook found", game_version=game_version)
            return False
            
        except Exception as e:
            self.logger.error("Error checking hook compatibility", 
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
            if not await self._verify_signature(encrypted_content, script_info['signature']):
                raise SecurityException("Script signature verification failed")
            
            # Step 5: Decrypt file in memory
            decrypted_content = self._decrypt_script(encrypted_content)
            
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
        
        Returns:
            Dictionary representing the remote manifest
            
        Raises:
            aiohttp.ClientError: If network request fails
            json.JSONDecodeError: If response is not valid JSON
        """
        manifest_url = self.config.get("frida.manifest_url")
        if not manifest_url:
            raise SecurityException("Manifest URL not configured")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(manifest_url) as response:
                    response.raise_for_status()  # Raise exception for HTTP errors
                    return await response.json()
        except aiohttp.ClientError as e:
            self.logger.error("Failed to fetch remote manifest", url=manifest_url, error=str(e))
            raise
        except json.JSONDecodeError as e:
            self.logger.error("Invalid JSON in remote manifest", url=manifest_url, error=str(e))
            raise
    
    async def _download_encrypted_script(self, url: str) -> bytes:
        """
        Download the encrypted script from the specified URL.
        
        Args:
            url: URL to download the encrypted script from
            
        Returns:
            Raw bytes of the encrypted script
            
        Raises:
            aiohttp.ClientError: If network request fails
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    response.raise_for_status()  # Raise exception for HTTP errors
                    return await response.read()
        except aiohttp.ClientError as e:
            self.logger.error("Failed to download encrypted script", url=url, error=str(e))
            raise
    
    async def _verify_signature(self, content: bytes, signature_hex: str) -> bool:
        """
        Verify the cryptographic signature of the content.
        
        Args:
            content: The content to verify (encrypted bytes)
            signature_hex: Hexadecimal string representation of the signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Load the public key from configuration
            public_key_path = self.config.get("frida.public_key_path")
            if not public_key_path:
                self.logger.error("Public key path not configured")
                return False
            
            # Resolve relative path
            if not Path(public_key_path).is_absolute():
                # Assume relative to project root
                current_file = Path(__file__)
                project_root = current_file.parent.parent.parent.parent
                public_key_path = project_root / public_key_path
            
            if not Path(public_key_path).exists():
                self.logger.error("Public key file not found", path=public_key_path)
                return False
            
            # Load the RSA public key
            with open(public_key_path, 'rb') as key_file:
                public_key = RSA.import_key(key_file.read())
            
            # Create SHA256 hash of the content
            hash_obj = SHA256.new(content)
            
            # Verify signature
            try:
                pkcs1_15.new(public_key).verify(hash_obj, bytes.fromhex(signature_hex))
                return True
            except ValueError:
                # Signature verification failed
                return False
                
        except Exception as e:
            self.logger.error("Error during signature verification", error=str(e))
            return False
    
    def _decrypt_script(self, encrypted_content: bytes) -> str:
        """
        Decrypt the script content using AES GCM.
        
        Args:
            encrypted_content: Encrypted bytes containing nonce, tag, and ciphertext
            
        Returns:
            Decrypted script content as string
            
        Raises:
            SecurityException: If decryption fails
        """
        try:
            # Get the AES key from configuration
            aes_key_hex = self.config.get("secrets.script_encryption_key")
            if not aes_key_hex:
                raise SecurityException("Script encryption key not configured")
            
            aes_key = bytes.fromhex(aes_key_hex)
            
            # Unpack the payload: nonce (16 bytes) + tag (16 bytes) + ciphertext (rest)
            if len(encrypted_content) < 32:
                raise SecurityException("Invalid encrypted content length")
            
            nonce = encrypted_content[:16]
            tag = encrypted_content[16:32]
            ciphertext = encrypted_content[32:]
            
            # Create AES cipher and decrypt
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            try:
                decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted_bytes.decode('utf-8')
            except ValueError as e:
                raise SecurityException(f"Decryption failed - content may be tampered with: {str(e)}")
                
        except SecurityException:
            raise
        except Exception as e:
            raise SecurityException(f"Script decryption failed: {str(e)}")
    
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