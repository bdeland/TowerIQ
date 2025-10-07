import asyncio
import hashlib
import lzma
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import aiohttp

from ..core.async_utils import (wait_for_condition,
                                wait_for_condition_with_result)
from ..core.utils import AdbError, AdbWrapper


class FridaServerSetupError(Exception):
    """Raised when frida-server setup fails."""
    pass

class FridaServerManager:
    DEVICE_PATH = "/data/local/tmp/frida-server"

    def __init__(self, logger: Any, adb: AdbWrapper):
        self.logger = logger.bind(source="FridaServerManager")
        self.adb = adb
        self.cache_dir = Path(__file__).parent.parent.parent / "data" / "frida-server"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    async def provision(self, device_id: str, arch: str, target_version: str) -> bool:
        """
        Ensure a compatible frida-server is running on the device.

        Returns:
            True if provisioning was successful, False otherwise
        """
        try:
            self.logger.info(f"Provisioning frida-server v{target_version} for {arch} on {device_id}")

            # 1. Download binary if needed
            try:
                local_path = await self._get_frida_server_binary(arch, target_version)
            except Exception as e:
                self.logger.error(f"Failed to get frida-server binary: {e}")
                return False

            # 2. Push to device if it's missing or outdated
            try:
                if await self._is_push_required(device_id, local_path):
                    await self._push_to_device(device_id, local_path)
            except Exception as e:
                self.logger.error(f"Failed to push frida-server to device: {e}")
                return False

            # 3. Start the server
            try:
                await self._start_server(device_id)
            except Exception as e:
                self.logger.error(f"Failed to start frida-server: {e}")
                return False

            # 4. Verify it's responsive
            try:
                await self._wait_for_responsive(device_id, target_version=target_version)
            except FridaServerSetupError as e:
                self.logger.error(f"Server verification failed: {e}")
                return False
            except Exception as e:
                self.logger.error(f"Failed to verify frida-server responsiveness: {e}")
                return False

            self.logger.info("Frida-server provisioning successful.")
            return True

        except Exception as e:
            self.logger.error(f"Frida-server provisioning failed: {e}")
            return False

    async def _get_frida_server_binary(self, arch: str, version: str) -> Path:
        """
        Download and verify frida-server binary with retry logic and checksum verification.
        
        Args:
            arch: Device architecture (e.g., 'arm64-v8a', 'x86_64')
            version: Frida version to download
            
        Returns:
            Path to the verified frida-server binary
            
        Raises:
            FridaServerSetupError: If download or verification fails after all retries
        """
        arch_map = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86_64": "x86_64", "x86": "x86"}
        frida_arch = arch_map.get(arch, arch)
        binary_filename = f"frida-server-{version}-android-{frida_arch}"
        local_path = self.cache_dir / binary_filename

        # Return cached binary if it exists
        if local_path.exists():
            self.logger.debug(f"Using cached frida-server binary: {local_path}")
            return local_path

        # Download with retry logic
        self.logger.info(f"Downloading frida-server v{version} for {frida_arch}...")
        
        try:
            compressed_data = await self._download_with_retry(
                version=version,
                binary_filename=binary_filename,
                frida_arch=frida_arch
            )
            
            # Decompress the data
            try:
                self.logger.debug(f"Decompressing {binary_filename}.xz...")
                decompressed_data = lzma.decompress(compressed_data)
                self.logger.debug(f"Decompressed size: {len(decompressed_data)} bytes")
            except lzma.LZMAError as e:
                error_msg = f"Failed to decompress frida-server binary: {e}"
                self.logger.error(error_msg)
                raise FridaServerSetupError(error_msg) from e
            
            # Write to temporary file first (atomic operation)
            try:
                temp_fd, temp_path = tempfile.mkstemp(
                    dir=self.cache_dir,
                    prefix=f"{binary_filename}_",
                    suffix=".tmp"
                )
                temp_path_obj = Path(temp_path)
                
                try:
                    # Write decompressed data
                    with open(temp_fd, 'wb') as f:
                        f.write(decompressed_data)
                    
                    # Set executable permissions
                    temp_path_obj.chmod(0o755)
                    
                    # Verify it's a valid ELF binary (basic check)
                    if len(decompressed_data) < 4 or decompressed_data[:4] != b'\x7fELF':
                        error_msg = f"Downloaded file is not a valid ELF binary"
                        self.logger.error(error_msg)
                        temp_path_obj.unlink(missing_ok=True)
                        raise FridaServerSetupError(error_msg)
                    
                    # Atomic rename
                    temp_path_obj.rename(local_path)
                    self.logger.info(f"Successfully downloaded and verified frida-server to {local_path}")
                    
                except Exception:
                    # Cleanup temp file on any error
                    temp_path_obj.unlink(missing_ok=True)
                    raise
                    
            except OSError as e:
                error_msg = f"Failed to write frida-server binary to {local_path}: {e}"
                self.logger.error(error_msg)
                raise FridaServerSetupError(error_msg) from e
            
            return local_path
            
        except FridaServerSetupError:
            raise
        except Exception as e:
            error_msg = f"Unexpected error downloading frida-server: {e}"
            self.logger.error(error_msg)
            raise FridaServerSetupError(error_msg) from e

    async def _download_with_retry(
        self,
        version: str,
        binary_filename: str,
        frida_arch: str,
        max_retries: int = 3,
        base_delay: float = 1.0
    ) -> bytes:
        """
        Download frida-server binary with retry logic and checksum verification.
        
        Args:
            version: Frida version
            binary_filename: Name of the binary file
            frida_arch: Frida architecture string
            max_retries: Maximum number of retry attempts
            base_delay: Base delay in seconds for exponential backoff
            
        Returns:
            Compressed binary data
            
        Raises:
            FridaServerSetupError: If download fails after all retries
        """
        url = f"https://github.com/frida/frida/releases/download/{version}/{binary_filename}.xz"
        
        last_error = None
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    delay = base_delay * (2 ** (attempt - 1))
                    self.logger.info(f"Retrying download in {delay}s (attempt {attempt + 1}/{max_retries})...")
                    await asyncio.sleep(delay)
                
                # Create session with timeouts
                timeout = aiohttp.ClientTimeout(
                    total=300,  # 5 minutes total
                    connect=30,  # 30 seconds to connect
                    sock_read=60  # 60 seconds between reads
                )
                
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    # Download the binary
                    compressed_data = await self._download_file(
                        session=session,
                        url=url,
                        filename=binary_filename
                    )
                    
                    # Try to verify checksum
                    checksum_verified = await self._verify_checksum(
                        session=session,
                        version=version,
                        binary_filename=binary_filename,
                        frida_arch=frida_arch,
                        compressed_data=compressed_data
                    )
                    
                    if not checksum_verified:
                        self.logger.warning(
                            "Checksum verification skipped (no checksum file available). "
                            "Proceeding with download."
                        )
                    
                    return compressed_data
                    
            except aiohttp.ClientError as e:
                last_error = e
                self.logger.warning(f"Download attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    error_msg = f"Failed to download frida-server after {max_retries} attempts: {e}"
                    self.logger.error(error_msg)
                    raise FridaServerSetupError(error_msg) from e
                    
            except asyncio.TimeoutError as e:
                last_error = e
                self.logger.warning(f"Download attempt {attempt + 1} timed out: {e}")
                if attempt == max_retries - 1:
                    error_msg = f"Download timed out after {max_retries} attempts"
                    self.logger.error(error_msg)
                    raise FridaServerSetupError(error_msg) from e
                    
            except Exception as e:
                # For unexpected errors, don't retry
                error_msg = f"Unexpected error during download: {e}"
                self.logger.error(error_msg)
                raise FridaServerSetupError(error_msg) from e
        
        # Should not reach here, but just in case
        error_msg = f"Failed to download frida-server after {max_retries} attempts"
        if last_error:
            error_msg += f": {last_error}"
        raise FridaServerSetupError(error_msg)

    async def _download_file(
        self,
        session: aiohttp.ClientSession,
        url: str,
        filename: str
    ) -> bytes:
        """
        Download a file with progress logging.
        
        Args:
            session: aiohttp session
            url: URL to download from
            filename: Name of the file being downloaded
            
        Returns:
            Downloaded file data
            
        Raises:
            aiohttp.ClientError: If download fails
        """
        start_time = time.time()
        
        async with session.get(url) as response:
            response.raise_for_status()
            
            # Get content length if available
            content_length = response.headers.get('Content-Length')
            if content_length:
                total_size = int(content_length)
                self.logger.info(f"Downloading {filename}.xz ({total_size / 1024 / 1024:.2f} MB)...")
                
                # Validate size (frida-server binaries are typically 30-80 MB compressed)
                if total_size < 1_000_000:  # Less than 1 MB
                    raise aiohttp.ClientError(f"File size too small: {total_size} bytes")
                if total_size > 200_000_000:  # More than 200 MB
                    raise aiohttp.ClientError(f"File size too large: {total_size} bytes")
            else:
                total_size = None
                self.logger.info(f"Downloading {filename}.xz (size unknown)...")
            
            # Download with progress tracking
            downloaded = 0
            chunks = []
            last_progress_log = 0
            
            async for chunk in response.content.iter_chunked(8192):
                chunks.append(chunk)
                downloaded += len(chunk)
                
                # Log progress every 10 MB or 25%
                if total_size:
                    progress_pct = (downloaded / total_size) * 100
                    if progress_pct - last_progress_log >= 25:
                        self.logger.debug(
                            f"Download progress: {downloaded / 1024 / 1024:.2f} MB "
                            f"({progress_pct:.1f}%)"
                        )
                        last_progress_log = progress_pct
                elif downloaded - last_progress_log >= 10_000_000:  # Every 10 MB
                    self.logger.debug(f"Download progress: {downloaded / 1024 / 1024:.2f} MB")
                    last_progress_log = downloaded
            
            compressed_data = b''.join(chunks)
            duration = time.time() - start_time
            
            # Calculate speed, avoid division by zero for very fast downloads
            if duration > 0:
                speed_mbps = len(compressed_data) / 1024 / 1024 / duration
                self.logger.info(
                    f"Download completed: {len(compressed_data) / 1024 / 1024:.2f} MB "
                    f"in {duration:.1f}s ({speed_mbps:.2f} MB/s)"
                )
            else:
                self.logger.info(
                    f"Download completed: {len(compressed_data) / 1024 / 1024:.2f} MB "
                    f"in < 0.1s"
                )
            
            return compressed_data

    async def _verify_checksum(
        self,
        session: aiohttp.ClientSession,
        version: str,
        binary_filename: str,
        frida_arch: str,
        compressed_data: bytes
    ) -> bool:
        """
        Verify the checksum of downloaded data against GitHub release checksums.
        
        Args:
            session: aiohttp session
            version: Frida version
            binary_filename: Name of the binary file
            frida_arch: Frida architecture string
            compressed_data: The downloaded compressed data
            
        Returns:
            True if checksum verified, False if checksum file not available
            
        Raises:
            FridaServerSetupError: If checksum verification fails
        """
        # Try common checksum file patterns
        checksum_urls = [
            f"https://github.com/frida/frida/releases/download/{version}/{binary_filename}.xz.sha256",
            f"https://github.com/frida/frida/releases/download/{version}/SHA256SUMS",
            f"https://github.com/frida/frida/releases/download/{version}/checksums.txt",
        ]
        
        for checksum_url in checksum_urls:
            try:
                async with session.get(checksum_url) as response:
                    if response.status == 404:
                        continue
                    response.raise_for_status()
                    checksum_content = await response.text()
                    
                    # Parse checksum
                    expected_checksum = None
                    if checksum_url.endswith('.sha256'):
                        # Single file checksum
                        expected_checksum = checksum_content.strip().split()[0]
                    else:
                        # Multi-file checksum (find the line for our file)
                        for line in checksum_content.splitlines():
                            if f"{binary_filename}.xz" in line:
                                expected_checksum = line.strip().split()[0]
                                break
                    
                    if expected_checksum:
                        # Compute actual checksum
                        actual_checksum = hashlib.sha256(compressed_data).hexdigest()
                        
                        self.logger.debug(
                            f"Verifying checksum: expected={expected_checksum}, actual={actual_checksum}"
                        )
                        
                        if actual_checksum.lower() != expected_checksum.lower():
                            error_msg = (
                                f"Checksum verification failed for {binary_filename}.xz: "
                                f"expected {expected_checksum}, got {actual_checksum}"
                            )
                            self.logger.error(error_msg)
                            raise FridaServerSetupError(error_msg)
                        
                        self.logger.info(f"Checksum verification passed for {binary_filename}.xz")
                        return True
                        
            except aiohttp.ClientError:
                # Try next checksum URL
                continue
            except FridaServerSetupError:
                # Re-raise checksum failures
                raise
            except Exception as e:
                self.logger.debug(f"Error checking {checksum_url}: {e}")
                continue
        
        # No checksum file found - this is OK, just log it
        return False

    async def _is_push_required(self, device_id: str, local_path: Path) -> bool:
        try:
            with open(local_path, 'rb') as f:
                local_hash = hashlib.sha256(f.read()).hexdigest()
            device_hash_output = await self.adb.shell(device_id, f"sha256sum {self.DEVICE_PATH}")
            device_hash = device_hash_output.split()[0]
            return local_hash != device_hash
        except (AdbError, FileNotFoundError, IndexError):
            return True

    async def _push_to_device(self, device_id: str, local_path: Path):
        self.logger.info(f"Pushing frida-server to {device_id}:{self.DEVICE_PATH}")

        try:
            # First try direct push (works on some devices)
            await self.adb.push(device_id, str(local_path), self.DEVICE_PATH)
            await self.adb.shell(device_id, f"chmod 755 {self.DEVICE_PATH}")
            self.logger.info("Direct push successful")
        except Exception as e:
            self.logger.warning(f"Direct push failed: {e}, trying alternative method")

            # Alternative method: push to /sdcard first, then move with root
            try:
                temp_path = "/sdcard/frida-server"
                await self.adb.push(device_id, str(local_path), temp_path)
                await self.adb.shell(device_id, f"su -c 'cp {temp_path} {self.DEVICE_PATH} && chmod 755 {self.DEVICE_PATH}'")
                await self.adb.shell(device_id, f"rm {temp_path}")
                self.logger.info("Alternative push method successful")
            except Exception as e2:
                self.logger.error(f"Alternative push method also failed: {e2}")
                raise e2

    async def _start_server(self, device_id: str):
        """
        Start frida-server using proper wait conditions instead of fixed delays.
        
        Implements Pattern #3: Poll properly with exponential backoff.
        """
        self.logger.info("Starting frida-server on device...")
        try:
            # Kill any existing frida-server processes
            await self.stop_server(device_id)
            
            # Wait for process to actually be killed (poll instead of sleep)
            async def check_stopped() -> bool:
                try:
                    pid_output = await self.adb.shell(device_id, "pidof frida-server")
                    return not pid_output.strip()  # True if no process found
                except AdbError:
                    return True  # Assume stopped if pidof fails
            
            await wait_for_condition(
                check_stopped,
                timeout=3.0,
                initial_delay=0.1,
                max_delay=0.5,
                condition_name="frida-server stopped"
            )

            # Use a more reliable method to start frida-server in background
            # Try multiple approaches with shorter timeouts to avoid hanging
            start_commands = [
                f"su -c 'nohup {self.DEVICE_PATH} > /dev/null 2>&1 &'",
                f"su -c '{self.DEVICE_PATH} &'",
                f"su -c 'setsid {self.DEVICE_PATH} &'",
                f"su -c 'nohup {self.DEVICE_PATH} -t 0 > /dev/null 2>&1 &'"
            ]

            started = False
            for i, cmd in enumerate(start_commands):
                try:
                    self.logger.debug(f"Trying start method {i+1}: {cmd}")
                    # Use shorter timeout to prevent hanging
                    await self.adb.shell(device_id, cmd, timeout=5.0)
                    self.logger.debug(f"Start command {i+1} completed successfully")
                    started = True
                    break
                except AdbError as e:
                    self.logger.warning(f"Start method {i+1} failed: {e}")
                    if i == len(start_commands) - 1:
                        # If all methods fail, raise the last error
                        raise AdbError(f"All frida-server start methods failed. Last error: {e}")

            if not started:
                raise AdbError("Failed to start frida-server with any method")

            # Wait for process to actually start (poll instead of fixed delay)
            async def check_started() -> bool:
                try:
                    pid_output = await self.adb.shell(device_id, "pidof frida-server")
                    return bool(pid_output.strip())
                except AdbError:
                    return False
            
            process_started = await wait_for_condition(
                check_started,
                timeout=5.0,
                initial_delay=0.2,
                max_delay=1.0,
                condition_name="frida-server started"
            )
            
            if process_started:
                try:
                    pid_output = await self.adb.shell(device_id, "pidof frida-server")
                    self.logger.info(f"Frida-server process started with PID: {pid_output.strip()}")
                except AdbError:
                    pass
            else:
                self.logger.warning("Frida-server process not found after startup attempts")
                
        except Exception as e:
            self.logger.error(f"Error in _start_server: {e}")
            raise

    async def _wait_for_responsive(
        self,
        device_id: str,
        target_version: str,
        frida_instance=None,
        timeout: int = 15,
    ) -> bool:
        """
        Wait for frida-server to become responsive using proper polling.
        
        Implements Pattern #3: Poll properly with exponential backoff + jitter.
        """
        self.logger.info(
            f"Waiting for frida-server to become responsive on {device_id}"
            f" (expecting version {target_version})"
        )

        async def check_responsive() -> tuple[bool, Optional[Exception]]:
            """Check if frida-server is responsive."""
            try:
                await self._verify_installation(device_id)
                await self._verify_running_state(device_id)
                await self._verify_version(device_id, target_version)

                if frida_instance is not None:
                    try:
                        loop = asyncio.get_running_loop()
                        device = await loop.run_in_executor(
                            None, lambda: frida_instance.get_device(id=device_id, timeout=1)
                        )
                        await loop.run_in_executor(None, device.enumerate_processes)
                    except Exception as e:
                        message = f"Failed to communicate with frida-server API: {e}"
                        return (False, FridaServerSetupError(message))

                return (True, None)

            except FridaServerSetupError as e:
                return (False, e)
            except Exception as e:
                message = f"Unexpected error while verifying frida-server on {device_id}: {e}"
                return (False, FridaServerSetupError(message))

        # Use proper polling with exponential backoff
        success, last_error = await wait_for_condition_with_result(
            check_responsive,
            timeout=float(timeout),
            initial_delay=0.5,
            max_delay=2.0,
            backoff_factor=1.5,
            condition_name=f"frida-server responsive on {device_id}"
        )

        if success:
            self.logger.info(f"Frida-server passed verification checks on {device_id}")
            return True
        
        if last_error is not None:
            self.logger.error(
                f"Frida-server failed verification after retries on {device_id}: {last_error}"
            )
            if isinstance(last_error, Exception):
                raise last_error
            raise FridaServerSetupError(str(last_error))

        message = "Frida-server verification failed for unknown reasons."
        self.logger.error(f"{message} (device {device_id})")
        raise FridaServerSetupError(message)

    async def _verify_installation(self, device_id: str) -> None:
        self.logger.debug(
            f"Checking frida-server installation at {self.DEVICE_PATH} on {device_id}."
        )
        try:
            await self.adb.shell(device_id, f"ls {self.DEVICE_PATH}")
        except AdbError as e:
            message = f"Frida-server binary not found at {self.DEVICE_PATH}"
            self.logger.error(
                f"Frida-server installation check failed on {device_id}: {e}"
            )
            raise FridaServerSetupError(message) from e

    async def _verify_running_state(self, device_id: str) -> None:
        self.logger.debug(f"Checking frida-server running state on {device_id}.")
        try:
            pid_output = await self.adb.shell(device_id, "pidof frida-server")
        except AdbError as e:
            message = "Failed to query frida-server process list"
            self.logger.error(
                f"Frida-server running-state check failed on {device_id}: {e}"
            )
            raise FridaServerSetupError(message) from e

        if not pid_output.strip():
            message = "Frida-server process not running on device"
            self.logger.error(f"{message} {device_id}")
            raise FridaServerSetupError(message)

    async def _verify_version(self, device_id: str, expected_version: str) -> None:
        self.logger.debug(
            f"Checking frida-server version on {device_id} (expected {expected_version})."
        )
        try:
            version_output = await self.adb.shell(
                device_id, f"{self.DEVICE_PATH} --version"
            )
        except AdbError as e:
            message = "Failed to execute frida-server for version check"
            self.logger.error(
                f"Frida-server version check failed on {device_id}: {e}"
            )
            raise FridaServerSetupError(message) from e

        actual_version = ""
        for line in version_output.splitlines():
            stripped = line.strip()
            if stripped:
                actual_version = stripped
                break

        if not actual_version:
            message = "Could not determine frida-server version"
            self.logger.error(f"{message} on {device_id}")
            raise FridaServerSetupError(message)

        if actual_version != expected_version:
            message = (
                "Frida-server version mismatch: "
                f"expected {expected_version}, got {actual_version}"
            )
            self.logger.error(f"{message} on {device_id}")
            raise FridaServerSetupError(message)

    async def start_server(self, device_id: str) -> bool:
        """
        Start the frida-server on the device with proper wait conditions.

        Implements Pattern #3: Poll properly with exponential backoff.

        Args:
            device_id: Device serial ID

        Returns:
            True if server started successfully, False otherwise
        """
        self.logger.info(f"Starting frida-server on {device_id}")

        try:
            # Check if server binary exists
            try:
                await self.adb.shell(device_id, f"ls {self.DEVICE_PATH}")
            except AdbError:
                self.logger.error(f"Frida server binary not found at {self.DEVICE_PATH}")
                return False

            # Kill any existing processes first
            await self.stop_server(device_id)

            # Start the server (already uses wait_for_condition internally)
            await self._start_server(device_id)

            # Verify it's running using proper polling
            async def check_running() -> tuple[bool, Optional[str]]:
                """Check if frida-server is running and return PID."""
                try:
                    pid_output = await self.adb.shell(device_id, "pidof frida-server")
                    pid = pid_output.strip()
                    if pid:
                        return (True, pid)
                    return (False, None)
                except AdbError:
                    return (False, None)
            
            success, pid = await wait_for_condition_with_result(
                check_running,
                timeout=10.0,
                initial_delay=0.5,
                max_delay=2.0,
                backoff_factor=1.5,
                condition_name="frida-server running"
            )

            if success and pid:
                self.logger.info(f"Frida-server started successfully with PID: {pid}")
                return True
            
            self.logger.error("Frida-server failed to start - no process found after polling")
            return False

        except Exception as e:
            self.logger.error(f"Error starting frida-server: {e}")
            return False

    async def stop_server(self, device_id: str) -> bool:
        """
        Stop the frida-server on the device with proper wait conditions.

        Implements Pattern #3: Poll properly with exponential backoff.

        Args:
            device_id: Device serial ID

        Returns:
            True if server stopped successfully, False otherwise
        """
        self.logger.info(f"Stopping frida-server on {device_id}")

        try:
            # First check if frida-server is actually running
            try:
                pid_output = await self.adb.shell(device_id, "pidof frida-server")
                if not pid_output.strip():
                    self.logger.info("No frida-server process found - already stopped")
                    return True
            except AdbError:
                self.logger.info("Could not check frida-server PID - assuming not running")
                return True

            # Try multiple methods to stop the server
            stop_commands = [
                "su -c 'pkill -f frida-server'",
                "su -c 'pkill frida-server'",
                "su -c 'killall frida-server'",
                "pkill -f frida-server",
                "pkill frida-server",
                "killall frida-server"
            ]

            stopped = False
            for cmd in stop_commands:
                try:
                    await self.adb.shell(device_id, cmd, timeout=5.0)
                    stopped = True
                    self.logger.debug(f"Stop command succeeded: {cmd}")
                    break
                except AdbError:
                    continue

            if stopped:
                # Wait for process to actually stop (poll instead of sleep)
                async def check_stopped() -> bool:
                    try:
                        pid_output = await self.adb.shell(device_id, "pidof frida-server")
                        return not pid_output.strip()  # True if process stopped
                    except AdbError:
                        return True  # Assume stopped if pidof fails
                
                process_stopped = await wait_for_condition(
                    check_stopped,
                    timeout=5.0,
                    initial_delay=0.2,
                    max_delay=1.0,
                    condition_name="frida-server stopped"
                )

                if process_stopped:
                    self.logger.info("Frida-server stopped successfully")
                    return True
                else:
                    self.logger.warning("Frida-server process still running after stop attempt")
                    # Try one more aggressive stop
                    try:
                        await self.adb.shell(device_id, "su -c 'kill -9 $(pidof frida-server)'", timeout=5.0)
                        
                        # Check again with polling
                        force_stopped = await wait_for_condition(
                            check_stopped,
                            timeout=3.0,
                            initial_delay=0.1,
                            max_delay=0.5,
                            condition_name="frida-server force-stopped"
                        )
                        
                        if force_stopped:
                            self.logger.info("Frida-server force-stopped successfully")
                            return True
                    except AdbError:
                        pass
                    return False
            else:
                self.logger.warning("No frida-server process found to stop")
                return True  # Consider this success if no process was running

        except Exception as e:
            self.logger.error(f"Error stopping frida-server: {e}")
            return False

    async def install_server(self, device_id: str, arch: str, target_version: str) -> bool:
        """
        Install frida-server on the device without starting it.

        Args:
            device_id: Device serial ID
            arch: Device architecture
            target_version: Frida version to install

        Returns:
            True if installation successful, False otherwise
        """
        self.logger.info(f"Installing frida-server v{target_version} for {arch} on {device_id}")

        try:
            # Download binary if needed
            local_path = await self._get_frida_server_binary(arch, target_version)

            # Push to device
            await self._push_to_device(device_id, local_path)

            self.logger.info("Frida-server installation completed")
            return True

        except Exception as e:
            self.logger.error(f"Error installing frida-server: {e}")
            return False

    async def remove_server(self, device_id: str) -> bool:
        """
        Remove frida-server from the device.

        Args:
            device_id: Device serial ID

        Returns:
            True if removal successful, False otherwise
        """
        self.logger.info(f"Removing frida-server from {device_id}")

        try:
            # Stop the server first
            await self.stop_server(device_id)

            # Remove the binary
            try:
                await self.adb.shell(device_id, f"rm {self.DEVICE_PATH}")
                self.logger.info("Frida-server binary removed successfully")
                return True
            except AdbError as e:
                self.logger.warning(f"Could not remove frida-server binary: {e}")
                return False

        except Exception as e:
            self.logger.error(f"Error removing frida-server: {e}")
            return False

    async def is_server_installed(self, device_id: str) -> bool:
        """
        Check if frida-server is installed on the device.

        Args:
            device_id: Device serial ID

        Returns:
            True if server is installed, False otherwise
        """
        try:
            await self.adb.shell(device_id, f"ls {self.DEVICE_PATH}")
            return True
        except AdbError:
            return False

    async def get_server_version(self, device_id: str) -> str | None:
        """
        Get the version of installed frida-server.

        Args:
            device_id: Device serial ID

        Returns:
            Version string or None if not available
        """
        try:
            version_output = await self.adb.shell(device_id, f"{self.DEVICE_PATH} --version")
            return version_output.strip()
        except AdbError:
            return None
            return None
