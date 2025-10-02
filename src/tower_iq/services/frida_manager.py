import asyncio
import hashlib
import lzma
from pathlib import Path
from typing import Any, Optional
import aiohttp

from ..core.utils import AdbWrapper, AdbError

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
        arch_map = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86_64": "x86_64", "x86": "x86"}
        frida_arch = arch_map.get(arch, arch)
        binary_filename = f"frida-server-{version}-android-{frida_arch}"
        local_path = self.cache_dir / binary_filename

        if local_path.exists():
            return local_path

        self.logger.info(f"Downloading frida-server v{version} for {frida_arch}...")
        url = f"https://github.com/frida/frida/releases/download/{version}/{binary_filename}.xz"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                response.raise_for_status()
                compressed_data = await response.read()

        decompressed_data = lzma.decompress(compressed_data)
        local_path.write_bytes(decompressed_data)
        local_path.chmod(0o755)
        return local_path

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
        self.logger.info("Starting frida-server on device...")
        try:
            # Kill any existing frida-server processes
            await self.stop_server(device_id)
            await asyncio.sleep(1)  # Give it time to clean up

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

            # Give the server a moment to start
            await asyncio.sleep(2)

            # Quick check to see if the process exists for faster feedback
            try:
                pid_output = await self.adb.shell(device_id, "pidof frida-server")
                if pid_output.strip():
                    self.logger.info(f"Frida-server process found with PID: {pid_output.strip()}")
                else:
                    self.logger.warning("Frida-server process not found after startup")
            except AdbError:
                self.logger.debug("Could not check frida-server PID - process may not be running yet")
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
        self.logger.info(
            f"Waiting for frida-server to become responsive on {device_id}"
            f" (expecting version {target_version})"
        )

        last_error: Optional[FridaServerSetupError] = None

        for attempt in range(1, timeout + 1):
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
                        self.logger.error(
                            f"Frida-server API responsiveness check failed on {device_id}: {e}"
                        )
                        raise FridaServerSetupError(message) from e

                self.logger.info(
                    f"Frida-server passed verification checks on {device_id}."
                )
                return True

            except FridaServerSetupError as e:
                last_error = e
                if attempt < timeout:
                    self.logger.debug(
                        f"Frida-server verification attempt {attempt} failed for {device_id}: {e}."
                        " Retrying..."
                    )
                    await asyncio.sleep(1)
            except Exception as e:
                message = f"Unexpected error while verifying frida-server on {device_id}: {e}"
                self.logger.error(message)
                last_error = FridaServerSetupError(message)
                if attempt < timeout:
                    await asyncio.sleep(1)

        if last_error is not None:
            self.logger.error(
                f"Frida-server failed verification after retries on {device_id}: {last_error}"
            )
            raise last_error

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
        Start the frida-server on the device.

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

            # Start the server
            await self._start_server(device_id)

            # Give it more time to start up
            await asyncio.sleep(3)

            # Verify it's running with multiple checks
            for attempt in range(3):
                try:
                    pid_output = await self.adb.shell(device_id, "pidof frida-server")
                    if pid_output.strip():
                        self.logger.info(f"Frida-server started successfully with PID: {pid_output.strip()}")
                        return True
                    else:
                        self.logger.warning(f"Frida-server process not found on attempt {attempt + 1}")
                        if attempt < 2:
                            await asyncio.sleep(2)  # Wait a bit more before next check
                except AdbError:
                    self.logger.warning(f"Could not check frida-server PID on attempt {attempt + 1}")
                    if attempt < 2:
                        await asyncio.sleep(2)

            self.logger.error("Frida-server failed to start - no process found after multiple attempts")
            return False

        except Exception as e:
            self.logger.error(f"Error starting frida-server: {e}")
            return False

    async def stop_server(self, device_id: str) -> bool:
        """
        Stop the frida-server on the device.

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
                # Give it time to stop
                await asyncio.sleep(2)

                # Verify it's stopped
                try:
                    pid_output = await self.adb.shell(device_id, "pidof frida-server")
                    if not pid_output.strip():
                        self.logger.info("Frida-server stopped successfully")
                        return True
                    else:
                        self.logger.warning("Frida-server process still running after stop attempt")
                        # Try one more aggressive stop
                        try:
                            await self.adb.shell(device_id, "su -c 'kill -9 $(pidof frida-server)'", timeout=5.0)
                            await asyncio.sleep(1)
                            pid_output = await self.adb.shell(device_id, "pidof frida-server")
                            if not pid_output.strip():
                                self.logger.info("Frida-server force-stopped successfully")
                                return True
                        except AdbError:
                            pass
                        return False
                except AdbError:
                    # If pidof fails, assume it's stopped
                    self.logger.info("Frida-server stopped successfully")
                    return True
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
