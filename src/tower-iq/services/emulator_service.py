"""
TowerIQ Emulator Service

This module provides the EmulatorService class for managing Android emulator
connections, ADB communication, and frida-server installation/management.

Refactored to use a deterministic approach for frida-server management:
- Uses the installed Python `frida` library version as the single source of truth.
- Verifies server health by attempting a real connection via `frida.get_device()`,
  which is more reliable than checking for a process with `ps`.
"""

import asyncio
import hashlib
import json
import lzma
import subprocess
from pathlib import Path
from typing import Any, Optional, Set, Dict

import aiohttp
from aiohttp import ClientResponseError

try:
    import frida
    # Import the correct exception class
    FridaError = Exception  # Fallback for older frida versions
    try:
        from frida import InvalidArgumentError, InvalidOperationError, ServerNotRunningError
        # Use a union of common Frida exceptions
        FridaError = (InvalidArgumentError, InvalidOperationError,
                      ServerNotRunningError, Exception)
    except ImportError:
        # If specific exceptions aren't available, use base Exception
        FridaError = Exception
except ImportError:
    frida = None
    FridaError = Exception  # Define for type checking even if frida is not installed

from ..core.config import ConfigurationManager
from src.tower_iq.core.utils import AdbWrapper, AdbError
from .frida_manager import FridaServerManager, FridaServerSetupError


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
        self.adb = AdbWrapper(self.logger)
        self.frida_manager = FridaServerManager(self.logger, self.adb)

        # Performance optimization: caching
        self._device_properties_cache: Dict[str, Dict[str, str]] = {}
        self._app_metadata_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_timeout = 300  # 5 minutes cache timeout
        self._cache_timestamps: Dict[str, float] = {}

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
            # Add timeout for the entire device discovery process
            devices = await asyncio.wait_for(
                self._get_connected_devices(),
                timeout=3.0
            )

            if not devices:
                self.logger.info("No ADB devices found")
                return None

            if len(devices) == 1 and device_id is None:
                target_device = devices[0]
                self.logger.info(
                    "Single device found, connecting", device=target_device)
            elif device_id in devices:
                target_device = device_id
                self.logger.info(
                    "Target device found, connecting", device=target_device)
            elif device_id is None:
                self.logger.info(
                    "Multiple devices found, please specify one", devices=devices)
                return None
            else:
                self.logger.error("Target device not found",
                                  device=device_id, available=devices)
                return None

            if await self._test_device_connection(target_device):
                self.connected_device = target_device
                self.logger.info(
                    "Successfully connected to device", device=target_device)
                # Get and cache architecture on successful connection
                await self.get_device_architecture(target_device)
                return target_device
            else:
                self.logger.error(
                    "Failed to establish connection to device", device=target_device)
                return None

        except asyncio.TimeoutError:
            self.logger.warning("Device discovery timed out.")
            return None
        except Exception as e:
            self.logger.error("Error during device discovery", error=str(e))
            return None

    async def get_device_architecture(self, device_id: str) -> str:
        """Get the CPU architecture of the specified device."""
        try:
            architecture = await self.adb.shell(device_id, "getprop ro.product.cpu.abi")
            self.logger.info("Device architecture detected",
                             device=device_id, arch=architecture)
            self.device_architecture = architecture
            return architecture
        except AdbError as e:
            self.logger.error("Error getting device architecture",
                              device=device_id, error=str(e))
            raise RuntimeError(
                f"Failed to get device architecture: {e}") from e

    async def ensure_frida_server_is_running(self, device_id: str) -> None:
        """
        Ensures a compatible frida-server is running on the device.

        This method is idempotent and performs the following steps:
        1. Checks if a responsive frida-server is already running using a real connection.
        2. Determines the required server version from the installed `frida` library.
        3. Downloads the correct server binary if not already cached.
        4. Pushes the binary to the device if it's missing or outdated.
        5. Starts the server and verifies it becomes responsive.

        Args:
            device_id: The serial ID of the target device.

        Raises:
            FridaServerSetupError: If the setup process fails at any step.
        """
        if frida is None:
            raise FridaServerSetupError(
                "Frida library is not installed. Please run 'pip install frida frida-tools'.")
        self.logger.info(
            "Starting frida-server setup check...", device=device_id)
        try:
            arch = self.device_architecture or await self.get_device_architecture(device_id)
            await self.frida_manager.provision(device_id, arch)
        except (AdbError, FridaServerSetupError, Exception) as e:
            self.logger.error(
                "Frida-server provisioning failed.", error=str(e))
            raise FridaServerSetupError(
                f"Failed to set up frida-server: {e}") from e

    async def _get_frida_server_version(self, arch: str, version: str) -> Path:
        """
        Downloads and caches a specific version of frida-server for the given architecture.
        """
        try:
            cache_dir = Path(
                __file__).parent.parent.parent.parent / "data" / "frida-server"
            cache_dir.mkdir(parents=True, exist_ok=True)

            # Map common getprop architectures to Frida's release naming convention.
            arch_map = {
                "arm64-v8a": "arm64",
                "armeabi-v7a": "arm",
                "x86_64": "x86_64",
                "x86": "x86",
            }
            frida_arch = arch_map.get(arch, arch)

            binary_filename = f"frida-server-{version}-android-{frida_arch}"
            local_path = cache_dir / binary_filename

            if local_path.exists():
                self.logger.info("Using cached frida-server",
                                 version=version, path=str(local_path))
                return local_path

            self.logger.info("Downloading frida-server",
                             version=version, architecture=frida_arch)
            download_url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{frida_arch}.xz"

            async with aiohttp.ClientSession() as session:
                async with session.get(download_url) as response:
                    response.raise_for_status()
                    compressed_data = await response.read()

            self.logger.info("Decompressing frida-server archive...")
            decompressed_data = lzma.decompress(compressed_data)

            with open(local_path, 'wb') as f:
                f.write(decompressed_data)

            local_path.chmod(0o755)
            self.logger.info(
                "Successfully downloaded and cached frida-server", path=str(local_path))
            return local_path

        except ClientResponseError as e:
            if e.status == 404:
                msg = f"Frida-server version {version} for arch {frida_arch} not found at {download_url}. Check your `frida` library version and device architecture."
                self.logger.error(msg)
                raise FileNotFoundError(msg) from e
            self.logger.error(
                "HTTP error downloading frida-server", status=e.status, error=str(e))
            raise
        except Exception as e:
            self.logger.error("Failed to get frida-server version",
                              arch=arch, version=version, error=str(e))
            raise

    async def start_frida_server(self, device_id: str, device_path: str = "/data/local/tmp/frida-server") -> None:
        """
        Starts the frida-server process on the device in the background.
        It kills any existing server process before starting a new one.

        Uses a persistent shell approach to work around emulator issues where
        nohup doesn't properly detach processes from the shell session.
        """
        self.logger.debug(
            "Ensuring no old frida-server processes are running.")
        await self._kill_frida_server(device_id)

        # Give a moment for the port to be released after killing the process.
        await asyncio.sleep(0.5)

        self.logger.info("Starting frida-server with persistent shell approach.",
                         device=device_id, path=device_path)

        try:
            # Use a more robust approach that works with problematic emulators like MuMu Player
            # Create a shell script that properly daemonizes the process
            daemon_script = f"""
su -c '
# Create a proper daemon process that survives shell termination
setsid {device_path} </dev/null >/dev/null 2>&1 &
# Double fork to ensure complete detachment
if [ $? -eq 0 ]; then
    echo "frida-server started successfully"
else
    echo "failed to start frida-server"
    exit 1
fi
'
"""

            self.logger.debug("Executing daemon script",
                              script=daemon_script.strip())
            start_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", daemon_script,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await start_proc.communicate()

            # Check if the daemon script reported success
            self.logger.debug("Daemon script execution completed",
                              returncode=start_proc.returncode,
                              stdout=stdout.decode().strip() if stdout else None,
                              stderr=stderr.decode().strip() if stderr else None)

            if start_proc.returncode == 0:
                output = stdout.decode().strip()
                if "successfully" in output:
                    self.logger.info(
                        "Frida-server daemon script completed successfully")
                else:
                    self.logger.warning(
                        "Frida-server daemon script completed but with unexpected output", output=output)
            else:
                error_output = stderr.decode().strip()
                self.logger.error("Frida-server daemon script failed",
                                  returncode=start_proc.returncode,
                                  error=error_output)

            # The real verification happens in `is_frida_server_responsive`.
        except Exception as e:
            self.logger.error(
                "Error executing start command for frida-server", error=str(e))
            raise RuntimeError(
                "Failed to execute frida-server start command") from e

    async def is_frida_server_responsive(self, device_id: str) -> bool:
        """
        Comprehensive check to verify frida-server is running and healthy on the device.

        This method performs multiple verification steps:
        1. Checks if frida-server process is actually running
        2. Verifies the binary can execute and report its version
        3. Tests actual Frida connection and functionality
        4. Attempts a simple script injection test

        Args:
            device_id: Device serial ID

        Returns:
            True if frida-server is fully functional, False otherwise
        """
        if frida is None:
            self.logger.debug("Frida library not available")
            return False

        self.logger.debug(
            "Starting comprehensive frida-server health check", device=device_id)

        # Step 1: Check if frida-server process is actually running
        if not await self._is_frida_process_running(device_id):
            self.logger.debug("Frida-server process not found running")
            return False

        # Step 2: Verify the binary can execute and report version
        if not await self._can_frida_server_execute(device_id):
            self.logger.debug("Frida-server binary cannot execute properly")
            return False

        # Step 3: Test Frida connection and basic functionality
        if not await self._test_frida_connection(device_id):
            self.logger.debug("Frida connection test failed")
            return False

        # Step 4: Test script injection capability (optional - some emulators have restrictions)
        injection_works = await self._test_frida_injection(device_id)
        if not injection_works:
            self.logger.info(
                "Frida script injection test failed - this may be normal on some emulators with security restrictions")
            # Don't fail the overall check - injection to system processes might be restricted
            # but injection to user apps (which is what we actually need) might still work

        self.logger.debug("Frida-server passed core health checks",
                          device=device_id, injection_test_passed=injection_works)
        return True

    async def _is_frida_process_running(self, device_id: str) -> bool:
        """Check if frida-server process is actually running."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "ps -A",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await result.communicate()

            if result.returncode == 0:
                output = stdout.decode()
                # Look for frida-server process
                frida_lines = []
                for line in output.split('\n'):
                    if 'frida-server' in line and not line.strip().startswith('#'):
                        frida_lines.append(line.strip())
                        self.logger.debug(
                            "Found frida-server process", line=line.strip())
                        return True

                # If no frida-server found, log some context
                if not frida_lines:
                    self.logger.info(
                        "No frida-server process found in ps output")
                    # Log a few sample lines to see what processes are running
                    # First 10 lines for context
                    lines = output.split('\n')[:10]
                    self.logger.debug("Sample ps output", lines=lines)
            else:
                self.logger.debug("ps command failed",
                                  returncode=result.returncode)

            return False
        except Exception as e:
            self.logger.debug("Error checking frida process", error=str(e))
            return False

    async def _can_frida_server_execute(self, device_id: str) -> bool:
        """Test if frida-server binary can execute and report version."""
        try:
            # Test if the binary can execute and report version
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "su -c '/data/local/tmp/frida-server --version'",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=5.0)

            if result.returncode == 0 and stdout:
                version_output = stdout.decode().strip()
                if version_output and not version_output.startswith('su:'):
                    self.logger.info(
                        "Frida-server version check passed", version=version_output)
                    return True

            self.logger.info("Frida-server version check failed",
                             returncode=result.returncode,
                             stdout=stdout.decode() if stdout else None,
                             stderr=stderr.decode() if stderr else None)
            return False

        except asyncio.TimeoutError:
            self.logger.info("Frida-server version check timed out")
            return False
        except Exception as e:
            self.logger.info(
                "Error testing frida-server execution", error=str(e))
            return False

    async def _test_frida_connection(self, device_id: str) -> bool:
        """Test basic Frida connection functionality."""
        def _check_connection():
            try:
                assert frida is not None
                # Attempt to get device with shorter timeout
                device = frida.get_device(id=device_id, timeout=3)
                # Test basic functionality
                processes = device.enumerate_processes()
                # Verify we got a reasonable process list
                if len(processes) < 5:  # Android should have many system processes
                    self.logger.debug(
                        "Suspiciously few processes returned", count=len(processes))
                    return False
                return True
            except Exception as e:
                self.logger.debug(f"Frida connection test failed: {e}")
                return False

        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _check_connection)
        except Exception as e:
            self.logger.debug(
                "Error in frida connection test executor", error=str(e))
            return False

    async def _test_frida_injection(self, device_id: str) -> bool:
        """Test script injection capability with a simple test."""
        def _test_injection():
            try:
                assert frida is not None
                device = frida.get_device(id=device_id, timeout=3)

                # Find a system process to test injection (avoid user apps)
                processes = device.enumerate_processes()
                system_process = None
                available_processes = []

                for proc in processes:
                    available_processes.append(
                        f"{proc.name} (PID: {proc.pid})")
                    # Look for a stable system process
                    if proc.name in ['system_server', 'zygote', 'init'] and proc.pid > 1:
                        system_process = proc
                        break

                if not system_process:
                    self.logger.info("No suitable system process found for injection test",
                                     # Show first 10
                                     available_processes=available_processes[:10])
                    return False

                self.logger.info("Attempting injection test",
                                 target_process=system_process.name,
                                 target_pid=system_process.pid)

                # Attempt to attach to the system process
                session = device.attach(system_process.pid)

                # Create a minimal test script
                test_script = """
                console.log("TowerIQ frida test injection successful");
                """

                script = session.create_script(test_script)
                script.load()

                # Clean up
                script.unload()
                session.detach()

                self.logger.info("Frida injection test passed",
                                 target_process=system_process.name)
                return True

            except Exception as e:
                self.logger.info(f"Frida injection test failed: {e}")
                return False

        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _test_injection)
        except Exception as e:
            self.logger.info(
                "Error in frida injection test executor", error=str(e))
            return False

    async def _kill_frida_server(self, device_id: str):
        """Kills any running frida-server process on the device using `pkill`."""
        self.logger.debug(
            "Attempting to kill frida-server process.", device=device_id)

        # `pkill` is generally available on modern Android and is more reliable.
        # Run with `su -c` for root permissions.
        kill_cmd = "su -c 'pkill frida-server'"
        try:
            kill_result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", kill_cmd,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            # Don't wait too long for a command that might not exist.
            await asyncio.wait_for(kill_result.communicate(), timeout=3.0)
            self.logger.debug("Frida-server kill command sent.")
        except asyncio.TimeoutError:
            self.logger.warning(
                "pkill command timed out. It might not be available on this device.")
        except Exception as e:
            self.logger.warning("Error sending kill command", error=str(e))

    async def _scan_and_connect_network_devices(self):
        """Scans common localhost ports for emulators and tries to connect."""
        self.logger.info(
            "Scanning for network-based emulators on localhost...")
        # Common ports for Android emulators (Nox, Memu, LDPlayer, etc.) plus MuMu Player
        ports_to_scan = list(range(5555, 5585, 2)) + [7555]

        tasks = [self._try_adb_connect("127.0.0.1", port)
                 for port in ports_to_scan]
        await asyncio.gather(*tasks)
        self.logger.info("Network scan completed.")

    async def _try_adb_connect(self, ip: str, port: int):
        """Attempts to 'adb connect' to a given IP and port with a timeout."""
        target = f"{ip}:{port}"
        try:
            process = await asyncio.create_subprocess_exec(
                "adb", "connect", target,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=2.0)
            output = stdout.decode().strip()
            if "connected to" in output or "already connected" in output:
                self.logger.debug(
                    f"Successfully connected to emulator at {target}")
        except asyncio.TimeoutError:
            self.logger.debug(
                f"Connection attempt to {target} timed out (port likely closed).")
        except Exception as e:
            self.logger.warning(
                f"Error trying to connect to {target}", error=str(e))

    async def get_game_pid(self, device_id: str, package_name: str) -> Optional[int]:
        """Find the Process ID for the running game package."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "pidof", package_name,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout, _ = await result.communicate()

            if result.returncode == 0:
                pid_str = stdout.decode().strip()
                if pid_str and pid_str.isdigit():
                    return int(pid_str)

            return None

        except Exception as e:
            self.logger.error("Error getting game PID",
                              device=device_id, package=package_name, error=str(e))
            return None

    async def get_installed_third_party_packages(self, device_id: str) -> list[dict]:
        """Get a list of running third-party apps only, filtered to exclude system packages."""
        self.logger.info(
            "Getting running third-party packages", device=device_id)

        try:
            running_processes = await self._get_running_processes_map(device_id)
            third_party_packages = await self._get_third_party_packages_list(device_id)

            results = []

            for package_name in third_party_packages:
                try:
                    # Only include packages that are currently running
                    if package_name not in running_processes:
                        continue

                    # Filter out system packages
                    if self.is_system_package(package_name):
                        self.logger.debug(
                            "Filtering out system package", package=package_name)
                        continue

                    package_info = await self._get_package_rich_info(device_id, package_name)

                    results.append({
                        'name': package_info.get('name', package_name),
                        'package': package_name,
                        'version': package_info.get('version', 'Unknown'),
                        'is_running': True,  # All results are running by definition
                        'pid': running_processes.get(package_name)
                    })
                except Exception as e:
                    self.logger.warning(
                        "Error getting info for package", package=package_name, error=str(e))

            results.sort(key=lambda x: x['name'].lower())
            self.logger.info("Retrieved running third-party package information",
                             device=device_id, count=len(results))
            return results

        except Exception as e:
            self.logger.error(
                "Error getting running third-party packages", device=device_id, error=str(e))
            return []

    def is_system_package(self, package_name: str) -> bool:
        """
        Determine if a package is a system package that should be filtered out.

        Args:
            package_name: Package name to check

        Returns:
            True if package should be filtered out as a system package
        """
        system_package_patterns = [
            # Google system packages
            'com.google.android.',
            'com.google.ar.',
            'com.google.intelligence.',

            # Android system packages
            'com.android.',
            'android.',

            # Manufacturer system packages
            'com.qualcomm.',
            'com.samsung.android.',
            'com.samsung.knox.',
            'com.sec.android.',
            'com.lge.android.',
            'com.htc.android.',
            'com.sony.android.',
            'com.huawei.android.',
            'com.xiaomi.android.',
            'com.oppo.android.',
            'com.vivo.android.',
            'com.oneplus.android.',

            # Common system services
            'com.android.systemui',
            'com.android.settings',
            'com.android.launcher',
            'com.android.phone',
            'com.android.contacts',
            'com.android.calendar',
            'com.android.camera',
            'com.android.gallery',
            'com.android.music',
            'com.android.email',
            'com.android.browser',
            'com.android.calculator',
            'com.android.clock',
            'com.android.deskclock',
            'com.android.dialer',
            'com.android.mms',
            'com.android.providers.',
            'com.android.server.',

            # Specific problematic packages mentioned in requirements
            'com.google.android.safetycore',
            'com.google.android.gms',
            'com.google.android.gsf',
            'com.google.android.webview',
            'com.google.android.tts',
            'com.google.android.packageinstaller',
            'com.google.android.permissioncontroller',
        ]

        # Check if package name starts with any system pattern
        for pattern in system_package_patterns:
            if package_name.startswith(pattern):
                return True

        # Additional checks for exact matches of problematic packages
        system_exact_matches = {
            'system',
            'android',
            'com.android.shell',
            'com.android.externalstorage',
            'com.android.documentsui',
            'com.android.defcontainer',
            'com.android.vpndialogs',
            'com.android.keychain',
            'com.android.location.fused',
            'com.android.managedprovisioning',
            'com.android.proxyhandler',
            'com.android.statementservice',
            'com.android.sharedstoragebackup',
        }

        return package_name in system_exact_matches

    async def _get_running_processes_map(self, device_id: str) -> dict[str, int]:
        """Get a mapping of running package names to their PIDs."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "ps", "-A",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            if result.returncode != 0:
                self.logger.warning(
                    "Failed to get running processes", error=stderr.decode())
                return {}

            running_processes = {}
            lines = stdout.decode().strip().split('\n')
            for line in lines[1:]:  # Skip header
                fields = line.split()
                if len(fields) >= 9:
                    try:
                        pid = int(fields[1])
                        process_name = fields[-1]
                        if '.' in process_name and not process_name.startswith('['):
                            running_processes[process_name] = pid
                    except (ValueError, IndexError):
                        continue
            return running_processes
        except Exception as e:
            self.logger.error(
                "Error getting running processes map", error=str(e))
            return {}

    async def _get_third_party_packages_list(self, device_id: str) -> list[str]:
        """Get list of third-party (user-installed) package names."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "pm", "list", "packages", "-3",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            if result.returncode != 0:
                self.logger.warning(
                    "Failed to get third-party packages", error=stderr.decode())
                return []

            return [
                line.replace('package:', '').strip()
                for line in stdout.decode().strip().split('\n')
                if line.startswith('package:')
            ]
        except Exception as e:
            self.logger.error(
                "Error getting third-party packages list", error=str(e))
            return []

    async def _get_package_rich_info(self, device_id: str, package_name: str) -> dict:
        """Get rich information for a specific package."""
        try:
            # Get comprehensive app metadata
            metadata = await self.get_app_metadata(device_id, package_name)
            return metadata
        except Exception as e:
            self.logger.warning("Error getting rich package info",
                                package=package_name, error=str(e))
            return {'name': package_name, 'version': 'Unknown'}

    async def get_app_metadata(self, device_id: str, package_name: str) -> dict[str, Any]:
        """
        Get comprehensive app metadata including display name, version, and icon.

        Args:
            device_id: Device serial ID
            package_name: Package name to get metadata for

        Returns:
            Dictionary containing app metadata
        """
        # Check cache first
        cache_key = f"{device_id}_{package_name}_metadata"
        cached_metadata = self._get_cached_app_metadata(cache_key)
        if cached_metadata:
            self.logger.debug("Using cached app metadata",
                              package=package_name)
            return cached_metadata

        self.logger.debug("Getting app metadata",
                          device=device_id, package=package_name)

        try:
            # Get basic package information via dumpsys
            basic_info = await self._get_basic_package_info(device_id, package_name)

            # Get display name
            display_name = await self.get_app_display_name(device_id, package_name)
            if display_name and display_name != package_name:
                basic_info['name'] = display_name

            # Try to get app icon data
            icon_data = await self.get_app_icon_data(device_id, package_name)
            if icon_data:
                basic_info['icon_data'] = icon_data

            # Cache the results
            self._cache_app_metadata(cache_key, basic_info)

            self.logger.debug("App metadata gathered and cached",
                              package=package_name, has_icon=bool(icon_data))
            return basic_info

        except Exception as e:
            self.logger.warning("Error getting app metadata",
                                package=package_name, error=str(e))
            return {'name': package_name, 'version': 'Unknown'}

    async def _get_basic_package_info(self, device_id: str, package_name: str) -> dict[str, Any]:
        """Get basic package information via dumpsys."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", f"dumpsys package {package_name}",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await result.communicate()

            package_info = {
                'name': package_name,
                'version': 'Unknown',
                'version_code': 0,
                'install_time': None,
                'last_update_time': None,
                'is_debuggable': False
            }

            if result.returncode == 0:
                output = stdout.decode().strip()
                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith('versionName='):
                        package_info['version'] = line.replace(
                            'versionName=', '').strip()
                    elif line.startswith('versionCode='):
                        try:
                            version_code = line.replace(
                                'versionCode=', '').strip()
                            package_info['version_code'] = int(
                                version_code.split()[0])
                        except (ValueError, IndexError):
                            pass
                    elif line.startswith('application-label:'):
                        label = line.replace(
                            'application-label:', '').strip().strip("'\"")
                        if label:
                            package_info['name'] = label
                    elif 'FLAG_DEBUGGABLE' in line:
                        package_info['is_debuggable'] = True

            return package_info
        except Exception as e:
            self.logger.debug("Error getting basic package info",
                              package=package_name, error=str(e))
            return {'name': package_name, 'version': 'Unknown'}

    async def get_app_display_name(self, device_id: str, package_name: str) -> str:
        """
        Get human-readable app name from package manager.

        Args:
            device_id: Device serial ID
            package_name: Package name

        Returns:
            Human-readable app display name
        """
        try:
            # Try multiple methods to get the display name

            # Method 1: Use pm list packages with -f flag to get APK path, then aapt
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", f"pm path {package_name}",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await result.communicate()

            if result.returncode == 0 and stdout:
                apk_path = stdout.decode().strip().replace('package:', '')
                if apk_path:
                    # Try to get label using aapt (if available)
                    label = await self._get_label_from_aapt(device_id, apk_path)
                    if label:
                        return label

            # Method 2: Try to get from dumpsys package (fallback)
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", f"dumpsys package {package_name} | grep -E 'application-label|label='",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await result.communicate()

            if result.returncode == 0 and stdout:
                for line in stdout.decode().strip().split('\n'):
                    line = line.strip()
                    if 'application-label:' in line:
                        label = line.split(
                            'application-label:')[-1].strip().strip("'\"")
                        if label and label != package_name:
                            return label
                    elif 'label=' in line:
                        label = line.split('label=')[-1].strip().strip("'\"")
                        if label and label != package_name:
                            return label

            # Method 3: Fallback to package name
            return package_name

        except Exception as e:
            self.logger.debug("Error getting app display name",
                              package=package_name, error=str(e))
            return package_name

    async def _get_label_from_aapt(self, device_id: str, apk_path: str) -> Optional[str]:
        """Try to get app label using aapt tool."""
        try:
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", f"aapt dump badging {apk_path} | grep 'application-label'",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await result.communicate()

            if result.returncode == 0 and stdout:
                output = stdout.decode().strip()
                # Parse application-label:'App Name'
                if 'application-label:' in output:
                    label = output.split(
                        'application-label:')[-1].strip().strip("'\"")
                    if label:
                        return label

            return None
        except Exception:
            return None

    async def get_app_icon_data(self, device_id: str, package_name: str) -> Optional[bytes]:
        """
        Extract app icon as PNG data.

        Args:
            device_id: Device serial ID
            package_name: Package name

        Returns:
            Icon data as bytes, or None if not available
        """
        try:
            # This is a simplified implementation - getting icons from Android is complex
            # For now, we'll return None and implement icon display later if needed
            # Full implementation would require extracting icons from APK files

            self.logger.debug(
                "Icon extraction not yet implemented", package=package_name)
            return None

        except Exception as e:
            self.logger.debug("Error getting app icon",
                              package=package_name, error=str(e))
            return None

    async def find_connected_devices(self) -> list[dict]:
        """Find all connected ADB devices and return detailed information."""
        self.logger.info("Scanning for connected ADB devices")
        try:
            devices = await asyncio.wait_for(self.adb.list_devices(), timeout=10.0)
            if not devices:
                self.logger.info("No connected devices found")
                return []

            tasks = [self._get_device_info(serial) for serial in devices]
            detailed_devices = await asyncio.gather(*tasks)

            self.logger.info("Found connected devices",
                             count=len(detailed_devices))
            return detailed_devices
        except asyncio.TimeoutError:
            self.logger.warning("Device scanning timed out")
            return []
        except Exception as e:
            self.logger.error("Error finding connected devices", error=str(e))
            return []

    async def _get_device_info(self, device_id: str) -> dict:
        """Get basic information about a device."""
        try:
            model = await self.adb.shell(device_id, "getprop ro.product.model")
            name = model or f"Device {device_id}"
            return {'serial': device_id, 'name': name, 'status': 'connected'}
        except AdbError as e:
            self.logger.warning("Error getting device info",
                                device=device_id, error=str(e))
            return {'serial': device_id, 'name': f"Device {device_id}", 'status': 'error'}

    async def is_connected(self) -> bool:
        """Check if there's an active device connection."""
        if not self.connected_device:
            return False
        return await self._test_device_connection(self.connected_device)

    async def _get_connected_devices(self) -> list[str]:
        """Get list of connected ADB devices using both standard discovery and network scan."""
        self.logger.info("Starting comprehensive device discovery...")
        await self._scan_and_connect_network_devices()
        try:
            devices = await self.adb.list_devices()
            if devices:
                self.logger.info(
                    "Comprehensive discovery completed.", final_devices=devices)
            else:
                self.logger.warning(
                    "No devices found after comprehensive discovery.")
            return devices
        except AdbError as e:
            self.logger.error(
                "Error during final device consolidation", error=str(e))
            return []

    async def get_enhanced_device_info(self, device_id: str) -> dict[str, Any]:
        print(f"DEBUG: get_enhanced_device_info called for {device_id}")
        """
        Get comprehensive device information including model, Android version, etc.

        Args:
            device_id: Device serial ID

        Returns:
            Dictionary containing enhanced device information
        """
        self.logger.debug("Gathering enhanced device info", device=device_id)

        try:
            # Define properties to gather
            properties = [
                'ro.product.model',           # Device model
                'ro.product.manufacturer',    # Manufacturer
                'ro.product.name',           # Product name
                'ro.build.version.release',   # Android version
                'ro.build.version.sdk',       # API level
                'ro.product.cpu.abi',        # Architecture
                'ro.kernel.qemu',            # Emulator detection
                'ro.build.characteristics'    # Device characteristics
            ]

            self.logger.debug(f"Requesting device properties: {properties}", device=device_id)
            # Gather device properties
            device_props = await self.get_device_properties(device_id, properties)
            self.logger.debug(f"Device properties returned: {device_props}", device=device_id)

            # Format the information
            enhanced_info = {
                'serial': device_id,
                'model': device_props.get('ro.product.model', 'Unknown'),
                'manufacturer': device_props.get('ro.product.manufacturer', 'Unknown'),
                'android_version': device_props.get('ro.build.version.release', 'Unknown'),
                'api_level': self._parse_api_level(device_props.get('ro.build.version.sdk', '0')),
                'architecture': device_props.get('ro.product.cpu.abi', 'Unknown'),
                'is_emulator': self._detect_emulator(device_props),
                'device_name': device_props.get('ro.product.name', 'Unknown'),
                'status': 'Online'  # Changed from 'Connected' to avoid confusion
            }

            self.logger.debug(f"Enhanced device info gathered: {enhanced_info}", device=device_id)
            return enhanced_info

        except Exception as e:
            self.logger.error(
                "Error gathering enhanced device info", device=device_id, error=str(e))
            # Return basic info as fallback
            return {
                'serial': device_id,
                'model': 'Unknown',
                'manufacturer': 'Unknown',
                'android_version': 'Unknown',
                'api_level': 0,
                'architecture': 'Unknown',
                'is_emulator': False,
                'device_name': 'Unknown',
                'status': 'Online'
            }

    async def get_device_properties(self, device_id: str, properties: list[str]) -> dict[str, str]:
        print(f"DEBUG: get_device_properties called for {device_id} with {properties}")
        """
        Get specific device properties via getprop commands with caching.

        Args:
            device_id: Device serial ID
            properties: List of property names to retrieve

        Returns:
            Dictionary mapping property names to values
        """
        # Check cache first
        cache_key = f"{device_id}_properties"
        if self._is_cache_valid(cache_key):
            cached_props = self._device_properties_cache.get(cache_key, {})
            # Check if all requested properties are in cache
            if all(prop in cached_props for prop in properties):
                self.logger.debug(f"Using cached device properties: {cached_props}", device=device_id)
                return {prop: cached_props[prop] for prop in properties}

        self.logger.debug(f"Gathering device properties from device: {device_id}", properties=properties)

        result = {}

        try:
            # Build a single getprop command for efficiency
            prop_commands = []
            for prop in properties:
                prop_commands.append(f"echo '{prop}:'; getprop {prop}")

            # Execute combined command
            combined_command = "; ".join(prop_commands)
            self.logger.debug(f"Running ADB shell command: {combined_command}", device=device_id)
            output = await self.adb.shell(device_id, combined_command)
            self.logger.debug(f"Raw ADB output for getprop: {output}", device=device_id)

            # Parse the output
            lines = output.split('\n')
            current_prop = None

            for line in lines:
                line = line.strip()
                if line.endswith(':'):
                    # This is a property name line
                    current_prop = line[:-1]
                elif current_prop and line:
                    # This is a property value line
                    result[current_prop] = line
                    current_prop = None

            self.logger.debug(f"Parsed device properties: {result}", device=device_id)
            # Cache the results
            self._cache_device_properties(cache_key, result)

            self.logger.debug("Device properties gathered and cached",
                              device=device_id, count=len(result))
            return result

        except AdbError as e:
            self.logger.warning(
                "Error getting device properties", device=device_id, error=str(e))
            return {}

    def _parse_api_level(self, api_level_str: str) -> int:
        """Parse API level string to integer."""
        try:
            return int(api_level_str)
        except (ValueError, TypeError):
            return 0

    def _detect_emulator(self, device_props: dict[str, str]) -> bool:
        """
        Detect if device is an emulator based on properties.

        Args:
            device_props: Dictionary of device properties

        Returns:
            True if device appears to be an emulator
        """
        # Check for emulator indicators
        emulator_indicators = [
            device_props.get('ro.kernel.qemu') == '1',
            'emulator' in device_props.get('ro.product.model', '').lower(),
            'sdk' in device_props.get('ro.product.name', '').lower(),
            'generic' in device_props.get('ro.product.name', '').lower(),
            device_props.get('ro.build.characteristics') == 'emulator'
        ]

        return any(emulator_indicators)

    def format_device_status(self, raw_status: str) -> str:
        """
        Convert ADB status to user-friendly format.

        Args:
            raw_status: Raw ADB device status

        Returns:
            User-friendly status string
        """
        status_map = {
            'device': 'Online',
            'offline': 'Offline',
            'unauthorized': 'Unauthorized',
            'no permissions': 'No Permissions'
        }

        return status_map.get(raw_status.lower(), raw_status)

    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is still valid based on timeout."""
        import time
        if cache_key not in self._cache_timestamps:
            return False

        elapsed = time.time() - self._cache_timestamps[cache_key]
        return elapsed < self._cache_timeout

    def _cache_device_properties(self, cache_key: str, properties: Dict[str, str]):
        """Cache device properties with timestamp."""
        import time
        self._device_properties_cache[cache_key] = properties
        self._cache_timestamps[cache_key] = time.time()
        self.logger.debug("Cached device properties",
                          cache_key=cache_key, count=len(properties))

    def _cache_app_metadata(self, cache_key: str, metadata: Dict[str, Any]):
        """Cache app metadata with timestamp."""
        import time
        self._app_metadata_cache[cache_key] = metadata
        self._cache_timestamps[cache_key] = time.time()
        self.logger.debug("Cached app metadata", cache_key=cache_key)

    def _get_cached_app_metadata(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached app metadata if valid."""
        if self._is_cache_valid(cache_key):
            return self._app_metadata_cache.get(cache_key)
        return None

    def clear_cache(self):
        """Clear all cached data."""
        self._device_properties_cache.clear()
        self._app_metadata_cache.clear()
        self._cache_timestamps.clear()
        self.logger.info("All caches cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        return {
            "device_properties_cached": len(self._device_properties_cache),
            "app_metadata_cached": len(self._app_metadata_cache),
            "total_cache_entries": len(self._cache_timestamps),
            "cache_timeout_seconds": self._cache_timeout
        }

    async def _test_device_connection(self, device_id: str) -> bool:
        """Test if we can communicate with the specified device."""
        try:
            output = await self.adb.shell(device_id, "echo test")
            return "test" in output
        except AdbError:
            return False

    async def _check_if_device_server_is_outdated(self, device_id: str, local_path: Path, device_path: str) -> bool:
        """Check if the frida-server on the device is outdated via SHA256 hash."""
        try:
            with open(local_path, 'rb') as f:
                local_hash = hashlib.sha256(f.read()).hexdigest()

            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", f"sha256sum {device_path} 2>/dev/null",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await result.communicate()

            if result.returncode == 0 and stdout:
                device_hash = stdout.decode().strip().split()[0]
                if local_hash == device_hash:
                    self.logger.debug(
                        "Device frida-server hash matches local version.")
                    return False
                self.logger.info("Device frida-server hash mismatch.",
                                 local_hash=local_hash[:8], device_hash=device_hash[:8])
                return True

            self.logger.info(
                "Device frida-server is missing or hash check failed. Assuming outdated.")
            return True
        except Exception as e:
            self.logger.error(
                "Error checking device frida-server status", error=str(e))
            return True  # Assume outdated on error for safety

    async def push_file(self, device_id: str, local_path: Path, device_path: str) -> None:
        """Push a file to the device, ensuring it's clean and executable."""
        self.logger.info("Pushing file to device",
                         local=str(local_path), device=device_path)
        try:
            await self.adb.shell(device_id, f"rm -f {device_path}")
            if not local_path.exists() or not local_path.is_file():
                raise Exception(
                    f"Local file does not exist or is not a file: {local_path}")
            target_dir = str(Path(device_path).parent)
            await self.adb.shell(device_id, f"mkdir -p {target_dir}")
            await self.adb.push(device_id, str(local_path), device_path)
            await self.adb.shell(device_id, f"ls -la {device_path}")
            await self.adb.shell(device_id, f"chmod 755 {device_path}")
            self.logger.info(
                "Successfully pushed and configured file on device.")
        except (AdbError, Exception) as e:
            self.logger.error("Error during file push operation", error=str(e))
            raise
