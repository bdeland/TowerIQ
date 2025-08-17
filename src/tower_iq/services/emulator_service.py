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
from ..core.utils import AdbWrapper, AdbError
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
        # Load cache timeout from config
        self._cache_timeout = config.get('emulator.cache_timeout_seconds', 300)  # 5 minutes cache timeout
        self._cache_timestamps: Dict[str, float] = {}

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

    async def ensure_frida_server_is_running(self) -> None:
        """
        Ensures a compatible frida-server is running on the connected device.

        This method is idempotent and performs the following steps:
        1. Checks if a responsive frida-server is already running using a real connection.
        2. Determines the required server version from the installed `frida` library.
        3. Downloads the correct server binary if not already cached.
        4. Pushes the binary to the device if it's missing or outdated.
        5. Starts the server and verifies it becomes responsive.

        Raises:
            RuntimeError: If no device is connected.
            FridaServerSetupError: If the setup process fails at any step.
        """
        if not self.connected_device:
            self.logger.error("Cannot perform action: no device is connected.")
            raise RuntimeError("An action was requested, but no device is connected.")
        device_id = self.connected_device
        
        if frida is None:
            raise FridaServerSetupError(
                "Frida library is not installed. Please run 'pip install frida frida-tools'.")
        self.logger.info(
            "Starting frida-server setup check...", device=device_id)
        try:
            arch = self.device_architecture or await self.get_device_architecture(device_id)
            target_version = frida.__version__
            await self.frida_manager.provision(device_id, arch, target_version)
        except (AdbError, FridaServerSetupError, Exception) as e:
            self.logger.error(
                "Frida-server provisioning failed.", error=str(e))
            raise FridaServerSetupError(
                f"Failed to set up frida-server: {e}") from e

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

    async def get_game_pid(self, package_name: str) -> Optional[int]:
        """Find the Process ID for the running game package on the connected device."""
        if not self.connected_device:
            self.logger.error("Cannot perform action: no device is connected.")
            raise RuntimeError("An action was requested, but no device is connected.")
        device_id = self.connected_device
        
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

    async def get_installed_third_party_packages(self) -> list[dict]:
        """Get a list of running third-party apps only, filtered to exclude system packages on the connected device."""
        if not self.connected_device:
            self.logger.error("Cannot perform action: no device is connected.")
            raise RuntimeError("An action was requested, but no device is connected.")
        device_id = self.connected_device
        
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
            metadata = await self.get_app_metadata(package_name)
            return metadata
        except Exception as e:
            self.logger.warning("Error getting rich package info",
                                package=package_name, error=str(e))
            return {'name': package_name, 'version': 'Unknown'}

    async def get_app_metadata(self, package_name: str) -> dict[str, Any]:
        """
        Get comprehensive app metadata including display name, version, and icon for the connected device.

        Args:
            package_name: Package name to get metadata for

        Returns:
            Dictionary containing app metadata
            
        Raises:
            RuntimeError: If no device is connected.
        """
        if not self.connected_device:
            self.logger.error("Cannot perform action: no device is connected.")
            raise RuntimeError("An action was requested, but no device is connected.")
        device_id = self.connected_device
        
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

    async def is_connected(self) -> bool:
        """Check if there's an active device connection."""
        if not self.connected_device:
            return False
        return await self._test_device_connection(self.connected_device)

    async def get_device_properties(self, device_id: str, properties: list[str]) -> dict[str, str]:
        """Get device properties using ADB shell getprop."""
        self.logger.debug("Getting device properties", device_id=device_id, properties=properties)
        
        cache_key = f"{device_id}_props_{hash(tuple(sorted(properties)))}"
        
        # Check cache first
        if self._is_cache_valid(cache_key):
            cached_props = self._device_properties_cache.get(cache_key, {})
            if cached_props:
                self.logger.debug("Using cached device properties", device_id=device_id)
                return cached_props

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

    async def list_devices_with_details(self) -> list[dict]:
        """
        Discover all available devices and gather their essential properties for UI display.
        
        This is the primary entry point for device listing in the two-phase API.
        It performs a stateless inspection operation that returns detailed information
        about all available devices without establishing any stateful connections.
        
        Returns:
            List of dictionaries containing detailed device information
        """
        self.logger.info("Starting device discovery with rich details")
        
        try:
            # Ensure network emulators are visible to ADB
            await self._scan_and_connect_network_devices()
            
            # Get all available device serials
            devices = await self.adb.list_devices()
            
            if not devices:
                self.logger.info("No ADB devices found")
                return []
            
            # Gather rich details for all devices in parallel
            tasks = [self._get_rich_device_details(serial) for serial in devices]
            detailed_devices = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out any exceptions and log them
            valid_devices = []
            for i, result in enumerate(detailed_devices):
                if isinstance(result, Exception):
                    self.logger.warning("Failed to get details for device", 
                                       device=devices[i], error=str(result))
                else:
                    valid_devices.append(result)
            
            self.logger.info("Device discovery completed", count=len(valid_devices))
            return valid_devices
            
        except Exception as e:
            self.logger.error("Error during device discovery", error=str(e))
            return []

    async def _get_rich_device_details(self, device_id: str) -> dict:
        """
        Get all necessary read-only properties for a single device.
        
        This method gathers comprehensive device information including model,
        Android version, API level, architecture, and connection status.
        
        Args:
            device_id: The device serial ID
            
        Returns:
            Dictionary containing all device details
        """
        try:
            # Get essential device properties
            properties = [
                'ro.product.model',
                'ro.build.version.release', 
                'ro.build.version.sdk',
                'ro.product.cpu.abi'
            ]
            
            device_props = await self.get_device_properties(device_id, properties)
            
            # Determine if device has IP address (network device)
            is_network_device = ':' in device_id
            
            # Build the device details dictionary
            device_details = {
                'serial': device_id,
                'model': device_props.get('ro.product.model', 'Unknown Device'),
                'android_version': device_props.get('ro.build.version.release', 'Unknown'),
                'api_level': self._parse_api_level(device_props.get('ro.build.version.sdk', '0')),
                'architecture': device_props.get('ro.product.cpu.abi', 'unknown'),
                'status': 'Online',
                'is_network_device': is_network_device
            }
            
            # Add IP address if it's a network device
            if is_network_device:
                device_details['ip_address'] = device_id.split(':')[0]
                device_details['port'] = device_id.split(':')[1]
            
            self.logger.debug("Gathered rich device details", 
                             device=device_id, details=device_details)
            return device_details
            
        except Exception as e:
            self.logger.warning("Error getting rich device details", 
                               device=device_id, error=str(e))
            # Return basic info even if detailed gathering fails
            return {
                'serial': device_id,
                'model': 'Unknown Device',
                'android_version': 'Unknown',
                'api_level': 0,
                'architecture': 'unknown',
                'status': 'Error',
                'is_network_device': ':' in device_id
            }

    async def connect_to_device(self, device_id: str) -> bool:
        """
        Establish a stateful connection to a specific device.
        
        This method is part of the two-phase API. After using list_devices_with_details()
        to inspect available devices, this method formally "connects" to a chosen device,
        setting the internal state of the service for subsequent actions.
        
        Args:
            device_id: The serial ID of the device to connect to
            
        Returns:
            True if connection was successful, False otherwise
        """
        self.logger.info("Attempting to connect to device", device=device_id)
        
        try:
            # Verify the device is still reachable
            if not await self._test_device_connection(device_id):
                self.logger.error("Device is not reachable", device=device_id)
                return False
            
            # Set the connected device state
            self.connected_device = device_id
            
            # Pre-emptively get and cache the device's architecture
            self.device_architecture = await self.get_device_architecture(device_id)
            
            self.logger.info("Successfully connected to device", 
                            device=device_id, architecture=self.device_architecture)
            return True
            
        except Exception as e:
            self.logger.error("Failed to connect to device", 
                             device=device_id, error=str(e))
            return False

    async def disconnect_from_device(self) -> bool:
        """
        Disconnect from the currently connected device and reset internal state.
        
        This method is part of the two-phase API. It clears the internal state
        and resets the service to a disconnected state.
        
        Returns:
            True if disconnection was successful, False otherwise
        """
        if not self.connected_device:
            self.logger.info("No device currently connected")
            return True
        
        device_id = self.connected_device
        self.logger.info("Disconnecting from device", device=device_id)
        
        try:
            # Clear the connected device state
            self.connected_device = None
            self.device_architecture = None
            
            # Clear any cached data for this device
            self.clear_cache()
            
            self.logger.info("Successfully disconnected from device", device=device_id)
            return True
            
        except Exception as e:
            self.logger.error("Failed to disconnect from device", 
                             device=device_id, error=str(e))
            return False
