"""
TowerIQ Emulator Service

This module provides the EmulatorService class for managing Android emulator
operations. This service is designed to be stateless - all connection state
is managed by the SessionManager.

Key principles:
- Stateless operations only
- Simplified, focused methods
- Clear separation of concerns
- Centralized caching
"""

import asyncio
from typing import Any, Optional, Dict, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import socket

try:
    import frida
    FridaError = Exception
    try:
        from frida import InvalidArgumentError, InvalidOperationError, ServerNotRunningError
        FridaError = (InvalidArgumentError, InvalidOperationError, ServerNotRunningError, Exception)
    except ImportError:
        FridaError = Exception
except ImportError:
    frida = None
    FridaError = Exception

try:
    from device_detector import DeviceDetector
    DEVICE_DETECTOR_AVAILABLE = True
except ImportError:
    DeviceDetector = None
    DEVICE_DETECTOR_AVAILABLE = False

from ..core.config import ConfigurationManager
from ..core.errors import DeviceConnectionError
from ..core.utils import AdbWrapper, AdbError
from .frida_manager import FridaServerManager
from ..core.session import AdbStatus


# Module-level constants for configuration
_EMULATOR_INDICATORS = [
    'sdk', 'emulator', 'generic', 'android sdk built for',
    'mumu', 'mumuglobal', 'bluestacks', 'bst', 'nox', 'noxplayer',
    'ldplayer', 'ld', 'genymotion', 'geny'
]

_SYSTEM_PACKAGE_PATTERNS = [
    'com.google.android.',
    'com.android.',
    'android.',
    'com.qualcomm.',
    'com.samsung.android.',
    'com.sec.android.',
    'com.lge.android.',
    'com.htc.android.',
    'com.sony.android.',
    'com.huawei.android.',
    'com.xiaomi.android.',
    'com.oppo.android.',
    'com.vivo.android.',
    'com.oneplus.android.',
]

_SERVICE_PATTERNS = [
    'android.hardware.',
    'android.hidl.',
    'android.system.',
    'media.',
    'frida-server',
    'com.android.',
    'com.google.android.',
    'com.bluestacks.',
    'com.uncube.',
    'android.ext.',
    'android.process.',
    'com.google.process.',
]

# Additional patterns for packages that commonly fail dumpsys queries
_FAILURE_PATTERNS = [
    ':background',
    ':webview_service',
    ':quick_launch',
    ':instant_app_installer',
    ':sandboxed_process',
    ':isolated_process',
    ':persistent',
    ':unstable',
    ':ui',
    ':gms',
    ':gapps',
    ':vending',
    ':systemui',
    ':inputmethod',
    ':phone',
    ':defcontainer',
    ':gallery3d',
    ':media',
    ':launcher3',
    ':home',
    ':BstCommandProcessor',
]

_UNWANTED_SUFFIXES = [
    ' build', ' eng', ' user', ' userdebug', ' test-keys',
    ' release-keys', ' dev-keys', ' debug', ' debug-keys'
]


@dataclass
class Process:
    """Process information with all details loaded."""
    package: str
    name: str
    pid: int
    version: str
    is_system: bool = False

    def __post_init__(self):
        """Set default name if not provided."""
        if not self.name or self.name == self.package:
            # Extract readable name from package
            parts = self.package.split('.')
            if len(parts) > 1:
                self.name = parts[-1].title()
            else:
                self.name = self.package


@dataclass
class Device:
    """Device information with all details loaded."""
    serial: str
    model: str
    android_version: str
    api_level: int
    architecture: str
    status: str
    is_network_device: bool
    brand: Optional[str] = None
    device_name: Optional[str] = None  # Human-readable device name like "Samsung Galaxy S21 Ultra"
    ip_address: Optional[str] = None
    port: Optional[str] = None
    device_type: str = "device"  # "emulator" or "device"

    def __post_init__(self):
        """Set device type and network info based on serial."""
        if ':' in self.serial:
            self.is_network_device = True
            parts = self.serial.split(':')
            self.ip_address = parts[0]
            self.port = parts[1] if len(parts) > 1 else None
        else:
            self.is_network_device = False

        # Detect device type
        self._detect_device_type()

    def _detect_device_type(self):
        """Detect if device is emulator or physical device."""
        model_lower = self.model.lower()
        serial_lower = self.serial.lower()

        # Check indicators in model
        for indicator in _EMULATOR_INDICATORS:
            if indicator in model_lower:
                self.device_type = "emulator"
                return

        # Check serial patterns
        if serial_lower.startswith('emulator-') or 'emulator' in serial_lower:
            self.device_type = "emulator"
            return

        # Network devices are typically emulators
        if self.is_network_device:
            self.device_type = "emulator"
            return

        # Check for generic brand/manufacturer (common in emulators)
        if hasattr(self, 'brand') and self.brand and self.brand.lower() == 'generic':
            self.device_type = "emulator"
            return

        # Check for emulator indicators in brand/manufacturer
        if hasattr(self, 'brand') and self.brand:
            brand_lower = self.brand.lower()
            if brand_lower in ['generic', 'unknown']:
                self.device_type = "emulator"
                return

        # Default to physical device
        self.device_type = "device"


@dataclass
class CacheEntry:
    """Generic cache entry with expiration."""
    data: Any
    timestamp: datetime
    ttl_seconds: int = 300  # 5 minutes default

    def is_expired(self) -> bool:
        return datetime.now() - self.timestamp > timedelta(seconds=self.ttl_seconds)


class EmulatorService:
    """
    Stateless service for Android emulator operations.

    This service provides stateless operations for device discovery,
    process listing, and device information gathering. All connection
    state is managed by the SessionManager.
    """

    def __init__(self, config: ConfigurationManager, logger: Any) -> None:
        """Initialize the emulator service."""
        self.logger = logger.bind(source="EmulatorService")
        self.config = config
        self._verbose_debug = config.get('emulator.verbose_debug', False)
        self.adb = AdbWrapper(self.logger, self._verbose_debug)
        self.frida_manager = FridaServerManager(self.logger, self.adb)

        # Device detector is required for device information
        if DEVICE_DETECTOR_AVAILABLE:
            self.logger.debug("Device detector library available")
        else:
            self.logger.error("Device detector library is required but not available")

        # Centralized caching
        self._cache: Dict[str, CacheEntry] = {}
        self._cache_timeout = config.get('emulator.cache_timeout_seconds', 300)

        # Device discovery deduplication for Phase 1.2 of duplication fix
        self._discovery_lock = asyncio.Lock()
        self._last_discovery_time = None
        self._last_discovery_result = None
        self._discovery_cache_timeout = config.get('emulator.discovery_cache_timeout_seconds', 10)

    # --- Device Discovery ---

    def _is_discovery_cache_valid(self) -> bool:
        """Check if device discovery cache is valid and not expired."""
        if (self._last_discovery_time is None or
            self._last_discovery_result is None):
            return False

        now = datetime.now()
        time_since_discovery = (now - self._last_discovery_time).total_seconds()
        return time_since_discovery < self._discovery_cache_timeout

    async def discover_devices(self, timeout: float = 10.0, clear_cache: bool = False) -> List[Device]:
        """
        Discover all available devices with complete information.

        Args:
            timeout: Maximum time to wait for device discovery operations
            clear_cache: Whether to clear cached device properties before scanning

        Returns:
            List of Device objects with all information loaded
        """
        self.logger.info("Starting device discovery", clear_cache=clear_cache)

        # Clear discovery cache if requested
        if clear_cache:
            self._cache.clear()
            self._last_discovery_time = None
            self._last_discovery_result = None
            self.logger.info("Device cache cleared")

        # Use AsyncLock to prevent concurrent discovery operations
        async with self._discovery_lock:
            # Double-check cache validity after acquiring lock
            if not clear_cache and self._is_discovery_cache_valid():
                # Type narrowing: we know these are not None because of cache validity check
                assert self._last_discovery_time is not None
                assert self._last_discovery_result is not None
                
                self.logger.debug("Using cached device discovery results",
                                cache_age=(datetime.now() - self._last_discovery_time).total_seconds(),
                                device_count=len(self._last_discovery_result))
                return self._last_discovery_result.copy()  # Return a copy to prevent modification

            self.logger.debug("Cache miss or expired, performing new device discovery")

            try:
                # Ensure ADB server is running before attempting discovery
                await self._ensure_adb_server_running()

                # Get device list with timeout
                device_list = await asyncio.wait_for(
                    self._get_device_list(),
                    timeout=timeout
                )

                if not device_list:
                    self.logger.info("No devices found")
                    # Cache empty result
                    self._last_discovery_result = []
                    self._last_discovery_time = datetime.now()
                    return []

                # Get complete info for all devices concurrently
                device_tasks = [
                    self._get_complete_device_info(serial, status, timeout)
                    for serial, status in device_list
                ]

                devices = await asyncio.gather(*device_tasks, return_exceptions=True)

                # Filter out None results and exceptions
                valid_devices = []
                for device in devices:
                    if isinstance(device, Device):
                        valid_devices.append(device)
                    elif isinstance(device, Exception):
                        self.logger.warning("Failed to get device info", error=str(device), error_type=type(device).__name__)

                # Cache the results
                self._last_discovery_result = valid_devices
                self._last_discovery_time = datetime.now()

                self.logger.info("Device discovery completed", count=len(valid_devices))
                return valid_devices.copy()  # Return a copy to prevent modification

            except asyncio.TimeoutError:
                self.logger.error("Device discovery timed out")
                return []
            except Exception as e:
                self.logger.error("Device discovery failed", error=str(e), error_type=type(e).__name__)
                return []

    async def get_processes(self, device: Device, timeout: float = 10.0) -> List[Process]:
        """
        Get all processes on a device with complete information.

        Args:
            device: Device to query
            timeout: Maximum time to wait for process listing operations

        Returns:
            List of Process objects with all information loaded
        """
        try:
            # Test device connectivity first
            try:
                await asyncio.wait_for(
                    self._test_device_connection(device.serial),
                    timeout=timeout
                )
            except DeviceConnectionError as connection_error:
                self.logger.warning(
                    "Device not accessible",
                    device=device.serial,
                    reason=connection_error.reason,
                    status=connection_error.status,
                )
                return []

            # Get all processes with complete information
            processes = await asyncio.wait_for(
                self._get_all_processes(device.serial),
                timeout=timeout
            )

            self.logger.info("Retrieved processes", device=device.serial, count=len(processes))
            return processes

        except asyncio.TimeoutError:
            self.logger.error("Process listing timed out", device=device.serial)
            return []
        except Exception as e:
            self.logger.error("Failed to get processes", device=device.serial, error=str(e), error_type=type(e).__name__)
            return []

    async def get_all_processes_unfiltered(self, device: Device, timeout: float = 10.0) -> List[Process]:
        """
        Get ALL processes on a device without any filtering.

        Args:
            device: Device to query
            timeout: Maximum time to wait for process listing operations

        Returns:
            List of Process objects with minimal information (no detailed queries)
        """
        try:
            # Test device connectivity first
            try:
                await asyncio.wait_for(
                    self._test_device_connection(device.serial),
                    timeout=timeout
                )
            except DeviceConnectionError as connection_error:
                self.logger.warning(
                    "Device not accessible",
                    device=device.serial,
                    reason=connection_error.reason,
                    status=connection_error.status,
                )
                return []

            # Get all processes without any filtering
            processes = await asyncio.wait_for(
                self._get_all_processes_unfiltered(device.serial),
                timeout=timeout
            )

            self.logger.info("Retrieved all processes (unfiltered)", device=device.serial, count=len(processes))
            return processes

        except asyncio.TimeoutError:
            self.logger.error("Process listing timed out", device=device.serial)
            return []
        except Exception as e:
            self.logger.error("Failed to get processes", device=device.serial, error=str(e), error_type=type(e).__name__)
            return []

    async def find_target_process(self, device: Device, target_package: str = "com.TechTreeGames.TheTower", timeout: float = 10.0) -> Optional[Process]:
        """
        Find the target process (The Tower game) on the device.

        Args:
            device: Device to query
            target_package: Package name to search for (default: The Tower game)
            timeout: Maximum time to wait for process listing operations

        Returns:
            Process object if found, None otherwise
        """
        try:
            self.logger.info("Searching for target process", device=device.serial, target_package=target_package)

            # Get all processes
            processes = await self.get_processes(device, timeout)

            # Find the target process
            target_process = None
            for process in processes:
                if process.package == target_package:
                    target_process = process
                    break

            if target_process:
                self.logger.info("Target process found",
                               device=device.serial,
                               package=target_process.package,
                               name=target_process.name,
                               pid=target_process.pid)
            else:
                self.logger.warning("Target process not found",
                                  device=device.serial,
                                  target_package=target_package,
                                  available_packages=[p.package for p in processes[:10]])  # Log first 10 packages for debugging

            return target_process

        except Exception as e:
            self.logger.error("Failed to find target process",
                            device=device.serial,
                            target_package=target_package,
                            error=str(e),
                            error_type=type(e).__name__)
            return None

    # --- Private Methods ---

    async def _get_device_list(self) -> List[tuple[str, str]]:
        """Get list of available device serials with their status."""
        try:
            stdout, _ = await self.adb.run_command("devices", timeout=5.0)
            devices = []
            for line in stdout.split('\n')[1:]:  # Skip header
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        serial = parts[0].strip()
                        status = parts[1].strip()
                        devices.append((serial, status))
            return devices
        except AdbError:
            # Try to start ADB server once and retry
            self.logger.info("ADB may not be running; attempting to start server and retry device list")
            try:
                await self.adb.start_server()
                stdout, _ = await self.adb.run_command("devices", timeout=5.0)
                devices = []
                for line in stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            serial = parts[0].strip()
                            status = parts[1].strip()
                            devices.append((serial, status))
                return devices
            except AdbError as e2:
                self.logger.warning("Failed to get device list after starting ADB", error=str(e2))
                return []

    async def _ensure_adb_server_running(self) -> None:
        """Best-effort ensure ADB server is running (idempotent)."""
        try:
            await self.adb.start_server()
        except AdbError as e:
            # If start fails, log and continue; downstream calls will surface errors
            self.logger.warning("Unable to start ADB server", error=str(e))

    async def _get_complete_device_info(self, serial: str, adb_status: str, timeout: float) -> Optional[Device]:
        """Get complete device information using DeviceDetector."""
        try:
            # Pass raw ADB status directly to Device object
            # Get basic device properties needed for DeviceDetector
            properties = await asyncio.wait_for(
                self._get_device_properties(serial, [
                    'ro.product.model',
                    'ro.build.version.release',
                    'ro.build.version.sdk',
                    'ro.product.cpu.abi',
                    'ro.product.brand',
                    'ro.product.manufacturer',
                    'ro.product.name',
                    'ro.product.device'
                ]),
                timeout=timeout
            )

            model = properties.get('ro.product.model', 'Unknown Device')
            brand = properties.get('ro.product.brand', 'Unknown')
            manufacturer = properties.get('ro.product.manufacturer', 'Unknown')
            product_name = properties.get('ro.product.name', '')
            product_device = properties.get('ro.product.device', '')
            android_version = properties.get('ro.build.version.release', 'Unknown')

            # Use DeviceDetector to get enhanced device information
            device_info = await self._get_device_info_with_detector(
                model, brand, manufacturer, product_name, product_device, android_version
            )

            return Device(
                serial=serial,
                model=model,
                android_version=android_version,
                api_level=int(properties.get('ro.build.version.sdk', '0')),
                architecture=properties.get('ro.product.cpu.abi', 'unknown'),
                status=adb_status,  # Pass raw ADB status directly
                is_network_device=':' in serial,
                brand=device_info.get('brand', brand),
                device_name=device_info.get('device_name')
            )
        except Exception as e:
            self.logger.warning("Failed to get device info", device=serial, error=str(e), error_type=type(e).__name__)
            return None

    async def _get_all_processes(self, device_serial: str) -> List[Process]:
        """Get all processes with complete information."""
        try:
            # Get all running processes with ps command
            stdout, _ = await self.adb.run_command("-s", device_serial, "shell", "ps", "-A")

            processes = []
            for line in stdout.split('\n')[1:]:  # Skip header
                fields = line.split()
                if len(fields) >= 9:
                    try:
                        pid = int(fields[1])
                        process_name = fields[-1]

                        # Include ALL processes without filtering
                        # Check if it's a system package for display purposes
                        is_system = self._is_system_package(process_name)

                        # Try to get complete process info for all processes
                        process = await self._get_process_details(device_serial, process_name, pid)
                        if process:
                            processes.append(process)
                        else:
                            # Fallback: create basic process object for any process that wasn't handled
                            try:
                                process = Process(
                                    package=process_name,
                                    name=process_name,
                                    pid=pid,
                                    version="Unknown",
                                    is_system=is_system
                                )
                                processes.append(process)
                            except Exception as e:
                                self.logger.debug("Failed to create process object", process_name=process_name, error=str(e))
                                continue
                    except (ValueError, IndexError) as e:
                        self.logger.debug("Failed to parse process line", line=line, error=str(e))
                        continue

            # Sort by name, with user apps first
            processes.sort(key=lambda p: (p.is_system, p.name.lower()))
            return processes

        except AdbError as e:
            self.logger.warning("Failed to get processes", device=device_serial, error=str(e))
            return []

    async def _get_all_processes_unfiltered(self, device_serial: str) -> List[Process]:
        """Get ALL processes without any filtering or detailed queries."""
        try:
            # Get all running processes with ps command
            stdout, _ = await self.adb.run_command("-s", device_serial, "shell", "ps", "-A")

            processes = []
            for line in stdout.split('\n')[1:]:  # Skip header
                fields = line.split()
                if len(fields) >= 9:
                    try:
                        pid = int(fields[1])
                        process_name = fields[-1]

                        # Create basic process object for ALL processes
                        # Check if it's a system package for display purposes
                        is_system = self._is_system_package(process_name)

                        try:
                            process = Process(
                                package=process_name,
                                name=process_name,
                                pid=pid,
                                version="Unknown",
                                is_system=is_system
                            )
                            processes.append(process)
                        except Exception as e:
                            self.logger.debug("Failed to create process object", process_name=process_name, error=str(e))
                            continue
                    except (ValueError, IndexError) as e:
                        self.logger.debug("Failed to parse process line", line=line, error=str(e))
                        continue

            # Sort by name, with user apps first
            processes.sort(key=lambda p: (p.is_system, p.name.lower()))
            return processes

        except AdbError as e:
            self.logger.warning("Failed to get processes", device=device_serial, error=str(e))
            return []

    async def _get_process_details(self, device_serial: str, package: str, pid: int) -> Optional[Process]:
        """Get complete process details including name and version."""
        try:
            # Check if it's a system package
            is_system = self._is_system_package(package)

            # For system packages, return basic info without detailed queries
            if is_system:
                return Process(
                    package=package,
                    name=package,  # Use package name as fallback
                    pid=pid,
                    version="System",
                    is_system=True
                )

            # For user packages, try to get detailed info
            # Only attempt detailed queries for valid package names to avoid errors
            if self._is_valid_package_name(package):
                # Get app name and version concurrently
                name_task = self._get_package_property(device_serial, package, "application-label:")
                version_task = self._get_package_property(device_serial, package, "versionName=")

                name, version = await asyncio.gather(name_task, version_task, return_exceptions=True)

                # Handle exceptions
                if isinstance(name, Exception):
                    self.logger.debug("Failed to get app name", package=package, error=str(name))
                    name = None
                if isinstance(version, Exception):
                    self.logger.debug("Failed to get app version", package=package, error=str(version))
                    version = "Unknown"

                return Process(
                    package=package,
                    name=str(name) if name else package,
                    pid=pid,
                    version=str(version) if version else "Unknown",
                    is_system=is_system
                )
            else:
                # For non-valid package names (system processes, services, etc.), return basic info
                return Process(
                    package=package,
                    name=package,
                    pid=pid,
                    version="System",
                    is_system=is_system
                )

        except Exception as e:
            if self._verbose_debug:
                self.logger.debug("Failed to get process details", package=package, error=str(e), error_type=type(e).__name__)
            return None

    async def _get_package_property(self, device_serial: str, package: str, grep_pattern: str) -> Optional[str]:
        """Get a specific property from a package using dumpsys."""
        # Skip processes that don't have package information
        if not self._is_valid_package_name(package):
            return None

        try:
            # Try to get from dumpsys with a shorter timeout for faster failure
            stdout, _ = await self.adb.run_command("-s", device_serial, "shell",
                                                 f"dumpsys package {package} | grep '{grep_pattern}'",
                                                 timeout=3.0)

            for line in stdout.split('\n'):
                if grep_pattern in line:
                    if grep_pattern == "application-label:":
                        label = line.split('application-label:')[-1].strip().strip("'\"")
                        if label and label != package:
                            return label
                    elif grep_pattern == "versionName=":
                        return line.replace('versionName=', '').strip()

            return None
        except AdbError as e:
            # Only log at debug level to reduce noise - these failures are expected for system packages
            if self._verbose_debug:
                self.logger.debug("Failed to get package property", package=package, pattern=grep_pattern, error=str(e))
            return None

    def _is_valid_package_name(self, process_name: str) -> bool:
        """Check if a process name looks like a valid package name that can be queried."""
        # Skip system processes that don't have package information
        if process_name.startswith('[') or process_name.startswith('/'):
            return False

        # Skip sandboxed and isolated processes
        if ':sandboxed_process' in process_name or ':isolated_process' in process_name:
            return False

        # Skip system services (they have @ in their names)
        if '@' in process_name:
            return False

        # Skip processes that don't look like packages (no dots or too short)
        if '.' not in process_name or len(process_name) < 3:
            return False

        # Skip processes that look like system services or daemons
        if process_name.endswith('-service') or process_name.endswith('-daemon'):
            return False

        # Skip processes that contain system service patterns
        if any(pattern in process_name for pattern in _SERVICE_PATTERNS):
            return False

        # Skip packages that are known to fail dumpsys queries
        if any(pattern in process_name for pattern in _FAILURE_PATTERNS):
            return False

        # Special case: Always include The Tower game package
        if process_name == 'com.TechTreeGames.TheTower':
            return True

        return True

    def _is_system_package(self, package: str) -> bool:
        """Check if package is a system package."""
        # Include sandboxed and isolated processes as system processes
        if ':sandboxed_process' in package or ':isolated_process' in package:
            return True

        # Check for system package patterns
        if any(package.startswith(pattern) for pattern in _SYSTEM_PACKAGE_PATTERNS):
            return True

        # Check for service patterns
        if any(pattern in package for pattern in _SERVICE_PATTERNS):
            return True

        # Check for failure patterns (these are typically system packages)
        if any(pattern in package for pattern in _FAILURE_PATTERNS):
            return True

        return False

    async def _get_device_properties(self, device_serial: str, properties: List[str]) -> Dict[str, str]:
        """Get device properties with caching."""
        cache_key = f"props_{device_serial}_{hash(tuple(sorted(properties)))}"

        # Check cache
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        # Get properties
        try:
            prop_commands = [f"echo '{prop}:'; getprop {prop}" for prop in properties]
            combined_command = "; ".join(prop_commands)

            stdout, _ = await self.adb.run_command("-s", device_serial, "shell", combined_command)

            # Parse output
            result = {}
            lines = stdout.split('\n')
            current_prop = None

            for line in lines:
                line = line.strip()
                if line.endswith(':'):
                    current_prop = line[:-1]
                elif current_prop and line:
                    result[current_prop] = line
                    current_prop = None

            # Cache result
            self._set_cache(cache_key, result)
            return result

        except AdbError as e:
            self.logger.warning("Failed to get device properties", device=device_serial, error=str(e))
            return {}

    async def _get_device_status(self, device_serial: str) -> Optional[str]:
        """Return the raw ADB status for a device serial if available."""

        devices = await self._get_device_list()
        for serial, status in devices:
            if serial == device_serial:
                return status
        return None

    async def _test_device_connection(self, device_serial: str) -> bool:
        """Test if device is accessible and responsive."""

        status = await self._get_device_status(device_serial)

        if status is None:
            self.logger.warning("Device not present in adb device list", device=device_serial)
            raise DeviceConnectionError(device_serial, "not_found")

        normalized_status = status.lower()
        if normalized_status not in {"device", "online"}:
            self.logger.warning(
                "Device reported abnormal status",
                device=device_serial,
                status=normalized_status,
            )
            raise DeviceConnectionError(
                device_serial,
                "abnormal_status",
                status=normalized_status,
            )

        try:
            # Try a simple command to test connectivity
            stdout, _ = await self.adb.run_command("-s", device_serial, "shell", "echo", "test")
        except AdbError as error:
            self.logger.warning(
                "Device shell command failed",
                device=device_serial,
                error=str(error),
            )
            raise DeviceConnectionError(
                device_serial,
                "adb_command_failed",
                status=normalized_status,
                details=str(error),
            ) from error

        if stdout.strip() != "test":
            self.logger.warning(
                "Unexpected device echo response",
                device=device_serial,
                stdout=stdout.strip(),
            )
            raise DeviceConnectionError(
                device_serial,
                "unexpected_response",
                status=normalized_status,
                details=stdout.strip(),
            )

        self.logger.debug("Device connection test succeeded", device=device_serial)
        return True

    async def _get_device_info_with_detector(self, model: str, brand: str, manufacturer: str, product_name: str, product_device: str, android_version: str) -> Dict[str, Optional[str]]:
        """Get enhanced device information using DeviceDetector library."""
        if not DEVICE_DETECTOR_AVAILABLE or DeviceDetector is None:
            raise RuntimeError("DeviceDetector library is not available")

        # Create a user agent string that DeviceDetector can parse using actual Android version
        user_agent = f"Mozilla/5.0 (Linux; Android {android_version}; {model}) AppleWebKit/537.36"

        # Use DeviceDetector to parse the device information
        detector = DeviceDetector(user_agent)
        device_info = detector.parse()

        # Extract device information from DeviceDetector result
        device_data = device_info.get('device', {}) if isinstance(device_info, dict) else {}
        brand_name = device_data.get('brand', brand) if isinstance(device_data, dict) else brand
        model_name = device_data.get('model', model) if isinstance(device_data, dict) else model

        # Generate device name
        device_name = None
        if brand_name and brand_name.lower() != 'unknown':
            if model_name and model_name.lower() != 'unknown device':
                device_name = f"{brand_name} {model_name}"
            else:
                device_name = brand_name
        else:
            device_name = model_name if model_name != "Unknown Device" else "Unknown Device"

        # Clean up the device name
        device_name = self._clean_device_name(device_name)

        return {
            'brand': brand_name,
            'device_name': device_name
        }

    def _clean_device_name(self, device_name: str) -> str:
        """Clean and format device name for better readability."""
        if not device_name:
            return "Unknown Device"

        # Remove common unwanted suffixes
        cleaned_name = device_name
        for suffix in _UNWANTED_SUFFIXES:
            # Use case-insensitive replacement
            suffix_lower = suffix.lower()
            while cleaned_name.lower().endswith(suffix_lower):
                # Find the actual suffix in the original case
                end_pos = len(cleaned_name) - len(suffix)
                if end_pos >= 0:
                    cleaned_name = cleaned_name[:end_pos]
                else:
                    break

        # Remove extra whitespace
        cleaned_name = ' '.join(cleaned_name.split())

        # Capitalize properly
        cleaned_name = cleaned_name.title()

        return cleaned_name

    # --- Frida Server Management ---

    async def ensure_frida_server_is_running(
        self,
        device: Optional[Device] = None,
        device_identifier: Optional[str] = None,
    ) -> bool:
        """
        Ensure frida-server is running on the connected device.

        Args:
            device: Device to provision frida-server on.
            device_identifier: Device serial/identifier to resolve when a Device object
                isn't provided. If neither device nor identifier are provided, the first
                available device will be used (legacy behaviour).

        Returns:
            True if frida-server is ready, False otherwise
        """
        if not frida:
            self.logger.error("Frida library not available")
            return False

        try:
            device = await self._resolve_device_for_frida(device, device_identifier)
            if device is None:
                return False

            # Use the frida manager to provision the server for the specific device
            target_version = frida.__version__
            await self.frida_manager.provision(device.serial, device.architecture, target_version)

            self.logger.info("Frida server setup completed", device=device.serial)
            return True

        except Exception as e:
            self.logger.error("Frida server setup failed", error=str(e), error_type=type(e).__name__)
            return False

    async def _resolve_device_for_frida(
        self,
        device: Optional[Device],
        device_identifier: Optional[str],
    ) -> Optional[Device]:
        """Resolve a device object for frida provisioning based on provided inputs."""

        if device:
            if device_identifier and device.serial != device_identifier:
                self.logger.warning(
                    "Provided device does not match specified identifier",
                    provided=device.serial,
                    requested=device_identifier,
                )
            return device

        if device_identifier:
            devices = await self.discover_devices(timeout=5.0)
            for candidate in devices:
                if candidate.serial == device_identifier:
                    return candidate

            self.logger.error(
                "Specified device not found for frida-server setup",
                device=device_identifier,
            )
            return None

        devices = await self.discover_devices(timeout=5.0)
        if not devices:
            self.logger.error("No devices available for frida-server setup")
            return None

        return devices[0]

    # --- Caching ---

    def _get_cache(self, key: str) -> Optional[Any]:
        """Get cached value if not expired."""
        entry = self._cache.get(key)
        if entry and not entry.is_expired():
            return entry.data
        elif entry and entry.is_expired():
            del self._cache[key]
        return None

    def _set_cache(self, key: str, data: Any, ttl_seconds: Optional[int] = None) -> None:
        """Set cached value with TTL."""
        ttl = ttl_seconds or self._cache_timeout
        self._cache[key] = CacheEntry(data=data, timestamp=datetime.now(), ttl_seconds=ttl)

    # --- ADB Server Management ---

    async def start_adb_server(self) -> None:
        """Start the ADB server."""
        await self.adb.start_server()

    async def kill_adb_server(self) -> None:
        """Kill the ADB server."""
        await self.adb.kill_server()

    async def restart_adb_server(self) -> None:
        """Restart the ADB server."""
        await self.adb.restart_server()


    async def is_adb_server_running(self) -> bool:
        """Check if the local ADB server is listening on port 5037."""
        try:
            with socket.create_connection(("127.0.0.1", 5037), timeout=0.5):
                return True
        except Exception:
            return False

    async def get_adb_version(self) -> Optional[str]:
        """Return adb version string if available."""
        try:
            stdout, _ = await self.adb.run_command("--version", timeout=2.0)
            # First line usually like: Android Debug Bridge version 1.0.41
            first_line = stdout.split("\n", 1)[0].strip()
            return first_line
        except Exception:
            return None

    async def get_adb_status(self) -> AdbStatus:
        """Return complete ADB server status."""
        try:
            running = await self.is_adb_server_running()
            version = await self.get_adb_version() if running else None
            return AdbStatus(running=running, version=version)
        except Exception as e:
            self.logger.warning("Failed to get ADB status", error=str(e))
            return AdbStatus(running=False, version=None)
