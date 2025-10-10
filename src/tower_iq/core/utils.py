import asyncio
import subprocess
from datetime import datetime
from typing import Tuple


def format_currency(value: float, symbol: str = "$", pad_to_cents: bool = False) -> str:
    """
    Formats a number into a Grafana-style abbreviated currency string up to decillion.
    Always rounds to 2 decimal places, no commas, negative sign always to the left of the symbol (e.g., -$1.23M), symbol prefix.
    If pad_to_cents is True, always show two decimal places (e.g., $0.00, $123.00) even for values < 1e3.
    """
    thresholds = [
        (1e33, "D"),
        (1e30, "N"),
        (1e27, "O"),
        (1e24, "S"),
        (1e21, "s"),
        (1e18, "Q"),
        (1e15, "q"),
        (1e12, "T"),
        (1e9,  "B"),
        (1e6,  "M"),
        (1e3,  "K"),
    ]
    abs_value = abs(value)
    for threshold, suffix in thresholds:
        if abs_value >= threshold:
            formatted = f"{abs_value / threshold:.2f}{suffix}"
            break
    else:
        if pad_to_cents:
            formatted = f"{abs_value:.2f}"
        else:
            formatted = f"{abs_value:.0f}" if abs_value == int(abs_value) else f"{abs_value:.2f}"
    if value < 0:
        return f"-{symbol}{formatted}"
    else:
        return f"{symbol}{formatted}"

def format_duration(seconds: float) -> str:
    """
    Formats a duration in seconds to DD:HH:MM:SS (days, hours, minutes, seconds).
    Always shows two digits for each field, omits days if zero.
    """
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days > 0:
        return f"{days:02}:{hours:02}:{minutes:02}:{secs:02}"
    else:
        return f"{hours:02}:{minutes:02}:{secs:02}"

class AdbError(Exception):
    """Custom exception for ADB command failures."""
    def __init__(self, message, stdout=None, stderr=None):
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr

class AdbWrapper:
    """A wrapper for executing ADB commands asynchronously."""

    def __init__(self, logger, verbose_debug: bool = False):
        self.logger = logger.bind(source="AdbWrapper")
        self.verbose_debug = verbose_debug

        # ADB server state tracking for Phase 1.1 of duplication fix
        self._server_running = None  # None = unknown, True = running, False = stopped
        self._last_check = None  # datetime of last server status check
        self._check_timeout = 30  # Cache timeout in seconds

    async def run_command(self, *args, timeout: float = 10.0) -> Tuple[str, str]:
        """
        Executes an ADB command and returns its output.

        Args:
            *args: Command and arguments for adb.
            timeout: Command timeout in seconds.

        Returns:
            A tuple of (stdout, stderr).

        Raises:
            AdbError: If the command returns a non-zero exit code or times out.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "adb", *args,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout_b, stderr_b = await asyncio.wait_for(process.communicate(), timeout=timeout)

            stdout = stdout_b.decode().strip()
            stderr = stderr_b.decode().strip()

            if process.returncode != 0:
                if self.verbose_debug:
                    self.logger.warning("ADB command failed", args=args, retcode=process.returncode, stderr=stderr)
                raise AdbError(f"ADB command failed: {' '.join(args)}", stdout, stderr)

            return stdout, stderr
        except asyncio.TimeoutError:
            raise AdbError(f"ADB command timed out after {timeout}s: {' '.join(args)}")
        except FileNotFoundError:
            raise AdbError("`adb` executable not found. Is it in your system's PATH?")
        except Exception as e:
            raise AdbError(f"An unexpected error occurred: {e}")

    async def shell(self, device_id: str, command: str, timeout: float = 10.0) -> str:
        """Executes a shell command on a device and returns stdout."""
        stdout, _ = await self.run_command("-s", device_id, "shell", command, timeout=timeout)
        return stdout

    async def push(self, device_id: str, local_path: str, device_path: str):
        """Pushes a file to the device."""
        await self.run_command("-s", device_id, "push", local_path, device_path)

    async def connect(self, host: str, port: int) -> str:
        """Connects to a network device."""
        stdout, _ = await self.run_command("connect", f"{host}:{port}", timeout=2.0)
        return stdout

    async def list_devices(self) -> list[str]:
        """Lists all connected device serials."""
        self.logger.debug("AdbWrapper.list_devices called (entry)")
        try:
            stdout, _ = await self.run_command("devices", timeout=5.0)
            devices = []
            for line in stdout.split('\n')[1:]:
                if '\tdevice' in line:
                    devices.append(line.split('\t')[0].strip())
            self.logger.debug(f"AdbWrapper.list_devices returning {len(devices)} devices: {devices}")
            return devices
        except AdbError as e:
            self.logger.error(f"AdbWrapper.list_devices caught AdbError: {e}")
            return [] # Return empty list if command fails

    async def _is_server_running_cached(self, force_check: bool = False) -> bool:
        """Check if ADB server is running using cached status when possible.
        
        Args:
            force_check: If True, bypass cache and perform fresh check
        """
        now = datetime.now()

        # Check if we have a valid cached result (unless forced)
        if (not force_check and
            self._server_running is not None and
            self._last_check is not None and
            (now - self._last_check).total_seconds() < self._check_timeout):
            self.logger.debug("Using cached ADB server status", cached_status=self._server_running)
            return self._server_running

        # Cache expired, forced, or no cache - check server status
        # Check port 5037 instead of running 'adb devices' to avoid auto-starting the server
        try:
            with socket.create_connection(("127.0.0.1", 5037), timeout=0.5):
                # Port is listening, server is running
                self._server_running = True
                self._last_check = now
                self.logger.debug("ADB server status checked and cached", status="running")
                return True
        except Exception:
            # Port is not listening, server is not running
            self._server_running = False
            self._last_check = now
            self.logger.debug("ADB server status checked and cached", status="not running")
            return False

    async def start_server(self) -> None:
        """Start the ADB server only if it's not already running."""
        try:
            # Check cached status before attempting to start
            if await self._is_server_running_cached():
                self.logger.debug("ADB server already running, skipping start")
                return

            self.logger.info("Starting ADB server...")
            await self.run_command("start-server", timeout=10.0)

            # Update cache to reflect successful start
            self._server_running = True
            self._last_check = datetime.now()

            self.logger.info("ADB server started successfully")
        except AdbError as e:
            # Reset cache on error to force recheck next time
            self._server_running = False
            self._last_check = datetime.now()
            self.logger.error(f"Failed to start ADB server: {e}")
            raise

    async def kill_server(self) -> None:
        """Kill the ADB server."""
        try:
            self.logger.info("Killing ADB server...")
            await self.run_command("kill-server", timeout=10.0)

            # Update cache to reflect server being killed
            self._server_running = False
            self._last_check = datetime.now()

            self.logger.info("ADB server killed successfully")
        except AdbError as e:
            # Reset cache on error to force recheck next time
            self._server_running = None
            self._last_check = None
            self.logger.error(f"Failed to kill ADB server: {e}")
            raise

    async def restart_server(self) -> None:
        """Restart the ADB server using proper condition waiting."""
        from .async_utils import wait_for_condition
        
        try:
            self.logger.info("Restarting ADB server...")
            await self.kill_server()
            
            # Wait for server to actually stop (not arbitrary delay)
            # Use force_check=True to bypass cache during verification
            async def server_stopped():
                return not await self._is_server_running_cached(force_check=True)
            
            stopped = await wait_for_condition(
                server_stopped,
                timeout=5.0,
                initial_delay=0.1,
                max_delay=0.5,  # Reduced from 1.0s since we need faster checks
                condition_name="ADB server stopped"
            )
            
            if not stopped:
                self.logger.warning("Timed out waiting for ADB server to stop, proceeding anyway")
            
            await self.start_server()
            
            # Verify server is actually running (not just assuming)
            # Use force_check=True to bypass cache during verification
            async def server_running():
                return await self._is_server_running_cached(force_check=True)
            
            started = await wait_for_condition(
                server_running,
                timeout=5.0,
                initial_delay=0.1,
                max_delay=0.5,  # Reduced from 1.0s since we need faster checks
                condition_name="ADB server started"
            )
            
            if started:
                self.logger.info("ADB server restarted successfully")
            else:
                self.logger.error("ADB server restart completed but verification check failed")
                raise AdbError("ADB server failed to start after restart")
                
        except AdbError as e:
            self.logger.error(f"Failed to restart ADB server: {e}")
            raise
