import asyncio
import subprocess
from typing import Optional, Tuple

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

    def __init__(self, logger):
        self.logger = logger.bind(source="AdbWrapper")

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