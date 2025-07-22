import asyncio
import hashlib
import lzma
from pathlib import Path
from typing import Any
import aiohttp
import frida

from src.tower_iq.core.utils import AdbWrapper, AdbError

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

    async def provision(self, device_id: str, arch: str):
        """
        Ensure a compatible frida-server is running on the device.
        """
        target_version = frida.__version__
        self.logger.info(f"Provisioning frida-server v{target_version} for {arch} on {device_id}")

        # 1. Download binary if needed
        local_path = await self._get_frida_server_binary(arch, target_version)

        # 2. Push to device if it's missing or outdated
        if await self._is_push_required(device_id, local_path):
            await self._push_to_device(device_id, local_path)
        
        # 3. Start the server
        await self._start_server(device_id)

        # 4. Verify it's responsive
        if not await self._wait_for_responsive(device_id):
            raise FridaServerSetupError("Server was started but failed to become responsive.")
        
        self.logger.info("Frida-server provisioning successful.")

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
        await self.adb.push(device_id, str(local_path), self.DEVICE_PATH)
        await self.adb.shell(device_id, f"chmod 755 {self.DEVICE_PATH}")

    async def _start_server(self, device_id: str):
        self.logger.info("Starting frida-server on device...")
        try:
            # Kill any existing frida-server processes
            await self.adb.shell(device_id, "su -c 'pkill frida-server'", timeout=5.0)
            await asyncio.sleep(1)  # Give it time to clean up
        except AdbError:
            pass
        
        # Use a more reliable method to start frida-server in background
        # Try multiple approaches with shorter timeouts to avoid hanging
        start_commands = [
            f"su -c 'nohup {self.DEVICE_PATH} > /dev/null 2>&1 &'",
            f"su -c '{self.DEVICE_PATH} &'",
            f"su -c 'setsid {self.DEVICE_PATH} &'"
        ]
        
        for i, cmd in enumerate(start_commands):
            try:
                self.logger.debug(f"Trying start method {i+1}: {cmd}")
                # Use shorter timeout to prevent hanging
                await self.adb.shell(device_id, cmd, timeout=3.0)
                self.logger.debug(f"Start command {i+1} completed successfully")
                break
            except AdbError as e:
                self.logger.warning(f"Start method {i+1} failed: {e}")
                if i == len(start_commands) - 1:
                    # If all methods fail, raise the last error
                    raise AdbError(f"All frida-server start methods failed. Last error: {e}")
        
        # Give the server a moment to start
        await asyncio.sleep(2)

    async def _wait_for_responsive(self, device_id: str, timeout: int = 15) -> bool:
        self.logger.info("Waiting for frida-server to become responsive...")
        for _ in range(timeout):
            try:
                device = await asyncio.get_running_loop().run_in_executor(
                    None, lambda: frida.get_device(id=device_id, timeout=1)
                )
                await asyncio.get_running_loop().run_in_executor(None, device.enumerate_processes)
                self.logger.info("Frida-server is responsive.")
                return True
            except Exception:
                await asyncio.sleep(1)
        return False 