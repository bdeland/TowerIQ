
### **Instructions for AI Coding Agent**

**Objective:** Update the `emulator_service.py` file to implement a more robust, multi-stage Android device discovery mechanism that can find network-based emulators (like MuMu Player) and improve the Frida server management logic.

**File to Modify:** `emulator_service.py`

---

**Step 1: Add New Helper Methods for Network Scanning and Process Management**

Add the following three new helper methods to the `EmulatorService` class. A good location is after the `is_frida_server_running` method.

```python
    # ### NEW ### Helper to kill frida-server
    async def _kill_frida_server(self, device_id: str):
        """Kills any running frida-server process on the device."""
        self.logger.debug("Attempting to kill frida-server process.", device=device_id)
        await asyncio.create_subprocess_exec(
            "adb", "-s", device_id, "shell", "su", "-c", "killall frida-server",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.frida_server_running = False

    # ### NEW ###: Method to scan and connect to network emulators
    async def _scan_and_connect_network_devices(self):
        """Scans common localhost ports for emulators and tries to connect."""
        self.logger.info("Scanning for network-based emulators on localhost...")
        # Common ports for Android emulators (Nox, Memu, LDPlayer, etc.) plus MuMu Player
        ports_to_scan = list(range(5555, 5585, 2)) + [7555] # Add other known ports here if needed
        
        tasks = [self._try_adb_connect("127.0.0.1", port) for port in ports_to_scan]
        await asyncio.gather(*tasks)
        self.logger.info("Network scan completed.")

    # ### NEW ###: Helper for the network scan
    async def _try_adb_connect(self, ip: str, port: int):
        """Attempts to 'adb connect' to a given IP and port with a timeout."""
        target = f"{ip}:{port}"
        try:
            process = await asyncio.create_subprocess_exec(
                "adb", "connect", target,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            # Short timeout per connection attempt
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=2.0)
            output = stdout.decode().strip()
            if "connected to" in output or "already connected" in output:
                self.logger.debug(f"Successfully connected to emulator at {target}")
        except asyncio.TimeoutError:
            # This is expected for ports that are not open or not responsive
            self.logger.debug(f"Connection attempt to {target} timed out.")
        except Exception as e:
            self.logger.warning(f"Error trying to connect to {target}", error=str(e))
```

---

**Step 2: Replace the Core Device Discovery Method**

Replace the entire `_get_connected_devices` method with the following new implementation. This new version performs the three-stage discovery process.

```python
    async def _get_connected_devices(self) -> list[str]:
        """
        Get list of connected ADB devices using both standard discovery and network scan.
        This is the new "bulletproof" method.
        """
        self.logger.info("Starting comprehensive device discovery...")
        
        # Use a set to automatically handle duplicate device entries
        found_devices: Set[str] = set()
        
        # --- Stage 1: Standard 'adb devices' command ---
        try:
            process = await asyncio.create_subprocess_exec("adb", "devices", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=8.0)
            
            if process.returncode == 0:
                lines = stdout.decode().split('\n')[1:]
                for line in lines:
                    if '\tdevice' in line:
                        device_id = line.split('\t')[0].strip()
                        if device_id:
                            found_devices.add(device_id)
                self.logger.info("Standard discovery found devices", devices=list(found_devices))
            else:
                self.logger.warning("Standard 'adb devices' command failed.", error=stderr.decode())
        except asyncio.TimeoutError:
            self.logger.error("Standard 'adb devices' command timed out.")
        except Exception as e:
            self.logger.error("Error during standard device discovery", error=str(e))

        # --- Stage 2: Proactive network scan for emulators ---
        await self._scan_and_connect_network_devices()

        # --- Stage 3: Final 'adb devices' to consolidate all findings ---
        try:
            process = await asyncio.create_subprocess_exec("adb", "devices", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=8.0)
            
            if process.returncode == 0:
                lines = stdout.decode().split('\n')[1:]
                for line in lines:
                    if '\tdevice' in line:
                        device_id = line.split('\t')[0].strip()
                        if device_id:
                            found_devices.add(device_id)
            else:
                self.logger.warning("Final 'adb devices' command failed.", error=stderr.decode())
        except asyncio.TimeoutError:
            self.logger.error("Final 'adb devices' command timed out.")
        except Exception as e:
            self.logger.error("Error during final device consolidation", error=str(e))
            
        if found_devices:
            self.logger.info("Comprehensive discovery completed.", final_devices=list(found_devices))
        else:
            self.logger.warning("No devices found after comprehensive discovery.")
            
        return list(found_devices)
```

---

**Step 3: Update Public Methods to Accommodate Longer Scan Times**

Modify the `find_and_connect_device` and `find_connected_devices` methods to increase their timeouts.

**In `find_and_connect_device`:**
Change the `asyncio.wait_for` call:
*   **From:** `timeout=20.0`
*   **To:** `timeout=30.0`

**In `find_connected_devices`:**
Change the `asyncio.wait_for` call:
*   **From:** `timeout=12.0`
*   **To:** `timeout=30.0`

---

**Step 4: Improve Frida Server Management Logic**

Replace the `ensure_frida_server_is_running`, `start_frida_server`, and `is_frida_server_running` methods with their more robust versions below.

```python
    async def ensure_frida_server_is_running(self, device_id: str) -> None:
        """
        Execute the full idempotent setup logic for frida-server.
        
        This method ensures that the latest frida-server is downloaded, pushed to the device
        if needed, and is running with the correct version.
        
        Args:
            device_id: Device serial ID
            
        Raises:
            FridaServerSetupError: If any step of the setup fails
        """
        try:
            self.logger.info("Starting frida-server setup...", device=device_id)
            arch = await self.get_device_architecture(device_id)
            
            local_path, version = await self._get_latest_frida_server_local(arch)
            
            device_path = "/data/local/tmp/frida-server"
            
            needs_push = await self._check_if_device_server_is_outdated(device_id, local_path, device_path)
            
            if needs_push:
                self.logger.info("Device frida-server is outdated or missing. Pushing new version.", version=version)
                await self.push_file(device_id, local_path, device_path)
            else:
                self.logger.info("Device frida-server is up-to-date. No push needed.")

            is_running = await self.is_frida_server_running(device_id, expected_version=version)
            if not is_running:
                self.logger.info("Frida-server process not running or has wrong version. Starting it now.")
                await self.start_frida_server(device_id, device_path)
            else:
                self.logger.info("Frida-server process is already running with the correct version.")

            self.logger.info("Frida-server setup complete.", device=device_id, version=version)
        
        except Exception as e:
            self.logger.error("Frida-server setup failed.", error=str(e))
            raise FridaServerSetupError(str(e)) from e
    
    async def start_frida_server(self, device_id: str, device_path: str = "/data/local/tmp/frida-server") -> None:
        """
        Start the frida-server process on the device with post-start verification.
        
        Args:
            device_id: Device serial ID
            device_path: Path to the frida-server binary on the device
            
        Raises:
            Exception: If frida-server fails to start or verification fails
        """
        self.logger.info("Starting frida-server", device=device_id, path=device_path)
        
        try:
            # Kill any existing instances first to ensure a clean start
            await self._kill_frida_server(device_id)
            await asyncio.sleep(1) # Give a moment for the process to die

            # Start frida-server in the background using nohup
            await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "su", "-c", 
                f"nohup {device_path} > /dev/null 2>&1 &",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            await asyncio.sleep(3) # Give it a moment to initialize
            
            if not await self.is_frida_server_running(device_id):
                error_check = await asyncio.create_subprocess_exec(
                    "adb", "-s", device_id, "shell", "su", "-c", f"{device_path} --version",
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                _, error_stderr = await error_check.communicate()
                error_msg = error_stderr.decode().strip() if error_stderr else "Frida-server failed to start - check device permissions and architecture compatibility"
                raise Exception(f"Frida-server failed to start: {error_msg}")
            
            self.logger.info("frida-server started successfully", device=device_id)
            self.frida_server_running = True
                
        except Exception as e:
            self.logger.error("Error starting frida-server", device=device_id, error=str(e))
            raise
    
    async def is_frida_server_running(self, device_id: str, expected_version: Optional[str] = None) -> bool:
        """
        Check if frida-server is running on the device and optionally verify version.
        
        Args:
            device_id: Device serial ID
            expected_version: Expected version string to check against (optional)
            
        Returns:
            True if frida-server is running (and version matches if provided), False otherwise
        """
        try:
            # First check if frida-server process is running
            result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "ps", "-A", "|", "grep", "frida-server",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            if result.returncode != 0 or not stdout:
                self.frida_server_running = False
                return False

            if not expected_version:
                self.frida_server_running = True
                return True
            
            device_path = "/data/local/tmp/frida-server"
            version_result = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", f"su -c '{device_path} --version'",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            version_stdout, _ = await version_result.communicate()

            if version_result.returncode == 0:
                running_version = version_stdout.decode().strip()
                if expected_version in running_version:
                    self.logger.info("Frida-server version verified", version=running_version)
                    self.frida_server_running = True
                    return True
                else:
                    self.logger.warning("Frida-server version mismatch, killing process.", 
                                      expected=expected_version, running=running_version)
                    await self._kill_frida_server(device_id)
                    return False
            else:
                self.logger.warning("Could not verify frida-server version, killing process to be safe.")
                await self._kill_frida_server(device_id)
                return False
                
        except Exception as e:
            self.logger.error("Error checking frida-server status", device=device_id, error=str(e))
            return False
```

---

**Step 5: Consolidate File Pushing Logic and Remove Redundancy**

Replace the existing `push_file` method with this improved version. Then, remove the methods that are now redundant.

**Replace `push_file` with:**
```python
    async def push_file(self, device_id: str, local_path: Path, device_path: str) -> None:
        """
        Push a file from local filesystem to the Android device, ensuring it's clean and executable.
        
        Args:
            device_id: Device serial ID
            local_path: Path to the local file
            device_path: Path on the device where to place the file
            
        Raises:
            Exception: If the file push operation fails
        """
        self.logger.info("Pushing file to device", local=str(local_path), device=device_path)
        try:
            # Step 1: Remove old file first to prevent issues
            await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "rm", "-f", device_path,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            # Step 2: Push the new file
            push_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "push", str(local_path), device_path,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            _, stderr = await push_proc.communicate()
            if push_proc.returncode != 0:
                raise Exception(f"Failed to push file: {stderr.decode().strip()}")
            
            # Step 3: Set executable permissions
            chmod_proc = await asyncio.create_subprocess_exec(
                "adb", "-s", device_id, "shell", "chmod", "755", device_path,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            _, stderr = await chmod_proc.communicate()
            if chmod_proc.returncode != 0:
                raise Exception(f"Failed to set executable permissions: {stderr.decode().strip()}")
            
            self.logger.info("Successfully pushed and configured file on device.")
                
        except Exception as e:
            self.logger.error("Error during file push operation", error=str(e))
            raise
```

**Remove the following methods entirely:**
*   `install_frida_server`
*   `_push_file_to_device`
*   `_set_executable_permissions`

---
**Final Check:** After applying all changes, the file should contain the new network scanning logic in `_get_connected_devices`, the new helper methods (`_kill_frida_server`, `_scan_and_connect_network_devices`, `_try_adb_connect`), updated timeouts, and the cleaned-up Frida/file-pushing methods. The redundant methods should be gone.