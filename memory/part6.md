
### **Task 1.2: Implement Intelligent `frida-server` Management in `EmulatorService` (Revised with Live Download)**

*   **Component to Modify:** `src/tower_iq/services/emulator_service.py`
*   **Actions:**

    1.  **Create the Orchestration Method:**
        *   **Method:** `async def ensure_frida_server_is_running(self, device_id: str) -> None:`
        *   **Purpose:** To execute the full idempotent setup logic for `frida-server`.
        *   **Implementation:** It will call the helper methods below in sequence. This method must raise a specific `FridaServerSetupError` with a clear message on any failure.
            ```python
            # Inside ensure_frida_server_is_running...
            try:
                self.logger.info("Starting frida-server setup...", device=device_id)
                arch = await self.get_device_architecture(device_id)
                
                # This single method now handles download/caching.
                local_path, version = await self._get_latest_frida_server_local(arch)
                
                device_path = "/data/local/tmp/frida-server"
                
                needs_push = await self._check_if_device_server_is_outdated(device_id, local_path, device_path)
                
                if needs_push:
                    self.logger.info("Device frida-server is outdated or missing. Pushing new version.", version=version)
                    await self.push_file(device_id, local_path, device_path)
                else:
                    self.logger.info("Device frida-server is up-to-date. No push needed.")

                is_running = await self.is_frida_server_running(device_id, version) # Pass version to check
                if not is_running:
                    self.logger.info("Frida-server process not running. Starting it now.")
                    await self.start_frida_server(device_id, device_path)
                else:
                    self.logger.info("Frida-server process is already running.")

                self.logger.info("Frida-server setup complete.", device=device_id, version=version)
            
            except Exception as e:
                self.logger.error("Frida-server setup failed.", error=str(e))
                raise FridaServerSetupError(str(e)) from e
            ```

    2.  **Implement Helper Methods:**

        *   **NEW/REWRITTEN Method:** `async def _get_latest_frida_server_local(self, arch: str) -> tuple[Path, str]:`
            *   **Purpose:** This is the core of the new logic. It ensures the latest version of `frida-server` for the given architecture is available locally, downloading it if necessary.
            *   **Returns:** A tuple containing the `Path` to the local binary and its `version` string.
            *   **Implementation:**
                1.  **Get Latest Version:** Use `aiohttp` to make a GET request to the Frida GitHub API releases endpoint: `https://api.github.com/repos/frida/frida/releases/latest`.
                2.  Parse the JSON response to get the latest version tag (e.g., `"16.3.5"`).
                3.  **Construct Paths:** Define a local cache directory (e.g., `data/frida-server/`) and the expected filename for the binary: `frida-server-<version>-android-<arch>`.
                4.  **Check Cache:** Check if this specific version already exists locally. If it does, log "Using cached version" and return the path and version.
                5.  **Download if Missing:** If the file doesn't exist:
                    *   Construct the download URL for the `.xz` archive from the GitHub release assets (e.g., `https://github.com/frida/frida/releases/download/<version>/frida-server-<version>-android-<arch>.xz`).
                    *   Use `aiohttp` to download the `.xz` file into memory or a temporary file.
                    *   Use the `lzma` library to decompress the archive.
                    *   Save the resulting binary to the local cache path.
                    *   Log "Successfully downloaded and cached frida-server."
                6.  Return the final local path and the version string.

        *   **REVISED Method:** `async def _check_if_device_server_is_outdated(self, device_id: str, local_path: Path, device_path: str) -> bool:`
            *   **Action:** No change in logic, but it's now more important than ever. It compares the hash of the local binary (which we now know is the latest version) with the hash of the binary on the device.

        *   **REVISED Method:** `async def is_frida_server_running(self, device_id: str, expected_version: str) -> bool:`
            *   **Action:** This method must be enhanced to not only check if the process is running, but if the *correct version* is running.
            *   **New Logic:**
                1.  Check if `frida-server` is in the `ps -A` output. If not, return `False`.
                2.  If it is running, execute `adb shell "<device_path> --version"`.
                3.  Parse the output and compare it to the `expected_version` string.
                4.  If the versions don't match, log a warning, run a command to `killall frida-server` on the device, and return `False` (this will trigger the `start_frida_server` method to launch the correct version).
                5.  If the versions match, return `True`.

        *   **REVISED Method:** `async def start_frida_server(self, device_id: str, device_path: str) -> None:`
            *   **Action:** This method's logic is mostly the same, but it must now perform a post-start verification.
            *   **New Logic:**
                1.  Run `adb shell "su -c <device_path> &"` to start the server.
                2.  `await asyncio.sleep(2)` to give it a moment to initialize.
                3.  Call `await self.is_frida_server_running(...)` again to confirm that the process has actually started and is the correct version. If this final check fails, raise an exception.

        *   **Method:** `async def push_file(self, device_id: str, local_path: Path, device_path: str) -> None:`
            *   **Action:** No change. The existing logic to `rm` the old file and then `push` the new one is correct.