### **TowerIQ - `FridaService` Finalization Task List**

**Objective:** To complete the `FridaService` by replacing all placeholder security and compatibility logic with the final, functional implementations using `aiohttp` and `pycryptodome`.

---

### **Task 1: Correct and Finalize the Hook Compatibility Check**

*   **Goal:** To fix the logic in `check_hook_compatibility` so it checks against the *remote* manifest, not a local file.
*   **Component to Modify:** `src/tower_iq/services/frida_service.py`
*   **Actions:**

    1.  **Rewrite `check_hook_compatibility(self, game_version: str) -> bool`:**
        *   **Remove** the current logic that loads a local `hook_contract.yaml`.
        *   **New Logic:**
            1.  Call `manifest = await self._fetch_remote_manifest()`.
            2.  Check if the `manifest` dictionary and the `manifest['hooks']` list exist.
            3.  Iterate through the `hooks` list and check if any dictionary in the list has a `'game_version'` key that matches the `game_version` argument.
            4.  Return `True` if a match is found, otherwise return `False`.

---

### **Task 2: Implement the Production Secure Download Workflow**

*   **Goal:** To replace all the dummy methods in `_download_and_verify_script` with real networking and cryptography.
*   **Component to Modify:** `src/tower_iq/services/frida_service.py`
*   **Actions:**

    1.  **Implement `_fetch_remote_manifest(self) -> dict`:**
        *   **Action:** Replace the current logic that creates a dummy local file.
        *   **New Logic:**
            1.  Get the manifest URL from your configuration: `manifest_url = self.config.get("frida.manifest_url")`.
            2.  Use `aiohttp.ClientSession` to perform an async `GET` request to `manifest_url`.
            3.  Await the response and parse the body as JSON (`await response.json()`).
            4.  Return the resulting dictionary.
            5.  Wrap the logic in a `try...except` block to handle network errors (`aiohttp.ClientError`) and JSON parsing errors.

    2.  **Implement `_download_encrypted_script(self, url: str) -> bytes`:**
        *   **Action:** Replace the `return b"dummy_encrypted_content"`.
        *   **New Logic:**
            1.  Use `aiohttp.ClientSession` to perform an async `GET` request to the provided `url`.
            2.  Await the response and return the raw bytes of the body (`await response.read()`).
            3.  Handle potential network errors.

    3.  **Implement `_verify_signature(self, content: bytes, signature_hex: str) -> bool`:**
        *   **Action:** Replace the `return True` placeholder.
        *   **New Logic:**
            1.  Load your public key from a bundled resource file (e.g., `resources/public_key.pem`). The path to this key should be in your `main_config.yaml`.
            2.  Import the key using `from Crypto.PublicKey import RSA`.
            3.  Create a SHA256 hash of the `content` (the encrypted bytes) using `from Crypto.Hash import SHA256`.
            4.  Import the signature scheme: `from Crypto.Signature import pkcs1_15`.
            5.  Use `pkcs1_15.new(public_key).verify(hash_obj, bytes.fromhex(signature_hex))`. This will raise a `ValueError` on failure.
            6.  Return `True` if verification succeeds, `False` if it fails (by catching the `ValueError`).

    4.  **Implement `_decrypt_script(self, encrypted_content: bytes) -> str`:**
        *   **Action:** Replace the dummy script return.
        *   **New Logic:**
            1.  Get the master AES key from your configuration: `aes_key_hex = self.config.get("secrets.script_encryption_key")`. Convert it to bytes: `aes_key = bytes.fromhex(aes_key_hex)`.
            2.  Import the AES cipher: `from Crypto.Cipher import AES`.
            3.  **Unpack the payload:** As designed in our build script, the `encrypted_content` contains the nonce, tag, and ciphertext concatenated. You must unpack them:
                ```python
                nonce = encrypted_content[:16]
                tag = encrypted_content[16:32]
                ciphertext = encrypted_content[32:]
                ```
            4.  Create a new AES cipher instance: `cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)`.
            5.  Call `decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)`. This will raise a `ValueError` if the tag is invalid (i.e., the content was tampered with).
            6.  Return the result as a UTF-8 string: `decrypted_bytes.decode('utf-8')`.

---

### **Task 3: Refine Configuration Integration**

*   **Goal:** To ensure all necessary configuration is cleanly passed from the `ConfigurationManager` instead of being hardcoded.
*   **Component to Modify:** `src/tower_iq/services/frida_service.py` and `config/main_config.yaml`.
*   **Actions:**

    1.  **Update `main_config.yaml`:** Ensure the following keys exist:
        ```yaml
        frida:
          manifest_url: "https://github.com/bdeland/toweriq-hooks/raw/main/manifest.json"
          public_key_path: "resources/public_key.pem" 
        ```
    2.  **Update `.env.example`:** Add `SCRIPT_ENCRYPTION_KEY=""`.
    3.  **Update `ConfigurationManager`:** In `_merge_configs`, add logic to pull `SCRIPT_ENCRYPTION_KEY` from the environment and place it at `secrets.script_encryption_key`.
    4.  **Update `FridaService`:** In `_download_and_verify_script`, ensure you use `self.config.get(...)` to retrieve these new configuration values rather than using hardcoded paths or keys.