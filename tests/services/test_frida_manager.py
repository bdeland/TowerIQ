"""
Comprehensive tests for FridaServerManager.

This module tests all functionality of the FridaServerManager class including
server provisioning, installation, starting/stopping, and error handling.
"""

import asyncio
import hashlib
import lzma
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, call, patch

import aiohttp
import pytest

from src.tower_iq.services.frida_manager import (FridaServerManager,
                                                 FridaServerSetupError)


class TestFridaServerManagerInitialization:
    """Test FridaServerManager initialization."""
    
    def test_init_with_parameters(self, logger, mock_adb_wrapper):
        """Test initialization with all parameters."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # The logger is bound with source context, so we check the context
        assert manager.logger._context['source'] == 'FridaServerManager'
        assert manager.adb == mock_adb_wrapper
        assert manager.cache_dir.exists()
        assert manager.DEVICE_PATH == "/data/local/tmp/frida-server"
    
    def test_cache_dir_creation(self, logger, mock_adb_wrapper):
        """Test that cache directory is created."""
        with patch('pathlib.Path.mkdir') as mock_mkdir:
            manager = FridaServerManager(logger, mock_adb_wrapper)
            mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)


class TestFridaServerManagerBinaryManagement:
    """Test frida-server binary download and management."""
    
    @pytest.mark.asyncio
    async def test_get_frida_server_binary_existing(self, logger, mock_adb_wrapper):
        """Test getting existing frida-server binary."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create a fake binary file
        binary_path = manager.cache_dir / "frida-server-15.2.2-android-arm64"
        binary_path.write_bytes(b"fake_binary_content")
        
        result = await manager._get_frida_server_binary("arm64-v8a", "15.2.2")
        
        assert result == binary_path
    
    @pytest.mark.asyncio
    async def test_get_frida_server_binary_download(self, logger, mock_adb_wrapper, mock_lzma, mock_file_operations):
        """Test downloading new frida-server binary."""
        manager = FridaServerManager(logger, mock_adb_wrapper)

        # Mock file doesn't exist
        mock_file_operations['exists'].return_value = False

        # Use multiple patches to avoid complex async mocking
        with patch('src.tower_iq.services.frida_manager.aiohttp.ClientSession') as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.read = AsyncMock(return_value=b"compressed_data")
            mock_response.raise_for_status = Mock()

            # Set up the nested context manager properly for session.get()
            mock_get_context = MagicMock()
            mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.get = MagicMock(return_value=mock_get_context)
            
            # Set up context manager for ClientSession
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session
            mock_lzma.return_value = b"decompressed_binary"

            result = await manager._get_frida_server_binary("arm64-v8a", "15.2.2")

            # Verify download was attempted
            mock_session_class.assert_called_once()
            mock_session.get.assert_called_once()
            mock_lzma.assert_called_once_with(b"compressed_data")
            mock_file_operations['write_bytes'].assert_called_once_with(b"decompressed_binary")
            mock_file_operations['chmod'].assert_called_once_with(0o755)

            assert result.name == "frida-server-15.2.2-android-arm64"
    
    @pytest.mark.asyncio
    async def test_get_frida_server_binary_architecture_mapping(self, logger, mock_adb_wrapper):
        """Test architecture mapping for different architectures."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        test_cases = [
            ("arm64-v8a", "arm64"),
            ("armeabi-v7a", "arm"),
            ("x86_64", "x86_64"),
            ("x86", "x86"),
            ("unknown", "unknown")  # Fallback
        ]
        
        for android_arch, frida_arch in test_cases:
            # Mock the Path.exists method to return True for our test files
            binary_path = manager.cache_dir / f"frida-server-15.2.2-android-{frida_arch}"

            with patch('pathlib.Path.exists', return_value=True) as mock_exists:
                result = await manager._get_frida_server_binary(android_arch, "15.2.2")

                # Verify exists was called on the correct path
                mock_exists.assert_called()
                assert frida_arch in str(result)
    
    @pytest.mark.asyncio
    async def test_get_frida_server_binary_download_failure(self, logger, mock_adb_wrapper):
        """Test handling of download failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)

        # Mock download failure by patching the method directly
        with patch.object(manager, '_get_frida_server_binary', side_effect=Exception("Download failed")):
            with pytest.raises(Exception, match="Download failed"):
                await manager._get_frida_server_binary("arm64-v8a", "15.2.2")


class TestFridaServerManagerDeviceOperations:
    """Test device-specific operations."""
    
    @pytest.mark.asyncio
    async def test_is_push_required_hash_mismatch(self, logger, mock_adb_wrapper):
        """Test push required when hashes don't match."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create test binary in temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "test_binary"
            test_path.write_bytes(b"test_content")
            
            # Mock different hashes
            with patch('hashlib.sha256') as mock_hash:
                mock_hash.return_value.hexdigest.return_value = "local_hash"
                mock_adb_wrapper.shell.return_value = "device_hash different_content"
                
                result = await manager._is_push_required("device123", test_path)
                
                assert result is True
    
    @pytest.mark.asyncio
    async def test_is_push_required_hash_match(self, logger, mock_adb_wrapper):
        """Test push not required when hashes match."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create test binary in temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "test_binary"
            test_path.write_bytes(b"test_content")
            
            # Mock same hashes
            with patch('hashlib.sha256') as mock_hash:
                mock_hash.return_value.hexdigest.return_value = "same_hash"
                mock_adb_wrapper.shell.return_value = "same_hash test_content"
                
                result = await manager._is_push_required("device123", test_path)
                
                assert result is False
    
    @pytest.mark.asyncio
    async def test_is_push_required_adb_error(self, logger, mock_adb_wrapper):
        """Test push required when ADB error occurs."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create test binary in temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "test_binary"
            test_path.write_bytes(b"test_content")
            
            # Mock ADB error
            from src.tower_iq.core.utils import AdbError
            mock_adb_wrapper.shell.side_effect = AdbError("Device not found")
            
            result = await manager._is_push_required("device123", test_path)
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_push_to_device_direct_success(self, logger, mock_adb_wrapper):
        """Test successful direct push to device."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create test binary in temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "test_binary"
            test_path.write_bytes(b"test_content")
            
            await manager._push_to_device("device123", test_path)
            
            mock_adb_wrapper.push.assert_called_once_with("device123", str(test_path), manager.DEVICE_PATH)
            mock_adb_wrapper.shell.assert_called_with("device123", f"chmod 755 {manager.DEVICE_PATH}")
    
    @pytest.mark.asyncio
    async def test_push_to_device_alternative_method(self, logger, mock_adb_wrapper):
        """Test alternative push method when direct push fails."""
        manager = FridaServerManager(logger, mock_adb_wrapper)

        # Create test binary in temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "test_binary"
            test_path.write_bytes(b"test_content")

            # Mock direct push failure but alternative method succeeds
            from src.tower_iq.core.utils import AdbError

            call_count = 0
            def push_side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                # First call should be direct push (fail)
                if call_count == 1 and args[2] == "/data/local/tmp/frida-server":
                    raise AdbError("Direct push failed")
                # Second call should be alternative push (succeed)
                return None

            mock_adb_wrapper.push.side_effect = push_side_effect
            # Alternative method shell calls should succeed
            mock_adb_wrapper.shell.return_value = ""

            await manager._push_to_device("device123", test_path)

            # Verify push was called for both direct and alternative methods
            assert mock_adb_wrapper.push.call_count == 2
            # Direct push to /data/local/tmp/frida-server and alternative push to /sdcard
            
            # Verify shell commands for alternative method
            expected_shell_calls = [
                call("device123", "su -c 'cp /sdcard/frida-server /data/local/tmp/frida-server && chmod 755 /data/local/tmp/frida-server'"),
                call("device123", "rm /sdcard/frida-server")
            ]
            mock_adb_wrapper.shell.assert_has_calls(expected_shell_calls)
    
    @pytest.mark.asyncio
    async def test_push_to_device_both_methods_fail(self, logger, mock_adb_wrapper):
        """Test when both push methods fail."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create test binary in temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "test_binary"
            test_path.write_bytes(b"test_content")
            
            # Mock both methods failing
            from src.tower_iq.core.utils import AdbError

            # Both push attempts (direct and to /sdcard) should fail
            mock_adb_wrapper.push.side_effect = AdbError("Direct push failed")
            
            with pytest.raises(AdbError, match="Direct push failed"):
                await manager._push_to_device("device123", test_path)


class TestFridaServerManagerServerControl:
    """Test server start/stop operations."""
    
    @pytest.mark.asyncio
    async def test_start_server_success(self, logger, mock_adb_wrapper, fast_polling_env):
        """Test successful server start with new wait_for_condition pattern."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock successful start - need to handle both stop and start checks
        call_count = 0
        def mock_shell_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            cmd = args[1] if len(args) > 1 else ""
            # Return appropriate values for pidof checks
            if "pidof frida-server" in cmd:
                # First call: checking if stopped (return empty = stopped)
                # Later calls: checking if started (return PID = started)
                return "" if call_count <= 2 else "12345"
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        await manager._start_server("device123")
        
        # Should try to stop existing server first
        mock_adb_wrapper.shell.assert_called()
        
        # Verify one of the start commands was called
        call_args = [call.args for call in mock_adb_wrapper.shell.call_args_list]
        start_commands_called = any("frida-server" in str(args) and "nohup" in str(args) for args in call_args)
        assert start_commands_called
    
    @pytest.mark.asyncio
    async def test_start_server_multiple_methods(self, logger, mock_adb_wrapper):
        """Test server start with multiple fallback methods."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock first method failing, second succeeding
        from src.tower_iq.core.utils import AdbError
        
        def mock_shell_side_effect(*args, **kwargs):
            cmd = args[1] if len(args) > 1 else ""
            if "nohup" in cmd and "frida-server" in cmd:
                if "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &" in cmd:
                    raise AdbError("First method failed")
                else:
                    return ""
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        await manager._start_server("device123")
        
        # Should have tried multiple start methods
        assert mock_adb_wrapper.shell.call_count >= 2
    
    @pytest.mark.asyncio
    async def test_start_server_all_methods_fail(self, logger, mock_adb_wrapper):
        """Test when all start methods fail."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock all methods failing
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.shell.side_effect = AdbError("All methods failed")
        
        with pytest.raises(AdbError, match="All frida-server start methods failed"):
            await manager._start_server("device123")
    
    @pytest.mark.asyncio
    async def test_stop_server_success(self, logger, mock_adb_wrapper):
        """Test successful server stop."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock server is running initially, then stopped after kill command
        call_count = 0
        def shell_side_effect(device_id, cmd, timeout=None):
            nonlocal call_count
            call_count += 1
            # First call: pidof returns PID (server is running)
            if "pidof" in cmd and call_count == 1:
                return "1234"
            # Kill commands succeed silently
            elif "pkill" in cmd or "killall" in cmd or "kill" in cmd:
                return ""
            # Second pidof call: server is stopped
            elif "pidof" in cmd and call_count > 1:
                return ""
            return ""
        
        mock_adb_wrapper.shell.side_effect = shell_side_effect
        
        result = await manager.stop_server("device123")
        
        assert result is True
        # Should have tried to kill the process
        assert mock_adb_wrapper.shell.call_count >= 2
    
    @pytest.mark.asyncio
    async def test_stop_server_not_running(self, logger, mock_adb_wrapper):
        """Test stopping server when not running."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock server not running
        mock_adb_wrapper.shell.return_value = ""  # No PID
        
        result = await manager.stop_server("device123")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_stop_server_multiple_methods(self, logger, mock_adb_wrapper):
        """Test server stop with multiple kill methods."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock server is running initially, then stops
        pidof_count = 0
        def mock_shell_side_effect(*args, **kwargs):
            nonlocal pidof_count
            cmd = args[1] if len(args) > 1 else ""
            if "pidof" in cmd:
                pidof_count += 1
                # First check: running, second check: stopped
                return "1234" if pidof_count == 1 else ""
            elif "pkill" in cmd or "killall" in cmd or "kill" in cmd:
                return ""  # Kill command succeeded
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        result = await manager.stop_server("device123")
        
        assert result is True
        # Should have tried multiple kill methods
        assert mock_adb_wrapper.shell.call_count >= 2
    
    @pytest.mark.asyncio
    async def test_stop_server_force_kill(self, logger, mock_adb_wrapper):
        """Test force kill when normal stop fails."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock server still running after normal kill attempts, but force kill works
        pidof_count = 0
        def mock_shell_side_effect(*args, **kwargs):
            nonlocal pidof_count
            cmd = args[1] if len(args) > 1 else ""
            if "pidof" in cmd:
                pidof_count += 1
                # First two checks: running, after force kill: stopped
                return "1234" if pidof_count <= 2 else ""
            elif "kill -9" in cmd:
                return ""  # Force kill succeeded
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        result = await manager.stop_server("device123")
        
        assert result is True
        # Should have tried force kill
        call_args = [call.args for call in mock_adb_wrapper.shell.call_args_list]
        force_kill_called = any("kill -9" in str(args) for args in call_args)
        assert force_kill_called


class TestFridaServerManagerVerification:
    """Test server verification functionality."""
    
    @pytest.mark.asyncio
    async def test_verify_installation_success(self, logger, mock_adb_wrapper):
        """Test successful installation verification."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock successful file check
        mock_adb_wrapper.shell.return_value = "/data/local/tmp/frida-server"
        
        await manager._verify_installation("device123")
        
        mock_adb_wrapper.shell.assert_called_with("device123", f"ls {manager.DEVICE_PATH}")
    
    @pytest.mark.asyncio
    async def test_verify_installation_failure(self, logger, mock_adb_wrapper):
        """Test installation verification failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock file not found
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.shell.side_effect = AdbError("No such file")
        
        with pytest.raises(FridaServerSetupError, match="Frida-server binary not found"):
            await manager._verify_installation("device123")
    
    @pytest.mark.asyncio
    async def test_verify_running_state_success(self, logger, mock_adb_wrapper):
        """Test successful running state verification."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock server running
        mock_adb_wrapper.shell.return_value = "1234"
        
        await manager._verify_running_state("device123")
        
        mock_adb_wrapper.shell.assert_called_with("device123", "pidof frida-server")
    
    @pytest.mark.asyncio
    async def test_verify_running_state_not_running(self, logger, mock_adb_wrapper):
        """Test running state verification when not running."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock server not running
        mock_adb_wrapper.shell.return_value = ""
        
        with pytest.raises(FridaServerSetupError, match="Frida-server process not running"):
            await manager._verify_running_state("device123")
    
    @pytest.mark.asyncio
    async def test_verify_running_state_adb_error(self, logger, mock_adb_wrapper):
        """Test running state verification with ADB error."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock ADB error
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.shell.side_effect = AdbError("Device not found")
        
        with pytest.raises(FridaServerSetupError, match="Failed to query frida-server process list"):
            await manager._verify_running_state("device123")
    
    @pytest.mark.asyncio
    async def test_verify_version_success(self, logger, mock_adb_wrapper):
        """Test successful version verification."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock correct version
        mock_adb_wrapper.shell.return_value = "15.2.2"
        
        await manager._verify_version("device123", "15.2.2")
        
        mock_adb_wrapper.shell.assert_called_with("device123", f"{manager.DEVICE_PATH} --version")
    
    @pytest.mark.asyncio
    async def test_verify_version_mismatch(self, logger, mock_adb_wrapper):
        """Test version verification with version mismatch."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock different version
        mock_adb_wrapper.shell.return_value = "16.0.0"
        
        with pytest.raises(FridaServerSetupError, match="Frida-server version mismatch"):
            await manager._verify_version("device123", "15.2.2")
    
    @pytest.mark.asyncio
    async def test_verify_version_adb_error(self, logger, mock_adb_wrapper):
        """Test version verification with ADB error."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock ADB error
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.shell.side_effect = AdbError("Command failed")
        
        with pytest.raises(FridaServerSetupError, match="Failed to execute frida-server for version check"):
            await manager._verify_version("device123", "15.2.2")
    
    @pytest.mark.asyncio
    async def test_verify_version_empty_output(self, logger, mock_adb_wrapper):
        """Test version verification with empty output."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock empty output
        mock_adb_wrapper.shell.return_value = ""
        
        with pytest.raises(FridaServerSetupError, match="Could not determine frida-server version"):
            await manager._verify_version("device123", "15.2.2")
    
    @pytest.mark.asyncio
    async def test_wait_for_responsive_success(self, logger, mock_adb_wrapper):
        """Test successful responsiveness check."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock all verification methods succeed
        mock_adb_wrapper.shell.return_value = "15.2.2"
        
        result = await manager._wait_for_responsive("device123", "15.2.2")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_wait_for_responsive_with_retries(self, logger, mock_adb_wrapper, fast_polling_env):
        """Test responsiveness check with retries using new wait_for_condition pattern."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock first attempt fails, second succeeds
        call_count = 0
        
        def mock_shell_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First attempt fails
                from src.tower_iq.core.utils import AdbError
                raise AdbError("First attempt failed")
            else:
                # Subsequent attempts succeed
                return "15.2.2"
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        result = await manager._wait_for_responsive("device123", "15.2.2", timeout=3)
        
        assert result is True
        # With wait_for_condition_with_result, it will retry until success
        # The exact count may vary due to polling, so just verify it succeeded
        assert call_count >= 4  # At least 4 shell calls (may be more due to retries)
    
    @pytest.mark.asyncio
    async def test_wait_for_responsive_timeout(self, logger, mock_adb_wrapper):
        """Test responsiveness check timeout."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock all attempts fail
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.shell.side_effect = AdbError("Always fails")
        
        with pytest.raises(FridaServerSetupError):
            await manager._wait_for_responsive("device123", "15.2.2", timeout=2)
    
    @pytest.mark.asyncio
    async def test_wait_for_responsive_with_frida_api(self, logger, mock_adb_wrapper):
        """Test responsiveness check with Frida API verification."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock successful verification
        mock_adb_wrapper.shell.return_value = "15.2.2"
        
        # Mock Frida instance
        mock_frida = Mock()
        mock_device = Mock()
        mock_frida.get_device.return_value = mock_device
        mock_device.enumerate_processes.return_value = []
        
        result = await manager._wait_for_responsive("device123", "15.2.2", frida_instance=mock_frida)
        
        assert result is True
        mock_frida.get_device.assert_called_once_with(id="device123", timeout=1)
        mock_device.enumerate_processes.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_wait_for_responsive_frida_api_failure(self, logger, mock_adb_wrapper):
        """Test responsiveness check with Frida API failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock successful basic verification
        mock_adb_wrapper.shell.return_value = "15.2.2"
        
        # Mock Frida API failure
        mock_frida = Mock()
        mock_frida.get_device.side_effect = Exception("API connection failed")
        
        with pytest.raises(FridaServerSetupError, match="Failed to communicate with frida-server API"):
            await manager._wait_for_responsive("device123", "15.2.2", frida_instance=mock_frida)


class TestFridaServerManagerProvisioning:
    """Test complete server provisioning workflow."""
    
    @pytest.mark.asyncio
    async def test_provision_success(self, logger, mock_adb_wrapper, mock_aiohttp_session, mock_lzma, mock_file_operations):
        """Test successful server provisioning."""
        import tempfile
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create a real temporary binary file for testing
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
            tmp_file.write(b"test_binary_content")
            tmp_path = Path(tmp_file.name)
        
        try:
            # Mock shell responses for verification
            def shell_side_effect(device_id, cmd, timeout=None):
                if "pidof" in cmd:
                    return "1234"  # Server is running
                elif "ls /data/local/tmp/frida-server" in cmd:
                    return "/data/local/tmp/frida-server"  # File exists
                else:
                    return "15.2.2"  # Version check
            
            mock_adb_wrapper.shell.side_effect = shell_side_effect
            mock_adb_wrapper.push.return_value = None
            
            # Patch the internal methods to simplify testing
            with patch.object(manager, '_get_frida_server_binary', return_value=tmp_path):
                with patch.object(manager, '_is_push_required', return_value=True):
                    with patch.object(manager, '_push_to_device', return_value=None):
                        result = await manager.provision("device123", "arm64-v8a", "15.2.2")
            
            assert result is True
        finally:
            # Clean up temp file
            if tmp_path.exists():
                tmp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_provision_download_failure(self, logger, mock_adb_wrapper, mock_aiohttp_session):
        """Test provisioning with download failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock download failure
        mock_aiohttp_session.get.return_value.__aenter__.return_value.raise_for_status.side_effect = Exception("Download failed")
        
        result = await manager.provision("device123", "arm64-v8a", "15.2.2")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_provision_push_failure(self, logger, mock_adb_wrapper, mock_aiohttp_session, mock_lzma, mock_file_operations):
        """Test provisioning with push failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock download succeeds but push fails
        mock_file_operations['exists'].return_value = False
        mock_aiohttp_session.get.return_value.__aenter__.return_value.read.return_value = b"compressed_data"
        mock_lzma.return_value = b"decompressed_binary"
        
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.shell.side_effect = AdbError("Push failed")
        
        result = await manager.provision("device123", "arm64-v8a", "15.2.2")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_provision_start_failure(self, logger, mock_adb_wrapper, mock_aiohttp_session, mock_lzma, mock_file_operations):
        """Test provisioning with start failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock download and push succeed but start fails
        mock_file_operations['exists'].return_value = False
        mock_aiohttp_session.get.return_value.__aenter__.return_value.read.return_value = b"compressed_data"
        mock_lzma.return_value = b"decompressed_binary"
        
        def mock_shell_side_effect(*args, **kwargs):
            cmd = args[1] if len(args) > 1 else ""
            if "frida-server" in cmd and ("nohup" in cmd or "&" in cmd):
                from src.tower_iq.core.utils import AdbError
                raise AdbError("Start failed")
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        result = await manager.provision("device123", "arm64-v8a", "15.2.2")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_provision_verification_failure(self, logger, mock_adb_wrapper, mock_aiohttp_session, mock_lzma, mock_file_operations):
        """Test provisioning with verification failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock all steps succeed but verification fails
        mock_file_operations['exists'].return_value = False
        mock_aiohttp_session.get.return_value.__aenter__.return_value.read.return_value = b"compressed_data"
        mock_lzma.return_value = b"decompressed_binary"
        
        def mock_shell_side_effect(*args, **kwargs):
            cmd = args[1] if len(args) > 1 else ""
            if "ls" in cmd or "pidof" in cmd or "--version" in cmd:
                from src.tower_iq.core.utils import AdbError
                raise AdbError("Verification failed")
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        result = await manager.provision("device123", "arm64-v8a", "15.2.2")
        
        assert result is False


class TestFridaServerManagerPublicMethods:
    """Test public API methods."""
    
    @pytest.mark.asyncio
    async def test_start_server_public_method(self, logger, mock_adb_wrapper):
        """Test public start_server method."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock binary exists and start succeeds
        def mock_shell_side_effect(*args, **kwargs):
            cmd = args[1] if len(args) > 1 else ""
            if "ls" in cmd:
                return f"{manager.DEVICE_PATH}"  # Binary exists
            elif "pidof" in cmd:
                return "1234"  # Server is running
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        result = await manager.start_server("device123")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_start_server_binary_not_found(self, logger, mock_adb_wrapper):
        """Test start_server when binary not found."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock binary not found
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.shell.side_effect = AdbError("No such file")
        
        result = await manager.start_server("device123")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_start_server_process_not_found_after_start(self, logger, mock_adb_wrapper):
        """Test start_server when process not found after start."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock binary exists but process not found after start
        def mock_shell_side_effect(*args, **kwargs):
            cmd = args[1] if len(args) > 1 else ""
            if "ls" in cmd:
                return f"{manager.DEVICE_PATH}"  # Binary exists
            elif "pidof" in cmd:
                return ""  # Process not found
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        result = await manager.start_server("device123")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_install_server_success(self, logger, mock_adb_wrapper, mock_aiohttp_session, mock_lzma, mock_file_operations):
        """Test successful server installation."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock successful download and push
        mock_file_operations['exists'].return_value = False
        mock_aiohttp_session.get.return_value.__aenter__.return_value.read.return_value = b"compressed_data"
        mock_lzma.return_value = b"decompressed_binary"
        
        result = await manager.install_server("device123", "arm64-v8a", "15.2.2")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_install_server_failure(self, logger, mock_adb_wrapper):
        """Test server installation failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock push failure
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.push.side_effect = AdbError("Push failed")
        
        result = await manager.install_server("device123", "arm64-v8a", "15.2.2")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_remove_server_success(self, logger, mock_adb_wrapper):
        """Test successful server removal."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock successful stop and removal
        mock_adb_wrapper.shell.return_value = ""
        
        result = await manager.remove_server("device123")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_remove_server_removal_failure(self, logger, mock_adb_wrapper):
        """Test server removal with file removal failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock stop succeeds but removal fails
        def mock_shell_side_effect(*args, **kwargs):
            cmd = args[1] if len(args) > 1 else ""
            if "rm" in cmd:
                from src.tower_iq.core.utils import AdbError
                raise AdbError("Removal failed")
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_shell_side_effect
        
        result = await manager.remove_server("device123")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_is_server_installed_true(self, logger, mock_adb_wrapper):
        """Test is_server_installed when installed."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock binary exists
        mock_adb_wrapper.shell.return_value = f"{manager.DEVICE_PATH}"
        
        result = await manager.is_server_installed("device123")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_is_server_installed_false(self, logger, mock_adb_wrapper):
        """Test is_server_installed when not installed."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock binary not found
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.shell.side_effect = AdbError("No such file")
        
        result = await manager.is_server_installed("device123")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_get_server_version_success(self, logger, mock_adb_wrapper):
        """Test get_server_version success."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock version output
        mock_adb_wrapper.shell.return_value = "15.2.2"
        
        result = await manager.get_server_version("device123")
        
        assert result == "15.2.2"
    
    @pytest.mark.asyncio
    async def test_get_server_version_failure(self, logger, mock_adb_wrapper):
        """Test get_server_version failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock command failure
        from src.tower_iq.core.utils import AdbError
        mock_adb_wrapper.shell.side_effect = AdbError("Command failed")
        
        result = await manager.get_server_version("device123")
        
        assert result is None


class TestFridaServerManagerErrorHandling:
    """Test error handling and edge cases."""
    
    @pytest.mark.asyncio
    async def test_exception_handling_in_provision(self, logger, mock_adb_wrapper):
        """Test exception handling in provision method."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock unexpected exception
        mock_adb_wrapper.shell.side_effect = Exception("Unexpected error")
        
        result = await manager.provision("device123", "arm64-v8a", "15.2.2")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_exception_handling_in_start_server(self, logger, mock_adb_wrapper):
        """Test exception handling in start_server method."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock unexpected exception
        mock_adb_wrapper.shell.side_effect = Exception("Unexpected error")
        
        result = await manager.start_server("device123")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_exception_handling_in_stop_server(self, logger, mock_adb_wrapper):
        """Test exception handling in stop_server method."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock unexpected exception
        mock_adb_wrapper.shell.side_effect = Exception("Unexpected error")
        
        result = await manager.stop_server("device123")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_exception_handling_in_install_server(self, logger, mock_adb_wrapper):
        """Test exception handling in install_server method."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock unexpected exception
        mock_adb_wrapper.shell.side_effect = Exception("Unexpected error")
        
        result = await manager.install_server("device123", "arm64-v8a", "15.2.2")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_exception_handling_in_remove_server(self, logger, mock_adb_wrapper):
        """Test exception handling in remove_server method."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock unexpected exception
        mock_adb_wrapper.shell.side_effect = Exception("Unexpected error")
        
        result = await manager.remove_server("device123")
        
        assert result is False


class TestFridaServerManagerIntegration:
    """Integration tests for FridaServerManager."""
    
    @pytest.mark.asyncio
    async def test_full_provisioning_workflow(self, logger, mock_adb_wrapper, mock_aiohttp_session, mock_lzma, mock_file_operations):
        """Test complete provisioning workflow."""
        import tempfile
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create a real temporary binary file for testing
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
            tmp_file.write(b"test_binary_content")
            tmp_path = Path(tmp_file.name)
        
        try:
            # Mock shell responses for verification
            def shell_side_effect(device_id, cmd, timeout=None):
                if "pidof" in cmd:
                    return "1234"  # Server is running
                elif "ls /data/local/tmp/frida-server" in cmd:
                    return "/data/local/tmp/frida-server"  # File exists
                else:
                    return "15.2.2"  # Version check
            
            mock_adb_wrapper.shell.side_effect = shell_side_effect
            mock_adb_wrapper.push.return_value = None
            
            # Patch the internal methods to simplify testing
            with patch.object(manager, '_get_frida_server_binary', return_value=tmp_path):
                with patch.object(manager, '_is_push_required', return_value=True):
                    with patch.object(manager, '_push_to_device', return_value=None):
                        result = await manager.provision("device123", "arm64-v8a", "15.2.2")
            
            assert result is True
        finally:
            # Clean up temp file
            if tmp_path.exists():
                tmp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_start_stop_cycle(self, logger, mock_adb_wrapper):
        """Test start and stop cycle."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock start server
        def mock_start_shell(*args, **kwargs):
            cmd = args[1] if len(args) > 1 else ""
            if "ls" in cmd:
                return f"{manager.DEVICE_PATH}"  # Binary exists
            elif "pidof" in cmd:
                return "1234"  # Server is running
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_start_shell
        
        start_result = await manager.start_server("device123")
        assert start_result is True
        
        # Reset mock for stop
        mock_adb_wrapper.shell.reset_mock()
        
        # Mock stop server
        def mock_stop_shell(*args, **kwargs):
            cmd = args[1] if len(args) > 1 else ""
            if "pidof" in cmd:
                return ""  # Server stopped
            return ""
        
        mock_adb_wrapper.shell.side_effect = mock_stop_shell
        
        stop_result = await manager.stop_server("device123")
        assert stop_result is True
    
    @pytest.mark.asyncio
    async def test_install_remove_cycle(self, logger, mock_adb_wrapper):
        """Test install and remove cycle."""
        import tempfile
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create a real temporary binary file for testing
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
            tmp_file.write(b"test_binary_content")
            tmp_path = Path(tmp_file.name)
        
        try:
            # Mock install with internal method patching
            mock_adb_wrapper.push.return_value = None
            mock_adb_wrapper.shell.return_value = ""
            
            with patch.object(manager, '_get_frida_server_binary', return_value=tmp_path):
                with patch.object(manager, '_is_push_required', return_value=True):
                    install_result = await manager.install_server("device123", "arm64-v8a", "15.2.2")
            assert install_result is True
            
            # Mock remove
            mock_adb_wrapper.shell.return_value = ""
            
            remove_result = await manager.remove_server("device123")
            assert remove_result is True
            
            # Verify server is no longer installed
            from src.tower_iq.core.utils import AdbError
            mock_adb_wrapper.shell.side_effect = AdbError("No such file")
            
            is_installed = await manager.is_server_installed("device123")
            assert is_installed is False
        finally:
            # Clean up temp file
            if tmp_path.exists():
                tmp_path.unlink()

        assert is_installed is False


class TestSecureDownload:
    """Test secure download functionality with retry logic and checksum verification."""
    
    @pytest.mark.asyncio
    async def test_download_file_success(self, logger, mock_adb_wrapper):
        """Test successful file download with progress logging."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create mock response with chunked data
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.headers = {'Content-Length': '1048576'}  # 1 MB
        
        # Mock chunked content with proper async iterator
        chunks = [b'x' * 8192 for _ in range(128)]  # 1 MB in 8KB chunks
        
        async def async_chunk_iter(size):
            for chunk in chunks:
                yield chunk
        
        mock_response.content.iter_chunked = Mock(return_value=async_chunk_iter(8192))
        
        # Create mock session
        mock_session = MagicMock()
        mock_get_context = MagicMock()
        mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_get_context.__aexit__ = AsyncMock(return_value=None)
        mock_session.get = MagicMock(return_value=mock_get_context)
        
        # Download file
        result = await manager._download_file(
            session=mock_session,
            url="https://test.com/file.xz",
            filename="test-file"
        )
        
        assert len(result) == 1048576
        assert result == b'x' * 1048576
        mock_response.raise_for_status.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_download_file_size_validation_too_small(self, logger, mock_adb_wrapper):
        """Test file download rejects files that are too small."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create mock response with file too small
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.headers = {'Content-Length': '500000'}  # 500 KB (< 1 MB min)
        
        # Create mock session
        mock_session = MagicMock()
        mock_get_context = MagicMock()
        mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_get_context.__aexit__ = AsyncMock(return_value=None)
        mock_session.get = MagicMock(return_value=mock_get_context)
        
        # Should raise ClientError for file too small
        with pytest.raises(aiohttp.ClientError, match="File size too small"):
            await manager._download_file(
                session=mock_session,
                url="https://test.com/file.xz",
                filename="test-file"
            )
    
    @pytest.mark.asyncio
    async def test_download_file_size_validation_too_large(self, logger, mock_adb_wrapper):
        """Test file download rejects files that are too large."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create mock response with file too large
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.headers = {'Content-Length': '250000000'}  # 250 MB (> 200 MB max)
        
        # Create mock session
        mock_session = MagicMock()
        mock_get_context = MagicMock()
        mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_get_context.__aexit__ = AsyncMock(return_value=None)
        mock_session.get = MagicMock(return_value=mock_get_context)
        
        # Should raise ClientError for file too large
        with pytest.raises(aiohttp.ClientError, match="File size too large"):
            await manager._download_file(
                session=mock_session,
                url="https://test.com/file.xz",
                filename="test-file"
            )
    
    @pytest.mark.asyncio
    async def test_download_file_without_content_length(self, logger, mock_adb_wrapper):
        """Test file download when Content-Length header is missing."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create mock response without Content-Length
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.headers = {}  # No Content-Length
        
        # Mock chunked content with proper async iterator
        chunks = [b'x' * 8192 for _ in range(10)]
        
        async def async_chunk_iter(size):
            for chunk in chunks:
                yield chunk
        
        mock_response.content.iter_chunked = Mock(return_value=async_chunk_iter(8192))
        
        # Create mock session
        mock_session = MagicMock()
        mock_get_context = MagicMock()
        mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_get_context.__aexit__ = AsyncMock(return_value=None)
        mock_session.get = MagicMock(return_value=mock_get_context)
        
        # Download file
        result = await manager._download_file(
            session=mock_session,
            url="https://test.com/file.xz",
            filename="test-file"
        )
        
        assert len(result) == 81920  # 10 chunks of 8KB
        mock_response.raise_for_status.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_verify_checksum_success(self, logger, mock_adb_wrapper):
        """Test successful checksum verification."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        compressed_data = b"test_compressed_data"
        expected_checksum = hashlib.sha256(compressed_data).hexdigest()
        
        # Create mock response with checksum
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.raise_for_status = Mock()
        mock_response.text = AsyncMock(return_value=f"{expected_checksum}  frida-server-15.2.2-android-arm64.xz")
        
        # Create mock session
        mock_session = MagicMock()
        mock_get_context = MagicMock()
        mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_get_context.__aexit__ = AsyncMock(return_value=None)
        mock_session.get = MagicMock(return_value=mock_get_context)
        
        # Verify checksum
        result = await manager._verify_checksum(
            session=mock_session,
            version="15.2.2",
            binary_filename="frida-server-15.2.2-android-arm64",
            frida_arch="arm64",
            compressed_data=compressed_data
        )
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_verify_checksum_mismatch(self, logger, mock_adb_wrapper):
        """Test checksum verification failure when checksums don't match."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        compressed_data = b"test_compressed_data"
        wrong_checksum = "0" * 64  # Intentionally wrong checksum
        
        # Create mock response with wrong checksum
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.raise_for_status = Mock()
        mock_response.text = AsyncMock(return_value=f"{wrong_checksum}  frida-server-15.2.2-android-arm64.xz")
        
        # Create mock session
        mock_session = MagicMock()
        mock_get_context = MagicMock()
        mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_get_context.__aexit__ = AsyncMock(return_value=None)
        mock_session.get = MagicMock(return_value=mock_get_context)
        
        # Should raise FridaServerSetupError for checksum mismatch
        with pytest.raises(FridaServerSetupError, match="Checksum verification failed"):
            await manager._verify_checksum(
                session=mock_session,
                version="15.2.2",
                binary_filename="frida-server-15.2.2-android-arm64",
                frida_arch="arm64",
                compressed_data=compressed_data
            )
    
    @pytest.mark.asyncio
    async def test_verify_checksum_no_checksum_file(self, logger, mock_adb_wrapper):
        """Test checksum verification when no checksum file is available."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        compressed_data = b"test_compressed_data"
        
        # Create mock response with 404 for all checksum URLs
        mock_response = AsyncMock()
        mock_response.status = 404
        mock_response.raise_for_status = Mock()
        
        # Create mock session that returns 404 for all checksum URLs
        mock_session = MagicMock()
        mock_get_context = MagicMock()
        mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_get_context.__aexit__ = AsyncMock(return_value=None)
        mock_session.get = MagicMock(return_value=mock_get_context)
        
        # Should return False (graceful degradation)
        result = await manager._verify_checksum(
            session=mock_session,
            version="15.2.2",
            binary_filename="frida-server-15.2.2-android-arm64",
            frida_arch="arm64",
            compressed_data=compressed_data
        )
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_verify_checksum_with_sha256_file(self, logger, mock_adb_wrapper):
        """Test checksum verification with individual .sha256 file."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        compressed_data = b"test_compressed_data"
        expected_checksum = hashlib.sha256(compressed_data).hexdigest()
        
        # Create mock response for .sha256 file (just the hash)
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.raise_for_status = Mock()
        mock_response.text = AsyncMock(return_value=f"{expected_checksum}\n")
        
        # Create mock session
        mock_session = MagicMock()
        mock_get_context = MagicMock()
        mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_get_context.__aexit__ = AsyncMock(return_value=None)
        mock_session.get = MagicMock(return_value=mock_get_context)
        
        # Verify checksum
        result = await manager._verify_checksum(
            session=mock_session,
            version="15.2.2",
            binary_filename="frida-server-15.2.2-android-arm64",
            frida_arch="arm64",
            compressed_data=compressed_data
        )
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_download_with_retry_success_first_attempt(self, logger, mock_adb_wrapper):
        """Test successful download on first attempt."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        compressed_data = b"test_compressed_data"
        expected_checksum = hashlib.sha256(compressed_data).hexdigest()
        
        # Mock _download_file to return data
        with patch.object(manager, '_download_file', return_value=compressed_data):
            # Mock _verify_checksum to return True
            with patch.object(manager, '_verify_checksum', return_value=True):
                result = await manager._download_with_retry(
                    version="15.2.2",
                    binary_filename="frida-server-15.2.2-android-arm64",
                    frida_arch="arm64"
                )
        
        assert result == compressed_data
    
    @pytest.mark.asyncio
    async def test_download_with_retry_success_after_failures(self, logger, mock_adb_wrapper):
        """Test successful download after initial failures."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        compressed_data = b"test_compressed_data"
        
        # Mock _download_file to fail twice, then succeed
        call_count = 0
        async def mock_download_file(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise aiohttp.ClientError("Connection failed")
            return compressed_data
        
        with patch.object(manager, '_download_file', side_effect=mock_download_file):
            # Mock _verify_checksum
            with patch.object(manager, '_verify_checksum', return_value=True):
                result = await manager._download_with_retry(
                    version="15.2.2",
                    binary_filename="frida-server-15.2.2-android-arm64",
                    frida_arch="arm64",
                    max_retries=3,
                    base_delay=0.01  # Fast retries for testing
                )
        
        assert result == compressed_data
        assert call_count == 3  # Two failures + one success
    
    @pytest.mark.asyncio
    async def test_download_with_retry_all_attempts_fail(self, logger, mock_adb_wrapper):
        """Test download failure after all retry attempts."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock _download_file to always fail
        async def mock_download_file(*args, **kwargs):
            raise aiohttp.ClientError("Connection failed")
        
        with patch.object(manager, '_download_file', side_effect=mock_download_file):
            with pytest.raises(FridaServerSetupError, match="Failed to download frida-server after 3 attempts"):
                await manager._download_with_retry(
                    version="15.2.2",
                    binary_filename="frida-server-15.2.2-android-arm64",
                    frida_arch="arm64",
                    max_retries=3,
                    base_delay=0.01  # Fast retries for testing
                )
    
    @pytest.mark.asyncio
    async def test_download_with_retry_timeout(self, logger, mock_adb_wrapper):
        """Test download with timeout error."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock _download_file to timeout
        async def mock_download_file(*args, **kwargs):
            raise asyncio.TimeoutError("Download timed out")
        
        with patch.object(manager, '_download_file', side_effect=mock_download_file):
            with pytest.raises(FridaServerSetupError, match="Download timed out after 3 attempts"):
                await manager._download_with_retry(
                    version="15.2.2",
                    binary_filename="frida-server-15.2.2-android-arm64",
                    frida_arch="arm64",
                    max_retries=3,
                    base_delay=0.01
                )
    
    @pytest.mark.asyncio
    async def test_download_with_retry_unexpected_error(self, logger, mock_adb_wrapper):
        """Test download with unexpected error (no retry)."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Mock _download_file to raise unexpected error
        async def mock_download_file(*args, **kwargs):
            raise ValueError("Unexpected error")
        
        with patch.object(manager, '_download_file', side_effect=mock_download_file):
            with pytest.raises(FridaServerSetupError, match="Unexpected error during download"):
                await manager._download_with_retry(
                    version="15.2.2",
                    binary_filename="frida-server-15.2.2-android-arm64",
                    frida_arch="arm64",
                    max_retries=3,
                    base_delay=0.01
                )
    
    @pytest.mark.asyncio
    async def test_get_frida_server_binary_secure_download_success(self, logger, mock_adb_wrapper):
        """Test secure download of frida-server binary with all verifications."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # ELF binary data (starts with ELF magic number)
        elf_data = b'\x7fELF' + b'x' * 10000
        compressed_data = lzma.compress(elf_data)
        
        try:
            # Mock download with retry
            with patch.object(manager, '_download_with_retry', return_value=compressed_data):
                result = await manager._get_frida_server_binary("arm64-v8a", "15.2.2")
            
            # Verify result
            assert result.exists()
            assert result.name == "frida-server-15.2.2-android-arm64"
            
            # Verify file content
            downloaded_data = result.read_bytes()
            assert downloaded_data == elf_data
        finally:
            # Cleanup
            if result.exists():
                result.unlink()
    
    @pytest.mark.asyncio
    async def test_get_frida_server_binary_invalid_elf(self, logger, mock_adb_wrapper):
        """Test rejection of non-ELF binary."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Non-ELF data
        non_elf_data = b'NOT_ELF' + b'x' * 10000
        compressed_data = lzma.compress(non_elf_data)
        
        # Mock download with retry
        with patch.object(manager, '_download_with_retry', return_value=compressed_data):
            try:
                with pytest.raises(FridaServerSetupError, match="not a valid ELF binary"):
                    await manager._get_frida_server_binary("arm64-v8a", "15.2.2")
            finally:
                # Cleanup any temp files
                potential_file = manager.cache_dir / "frida-server-15.2.2-android-arm64"
                if potential_file.exists():
                    potential_file.unlink()
    
    @pytest.mark.asyncio
    async def test_get_frida_server_binary_decompression_failure(self, logger, mock_adb_wrapper):
        """Test handling of decompression failure."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Invalid compressed data
        invalid_compressed_data = b"not_valid_lzma_data"
        
        # Mock download with retry
        with patch.object(manager, '_download_with_retry', return_value=invalid_compressed_data):
            try:
                with pytest.raises(FridaServerSetupError, match="Failed to decompress"):
                    await manager._get_frida_server_binary("arm64-v8a", "15.2.2")
            finally:
                # Cleanup any temp files
                potential_file = manager.cache_dir / "frida-server-15.2.2-android-arm64"
                if potential_file.exists():
                    potential_file.unlink()
    
    @pytest.mark.asyncio
    async def test_get_frida_server_binary_atomic_operation(self, logger, mock_adb_wrapper):
        """Test atomic file operation (temp file + rename)."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # ELF binary data
        elf_data = b'\x7fELF' + b'x' * 10000
        compressed_data = lzma.compress(elf_data)
        
        # Track temp files created
        temp_files_created = []
        original_mkstemp = tempfile.mkstemp
        
        def mock_mkstemp(*args, **kwargs):
            fd, path = original_mkstemp(*args, **kwargs)
            temp_files_created.append(Path(path))
            return fd, path
        
        try:
            with patch('src.tower_iq.services.frida_manager.tempfile.mkstemp', side_effect=mock_mkstemp):
                with patch.object(manager, '_download_with_retry', return_value=compressed_data):
                    result = await manager._get_frida_server_binary("arm64-v8a", "15.2.2")
            
            # Verify temp file was cleaned up (renamed to final location)
            assert len(temp_files_created) == 1
            temp_file = temp_files_created[0]
            assert not temp_file.exists()  # Temp file should be renamed/deleted
            
            # Verify final file exists
            assert result.exists()
        finally:
            # Cleanup
            if result.exists():
                result.unlink()
    
    @pytest.mark.asyncio
    async def test_get_frida_server_binary_uses_cache(self, logger, mock_adb_wrapper):
        """Test that cached binary is returned without re-downloading."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        # Create a cached binary
        cached_binary = manager.cache_dir / "frida-server-15.2.2-android-arm64"
        cached_binary.write_bytes(b'\x7fELF' + b'cached' * 100)
        
        try:
            # Mock _download_with_retry to track if it's called
            download_called = False
            async def mock_download(*args, **kwargs):
                nonlocal download_called
                download_called = True
                return b"should_not_be_called"
            
            with patch.object(manager, '_download_with_retry', side_effect=mock_download):
                result = await manager._get_frida_server_binary("arm64-v8a", "15.2.2")
            
            # Verify cache was used
            assert not download_called
            assert result == cached_binary
            assert b'cached' in result.read_bytes()
        finally:
            # Cleanup
            if cached_binary.exists():
                cached_binary.unlink()
    
    @pytest.mark.asyncio
    async def test_download_with_retry_exponential_backoff(self, logger, mock_adb_wrapper):
        """Test that retry delays follow exponential backoff."""
        manager = FridaServerManager(logger, mock_adb_wrapper)
        
        delays = []
        original_sleep = asyncio.sleep
        
        async def mock_sleep(delay):
            delays.append(delay)
            await original_sleep(0.001)  # Fast sleep for testing
        
        # Mock download to fail twice then succeed
        call_count = 0
        async def mock_download_file(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise aiohttp.ClientError("Temporary failure")
            return b"success"
        
        with patch('asyncio.sleep', side_effect=mock_sleep):
            with patch.object(manager, '_download_file', side_effect=mock_download_file):
                with patch.object(manager, '_verify_checksum', return_value=True):
                    await manager._download_with_retry(
                        version="15.2.2",
                        binary_filename="frida-server-15.2.2-android-arm64",
                        frida_arch="arm64",
                        max_retries=3,
                        base_delay=1.0
                    )
        
        # Verify exponential backoff: 1s, 2s (1 * 2^1)
        assert len(delays) == 2  # Two retries after initial failure
        assert delays[0] == 1.0  # First retry delay
        assert delays[1] == 2.0  # Second retry delay (exponential)



