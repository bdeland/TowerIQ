"""
Comprehensive tests for AdbWrapper.

This module tests the AdbWrapper class functionality including:
- ADB server management (start, kill, restart)
- Command execution
- Status caching and invalidation
- Proper condition-based waiting patterns
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, Mock, call, patch

import pytest

from src.tower_iq.core.utils import AdbError, AdbWrapper


class TestAdbWrapperInitialization:
    """Test AdbWrapper initialization."""
    
    def test_init_with_logger(self, logger):
        """Test initialization with logger."""
        wrapper = AdbWrapper(logger, verbose_debug=False)
        
        assert wrapper.logger is not None
        assert wrapper.verbose_debug is False
        assert wrapper._server_running is None
        assert wrapper._last_check is None
        assert wrapper._check_timeout == 30
    
    def test_init_with_verbose_debug(self, logger):
        """Test initialization with verbose debug enabled."""
        wrapper = AdbWrapper(logger, verbose_debug=True)
        
        assert wrapper.verbose_debug is True


class TestAdbWrapperCommandExecution:
    """Test AdbWrapper command execution."""
    
    @pytest.mark.asyncio
    async def test_run_command_success(self, logger):
        """Test successful command execution."""
        wrapper = AdbWrapper(logger)
        
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            # Mock process
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"output\n", b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process
            
            stdout, stderr = await wrapper.run_command("devices")
            
            assert stdout == "output"
            assert stderr == ""
            mock_exec.assert_called_once_with(
                "adb", "devices",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
    
    @pytest.mark.asyncio
    async def test_run_command_failure(self, logger):
        """Test command execution with non-zero return code."""
        wrapper = AdbWrapper(logger, verbose_debug=True)
        
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"", b"error message"))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process
            
            with pytest.raises(AdbError, match="ADB command failed"):
                await wrapper.run_command("invalid-command")
    
    @pytest.mark.asyncio
    async def test_run_command_timeout(self, logger):
        """Test command execution timeout."""
        wrapper = AdbWrapper(logger)
        
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            # Simulate timeout by making communicate hang
            mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_exec.return_value = mock_process
            
            with pytest.raises(AdbError, match="timed out"):
                await wrapper.run_command("devices", timeout=0.1)
    
    @pytest.mark.asyncio
    async def test_run_command_adb_not_found(self, logger):
        """Test command execution when adb executable is not found."""
        wrapper = AdbWrapper(logger)
        
        with patch('asyncio.create_subprocess_exec', side_effect=FileNotFoundError()):
            with pytest.raises(AdbError, match="not found"):
                await wrapper.run_command("devices")


class TestAdbWrapperServerStatus:
    """Test ADB server status checking and caching."""
    
    @pytest.mark.asyncio
    async def test_is_server_running_cached_no_cache(self, logger):
        """Test server status check with no cache."""
        wrapper = AdbWrapper(logger)
        
        # Import socket from utils module to patch it in the right namespace
        import src.tower_iq.core.utils as utils_module
        with patch.object(utils_module.socket, 'create_connection') as mock_socket:
            # Mock successful connection (server is running)
            # No need to set return_value, just don't raise an exception
            
            result = await wrapper._is_server_running_cached()
            
            assert result is True
            assert wrapper._server_running is True
            assert wrapper._last_check is not None
            mock_socket.assert_called_once_with(("127.0.0.1", 5037), timeout=0.5)
    
    @pytest.mark.asyncio
    async def test_is_server_running_cached_with_valid_cache(self, logger):
        """Test server status check with valid cache."""
        wrapper = AdbWrapper(logger)
        wrapper._server_running = True
        wrapper._last_check = datetime.now()
        
        import src.tower_iq.core.utils as utils_module
        with patch.object(utils_module.socket, 'create_connection') as mock_socket:
            result = await wrapper._is_server_running_cached()
            
            assert result is True
            # Should not call socket.create_connection because cache is valid
            mock_socket.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_is_server_running_cached_expired_cache(self, logger):
        """Test server status check with expired cache."""
        wrapper = AdbWrapper(logger)
        wrapper._server_running = True
        wrapper._last_check = datetime.now() - timedelta(seconds=35)  # Expired
        
        import src.tower_iq.core.utils as utils_module
        with patch.object(utils_module.socket, 'create_connection') as mock_socket:
            # Mock successful connection (server is running)
            # No need to set return_value, just don't raise an exception
            
            result = await wrapper._is_server_running_cached()
            
            assert result is True
            # Should call socket.create_connection because cache expired
            mock_socket.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_is_server_running_cached_server_not_running(self, logger):
        """Test server status check when server is not running."""
        wrapper = AdbWrapper(logger)
        
        import src.tower_iq.core.utils as utils_module
        with patch.object(utils_module.socket, 'create_connection') as mock_socket:
            # Mock connection failure (server not running)
            mock_socket.side_effect = ConnectionRefusedError("Connection refused")
            
            result = await wrapper._is_server_running_cached()
            
            assert result is False
            assert wrapper._server_running is False
            assert wrapper._last_check is not None


class TestAdbWrapperStartServer:
    """Test ADB server start functionality."""
    
    @pytest.mark.asyncio
    async def test_start_server_when_not_running(self, logger):
        """Test starting server when it's not running."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, '_is_server_running_cached', new_callable=AsyncMock) as mock_check:
            mock_check.return_value = False
            
            with patch.object(wrapper, 'run_command', new_callable=AsyncMock) as mock_run:
                mock_run.return_value = ("", "")
                
                await wrapper.start_server()
                
                mock_check.assert_called_once()
                mock_run.assert_called_once_with("start-server", timeout=10.0)
                assert wrapper._server_running is True
    
    @pytest.mark.asyncio
    async def test_start_server_when_already_running(self, logger):
        """Test starting server when it's already running."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, '_is_server_running_cached', new_callable=AsyncMock) as mock_check:
            mock_check.return_value = True
            
            with patch.object(wrapper, 'run_command', new_callable=AsyncMock) as mock_run:
                await wrapper.start_server()
                
                mock_check.assert_called_once()
                # Should not call run_command because server is already running
                mock_run.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_start_server_failure(self, logger):
        """Test starting server failure."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, '_is_server_running_cached', new_callable=AsyncMock) as mock_check:
            mock_check.return_value = False
            
            with patch.object(wrapper, 'run_command', new_callable=AsyncMock) as mock_run:
                mock_run.side_effect = AdbError("Failed to start")
                
                with pytest.raises(AdbError):
                    await wrapper.start_server()
                
                # Cache should be updated to False on error
                assert wrapper._server_running is False


class TestAdbWrapperKillServer:
    """Test ADB server kill functionality."""
    
    @pytest.mark.asyncio
    async def test_kill_server_success(self, logger):
        """Test successfully killing server."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, 'run_command', new_callable=AsyncMock) as mock_run:
            mock_run.return_value = ("", "")
            
            await wrapper.kill_server()
            
            mock_run.assert_called_once_with("kill-server", timeout=10.0)
            assert wrapper._server_running is False
            assert wrapper._last_check is not None
    
    @pytest.mark.asyncio
    async def test_kill_server_failure(self, logger):
        """Test killing server failure."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, 'run_command', new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = AdbError("Failed to kill")
            
            with pytest.raises(AdbError):
                await wrapper.kill_server()
            
            # Cache should be cleared on error
            assert wrapper._server_running is None
            assert wrapper._last_check is None


class TestAdbWrapperRestartServer:
    """Test ADB server restart functionality with proper condition waiting."""
    
    @pytest.mark.asyncio
    async def test_restart_server_success(self, logger, fast_polling_env):
        """Test successful server restart with condition waiting."""
        wrapper = AdbWrapper(logger)
        
        # Track the sequence of operations
        operations = []
        
        async def mock_kill():
            operations.append("kill")
        
        async def mock_start():
            operations.append("start")
        
        # Mock the server status checks to simulate proper stop/start sequence
        check_count = [0]
        async def mock_check(force_check=False):
            check_count[0] += 1
            # First check: server is stopped (after kill)
            if check_count[0] <= 1:
                return False
            # Subsequent checks: server is running (after start)
            else:
                return True
        
        with patch.object(wrapper, 'kill_server', new_callable=AsyncMock) as mock_kill_fn:
            mock_kill_fn.side_effect = mock_kill
            
            with patch.object(wrapper, 'start_server', new_callable=AsyncMock) as mock_start_fn:
                mock_start_fn.side_effect = mock_start
                
                with patch.object(wrapper, '_is_server_running_cached', new_callable=AsyncMock) as mock_check_fn:
                    mock_check_fn.side_effect = mock_check
                    
                    await wrapper.restart_server()
                    
                    # Verify operations happened in correct order
                    assert operations == ["kill", "start"]
                    mock_kill_fn.assert_called_once()
                    mock_start_fn.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_restart_server_stop_timeout(self, logger, fast_polling_env):
        """Test restart when server doesn't stop in time."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, 'kill_server', new_callable=AsyncMock):
            with patch.object(wrapper, 'start_server', new_callable=AsyncMock):
                # Always report server as running (never stops)
                with patch.object(wrapper, '_is_server_running_cached', new_callable=AsyncMock) as mock_check:
                    mock_check.return_value = True
                    
                    # Should complete but log a warning
                    await wrapper.restart_server()
                    
                    # Verify warning was logged
                    logger.warning.assert_called()
                    warning_call = [call for call in logger.warning.call_args_list 
                                  if "Timed out waiting for ADB server to stop" in str(call)]
                    assert len(warning_call) > 0
    
    @pytest.mark.asyncio
    async def test_restart_server_start_verification_failure(self, logger, fast_polling_env):
        """Test restart when server fails to start."""
        wrapper = AdbWrapper(logger)
        
        check_count = [0]
        async def mock_check():
            check_count[0] += 1
            # First checks: stopped successfully
            if check_count[0] <= 3:
                return False
            # After start attempt: still not running (failed to start)
            else:
                return False
        
        with patch.object(wrapper, 'kill_server', new_callable=AsyncMock):
            with patch.object(wrapper, 'start_server', new_callable=AsyncMock):
                with patch.object(wrapper, '_is_server_running_cached', new_callable=AsyncMock) as mock_check_fn:
                    mock_check_fn.side_effect = mock_check
                    
                    with pytest.raises(AdbError, match="failed to start after restart"):
                        await wrapper.restart_server()
    
    @pytest.mark.asyncio
    async def test_restart_server_kill_failure(self, logger):
        """Test restart when kill operation fails."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, 'kill_server', new_callable=AsyncMock) as mock_kill:
            mock_kill.side_effect = AdbError("Failed to kill server")
            
            # The error message from kill_server is propagated through restart_server
            with pytest.raises(AdbError, match="Failed to (kill|restart ADB) server"):
                await wrapper.restart_server()
    
    @pytest.mark.asyncio
    async def test_restart_server_start_failure(self, logger, fast_polling_env):
        """Test restart when start operation fails."""
        wrapper = AdbWrapper(logger)
        
        async def mock_check():
            # Report server as stopped
            return False
        
        with patch.object(wrapper, 'kill_server', new_callable=AsyncMock):
            with patch.object(wrapper, 'start_server', new_callable=AsyncMock) as mock_start:
                mock_start.side_effect = AdbError("Failed to start server")
                
                with patch.object(wrapper, '_is_server_running_cached', new_callable=AsyncMock) as mock_check_fn:
                    mock_check_fn.side_effect = mock_check
                    
                    # The error message from start_server is propagated through restart_server
                    with pytest.raises(AdbError, match="Failed to (start|restart ADB) server"):
                        await wrapper.restart_server()
    
    @pytest.mark.asyncio
    async def test_restart_server_cache_invalidation(self, logger, fast_polling_env):
        """Test that restart properly uses force_check during verification."""
        wrapper = AdbWrapper(logger)
        
        # Set up initial cache state
        wrapper._server_running = True
        wrapper._last_check = datetime.now()
        
        check_count = [0]
        force_check_used = []
        
        async def mock_check(force_check=False):
            check_count[0] += 1
            force_check_used.append(force_check)
            # First check: stopped
            if check_count[0] <= 1:
                return False
            # After start: running
            else:
                return True
        
        with patch.object(wrapper, 'kill_server', new_callable=AsyncMock):
            with patch.object(wrapper, 'start_server', new_callable=AsyncMock):
                with patch.object(wrapper, '_is_server_running_cached', new_callable=AsyncMock) as mock_check_fn:
                    mock_check_fn.side_effect = mock_check
                    
                    await wrapper.restart_server()
                    
                    # Verify multiple checks were made (condition waiting)
                    assert check_count[0] >= 2
                    # Verify force_check=True was used during restart verification
                    assert all(force_check_used), "All restart verification checks should use force_check=True"
    
    @pytest.mark.asyncio
    async def test_restart_server_uses_wait_for_condition(self, logger, fast_polling_env):
        """Test that restart uses wait_for_condition with proper parameters."""
        wrapper = AdbWrapper(logger)
        
        check_count = [0]
        async def mock_check(force_check=False):
            check_count[0] += 1
            return False if check_count[0] <= 1 else True
        
        with patch.object(wrapper, 'kill_server', new_callable=AsyncMock):
            with patch.object(wrapper, 'start_server', new_callable=AsyncMock):
                with patch.object(wrapper, '_is_server_running_cached', new_callable=AsyncMock) as mock_check_fn:
                    mock_check_fn.side_effect = mock_check
                    
                    with patch('src.tower_iq.core.async_utils.wait_for_condition') as mock_wait:
                        # Make wait_for_condition actually call the condition function
                        async def actual_wait(condition, **kwargs):
                            for _ in range(3):
                                if await condition():
                                    return True
                                await asyncio.sleep(0.01)
                            return False
                        
                        mock_wait.side_effect = actual_wait
                        
                        await wrapper.restart_server()
                        
                        # Verify wait_for_condition was called twice (stop and start)
                        assert mock_wait.call_count == 2
                        
                        # Check parameters of wait_for_condition calls
                        calls = mock_wait.call_args_list
                        
                        # First call: waiting for server to stop
                        assert calls[0][1]['timeout'] == 5.0
                        assert calls[0][1]['initial_delay'] == 0.1
                        assert calls[0][1]['max_delay'] == 0.5
                        assert 'stopped' in calls[0][1]['condition_name'].lower()
                        
                        # Second call: waiting for server to start
                        assert calls[1][1]['timeout'] == 5.0
                        assert calls[1][1]['initial_delay'] == 0.1
                        assert calls[1][1]['max_delay'] == 0.5
                        assert 'started' in calls[1][1]['condition_name'].lower()


class TestAdbWrapperDeviceListing:
    """Test device listing functionality."""
    
    @pytest.mark.asyncio
    async def test_list_devices_success(self, logger):
        """Test successful device listing."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, 'run_command', new_callable=AsyncMock) as mock_run:
            mock_run.return_value = (
                "List of devices attached\nemulator-5554\tdevice\n192.168.1.100:5555\tdevice\n",
                ""
            )
            
            devices = await wrapper.list_devices()
            
            assert len(devices) == 2
            assert "emulator-5554" in devices
            assert "192.168.1.100:5555" in devices
    
    @pytest.mark.asyncio
    async def test_list_devices_empty(self, logger):
        """Test device listing with no devices."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, 'run_command', new_callable=AsyncMock) as mock_run:
            mock_run.return_value = ("List of devices attached\n", "")
            
            devices = await wrapper.list_devices()
            
            assert devices == []
    
    @pytest.mark.asyncio
    async def test_list_devices_failure(self, logger):
        """Test device listing failure."""
        wrapper = AdbWrapper(logger)
        
        with patch.object(wrapper, 'run_command', new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = AdbError("Command failed")
            
            devices = await wrapper.list_devices()
            
            # Should return empty list on failure
            assert devices == []


# Fixtures specific to this test module
@pytest.fixture
def mock_adb_wrapper(logger):
    """Provide a mock AdbWrapper for tests."""
    return AdbWrapper(logger)

