"""
Comprehensive tests for FridaService.

This module tests all functionality of the FridaService class including
message handling, script injection, attachment/detachment, and error handling.
"""

import asyncio
import json
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, Mock, call, patch

import pytest

from src.tower_iq.services.frida_service import (FridaService,
                                                 HookContractValidator)


class TestFridaServiceInitialization:
    """Test FridaService initialization and basic properties."""
    
    def test_init_with_all_parameters(self, config_manager, logger, event_loop, session_manager):
        """Test initialization with all parameters provided."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        assert service.config == config_manager
        assert service.logger == logger
        assert service._event_loop == event_loop
        assert service._session_manager == session_manager
        assert service._message_queue is not None
        assert service._shutdown_requested is False
        assert service.script_cache_dir.exists()
    
    def test_init_without_session_manager(self, config_manager, logger, event_loop):
        """Test initialization without session manager."""
        service = FridaService(config_manager, logger, event_loop)
        
        assert service._session_manager is None
        assert service._message_queue is not None
    
    def test_init_without_frida_available(self, config_manager, logger, event_loop):
        """Test initialization when frida is not available."""
        with patch('src.tower_iq.services.frida_service.frida', None):
            service = FridaService(config_manager, logger, event_loop)
            # Should still initialize successfully but log warning
            assert service._message_queue is not None
    
    def test_script_cache_dir_creation(self, config_manager, logger, event_loop):
        """Test that script cache directory is created."""
        with patch('pathlib.Path.home') as mock_home:
            mock_home.return_value = Mock()
            mock_home.return_value.__truediv__ = Mock()
            mock_cache_dir = Mock()
            mock_cache_dir.mkdir = Mock()
            mock_home.return_value.__truediv__.return_value = mock_cache_dir
            
            service = FridaService(config_manager, logger, event_loop)
            
            mock_cache_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)


class TestFridaServiceProperties:
    """Test FridaService properties and getters."""
    
    def test_queue_size_property(self, config_manager, logger, event_loop):
        """Test queue_size property."""
        service = FridaService(config_manager, logger, event_loop)
        
        # Initially empty
        assert service.queue_size == 0
        
        # Add a message
        service._message_queue.put_nowait({'test': 'message'})
        assert service.queue_size == 1
    
    def test_queue_size_without_queue(self, config_manager, logger, event_loop):
        """Test queue_size when queue is None."""
        service = FridaService(config_manager, logger, event_loop)
        service._message_queue = None
        
        assert service.queue_size == 0
    
    def test_is_attached_with_session_manager(self, config_manager, logger, event_loop, session_manager):
        """Test is_attached with session manager."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Not attached initially
        assert not service.is_attached()
        
        # Mock attached state
        session_manager.frida_session = Mock()
        session_manager.frida_attached_pid = 1234
        assert service.is_attached()
    
    def test_is_attached_without_session_manager(self, config_manager, logger, event_loop):
        """Test is_attached without session manager."""
        service = FridaService(config_manager, logger, event_loop)
        assert not service.is_attached()
    
    def test_get_attached_pid(self, config_manager, logger, event_loop, session_manager):
        """Test get_attached_pid method."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # No PID initially
        assert service.get_attached_pid() is None
        
        # Set PID
        session_manager.frida_attached_pid = 5678
        assert service.get_attached_pid() == 5678
    
    def test_get_attached_pid_without_session_manager(self, config_manager, logger, event_loop):
        """Test get_attached_pid without session manager."""
        service = FridaService(config_manager, logger, event_loop)
        assert service.get_attached_pid() is None


class TestFridaServiceMessageHandling:
    """Test message handling functionality."""
    
    @pytest.mark.asyncio
    async def test_get_message_success(self, config_manager, logger, event_loop):
        """Test successful message retrieval."""
        service = FridaService(config_manager, logger, event_loop)
        
        # Add a test message
        test_message = {'type': 'test', 'payload': {'data': 'test'}}
        service._message_queue.put_nowait(test_message)
        
        # Get the message
        result = await service.get_message()
        assert result == test_message
    
    @pytest.mark.asyncio
    async def test_get_message_without_queue(self, config_manager, logger, event_loop):
        """Test get_message when queue is not initialized."""
        service = FridaService(config_manager, logger, event_loop)
        service._message_queue = None
        
        with pytest.raises(RuntimeError, match="Message queue not initialized"):
            await service.get_message()
    
    @pytest.mark.asyncio
    async def test_get_message_shutdown_requested(self, config_manager, logger, event_loop):
        """Test get_message when shutdown is requested."""
        service = FridaService(config_manager, logger, event_loop)
        service._shutdown_requested = True
        
        with pytest.raises(RuntimeError, match="Shutdown requested"):
            await service.get_message()
    
    @pytest.mark.asyncio
    async def test_get_message_timeout(self, config_manager, logger, event_loop):
        """Test get_message timeout behavior."""
        service = FridaService(config_manager, logger, event_loop)
        
        # Should return None on timeout
        result = await service.get_message()
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_message_shutdown_signal(self, config_manager, logger, event_loop):
        """Test get_message with shutdown signal."""
        service = FridaService(config_manager, logger, event_loop)
        
        # Add shutdown signal
        service._message_queue.put_nowait({'type': '_shutdown_signal'})
        
        with pytest.raises(RuntimeError, match="Shutdown requested via poison pill"):
            await service.get_message()
    
    @pytest.mark.asyncio
    async def test_get_message_cancelled(self, config_manager, logger, event_loop):
        """Test get_message when task is cancelled."""
        service = FridaService(config_manager, logger, event_loop)
        
        # Create a task that will be cancelled
        async def get_message_task():
            return await service.get_message()
        
        task = asyncio.create_task(get_message_task())
        await asyncio.sleep(0.1)  # Let it start
        task.cancel()
        
        with pytest.raises(RuntimeError, match="Shutdown requested via task cancellation"):
            await task
    
    def test_queue_message_safely_success(self, config_manager, logger, event_loop):
        """Test successful message queuing."""
        service = FridaService(config_manager, logger, event_loop)
        
        test_message = {'type': 'test', 'data': 'test'}
        service._queue_message_safely(test_message)
        
        assert service.queue_size == 1
    
    def test_queue_message_safely_without_queue(self, config_manager, logger, event_loop):
        """Test message queuing when queue is not initialized."""
        service = FridaService(config_manager, logger, event_loop)
        service._message_queue = None
        
        # Should not raise exception, just log error
        service._queue_message_safely({'type': 'test'})
    
    def test_queue_message_safely_closed_loop(self, config_manager, logger, event_loop):
        """Test message queuing when event loop is closed."""
        service = FridaService(config_manager, logger, event_loop)
        service._event_loop = None
        
        # Should fallback to direct queuing
        service._queue_message_safely({'type': 'test'})
        assert service.queue_size == 1


class TestFridaServiceAttachment:
    """Test Frida attachment functionality."""
    
    @pytest.mark.asyncio
    async def test_attach_success(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test successful attachment to process."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock successful attachment
        mock_device = mock_frida.get_device.return_value
        mock_session = Mock()
        mock_device.attach.return_value = mock_session
        
        result = await service.attach(1234, "test-device")
        
        assert result is True
        assert session_manager.frida_device == mock_device
        assert session_manager.frida_session == mock_session
        assert session_manager.frida_attached_pid == 1234
        assert service._shutdown_requested is False
    
    @pytest.mark.asyncio
    async def test_attach_without_frida(self, config_manager, logger, event_loop, session_manager):
        """Test attachment when frida is not available."""
        with patch('src.tower_iq.services.frida_service.frida', None):
            service = FridaService(config_manager, logger, event_loop, session_manager)
            result = await service.attach(1234)
            assert result is False
    
    @pytest.mark.asyncio
    async def test_attach_with_local_device(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test attachment with local device (no device_id)."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        mock_device = mock_frida.get_local_device.return_value
        mock_session = Mock()
        mock_device.attach.return_value = mock_session
        
        result = await service.attach(1234)
        
        assert result is True
        mock_frida.get_local_device.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_attach_clears_stale_messages(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test that attach clears stale messages from queue."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Add some stale messages
        service._message_queue.put_nowait({'type': 'stale1'})
        service._message_queue.put_nowait({'type': 'stale2'})
        service._message_queue.put_nowait({'type': '_shutdown_signal'})
        
        # Mock successful attachment
        mock_device = mock_frida.get_device.return_value
        mock_session = Mock()
        mock_device.attach.return_value = mock_session
        
        result = await service.attach(1234)
        
        assert result is True
        assert service.queue_size == 0  # All stale messages cleared
    
    @pytest.mark.asyncio
    async def test_attach_creates_new_queue_if_none(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test that attach creates new queue if current one is None."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        service._message_queue = None
        
        # Mock successful attachment
        mock_device = mock_frida.get_device.return_value
        mock_session = Mock()
        mock_device.attach.return_value = mock_session
        
        result = await service.attach(1234)
        
        assert result is True
        assert service._message_queue is not None
    
    @pytest.mark.asyncio
    async def test_attach_handles_exception(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test attachment error handling."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock attachment failure
        mock_frida.get_device.side_effect = Exception("Device not found")
        
        result = await service.attach(1234)
        
        assert result is False


class TestFridaServiceDetachment:
    """Test Frida detachment functionality."""
    
    @pytest.mark.asyncio
    async def test_detach_graceful_success(self, config_manager, logger, event_loop, session_manager):
        """Test successful graceful detachment."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock session and script
        mock_session = Mock()
        mock_script = Mock()
        session_manager.frida_session = mock_session
        session_manager.frida_script = mock_script
        
        await service.detach()
        
        # Verify graceful cleanup was called
        mock_script.unload.assert_called_once()
        mock_session.detach.assert_called_once()
        assert session_manager.frida_script is None
        assert session_manager.frida_session is None
        assert service._shutdown_requested is True
    
    @pytest.mark.asyncio
    async def test_detach_force_cleanup(self, config_manager, logger, event_loop, session_manager):
        """Test force cleanup detachment."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock session and script
        mock_session = Mock()
        mock_script = Mock()
        session_manager.frida_session = mock_session
        session_manager.frida_script = mock_script
        
        await service.detach(force_cleanup=True)
        
        # Verify force cleanup was called
        mock_script.unload.assert_called_once()
        mock_session.detach.assert_called_once()
        session_manager.set_script_inactive.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_detach_timeout_handling(self, config_manager, logger, event_loop, session_manager):
        """Test detachment timeout handling."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock session and script that will timeout
        mock_session = Mock()
        mock_script = Mock()
        session_manager.frida_session = mock_session
        session_manager.frida_script = mock_script
        
        # Mock unload to timeout
        async def slow_unload():
            await asyncio.sleep(5)  # Longer than timeout
        
        mock_script.unload = slow_unload
        
        # Should complete despite timeout (falls back to force cleanup)
        await service.detach(timeout=0.1)
    
    @pytest.mark.asyncio
    async def test_detach_sends_poison_pill(self, config_manager, logger, event_loop, session_manager):
        """Test that detach sends poison pill to message queue."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        await service.detach()
        
        # Check that poison pill was sent
        assert service.queue_size == 1
        message = service._message_queue.get_nowait()
        assert message['type'] == '_shutdown_signal'
    
    @pytest.mark.asyncio
    async def test_detach_handles_exception(self, config_manager, logger, event_loop, session_manager):
        """Test detachment error handling."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock session that will raise exception
        mock_session = Mock()
        mock_session.detach.side_effect = Exception("Detach failed")
        session_manager.frida_session = mock_session
        
        # Should still complete cleanup
        await service.detach()
    
    @pytest.mark.asyncio
    async def test_detach_without_session_manager(self, config_manager, logger, event_loop):
        """Test detachment without session manager."""
        service = FridaService(config_manager, logger, event_loop)
        
        # Should complete without error
        await service.detach()


class TestFridaServiceScriptInjection:
    """Test script injection functionality."""
    
    @pytest.mark.asyncio
    async def test_inject_script_success(self, config_manager, logger, event_loop, session_manager):
        """Test successful script injection."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock session
        mock_session = Mock()
        mock_script = Mock()
        mock_session.create_script.return_value = mock_script
        session_manager.frida_session = mock_session
        
        script_content = "console.log('test script');"
        result = await service.inject_script(script_content)
        
        assert result is True
        mock_session.create_script.assert_called_once_with(script_content)
        mock_script.on.assert_called_once_with('message', service._on_message)
        mock_script.load.assert_called_once()
        assert session_manager.frida_script == mock_script
        session_manager.set_script_active.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_inject_script_without_session(self, config_manager, logger, event_loop, session_manager):
        """Test script injection without active session."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        script_content = "console.log('test script');"
        result = await service.inject_script(script_content)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_inject_script_with_metadata(self, config_manager, logger, event_loop, session_manager):
        """Test script injection with metadata extraction."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock session
        mock_session = Mock()
        mock_script = Mock()
        mock_session.create_script.return_value = mock_script
        session_manager.frida_session = mock_session
        
        script_content = '''/** TOWERIQ_HOOK_METADATA
{
    "scriptName": "Test Script",
    "targetPackage": "com.test.game"
}
*/
console.log('test script');'''
        
        result = await service.inject_script(script_content)
        
        assert result is True
        # Verify script name was extracted and passed to session manager
        session_manager.set_script_active.assert_called_once_with("Test Script")
    
    @pytest.mark.asyncio
    async def test_inject_script_handles_exception(self, config_manager, logger, event_loop, session_manager):
        """Test script injection error handling."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock session that will raise exception
        mock_session = Mock()
        mock_session.create_script.side_effect = Exception("Script creation failed")
        session_manager.frida_session = mock_session
        
        script_content = "console.log('test script');"
        result = await service.inject_script(script_content)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_inject_and_run_script_success(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test inject_and_run_script success."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock successful attachment and injection
        mock_device = mock_frida.get_device.return_value
        mock_session = Mock()
        mock_script = Mock()
        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        session_manager.frida_session = mock_session
        
        script_content = "console.log('test script');"
        result = await service.inject_and_run_script("test-device", 1234, script_content)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_inject_and_run_script_attach_fails(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test inject_and_run_script when attach fails."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock attachment failure
        mock_frida.get_device.side_effect = Exception("Device not found")
        
        script_content = "console.log('test script');"
        result = await service.inject_and_run_script("test-device", 1234, script_content)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_inject_and_run_script_injection_fails(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test inject_and_run_script when injection fails."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock successful attachment but failed injection
        mock_device = mock_frida.get_device.return_value
        mock_session = Mock()
        mock_session.create_script.side_effect = Exception("Script creation failed")
        mock_device.attach.return_value = mock_session
        
        script_content = "console.log('test script');"
        result = await service.inject_and_run_script("test-device", 1234, script_content)
        
        assert result is False


class TestFridaServiceMessageProcessing:
    """Test message processing and logging."""
    
    def test_log_clean_message_hook_log(self, config_manager, logger, event_loop):
        """Test clean logging of hook log messages."""
        service = FridaService(config_manager, logger, event_loop)
        
        message = {
            'type': 'send',
            'payload': {
                'type': 'hook_log',
                'payload': {
                    'event': 'hook_loaded',
                    'message': 'Hook on GameManager is live.',
                    'level': 'INFO'
                }
            }
        }
        
        # Should not raise exception
        service._log_clean_message(message)
    
    def test_log_clean_message_game_event(self, config_manager, logger, event_loop):
        """Test clean logging of game event messages."""
        service = FridaService(config_manager, logger, event_loop)
        
        message = {
            'type': 'send',
            'payload': {
                'type': 'game_event',
                'payload': {
                    'event': 'startNewRound',
                    'runId': 'test-run-id',
                    'seed': 'test-seed',
                    'tier': '1'
                }
            }
        }
        
        # Should not raise exception
        service._log_clean_message(message)
    
    def test_log_clean_message_game_metrics(self, config_manager, logger, event_loop):
        """Test clean logging of game metrics messages."""
        service = FridaService(config_manager, logger, event_loop)
        
        message = {
            'type': 'send',
            'payload': {
                'type': 'game_metric',
                'payload': {
                    'metrics': {
                        'coins_earned': 100,
                        'waves_completed': 5,
                        'damage_dealt': 1000
                    }
                }
            }
        }
        
        # Should not raise exception
        service._log_clean_message(message)
    
    def test_log_clean_message_skips_heartbeat(self, config_manager, logger, event_loop):
        """Test that heartbeat messages are skipped."""
        service = FridaService(config_manager, logger, event_loop)
        
        message = {
            'type': 'send',
            'payload': {
                'type': 'hook_log',
                'payload': {
                    'event': 'frida_heartbeat',
                    'message': 'Frida script is alive'
                }
            }
        }
        
        # Should not raise exception and should skip logging
        service._log_clean_message(message)
    
    def test_on_message_send_type(self, config_manager, logger, event_loop, session_manager):
        """Test _on_message with send type."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        session_manager.frida_attached_pid = 1234
        
        message = {
            'type': 'send',
            'payload': {
                'type': 'test',
                'payload': {'data': 'test'},
                'timestamp': '2024-01-01T12:00:00Z'
            }
        }
        
        service._on_message(message, None)
        
        # Message should be queued
        assert service.queue_size == 1
    
    def test_on_message_bulk_payload(self, config_manager, logger, event_loop, session_manager):
        """Test _on_message with bulk payload."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        session_manager.frida_attached_pid = 1234
        
        message = {
            'type': 'send',
            'payload': [
                {'type': 'test1', 'payload': {'data': 'test1'}},
                {'type': 'test2', 'payload': {'data': 'test2'}}
            ]
        }
        
        service._on_message(message, None)
        
        # Both messages should be queued
        assert service.queue_size == 2
    
    def test_on_message_heartbeat_updates_session_manager(self, config_manager, logger, event_loop, session_manager):
        """Test that heartbeat messages update session manager."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        message = {
            'type': 'send',
            'payload': {
                'type': 'hook_log',
                'payload': {
                    'event': 'frida_heartbeat',
                    'isGameReachable': True
                }
            }
        }
        
        service._on_message(message, None)
        
        session_manager.update_script_heartbeat.assert_called_once_with(True)
    
    def test_on_message_error_type(self, config_manager, logger, event_loop, session_manager):
        """Test _on_message with error type."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        session_manager.frida_attached_pid = 1234
        
        message = {
            'type': 'error',
            'description': 'Script error',
            'stack': 'at line 10',
            'fileName': 'script.js',
            'lineNumber': 10
        }
        
        service._on_message(message, None)
        
        # Error message should be queued
        assert service.queue_size == 1
    
    def test_on_message_handles_exception(self, config_manager, logger, event_loop, session_manager):
        """Test _on_message error handling."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Invalid message that will cause exception
        message = {'invalid': 'message'}
        
        # Should not raise exception
        service._on_message(message, None)


class TestFridaServiceHealthChecks:
    """Test health check and readiness functionality."""
    
    def test_is_ready_for_connection_success(self, config_manager, logger, event_loop):
        """Test is_ready_for_connection when ready."""
        with patch('src.tower_iq.services.frida_service.frida') as mock_frida:
            service = FridaService(config_manager, logger, event_loop)
            
            result = service.is_ready_for_connection()
            
            assert result is True
    
    def test_is_ready_for_connection_no_frida(self, config_manager, logger, event_loop):
        """Test is_ready_for_connection when frida is not available."""
        with patch('src.tower_iq.services.frida_service.frida', None):
            service = FridaService(config_manager, logger, event_loop)
            
            result = service.is_ready_for_connection()
            
            assert result is False
    
    def test_is_ready_for_connection_already_attached(self, config_manager, logger, event_loop, session_manager):
        """Test is_ready_for_connection when already attached."""
        with patch('src.tower_iq.services.frida_service.frida') as mock_frida:
            service = FridaService(config_manager, logger, event_loop, session_manager)
            
            # Mock attached state
            session_manager.frida_session = Mock()
            session_manager.frida_attached_pid = 1234
            
            result = service.is_ready_for_connection()
            
            assert result is False
    
    def test_is_ready_for_connection_shutdown_requested(self, config_manager, logger, event_loop):
        """Test is_ready_for_connection when shutdown is requested."""
        with patch('src.tower_iq.services.frida_service.frida') as mock_frida:
            service = FridaService(config_manager, logger, event_loop)
            service._shutdown_requested = True
            
            result = service.is_ready_for_connection()
            
            assert result is False
    
    def test_is_ready_for_connection_no_event_loop(self, config_manager, logger):
        """Test is_ready_for_connection when event loop is not set."""
        with patch('src.tower_iq.services.frida_service.frida') as mock_frida:
            service = FridaService(config_manager, logger, None)
            
            result = service.is_ready_for_connection()
            
            assert result is False
    
    def test_is_ready_for_connection_no_message_queue(self, config_manager, logger, event_loop):
        """Test is_ready_for_connection when message queue is not initialized."""
        with patch('src.tower_iq.services.frida_service.frida') as mock_frida:
            service = FridaService(config_manager, logger, event_loop)
            service._message_queue = None
            
            result = service.is_ready_for_connection()
            
            assert result is False
    
    def test_get_service_state(self, config_manager, logger, event_loop, session_manager):
        """Test get_service_state method."""
        with patch('src.tower_iq.services.frida_service.frida') as mock_frida:
            service = FridaService(config_manager, logger, event_loop, session_manager)
            
            # Mock attached state
            session_manager.frida_device = Mock()
            session_manager.frida_session = Mock()
            session_manager.frida_script = Mock()
            session_manager.frida_attached_pid = 1234
            
            state = service.get_service_state()
            
            assert state['frida_available'] is True
            assert state['is_attached'] is True
            assert state['attached_pid'] == 1234
            assert state['shutdown_requested'] is False
            assert state['event_loop_set'] is True
            assert state['message_queue_initialized'] is True
            assert state['device_connected'] is True
            assert state['session_active'] is True
            assert state['script_loaded'] is True
    
    def test_validate_service_health_healthy(self, config_manager, logger, event_loop, session_manager):
        """Test validate_service_health when healthy."""
        with patch('src.tower_iq.services.frida_service.frida') as mock_frida:
            service = FridaService(config_manager, logger, event_loop, session_manager)
            
            # Mock healthy state
            session_manager.frida_device = Mock()
            session_manager.frida_session = Mock()
            session_manager.frida_script = Mock()
            
            is_healthy, issues = service.validate_service_health()
            
            assert is_healthy is True
            assert len(issues) == 0
    
    def test_validate_service_health_unhealthy(self, config_manager, logger, event_loop):
        """Test validate_service_health when unhealthy."""
        with patch('src.tower_iq.services.frida_service.frida', None):
            service = FridaService(config_manager, logger, event_loop)
            
            is_healthy, issues = service.validate_service_health()
            
            assert is_healthy is False
            assert len(issues) > 0
            assert "Frida library not available" in issues


class TestFridaServiceHookCompatibility:
    """Test hook compatibility checking."""
    
    def test_check_local_hook_compatibility(self, config_manager, logger, event_loop, temp_hooks_dir):
        """Test local hook compatibility checking."""
        service = FridaService(config_manager, logger, event_loop)
        
        # Mock config to return our temp hooks dir
        config_manager.get_project_root.return_value = str(temp_hooks_dir.parent)
        
        # Should find compatible script
        result = service.check_local_hook_compatibility("com.test.game", "1.0.0")
        assert result is True
        
        # Should not find incompatible script
        result = service.check_local_hook_compatibility("com.different.game", "1.0.0")
        assert result is False


class TestHookContractValidator:
    """Test HookContractValidator (deprecated but still used)."""
    
    def test_hook_contract_validator_init(self, config_manager, logger):
        """Test HookContractValidator initialization."""
        validator = HookContractValidator(config_manager, logger)
        
        assert validator.config == config_manager
        assert validator.logger == logger
    
    def test_check_local_hook_compatibility(self, config_manager, logger, temp_hooks_dir):
        """Test hook compatibility checking."""
        validator = HookContractValidator(config_manager, logger)
        
        # Mock config to return our temp hooks dir
        config_manager.get_project_root.return_value = str(temp_hooks_dir.parent)
        
        # Should find compatible script
        result = validator.check_local_hook_compatibility("com.test.game", "1.0.0")
        assert result is True
        
        # Should not find incompatible script
        result = validator.check_local_hook_compatibility("com.different.game", "1.0.0")
        assert result is False


class TestFridaServiceIntegration:
    """Integration tests for FridaService."""
    
    @pytest.mark.asyncio
    async def test_full_attach_inject_detach_cycle(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test complete attach, inject, detach cycle."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock successful attachment
        mock_device = mock_frida.get_device.return_value
        mock_session = Mock()
        mock_script = Mock()
        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        session_manager.frida_session = mock_session
        
        # Test attachment
        attach_result = await service.attach(1234, "test-device")
        assert attach_result is True
        
        # Test script injection
        script_content = "console.log('test');"
        inject_result = await service.inject_script(script_content)
        assert inject_result is True
        
        # Test detachment
        await service.detach()
        
        # Verify cleanup
        assert session_manager.frida_session is None
        assert session_manager.frida_script is None
        assert service._shutdown_requested is True
    
    @pytest.mark.asyncio
    async def test_message_flow_integration(self, config_manager, logger, event_loop, session_manager):
        """Test complete message flow from injection to processing."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        session_manager.frida_attached_pid = 1234
        
        # Simulate receiving messages from Frida script
        test_messages = [
            {
                'type': 'send',
                'payload': {
                    'type': 'hook_log',
                    'payload': {
                        'event': 'hook_loaded',
                        'message': 'Hook loaded successfully',
                        'level': 'INFO'
                    }
                }
            },
            {
                'type': 'send',
                'payload': {
                    'type': 'game_event',
                    'payload': {
                        'event': 'startNewRound',
                        'runId': 'test-run',
                        'seed': 'test-seed',
                        'tier': '1'
                    }
                }
            }
        ]
        
        # Process messages
        for message in test_messages:
            service._on_message(message, None)
        
        # Verify messages were queued
        assert service.queue_size == 2
        
        # Retrieve messages
        message1 = await service.get_message()
        message2 = await service.get_message()
        
        assert message1['type'] == 'hook_log'
        assert message2['type'] == 'game_event'
        assert message1['pid'] == 1234
        assert message2['pid'] == 1234
    
    @pytest.mark.asyncio
    async def test_error_handling_integration(self, config_manager, logger, event_loop, session_manager, mock_frida):
        """Test error handling in complete workflow."""
        service = FridaService(config_manager, logger, event_loop, session_manager)
        
        # Mock attachment failure
        mock_frida.get_device.side_effect = Exception("Connection failed")
        
        # Should handle gracefully
        attach_result = await service.attach(1234)
        assert attach_result is False
        
        # Should still be able to detach without issues
        await service.detach()
        
        # Should report not ready for connection
        ready = service.is_ready_for_connection()
        assert ready is False

        assert ready is False


