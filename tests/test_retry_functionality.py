"""
Tests for retry and error recovery functionality in ConnectionStageManager.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from src.tower_iq.services.connection_stage_manager import (
    ConnectionStageManager, StageStatus, ConnectionStageInfo
)


@pytest.fixture
def mock_session_manager():
    """Create a mock session manager."""
    session_manager = MagicMock()
    session_manager.hook_activation_stage = "idle"
    session_manager.hook_activation_message = ""
    return session_manager


@pytest.fixture
def mock_emulator_service():
    """Create a mock emulator service."""
    service = MagicMock()
    service.is_frida_server_responsive = AsyncMock(return_value=True)
    service.ensure_frida_server_is_running = AsyncMock()
    service.start_frida_server = AsyncMock()
    return service


@pytest.fixture
def mock_frida_service():
    """Create a mock frida service."""
    service = MagicMock()
    service.check_local_hook_compatibility = MagicMock(return_value=True)
    service.attach = AsyncMock(return_value=True)
    service.inject_script = AsyncMock(return_value=True)
    service.session = None
    service.detach = AsyncMock()
    return service


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    logger = MagicMock()
    logger.bind.return_value = logger
    return logger


@pytest.fixture
def stage_manager(mock_session_manager, mock_emulator_service, mock_frida_service, mock_logger):
    """Create a ConnectionStageManager instance."""
    return ConnectionStageManager(
        mock_session_manager, mock_emulator_service, mock_frida_service, mock_logger
    )


@pytest.mark.asyncio
async def test_retry_failed_stage_success(stage_manager):
    """Test successful retry of a failed stage."""
    # Set up connection context
    stage_manager.current_device_id = "test_device"
    stage_manager.current_process_info = {"package": "com.test.app", "pid": 1234}
    
    # Mark a stage as failed
    stage = stage_manager.stage_map["frida_server_start"]
    stage.status = StageStatus.FAILED
    stage.error_details = "Test error"
    
    # Mock stage execution to succeed on retry
    stage_manager._execute_stage_logic = AsyncMock(return_value=True)
    
    result = await stage_manager.retry_failed_stage("frida_server_start")
    
    assert result is True
    assert stage.status == StageStatus.COMPLETED
    assert stage.error_details is None


@pytest.mark.asyncio
async def test_retry_failed_stage_no_context(stage_manager):
    """Test retry without active connection context."""
    result = await stage_manager.retry_failed_stage("frida_server_start")
    
    assert result is False


@pytest.mark.asyncio
async def test_retry_failed_stage_unknown_stage(stage_manager):
    """Test retry of unknown stage."""
    stage_manager.current_device_id = "test_device"
    stage_manager.current_process_info = {"package": "com.test.app"}
    
    result = await stage_manager.retry_failed_stage("unknown_stage")
    
    assert result is False


@pytest.mark.asyncio
async def test_retry_failed_stage_not_failed(stage_manager):
    """Test retry of stage that is not in failed state."""
    stage_manager.current_device_id = "test_device"
    stage_manager.current_process_info = {"package": "com.test.app"}
    
    # Stage is in completed state, not failed
    stage = stage_manager.stage_map["frida_server_start"]
    stage.status = StageStatus.COMPLETED
    
    result = await stage_manager.retry_failed_stage("frida_server_start")
    
    assert result is False


def test_get_user_friendly_error_message_frida_install(stage_manager):
    """Test user-friendly error messages for Frida installation errors."""
    # Network error
    network_error = Exception("Network connection failed")
    message = stage_manager.get_user_friendly_error_message("frida_server_install", network_error)
    assert "internet connection" in message.lower()
    
    # Permission error
    permission_error = Exception("Permission denied")
    message = stage_manager.get_user_friendly_error_message("frida_server_install", permission_error)
    assert "root access" in message.lower()
    
    # Storage error
    storage_error = Exception("No space left on device")
    message = stage_manager.get_user_friendly_error_message("frida_server_install", storage_error)
    assert "storage space" in message.lower()
    
    # Generic error
    generic_error = Exception("Unknown error")
    message = stage_manager.get_user_friendly_error_message("frida_server_install", generic_error)
    assert "connectivity" in message.lower()


def test_get_user_friendly_error_message_process_attachment(stage_manager):
    """Test user-friendly error messages for process attachment errors."""
    # Permission error
    permission_error = Exception("Permission denied")
    message = stage_manager.get_user_friendly_error_message("process_attachment", permission_error)
    assert "permission" in message.lower()
    
    # Process not found error
    process_error = Exception("Process not found")
    message = stage_manager.get_user_friendly_error_message("process_attachment", process_error)
    assert "application is running" in message.lower()
    
    # Timeout error
    timeout_error = Exception("Connection timeout")
    message = stage_manager.get_user_friendly_error_message("process_attachment", timeout_error)
    assert "timed out" in message.lower()


def test_get_user_friendly_error_message_script_injection(stage_manager):
    """Test user-friendly error messages for script injection errors."""
    # Permission error
    permission_error = Exception("Permission denied")
    message = stage_manager.get_user_friendly_error_message("script_injection", permission_error)
    assert "security settings" in message.lower()
    
    # Script error
    script_error = Exception("Script syntax error")
    message = stage_manager.get_user_friendly_error_message("script_injection", script_error)
    assert "script updates" in message.lower()
    
    # Memory error
    memory_error = Exception("Memory allocation failed")
    message = stage_manager.get_user_friendly_error_message("script_injection", memory_error)
    assert "memory" in message.lower()


def test_get_user_friendly_error_message_unknown_stage(stage_manager):
    """Test user-friendly error message for unknown stage."""
    error = Exception("Test error")
    message = stage_manager.get_user_friendly_error_message("unknown_stage", error)
    assert "unknown stage" in message.lower()


def test_get_retry_suggestion(stage_manager):
    """Test retry suggestions for different stages."""
    suggestions = {
        "frida_server_check": "device connection",
        "frida_server_install": "internet connection",
        "frida_server_start": "root access",
        "frida_server_verify": "connectivity",
        "hook_compatibility_check": "application version",
        "process_attachment": "application is running",
        "script_injection": "memory"
    }
    
    for stage_name, expected_keyword in suggestions.items():
        suggestion = stage_manager.get_retry_suggestion(stage_name)
        assert expected_keyword.lower() in suggestion.lower()
    
    # Test unknown stage
    unknown_suggestion = stage_manager.get_retry_suggestion("unknown_stage")
    assert "restart" in unknown_suggestion.lower()


def test_get_connection_health_status_healthy(stage_manager):
    """Test connection health status when all stages are completed."""
    # Mark all stages as completed
    for stage in stage_manager.stages:
        stage.status = StageStatus.COMPLETED
    
    health = stage_manager.get_connection_health_status()
    
    assert health["total_stages"] == 7
    assert health["completed_stages"] == 7
    assert health["failed_stages"] == 0
    assert health["active_stages"] == 0
    assert health["is_healthy"] is True
    assert health["current_stage"] is None
    assert health["last_error"] is None


def test_get_connection_health_status_with_failures(stage_manager):
    """Test connection health status with failed stages."""
    # Mark some stages as completed, one as failed, one as active
    stage_manager.stages[0].status = StageStatus.COMPLETED
    stage_manager.stages[1].status = StageStatus.COMPLETED
    stage_manager.stages[2].status = StageStatus.FAILED
    stage_manager.stages[2].error_details = "Test error"
    stage_manager.stages[3].status = StageStatus.ACTIVE
    stage_manager.stages[4].retry_count = 2
    
    health = stage_manager.get_connection_health_status()
    
    assert health["total_stages"] == 7
    assert health["completed_stages"] == 2
    assert health["failed_stages"] == 1
    assert health["active_stages"] == 1
    assert health["total_retries"] == 2
    assert health["is_healthy"] is False
    assert health["current_stage"] == stage_manager.stages[3].stage_name
    assert health["last_error"] == "Test error"


def test_get_connection_health_status_with_retries(stage_manager):
    """Test connection health status with retry counts."""
    # Add retry counts to stages
    stage_manager.stages[0].retry_count = 1
    stage_manager.stages[1].retry_count = 2
    stage_manager.stages[2].retry_count = 1
    
    health = stage_manager.get_connection_health_status()
    
    assert health["total_retries"] == 4


@pytest.mark.asyncio
async def test_retry_failed_stage_continues_with_remaining(stage_manager):
    """Test that retry continues with remaining stages after success."""
    # Set up connection context
    stage_manager.current_device_id = "test_device"
    stage_manager.current_process_info = {"package": "com.test.app", "pid": 1234}
    
    # Mark middle stage as failed, later stages as pending
    stage_manager.stages[2].status = StageStatus.FAILED  # frida_server_start
    stage_manager.stages[3].status = StageStatus.PENDING  # frida_server_verify
    stage_manager.stages[4].status = StageStatus.PENDING  # hook_compatibility_check
    
    # Mock stage execution to succeed
    stage_manager._execute_stage_logic = AsyncMock(return_value=True)
    
    result = await stage_manager.retry_failed_stage("frida_server_start")
    
    assert result is True
    # Should have executed the failed stage plus remaining pending stages
    assert stage_manager._execute_stage_logic.call_count >= 3


@pytest.mark.asyncio
async def test_retry_failed_stage_stops_on_subsequent_failure(stage_manager):
    """Test that retry stops if a subsequent stage fails."""
    # Set up connection context
    stage_manager.current_device_id = "test_device"
    stage_manager.current_process_info = {"package": "com.test.app", "pid": 1234}
    
    # Mark middle stage as failed
    stage_manager.stages[2].status = StageStatus.FAILED  # frida_server_start
    
    # Mock stage execution: first call succeeds, second fails
    call_count = 0
    async def mock_stage_logic(stage):
        nonlocal call_count
        call_count += 1
        return call_count == 1  # First call succeeds, second fails
    
    stage_manager._execute_stage_logic = AsyncMock(side_effect=mock_stage_logic)
    
    result = await stage_manager.retry_failed_stage("frida_server_start")
    
    assert result is False