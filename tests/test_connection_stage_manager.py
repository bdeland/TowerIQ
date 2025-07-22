"""
Tests for ConnectionStageManager functionality.
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


def test_stage_manager_initialization(stage_manager):
    """Test that stage manager initializes correctly."""
    assert len(stage_manager.stages) == 7
    assert len(stage_manager.stage_map) == 7
    assert not stage_manager.is_executing
    assert stage_manager.current_device_id is None
    assert stage_manager.current_process_info is None
    
    # Check that all expected stages are present
    expected_stages = [
        "frida_server_check",
        "frida_server_install", 
        "frida_server_start",
        "frida_server_verify",
        "hook_compatibility_check",
        "process_attachment",
        "script_injection"
    ]
    
    for stage_name in expected_stages:
        assert stage_name in stage_manager.stage_map
        stage = stage_manager.stage_map[stage_name]
        assert stage.status == StageStatus.PENDING


@pytest.mark.asyncio
async def test_execute_connection_flow_success(stage_manager, mock_session_manager):
    """Test successful connection flow execution."""
    device_id = "test_device"
    process_info = {
        'package': 'com.example.app',
        'version': '1.0.0',
        'pid': 1234
    }
    
    # Mock all stage executions to succeed
    stage_manager._execute_stage_logic = AsyncMock(return_value=True)
    
    result = await stage_manager.execute_connection_flow(device_id, process_info)
    
    assert result is True
    assert stage_manager.current_device_id == device_id
    assert stage_manager.current_process_info == process_info
    assert not stage_manager.is_executing  # Should be reset after completion
    
    # Verify session manager was updated
    assert mock_session_manager.hook_activation_stage == "success"
    assert "successfully" in mock_session_manager.hook_activation_message.lower()


@pytest.mark.asyncio
async def test_execute_connection_flow_failure(stage_manager, mock_session_manager):
    """Test connection flow with stage failure."""
    device_id = "test_device"
    process_info = {
        'package': 'com.example.app',
        'version': '1.0.0',
        'pid': 1234
    }
    
    # Mock stage logic to always fail (even with retries)
    stage_manager._execute_stage_logic = AsyncMock(return_value=False)
    
    result = await stage_manager.execute_connection_flow(device_id, process_info)
    
    assert result is False
    assert not stage_manager.is_executing
    
    # Verify session manager shows failure
    assert mock_session_manager.hook_activation_stage == "failed"


@pytest.mark.asyncio
async def test_execute_connection_flow_already_executing(stage_manager):
    """Test that connection flow rejects concurrent execution."""
    stage_manager.is_executing = True
    
    result = await stage_manager.execute_connection_flow("device", {})
    
    assert result is False


@pytest.mark.asyncio
async def test_execute_stage_with_retries(stage_manager):
    """Test stage execution with retry logic."""
    stage = ConnectionStageInfo(
        stage_name="test_stage",
        display_name="Test Stage",
        description="Test description"
    )
    
    # Mock stage logic to fail twice, then succeed
    call_count = 0
    async def mock_stage_logic(stage_info):
        nonlocal call_count
        call_count += 1
        return call_count >= 3  # Fail first 2 times, succeed on 3rd
    
    stage_manager._execute_stage_logic = AsyncMock(side_effect=mock_stage_logic)
    stage_manager.max_retries["test_stage"] = 3
    
    result = await stage_manager._execute_stage(stage)
    
    assert result is True
    assert stage.status == StageStatus.COMPLETED
    assert stage.retry_count == 2  # 2 retries before success
    assert stage.start_time is not None
    assert stage.end_time is not None


@pytest.mark.asyncio
async def test_execute_stage_max_retries_exceeded(stage_manager):
    """Test stage execution when max retries are exceeded."""
    stage = ConnectionStageInfo(
        stage_name="test_stage",
        display_name="Test Stage", 
        description="Test description"
    )
    
    # Mock stage logic to always fail
    stage_manager._execute_stage_logic = AsyncMock(return_value=False)
    stage_manager.max_retries["test_stage"] = 2
    
    result = await stage_manager._execute_stage(stage)
    
    assert result is False
    assert stage.status == StageStatus.FAILED
    assert stage.retry_count == 2
    assert stage.error_details is not None


@pytest.mark.asyncio
async def test_check_frida_server_already_running(stage_manager, mock_emulator_service):
    """Test Frida server check when server is already running."""
    mock_emulator_service.is_frida_server_responsive.return_value = True
    
    result = await stage_manager._check_frida_server("test_device")
    
    assert result is True
    
    # Check that install and start stages are marked as skipped
    install_stage = stage_manager.stage_map["frida_server_install"]
    start_stage = stage_manager.stage_map["frida_server_start"]
    assert install_stage.status == StageStatus.SKIPPED
    assert start_stage.status == StageStatus.SKIPPED


@pytest.mark.asyncio
async def test_check_frida_server_not_running(stage_manager, mock_emulator_service):
    """Test Frida server check when server is not running."""
    mock_emulator_service.is_frida_server_responsive.return_value = False
    
    result = await stage_manager._check_frida_server("test_device")
    
    assert result is True  # Should continue to installation
    
    # Check that stages are not skipped
    install_stage = stage_manager.stage_map["frida_server_install"]
    start_stage = stage_manager.stage_map["frida_server_start"]
    assert install_stage.status == StageStatus.PENDING
    assert start_stage.status == StageStatus.PENDING


@pytest.mark.asyncio
async def test_install_frida_server_success(stage_manager, mock_emulator_service):
    """Test successful Frida server installation."""
    result = await stage_manager._install_frida_server("test_device")
    
    assert result is True
    mock_emulator_service.ensure_frida_server_is_running.assert_called_once_with("test_device")


@pytest.mark.asyncio
async def test_install_frida_server_failure(stage_manager, mock_emulator_service):
    """Test Frida server installation failure."""
    mock_emulator_service.ensure_frida_server_is_running.side_effect = Exception("Install failed")
    
    result = await stage_manager._install_frida_server("test_device")
    
    assert result is False


@pytest.mark.asyncio
async def test_start_frida_server_success(stage_manager, mock_emulator_service):
    """Test successful Frida server start."""
    result = await stage_manager._start_frida_server("test_device")
    
    assert result is True
    mock_emulator_service.start_frida_server.assert_called_once_with("test_device")


@pytest.mark.asyncio
async def test_verify_frida_server_success(stage_manager, mock_emulator_service):
    """Test successful Frida server verification."""
    mock_emulator_service.is_frida_server_responsive.return_value = True
    
    result = await stage_manager._verify_frida_server("test_device")
    
    assert result is True


@pytest.mark.asyncio
async def test_verify_frida_server_failure(stage_manager, mock_emulator_service):
    """Test Frida server verification failure."""
    mock_emulator_service.is_frida_server_responsive.return_value = False
    
    result = await stage_manager._verify_frida_server("test_device")
    
    assert result is False


@pytest.mark.asyncio
async def test_check_hook_compatibility_success(stage_manager, mock_frida_service):
    """Test successful hook compatibility check."""
    process_info = {
        'package': 'com.example.app',
        'version': '1.0.0'
    }
    
    result = await stage_manager._check_hook_compatibility(process_info)
    
    assert result is True
    mock_frida_service.check_local_hook_compatibility.assert_called_once_with(
        'com.example.app', '1.0.0'
    )


@pytest.mark.asyncio
async def test_check_hook_compatibility_failure(stage_manager, mock_frida_service):
    """Test hook compatibility check failure."""
    mock_frida_service.check_local_hook_compatibility.return_value = False
    process_info = {
        'package': 'com.example.app',
        'version': '1.0.0'
    }
    
    result = await stage_manager._check_hook_compatibility(process_info)
    
    assert result is False


@pytest.mark.asyncio
async def test_attach_to_process_success(stage_manager, mock_frida_service):
    """Test successful process attachment."""
    process_info = {
        'package': 'com.example.app',
        'pid': 1234
    }
    
    result = await stage_manager._attach_to_process("test_device", process_info)
    
    assert result is True
    mock_frida_service.attach.assert_called_once_with(1234, "test_device")


@pytest.mark.asyncio
async def test_attach_to_process_no_pid(stage_manager):
    """Test process attachment with missing PID."""
    process_info = {
        'package': 'com.example.app'
        # Missing PID
    }
    
    result = await stage_manager._attach_to_process("test_device", process_info)
    
    assert result is False


@pytest.mark.asyncio
async def test_inject_script_success(stage_manager, mock_frida_service):
    """Test successful script injection."""
    process_info = {
        'package': 'com.example.app',
        'version': '1.0.0'
    }
    
    result = await stage_manager._inject_script(process_info)
    
    assert result is True
    mock_frida_service.inject_script.assert_called_once_with('1.0.0')


@pytest.mark.asyncio
async def test_inject_script_failure(stage_manager, mock_frida_service):
    """Test script injection failure."""
    mock_frida_service.inject_script.return_value = False
    process_info = {
        'package': 'com.example.app',
        'version': '1.0.0'
    }
    
    result = await stage_manager._inject_script(process_info)
    
    assert result is False


def test_get_stage_status(stage_manager):
    """Test getting stage status."""
    stage = stage_manager.get_stage_status("frida_server_check")
    
    assert stage is not None
    assert stage.stage_name == "frida_server_check"
    assert stage.status == StageStatus.PENDING
    
    # Test non-existent stage
    assert stage_manager.get_stage_status("non_existent") is None


def test_get_all_stages_status(stage_manager):
    """Test getting all stages status."""
    stages = stage_manager.get_all_stages_status()
    
    assert len(stages) == 7
    assert all(isinstance(stage, ConnectionStageInfo) for stage in stages)


@pytest.mark.asyncio
async def test_cancel_connection_flow(stage_manager, mock_frida_service):
    """Test cancelling connection flow."""
    stage_manager.is_executing = True
    mock_frida_service.session = MagicMock()  # Simulate active session
    
    await stage_manager.cancel_connection_flow()
    
    assert not stage_manager.is_executing
    mock_frida_service.detach.assert_called_once()


def test_is_connection_active(stage_manager):
    """Test connection active status."""
    assert not stage_manager.is_connection_active()
    
    stage_manager.is_executing = True
    assert stage_manager.is_connection_active()


def test_reset_stages(stage_manager):
    """Test resetting stages to initial state."""
    # Modify a stage
    stage = stage_manager.stages[0]
    stage.status = StageStatus.COMPLETED
    stage.message = "Test message"
    stage.retry_count = 2
    
    stage_manager._reset_stages()
    
    # Verify stage is reset
    assert stage.status == StageStatus.PENDING
    assert stage.message == ""
    assert stage.retry_count == 0
    assert stage.start_time is None
    assert stage.end_time is None


def test_skip_stage(stage_manager):
    """Test skipping a stage."""
    stage_manager._skip_stage("frida_server_install")
    
    stage = stage_manager.stage_map["frida_server_install"]
    assert stage.status == StageStatus.SKIPPED
    assert "Skipped" in stage.message


def test_update_session_stage(stage_manager, mock_session_manager):
    """Test updating session manager with stage info."""
    stage_manager._update_session_stage("test_stage", "Test message")
    
    assert mock_session_manager.hook_activation_stage == "test_stage"
    assert mock_session_manager.hook_activation_message == "Test message"