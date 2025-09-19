import asyncio
from unittest.mock import AsyncMock, MagicMock

from tower_iq.core.session import ErrorInfo, ErrorType
from tower_iq.services.connection_flow_controller import (
    ConnectionFlowController,
    ConnectionStage,
    RetryStrategy,
)


def test_validate_device_connection_uses_session_manager_connect():
    session_manager = MagicMock()
    session_manager.connect_to_device = AsyncMock(return_value=True)

    emulator_service = MagicMock()
    device = MagicMock()
    device.serial = "device-123"
    emulator_service.discover_devices = AsyncMock(return_value=[device])

    cleanup_manager = MagicMock()

    controller = ConnectionFlowController(
        session_manager=session_manager,
        cleanup_manager=cleanup_manager,
        emulator_service=emulator_service,
    )

    result = asyncio.run(controller._validate_device_connection("device-123"))

    assert result is True
    emulator_service.discover_devices.assert_awaited_once()
    session_manager.connect_to_device.assert_awaited_once_with("device-123", emulator_service)


def test_validate_device_connection_missing_device_returns_false():
    session_manager = MagicMock()
    session_manager.connect_to_device = AsyncMock()

    emulator_service = MagicMock()
    emulator_service.discover_devices = AsyncMock(return_value=[])

    cleanup_manager = MagicMock()

    controller = ConnectionFlowController(
        session_manager=session_manager,
        cleanup_manager=cleanup_manager,
        emulator_service=emulator_service,
    )

    result = asyncio.run(controller._validate_device_connection("device-123"))

    assert result is False
    session_manager.connect_to_device.assert_not_called()


def test_device_validation_failure_propagates_error_info():
    session_manager = MagicMock()
    session_manager.connect_to_device = AsyncMock(return_value=False)
    session_manager.set_error_info = MagicMock()
    session_manager.transition_to_state = MagicMock()
    session_manager.update_stage_progress = MagicMock()

    emulator_service = MagicMock()
    device = MagicMock()
    device.serial = "device-123"
    emulator_service.discover_devices = AsyncMock(return_value=[device])

    cleanup_manager = MagicMock()

    controller = ConnectionFlowController(
        session_manager=session_manager,
        cleanup_manager=cleanup_manager,
        emulator_service=emulator_service,
    )

    controller._retry_config[ErrorType.UNKNOWN] = {
        "max_retries": 0,
        "strategy": RetryStrategy.NO_RETRY,
        "base_delay": 0,
        "max_delay": 0,
        "jitter": False,
    }

    controller._get_stage_recovery_suggestions = MagicMock(return_value=[])

    result = asyncio.run(
        controller._execute_stage_with_retry(
            ConnectionStage.DEVICE_VALIDATION,
            "device-123",
            process_info=None,
        )
    )

    assert result is False
    session_manager.set_error_info.assert_called_once()
    error_info_arg = session_manager.set_error_info.call_args[0][0]
    assert isinstance(error_info_arg, ErrorInfo)
    assert error_info_arg.error_type == ErrorType.UNKNOWN
