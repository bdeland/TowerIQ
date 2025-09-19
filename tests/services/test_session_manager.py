import asyncio
from unittest.mock import AsyncMock, MagicMock

from tower_iq.core import session as session_module
from tower_iq.core.errors import DeviceConnectionError
from tower_iq.core.session import SessionManager


def test_connect_to_device_retries_before_success(monkeypatch):
    session = SessionManager()
    emulator_service = MagicMock()

    emulator_service._test_device_connection = AsyncMock(
        side_effect=[
            DeviceConnectionError("serial-123", "abnormal_status", status="offline"),
            DeviceConnectionError("serial-123", "abnormal_status", status="offline"),
            True,
        ]
    )
    emulator_service._get_device_properties = AsyncMock(
        return_value={'ro.product.cpu.abi': 'arm64-v8a'}
    )

    sleep_mock = AsyncMock()
    monkeypatch.setattr(session_module.asyncio, "sleep", sleep_mock)

    result = asyncio.run(session.connect_to_device("serial-123", emulator_service))

    assert result is True
    assert session.connected_device_serial == "serial-123"
    assert emulator_service._test_device_connection.await_count == 3
    assert sleep_mock.await_count == 2
    emulator_service._get_device_properties.assert_awaited_once()


def test_connect_to_device_fails_after_max_retries(monkeypatch):
    session = SessionManager()
    emulator_service = MagicMock()

    emulator_service._test_device_connection = AsyncMock(
        side_effect=[
            DeviceConnectionError("serial-999", "not_found"),
            DeviceConnectionError("serial-999", "not_found"),
            DeviceConnectionError("serial-999", "not_found"),
        ]
    )
    emulator_service._get_device_properties = AsyncMock()

    sleep_mock = AsyncMock()
    monkeypatch.setattr(session_module.asyncio, "sleep", sleep_mock)

    result = asyncio.run(session.connect_to_device("serial-999", emulator_service))

    assert result is False
    assert session.connected_device_serial is None
    assert emulator_service._test_device_connection.await_count == 3
    assert sleep_mock.await_count == 2
    emulator_service._get_device_properties.assert_not_awaited()
