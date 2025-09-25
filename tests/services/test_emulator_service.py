import sys
import types
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import AsyncMock

import asyncio

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

sys.modules.setdefault("pandas", types.SimpleNamespace(DataFrame=lambda *args, **kwargs: None))


class _DummyStructlogLogger:
    def bind(self, **_kwargs):
        return self


def _dummy_get_logger():
    return _DummyStructlogLogger()


sys.modules.setdefault("structlog", types.SimpleNamespace(get_logger=_dummy_get_logger))

pyqt6_module = types.ModuleType("PyQt6")
qtcore_module = types.ModuleType("PyQt6.QtCore")


class _DummyQObject:
    pass


def _dummy_pyqt_signal(*_args, **_kwargs):
    def _signal(*_signal_args, **_signal_kwargs):
        return None

    return _signal


qtcore_module.QObject = _DummyQObject
qtcore_module.pyqtSignal = _dummy_pyqt_signal
qtcore_module.QMutex = type("QMutex", (), {})


class _DummyQMutexLocker:
    def __init__(self, *_args, **_kwargs):
        pass


qtcore_module.QMutexLocker = _DummyQMutexLocker
pyqt6_module.QtCore = qtcore_module

sys.modules.setdefault("PyQt6", pyqt6_module)
sys.modules.setdefault("PyQt6.QtCore", qtcore_module)
sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda *_args, **_kwargs: {}))


class _DummyClientResponse:
    async def read(self):
        return b""

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def raise_for_status(self):
        return None


class _DummyClientSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *_args, **_kwargs):
        return _DummyClientResponse()


sys.modules.setdefault("aiohttp", types.SimpleNamespace(ClientSession=_DummyClientSession))

from tower_iq.core.errors import DeviceConnectionError  # noqa: E402
from tower_iq.core.utils import AdbError  # noqa: E402
from tower_iq.services.emulator_service import EmulatorService, Device  # noqa: E402
import tower_iq.services.emulator_service as emulator_service_module  # noqa: E402


class DummyConfig:
    def get(self, _key, default=None):
        return default


class DummyLogger:
    def __init__(self):
        self.records = []

    def bind(self, **_kwargs):
        return self

    def _log(self, level, message, **kwargs):
        self.records.append((level, message, kwargs))

    def info(self, message, **kwargs):
        self._log("info", message, **kwargs)

    def error(self, message, **kwargs):
        self._log("error", message, **kwargs)

    def warning(self, message, **kwargs):
        self._log("warning", message, **kwargs)

    def debug(self, message, **kwargs):
        self._log("debug", message, **kwargs)


class RecordingFridaManager:
    def __init__(self):
        self.calls = []

    async def provision(self, serial, architecture, version):
        self.calls.append((serial, architecture, version))
        return True


def make_device(serial: str, architecture: str = "arm64-v8a") -> Device:
    return Device(
        serial=serial,
        model="Pixel",
        android_version="14",
        api_level=34,
        architecture=architecture,
        status="device",
        is_network_device=False,
    )


@pytest.fixture(autouse=True)
def patch_frida(monkeypatch):
    monkeypatch.setattr(
        emulator_service_module,
        "frida",
        SimpleNamespace(__version__="16.0.0"),
    )


def test_ensure_frida_server_uses_provided_device(monkeypatch):
    service = EmulatorService(DummyConfig(), DummyLogger())
    recorder = RecordingFridaManager()
    service.frida_manager = recorder

    discover_mock = AsyncMock(side_effect=AssertionError("discover_devices should not be called"))
    monkeypatch.setattr(service, "discover_devices", discover_mock)

    device = make_device("serial-002")

    result = asyncio.run(service.ensure_frida_server_is_running(device=device))

    assert result is True
    assert recorder.calls == [("serial-002", "arm64-v8a", "16.0.0")]


def test_ensure_frida_server_resolves_device_by_identifier(monkeypatch):
    service = EmulatorService(DummyConfig(), DummyLogger())
    recorder = RecordingFridaManager()
    service.frida_manager = recorder

    devices = [make_device("serial-001"), make_device("serial-002", "x86")]
    monkeypatch.setattr(service, "discover_devices", AsyncMock(return_value=devices))

    result = asyncio.run(service.ensure_frida_server_is_running(device_identifier="serial-002"))

    assert result is True
    assert recorder.calls == [("serial-002", "x86", "16.0.0")]


def test_ensure_frida_server_errors_when_identifier_missing(monkeypatch):
    service = EmulatorService(DummyConfig(), DummyLogger())
    recorder = RecordingFridaManager()
    service.frida_manager = recorder

    devices = [make_device("serial-001"), make_device("serial-003")]
    monkeypatch.setattr(service, "discover_devices", AsyncMock(return_value=devices))

    result = asyncio.run(service.ensure_frida_server_is_running(device_identifier="serial-002"))

    assert result is False
    assert recorder.calls == []


def test_test_device_connection_reports_offline(monkeypatch):
    service = EmulatorService(DummyConfig(), DummyLogger())

    monkeypatch.setattr(
        service,
        "_get_device_list",
        AsyncMock(return_value=[("emulator-5554", "offline")]),
    )
    service.adb.run_command = AsyncMock()

    with pytest.raises(DeviceConnectionError) as exc_info:
        asyncio.run(service._test_device_connection("emulator-5554"))

    assert exc_info.value.reason == "abnormal_status"
    assert exc_info.value.status == "offline"
    service.adb.run_command.assert_not_awaited()


def test_test_device_connection_handles_adb_failure(monkeypatch):
    service = EmulatorService(DummyConfig(), DummyLogger())

    monkeypatch.setattr(
        service,
        "_get_device_list",
        AsyncMock(return_value=[("emulator-5554", "device")]),
    )
    adb_error = AdbError("command failed")
    service.adb.run_command = AsyncMock(side_effect=adb_error)

    with pytest.raises(DeviceConnectionError) as exc_info:
        asyncio.run(service._test_device_connection("emulator-5554"))

    assert exc_info.value.reason == "adb_command_failed"
    assert exc_info.value.status == "device"
