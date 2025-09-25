import sys
import types
from pathlib import Path

import asyncio



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

from tower_iq.services.connection_stage_manager import ConnectionStageManager  # noqa: E402


class DummyLogger:
    def bind(self, **_kwargs):
        return self

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass


class DummySessionManager:
    def update_connection_stages(self, _stages):
        pass


class DummyFridaService:
    pass


class RecordingEmulatorService:
    def __init__(self):
        self.calls = []

    async def ensure_frida_server_is_running(self, **kwargs):
        self.calls.append(kwargs)
        return True


def test_stage_manager_passes_device_identifier_to_install():
    emulator_service = RecordingEmulatorService()
    manager = ConnectionStageManager(
        DummySessionManager(), emulator_service, DummyFridaService(), DummyLogger()
    )

    result = asyncio.run(manager._install_frida_server("serial-1234"))

    assert result is True
    assert emulator_service.calls == [{"device_identifier": "serial-1234"}]


def test_stage_manager_passes_device_identifier_to_start_and_verify():
    emulator_service = RecordingEmulatorService()
    manager = ConnectionStageManager(
        DummySessionManager(), emulator_service, DummyFridaService(), DummyLogger()
    )

    asyncio.run(manager._start_frida_server("serial-9876"))
    asyncio.run(manager._verify_frida_server("serial-9876"))

    assert emulator_service.calls == [
        {"device_identifier": "serial-9876"},
        {"device_identifier": "serial-9876"},
    ]
