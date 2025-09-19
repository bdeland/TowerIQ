import asyncio
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_PATH))

sys.modules.setdefault("pandas", types.ModuleType("pandas"))
sys.modules.setdefault("aiohttp", types.ModuleType("aiohttp"))


class _StructlogLogger:
    def bind(self, **kwargs):
        return self

    def __getattr__(self, _):  # pragma: no cover - simple stub
        def _noop(*args, **kwargs):
            return None

        return _noop


structlog_stub = types.ModuleType("structlog")
structlog_stub.get_logger = lambda: _StructlogLogger()
sys.modules.setdefault("structlog", structlog_stub)

import tower_iq  # noqa: E402  pylint: disable=wrong-import-position

services_stub = types.ModuleType("tower_iq.services")
services_stub.__path__ = [str(SRC_PATH / "tower_iq" / "services")]
sys.modules.setdefault("tower_iq.services", services_stub)

from tower_iq.core.utils import AdbError  # noqa: E402  pylint: disable=wrong-import-position
from tower_iq.services.frida_manager import (  # noqa: E402  pylint: disable=wrong-import-position
    FridaServerManager,
    FridaServerSetupError,
)


def _build_logger() -> MagicMock:
    logger = MagicMock()
    logger.bind.return_value = logger
    logger.info = MagicMock()
    logger.debug = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    return logger


def _build_adb() -> MagicMock:
    adb = MagicMock()
    adb.shell = AsyncMock()
    adb.push = AsyncMock()
    return adb


def test_wait_for_responsive_success():
    logger = _build_logger()
    adb = _build_adb()

    async def shell(device_id, command, timeout=10.0):
        if command.startswith("ls"):
            return "/data/local/tmp/frida-server"
        if command.startswith("pidof"):
            return "1234"
        if command.endswith("--version"):
            return "16.1.1"
        raise AssertionError(f"Unexpected command: {command}")

    adb.shell.side_effect = shell
    manager = FridaServerManager(logger, adb)

    result = asyncio.run(
        manager._wait_for_responsive("device-1", target_version="16.1.1", timeout=1)
    )

    assert result is True


def test_wait_for_responsive_missing_binary():
    logger = _build_logger()
    adb = _build_adb()

    async def shell(device_id, command, timeout=10.0):
        if command.startswith("ls"):
            raise AdbError("not found")
        return ""

    adb.shell.side_effect = shell
    manager = FridaServerManager(logger, adb)

    with pytest.raises(FridaServerSetupError) as exc:
        asyncio.run(
            manager._wait_for_responsive("device-1", target_version="16.1.1", timeout=1)
        )

    assert "binary" in str(exc.value)


def test_wait_for_responsive_process_not_running():
    logger = _build_logger()
    adb = _build_adb()

    async def shell(device_id, command, timeout=10.0):
        if command.startswith("ls"):
            return "/data/local/tmp/frida-server"
        if command.startswith("pidof"):
            return ""
        return ""

    adb.shell.side_effect = shell
    manager = FridaServerManager(logger, adb)

    with pytest.raises(FridaServerSetupError) as exc:
        asyncio.run(
            manager._wait_for_responsive("device-1", target_version="16.1.1", timeout=1)
        )

    assert "process not running" in str(exc.value)


def test_wait_for_responsive_version_mismatch():
    logger = _build_logger()
    adb = _build_adb()

    async def shell(device_id, command, timeout=10.0):
        if command.startswith("ls"):
            return "/data/local/tmp/frida-server"
        if command.startswith("pidof"):
            return "1234"
        if command.endswith("--version"):
            return "16.0.0"
        return ""

    adb.shell.side_effect = shell
    manager = FridaServerManager(logger, adb)

    with pytest.raises(FridaServerSetupError) as exc:
        asyncio.run(
            manager._wait_for_responsive("device-1", target_version="16.1.1", timeout=1)
        )

    assert "version mismatch" in str(exc.value)
