"""
Pytest configuration and fixtures for TowerIQ tests.

This module provides shared fixtures and configuration for all tests,
including support for the new async patterns that replaced sleep-based polling.
"""

import asyncio
import os
import subprocess
import sys
import time
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def logger():
    """Provide a mock logger for tests."""
    mock_logger = MagicMock()
    mock_logger.bind = MagicMock(return_value=mock_logger)
    mock_logger.info = MagicMock()
    mock_logger.debug = MagicMock()
    mock_logger.warning = MagicMock()
    mock_logger.error = MagicMock()
    return mock_logger


@pytest.fixture
def config_manager():
    """Provide a mock ConfigurationManager for tests."""
    mock_config = MagicMock()
    mock_config.get = MagicMock(return_value=None)
    return mock_config


@pytest.fixture
def event_loop():
    """Provide a new event loop for each test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def fast_polling_env(monkeypatch):
    """
    Fixture to speed up polling operations in tests.
    
    This reduces initial_delay and max_delay for wait_for_condition
    to make tests run faster without affecting production code.
    
    Usage:
        def test_something(fast_polling_env):
            # Tests using wait_for_condition will complete faster
            ...
    """
    # Patch asyncio.sleep to be faster in tests
    original_sleep = asyncio.sleep
    
    async def fast_sleep(delay):
        """Sleep but much faster for testing."""
        await original_sleep(min(delay, 0.01))  # Max 10ms sleep
    
    monkeypatch.setattr(asyncio, 'sleep', fast_sleep)
    return True


# ── Live emulator fixture ─────────────────────────────────────────────────────

def _resolve_adb(android_home: str) -> str:
    candidate = os.path.join(android_home, "platform-tools", "adb")
    return candidate if os.path.isfile(candidate) else "adb"


def _adb(*args, android_home: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_resolve_adb(android_home), *args],
        capture_output=True,
        text=True,
    )


def _find_emulator_serial(android_home: str) -> str | None:
    result = _adb("devices", android_home=android_home)
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("emulator-") and parts[1] == "device":
            return parts[0]
    return None


def _is_booted(serial: str, android_home: str) -> bool:
    result = _adb("-s", serial, "shell", "getprop", "sys.boot_completed", android_home=android_home)
    return result.returncode == 0 and result.stdout.strip() == "1"


@pytest.fixture(scope="session")
def live_emulator():
    """
    Session-scoped fixture that starts the TowerIQ_Test AVD headlessly and
    yields its ADB serial (e.g. 'emulator-5554').

    The emulator is stopped at the end of the test session.

    Tests that require a real ADB connection should use this fixture together
    with @pytest.mark.adb:

        @pytest.mark.adb
        def test_something(live_emulator):
            serial = live_emulator
            ...

    The fixture is automatically skipped when the Android SDK emulator binary
    is not found on the system (i.e. setup_android_sdk.sh has not been run).
    """
    android_home = os.environ.get("ANDROID_HOME", os.path.expanduser("~/android-sdk"))
    emulator_bin = os.path.join(android_home, "emulator", "emulator")

    if not os.path.isfile(emulator_bin):
        pytest.skip("Android SDK emulator not found. Run scripts/setup_android_sdk.sh first.")

    avd_name = os.environ.get("TOWERIQ_TEST_AVD", "TowerIQ_Test")
    boot_timeout = int(os.environ.get("TOWERIQ_EMULATOR_TIMEOUT", "180"))
    poll_interval = 3

    # Re-use an already-running emulator if present
    serial = _find_emulator_serial(android_home)
    emulator_proc = None

    if not serial:
        emulator_proc = subprocess.Popen(
            [
                emulator_bin,
                "-avd", avd_name,
                "-no-window",
                "-no-audio",
                "-no-snapshot",
                "-no-boot-anim",
                "-gpu", "swiftshader_indirect",
            ],
            env={**os.environ, "ANDROID_HOME": android_home},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.monotonic() + boot_timeout
        while time.monotonic() < deadline:
            serial = _find_emulator_serial(android_home)
            if serial:
                break
            time.sleep(poll_interval)
        else:
            emulator_proc.terminate()
            pytest.fail(f"Emulator did not appear within {boot_timeout}s.")

        deadline = time.monotonic() + boot_timeout
        while time.monotonic() < deadline:
            if _is_booted(serial, android_home):
                break
            time.sleep(poll_interval)
        else:
            emulator_proc.terminate()
            pytest.fail(f"Emulator boot did not complete within {boot_timeout}s.")

    yield serial

    if emulator_proc is not None:
        _adb("-s", serial, "emu", "kill", android_home=android_home)
        emulator_proc.wait(timeout=30)


# ── Configure pytest-asyncio ──────────────────────────────────────────────────

# Configure pytest-asyncio
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as an async test"
    )
