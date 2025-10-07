"""
Pytest configuration and fixtures for TowerIQ tests.

This module provides shared fixtures and configuration for all tests,
including support for the new async patterns that replaced sleep-based polling.
"""

import asyncio
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


# Configure pytest-asyncio
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as an async test"
    )
