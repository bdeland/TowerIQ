"""
Pytest configuration and shared fixtures for TowerIQ tests.

This module provides common fixtures and configuration for all test modules,
including mocks for external dependencies and test utilities.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
import structlog

# Configure structlog for testing
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)


@pytest.fixture
def logger():
    """Provide a test logger instance."""
    return structlog.get_logger().bind(source="TestLogger")


@pytest.fixture
def config_manager():
    """Provide a mock ConfigurationManager."""
    config = Mock()
    config.get.return_value = None
    config.get_project_root.return_value = "/test/project/root"
    
    # Common config values for frida tests
    config.get.side_effect = lambda key, default=None: {
        'frida.timeouts.queue_get': 2.0,
        'frida.timeouts.detach': 3.0,
    }.get(key, default)
    
    return config


@pytest.fixture
def session_manager():
    """Provide a mock SessionManager."""
    session_mgr = Mock()
    session_mgr.frida_device = None
    session_mgr.frida_session = None
    session_mgr.frida_script = None
    session_mgr.frida_attached_pid = None
    
    # Mock methods
    session_mgr.set_script_active = Mock()
    session_mgr.set_script_inactive = Mock()
    session_mgr.update_script_heartbeat = Mock()
    
    return session_mgr


@pytest.fixture
def mock_frida():
    """Provide a mock frida module."""
    with patch('src.tower_iq.services.frida_service.frida') as mock_frida:
        # Mock device
        mock_device = Mock()
        mock_device.attach.return_value = Mock()
        
        # Mock session
        mock_session = Mock()
        mock_script = Mock()
        mock_session.create_script.return_value = mock_script
        
        # Mock frida module functions
        mock_frida.get_device.return_value = mock_device
        mock_frida.get_local_device.return_value = mock_device
        
        # Mock script
        mock_script.load = Mock()
        mock_script.unload = Mock()
        mock_script.on = Mock()
        
        yield mock_frida


@pytest.fixture
def mock_adb_wrapper():
    """Provide a mock AdbWrapper."""
    adb = Mock()
    adb.shell = AsyncMock()
    adb.push = AsyncMock()
    
    # Default successful responses
    adb.shell.return_value = "success"
    adb.push.return_value = None
    
    return adb


@pytest.fixture
def temp_hooks_dir():
    """Provide a temporary directory for hook scripts."""
    with tempfile.TemporaryDirectory() as temp_dir:
        hooks_dir = Path(temp_dir) / "hooks"
        hooks_dir.mkdir()
        
        # Create a sample hook script with metadata
        sample_script = hooks_dir / "test_hook.js"
        sample_script.write_text('''/** TOWERIQ_HOOK_METADATA
{
    "scriptName": "Test Hook",
    "scriptDescription": "A test hook script",
    "targetPackage": "com.test.game",
    "targetApp": "Test Game",
    "supportedVersions": ["1.0.0", "1.1.0"],
    "fileName": "test_hook.js"
}
*/

console.log("Test hook loaded");
''')
        
        yield hooks_dir


@pytest.fixture
def event_loop():
    """Provide an event loop for async tests."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture
def mock_aiohttp_session():
    """Provide a mock aiohttp ClientSession."""
    with patch('aiohttp.ClientSession') as mock_session_class:
        mock_session = MagicMock()

        # Create a proper async context manager for the get method
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.read = AsyncMock(return_value=b"fake_binary_data")

        # Set up the async context manager chain for session.get()
        mock_get_context = MagicMock()
        mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_get_context.__aexit__ = AsyncMock(return_value=None)
        mock_session.get = MagicMock(return_value=mock_get_context)

        # Set up the session context manager
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session_class.return_value = mock_session

        yield mock_session


@pytest.fixture
def mock_lzma():
    """Provide a mock lzma module for decompression."""
    with patch('lzma.decompress') as mock_lzma:
        mock_lzma.return_value = b"decompressed_binary_data"
        yield mock_lzma


@pytest.fixture
def sample_frida_message():
    """Provide a sample Frida message for testing."""
    return {
        'type': 'send',
        'payload': {
            'type': 'hook_log',
            'payload': {
                'event': 'hook_loaded',
                'message': 'Hook on GameManager is live.',
                'level': 'INFO',
                'timestamp': '2024-01-01T12:00:00Z'
            },
            'timestamp': '2024-01-01T12:00:00Z'
        }
    }


@pytest.fixture
def sample_game_event_message():
    """Provide a sample game event message for testing."""
    return {
        'type': 'send',
        'payload': {
            'type': 'game_event',
            'payload': {
                'event': 'startNewRound',
                'runId': 'test-run-id-12345',
                'seed': 'test-seed',
                'tier': '1',
                'timestamp': '2024-01-01T12:00:00Z'
            },
            'timestamp': '2024-01-01T12:00:00Z'
        }
    }


@pytest.fixture
def sample_script_error():
    """Provide a sample script error for testing."""
    return {
        'type': 'error',
        'description': 'ReferenceError: undefined is not defined',
        'stack': 'at main (script.js:10:5)',
        'fileName': 'script.js',
        'lineNumber': 10
    }


@pytest.fixture
def temp_cache_dir():
    """Provide a temporary directory for cache files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        cache_dir = Path(temp_dir)
        yield cache_dir


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Setup test environment before each test."""
    # This fixture runs automatically before each test
    # Add any global test setup here
    pass


@pytest.fixture
def mock_file_operations():
    """Provide mocks for file operations."""
    with patch('pathlib.Path.exists') as mock_exists, \
         patch('pathlib.Path.mkdir') as mock_mkdir, \
         patch('pathlib.Path.write_bytes') as mock_write_bytes, \
         patch('pathlib.Path.chmod') as mock_chmod, \
         patch('pathlib.Path.read_text') as mock_read_text, \
         patch('builtins.open', mock_open()) as mock_file:
        
        # Default successful file operations
        mock_exists.return_value = True
        mock_mkdir.return_value = None
        mock_write_bytes.return_value = None
        mock_chmod.return_value = None
        mock_read_text.return_value = "test content"
        
        yield {
            'exists': mock_exists,
            'mkdir': mock_mkdir,
            'write_bytes': mock_write_bytes,
            'chmod': mock_chmod,
            'read_text': mock_read_text,
            'open': mock_file
        }


def mock_open(read_data="", **kwargs):
    """Helper function to create mock open."""
    from unittest.mock import mock_open as _mock_open
    return _mock_open(read_data=read_data, **kwargs)


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom settings."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )


# Async test support
@pytest.fixture(scope="session")
def event_loop_policy():
    """Set the event loop policy for the test session."""
    if hasattr(asyncio, 'WindowsProactorEventLoopPolicy'):
        # Use ProactorEventLoop on Windows for better compatibility
        policy = asyncio.WindowsProactorEventLoopPolicy()
    else:
        policy = asyncio.DefaultEventLoopPolicy()
    
    asyncio.set_event_loop_policy(policy)
    return policy



