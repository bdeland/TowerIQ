"""
Tests for performance optimizations and caching functionality in EmulatorService.
"""

import pytest
import time
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from src.tower_iq.services.emulator_service import EmulatorService


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing."""
    logger = MagicMock()
    logger.bind.return_value = logger
    return logger


@pytest.fixture
def mock_config():
    """Create a mock configuration manager."""
    return MagicMock()


@pytest.fixture
def emulator_service(mock_config, mock_logger):
    """Create an EmulatorService instance for testing."""
    return EmulatorService(mock_config, mock_logger)


@pytest.mark.asyncio
async def test_device_properties_caching(emulator_service):
    """Test that device properties are cached and reused."""
    # Mock ADB shell response
    mock_output = """ro.product.model:
Pixel 5
ro.product.manufacturer:
Google"""
    
    emulator_service.adb.shell = AsyncMock(return_value=mock_output)
    
    properties = ['ro.product.model', 'ro.product.manufacturer']
    
    # First call should hit ADB
    result1 = await emulator_service.get_device_properties('test_device', properties)
    assert emulator_service.adb.shell.call_count == 1
    assert result1['ro.product.model'] == 'Pixel 5'
    assert result1['ro.product.manufacturer'] == 'Google'
    
    # Second call should use cache
    result2 = await emulator_service.get_device_properties('test_device', properties)
    assert emulator_service.adb.shell.call_count == 1  # No additional calls
    assert result2 == result1
    
    # Verify cache contains the data
    cache_key = "test_device_properties"
    assert cache_key in emulator_service._device_properties_cache
    assert emulator_service._is_cache_valid(cache_key)


@pytest.mark.asyncio
async def test_device_properties_partial_cache_hit(emulator_service):
    """Test device properties with partial cache hit."""
    # Pre-populate cache with some properties
    cache_key = "test_device_properties"
    emulator_service._cache_device_properties(cache_key, {
        'ro.product.model': 'Cached Model',
        'ro.product.manufacturer': 'Cached Manufacturer'
    })
    
    # Request includes cached and new properties
    properties = ['ro.product.model', 'ro.product.manufacturer', 'ro.build.version.release']
    
    # Mock ADB response for new properties
    mock_output = """ro.product.model:
Pixel 5
ro.product.manufacturer:
Google
ro.build.version.release:
13"""
    
    emulator_service.adb.shell = AsyncMock(return_value=mock_output)
    
    # Should hit ADB because not all properties are cached
    result = await emulator_service.get_device_properties('test_device', properties)
    assert emulator_service.adb.shell.call_count == 1
    assert len(result) == 3


@pytest.mark.asyncio
async def test_app_metadata_caching(emulator_service):
    """Test that app metadata is cached and reused."""
    # Mock the dependencies
    emulator_service._get_basic_package_info = AsyncMock(return_value={
        'name': 'Test App',
        'version': '1.0.0',
        'version_code': 1
    })
    emulator_service.get_app_display_name = AsyncMock(return_value='Test App Display')
    emulator_service.get_app_icon_data = AsyncMock(return_value=None)
    
    # First call should execute all methods
    result1 = await emulator_service.get_app_metadata('test_device', 'com.test.app')
    assert emulator_service._get_basic_package_info.call_count == 1
    assert emulator_service.get_app_display_name.call_count == 1
    assert result1['name'] == 'Test App Display'
    
    # Second call should use cache
    result2 = await emulator_service.get_app_metadata('test_device', 'com.test.app')
    assert emulator_service._get_basic_package_info.call_count == 1  # No additional calls
    assert emulator_service.get_app_display_name.call_count == 1  # No additional calls
    assert result2 == result1
    
    # Verify cache contains the data
    cache_key = "test_device_com.test.app_metadata"
    assert cache_key in emulator_service._app_metadata_cache


def test_cache_timeout_validation(emulator_service):
    """Test cache timeout validation."""
    cache_key = "test_cache_key"
    
    # Fresh cache entry should be valid
    emulator_service._cache_timestamps[cache_key] = time.time()
    assert emulator_service._is_cache_valid(cache_key) is True
    
    # Old cache entry should be invalid
    emulator_service._cache_timestamps[cache_key] = time.time() - 400  # Older than 300s timeout
    assert emulator_service._is_cache_valid(cache_key) is False
    
    # Non-existent cache entry should be invalid
    assert emulator_service._is_cache_valid("non_existent_key") is False


def test_cache_device_properties(emulator_service):
    """Test device properties caching functionality."""
    cache_key = "test_device_props"
    properties = {
        'ro.product.model': 'Test Model',
        'ro.product.manufacturer': 'Test Manufacturer'
    }
    
    emulator_service._cache_device_properties(cache_key, properties)
    
    # Verify data is cached
    assert cache_key in emulator_service._device_properties_cache
    assert emulator_service._device_properties_cache[cache_key] == properties
    assert cache_key in emulator_service._cache_timestamps
    assert emulator_service._is_cache_valid(cache_key)


def test_cache_app_metadata(emulator_service):
    """Test app metadata caching functionality."""
    cache_key = "test_app_metadata"
    metadata = {
        'name': 'Test App',
        'version': '1.0.0',
        'package': 'com.test.app'
    }
    
    emulator_service._cache_app_metadata(cache_key, metadata)
    
    # Verify data is cached
    assert cache_key in emulator_service._app_metadata_cache
    assert emulator_service._app_metadata_cache[cache_key] == metadata
    assert cache_key in emulator_service._cache_timestamps
    assert emulator_service._is_cache_valid(cache_key)


def test_get_cached_app_metadata(emulator_service):
    """Test retrieving cached app metadata."""
    cache_key = "test_app_metadata"
    metadata = {'name': 'Test App', 'version': '1.0.0'}
    
    # Cache some metadata
    emulator_service._cache_app_metadata(cache_key, metadata)
    
    # Should retrieve cached data
    cached_data = emulator_service._get_cached_app_metadata(cache_key)
    assert cached_data == metadata
    
    # Should return None for expired cache
    emulator_service._cache_timestamps[cache_key] = time.time() - 400  # Expired
    cached_data = emulator_service._get_cached_app_metadata(cache_key)
    assert cached_data is None
    
    # Should return None for non-existent cache
    cached_data = emulator_service._get_cached_app_metadata("non_existent")
    assert cached_data is None


def test_clear_cache(emulator_service):
    """Test cache clearing functionality."""
    # Populate caches
    emulator_service._cache_device_properties("device_key", {'prop': 'value'})
    emulator_service._cache_app_metadata("app_key", {'name': 'App'})
    
    # Verify caches have data
    assert len(emulator_service._device_properties_cache) > 0
    assert len(emulator_service._app_metadata_cache) > 0
    assert len(emulator_service._cache_timestamps) > 0
    
    # Clear caches
    emulator_service.clear_cache()
    
    # Verify caches are empty
    assert len(emulator_service._device_properties_cache) == 0
    assert len(emulator_service._app_metadata_cache) == 0
    assert len(emulator_service._cache_timestamps) == 0


def test_get_cache_stats(emulator_service):
    """Test cache statistics functionality."""
    # Initially empty
    stats = emulator_service.get_cache_stats()
    assert stats['device_properties_cached'] == 0
    assert stats['app_metadata_cached'] == 0
    assert stats['total_cache_entries'] == 0
    assert stats['cache_timeout_seconds'] == 300
    
    # Add some cache entries
    emulator_service._cache_device_properties("device1", {'prop': 'value1'})
    emulator_service._cache_device_properties("device2", {'prop': 'value2'})
    emulator_service._cache_app_metadata("app1", {'name': 'App1'})
    
    # Check updated stats
    stats = emulator_service.get_cache_stats()
    assert stats['device_properties_cached'] == 2
    assert stats['app_metadata_cached'] == 1
    assert stats['total_cache_entries'] == 3


@pytest.mark.asyncio
async def test_cache_performance_improvement(emulator_service):
    """Test that caching provides performance improvement."""
    # Mock slow ADB operation
    async def slow_adb_shell(*args, **kwargs):
        await asyncio.sleep(0.1)  # Simulate 100ms delay
        return "ro.product.model:\nTest Model"
    
    emulator_service.adb.shell = AsyncMock(side_effect=slow_adb_shell)
    
    properties = ['ro.product.model']
    
    # First call - should be slow
    start_time = time.time()
    result1 = await emulator_service.get_device_properties('test_device', properties)
    first_call_time = time.time() - start_time
    
    # Second call - should be fast (cached)
    start_time = time.time()
    result2 = await emulator_service.get_device_properties('test_device', properties)
    second_call_time = time.time() - start_time
    
    # Verify results are the same
    assert result1 == result2
    
    # Verify second call is significantly faster
    assert second_call_time < first_call_time / 2  # At least 50% faster
    assert first_call_time > 0.05  # First call took some time
    assert second_call_time < 0.01  # Second call was very fast


@pytest.mark.asyncio
async def test_cache_invalidation_after_timeout(emulator_service):
    """Test that cache is invalidated after timeout."""
    # Mock ADB response
    emulator_service.adb.shell = AsyncMock(return_value="ro.product.model:\nTest Model")
    
    properties = ['ro.product.model']
    
    # First call
    await emulator_service.get_device_properties('test_device', properties)
    assert emulator_service.adb.shell.call_count == 1
    
    # Manually expire the cache
    cache_key = "test_device_properties"
    emulator_service._cache_timestamps[cache_key] = time.time() - 400  # Expired
    
    # Second call should hit ADB again due to expired cache
    await emulator_service.get_device_properties('test_device', properties)
    assert emulator_service.adb.shell.call_count == 2


def test_cache_key_generation(emulator_service):
    """Test that cache keys are generated correctly."""
    # Test device properties cache key
    device_id = "emulator-5554"
    package_name = "com.example.app"
    
    # Cache some data and verify keys
    emulator_service._cache_device_properties(f"{device_id}_properties", {'prop': 'value'})
    emulator_service._cache_app_metadata(f"{device_id}_{package_name}_metadata", {'name': 'App'})
    
    # Verify keys exist
    assert f"{device_id}_properties" in emulator_service._device_properties_cache
    assert f"{device_id}_{package_name}_metadata" in emulator_service._app_metadata_cache


@pytest.mark.asyncio
async def test_cache_with_different_devices(emulator_service):
    """Test that cache works correctly with different devices."""
    # Mock ADB responses for different devices
    async def mock_adb_shell(device_id, command):
        if device_id == "device1":
            return "ro.product.model:\nDevice 1 Model"
        else:
            return "ro.product.model:\nDevice 2 Model"
    
    emulator_service.adb.shell = AsyncMock(side_effect=mock_adb_shell)
    
    properties = ['ro.product.model']
    
    # Get properties for device1
    result1 = await emulator_service.get_device_properties('device1', properties)
    assert result1['ro.product.model'] == 'Device 1 Model'
    
    # Get properties for device2
    result2 = await emulator_service.get_device_properties('device2', properties)
    assert result2['ro.product.model'] == 'Device 2 Model'
    
    # Verify both are cached separately
    assert 'device1_properties' in emulator_service._device_properties_cache
    assert 'device2_properties' in emulator_service._device_properties_cache
    
    # Verify cached data is different
    cached1 = emulator_service._device_properties_cache['device1_properties']
    cached2 = emulator_service._device_properties_cache['device2_properties']
    assert cached1 != cached2