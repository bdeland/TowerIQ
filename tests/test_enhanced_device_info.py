"""
Tests for enhanced device information gathering in EmulatorService.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from src.tower_iq.services.emulator_service import EmulatorService
from src.tower_iq.core.utils import AdbError


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
async def test_get_device_properties_success(emulator_service):
    """Test successful device property gathering."""
    # Mock ADB shell response
    mock_output = """ro.product.model:
Pixel 5
ro.product.manufacturer:
Google
ro.build.version.release:
13
ro.build.version.sdk:
33"""
    
    emulator_service.adb.shell = AsyncMock(return_value=mock_output)
    
    properties = ['ro.product.model', 'ro.product.manufacturer', 'ro.build.version.release', 'ro.build.version.sdk']
    result = await emulator_service.get_device_properties('test_device', properties)
    
    expected = {
        'ro.product.model': 'Pixel 5',
        'ro.product.manufacturer': 'Google',
        'ro.build.version.release': '13',
        'ro.build.version.sdk': '33'
    }
    
    assert result == expected


@pytest.mark.asyncio
async def test_get_device_properties_adb_error(emulator_service):
    """Test device property gathering with ADB error."""
    emulator_service.adb.shell = AsyncMock(side_effect=AdbError("Connection failed"))
    
    properties = ['ro.product.model']
    result = await emulator_service.get_device_properties('test_device', properties)
    
    assert result == {}


@pytest.mark.asyncio
async def test_get_enhanced_device_info_success(emulator_service):
    """Test successful enhanced device info gathering."""
    # Mock the get_device_properties method
    mock_props = {
        'ro.product.model': 'Pixel 5',
        'ro.product.manufacturer': 'Google',
        'ro.build.version.release': '13',
        'ro.build.version.sdk': '33',
        'ro.product.cpu.abi': 'arm64-v8a',
        'ro.product.name': 'redfin',
        'ro.kernel.qemu': '0'
    }
    
    emulator_service.get_device_properties = AsyncMock(return_value=mock_props)
    
    result = await emulator_service.get_enhanced_device_info('test_device')
    
    expected = {
        'serial': 'test_device',
        'model': 'Pixel 5',
        'manufacturer': 'Google',
        'android_version': '13',
        'api_level': 33,
        'architecture': 'arm64-v8a',
        'is_emulator': False,
        'device_name': 'redfin',
        'status': 'Online'
    }
    
    assert result == expected


@pytest.mark.asyncio
async def test_get_enhanced_device_info_emulator_detection(emulator_service):
    """Test emulator detection in enhanced device info."""
    # Mock properties for an emulator
    mock_props = {
        'ro.product.model': 'Android SDK built for x86',
        'ro.product.manufacturer': 'Google',
        'ro.build.version.release': '11',
        'ro.build.version.sdk': '30',
        'ro.product.cpu.abi': 'x86',
        'ro.product.name': 'sdk_gphone_x86',
        'ro.kernel.qemu': '1'
    }
    
    emulator_service.get_device_properties = AsyncMock(return_value=mock_props)
    
    result = await emulator_service.get_enhanced_device_info('emulator-5554')
    
    assert result['is_emulator'] is True
    assert result['status'] == 'Online'


@pytest.mark.asyncio
async def test_get_enhanced_device_info_fallback(emulator_service):
    """Test enhanced device info with fallback on error."""
    # Mock an exception during property gathering
    emulator_service.get_device_properties = AsyncMock(side_effect=Exception("Test error"))
    
    result = await emulator_service.get_enhanced_device_info('test_device')
    
    expected_fallback = {
        'serial': 'test_device',
        'model': 'Unknown',
        'manufacturer': 'Unknown',
        'android_version': 'Unknown',
        'api_level': 0,
        'architecture': 'Unknown',
        'is_emulator': False,
        'device_name': 'Unknown',
        'status': 'Online'
    }
    
    assert result == expected_fallback


def test_parse_api_level(emulator_service):
    """Test API level parsing."""
    assert emulator_service._parse_api_level('33') == 33
    assert emulator_service._parse_api_level('invalid') == 0
    assert emulator_service._parse_api_level('') == 0


def test_detect_emulator(emulator_service):
    """Test emulator detection logic."""
    # Test real device
    real_device_props = {
        'ro.kernel.qemu': '0',
        'ro.product.model': 'Pixel 5',
        'ro.product.name': 'redfin'
    }
    assert emulator_service._detect_emulator(real_device_props) is False
    
    # Test emulator with qemu flag
    emulator_props_qemu = {
        'ro.kernel.qemu': '1',
        'ro.product.model': 'Android SDK',
        'ro.product.name': 'sdk_gphone'
    }
    assert emulator_service._detect_emulator(emulator_props_qemu) is True
    
    # Test emulator with model name
    emulator_props_model = {
        'ro.kernel.qemu': '0',
        'ro.product.model': 'Android Emulator',
        'ro.product.name': 'generic'
    }
    assert emulator_service._detect_emulator(emulator_props_model) is True


def test_format_device_status(emulator_service):
    """Test device status formatting."""
    assert emulator_service.format_device_status('device') == 'Online'
    assert emulator_service.format_device_status('offline') == 'Offline'
    assert emulator_service.format_device_status('unauthorized') == 'Unauthorized'
    assert emulator_service.format_device_status('unknown') == 'unknown'