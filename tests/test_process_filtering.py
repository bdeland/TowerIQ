"""
Tests for process filtering functionality in EmulatorService.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
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


def test_is_system_package_google_packages(emulator_service):
    """Test system package detection for Google packages."""
    # Should filter out Google system packages
    assert emulator_service.is_system_package('com.google.android.safetycore') is True
    assert emulator_service.is_system_package('com.google.android.gms') is True
    assert emulator_service.is_system_package('com.google.android.webview') is True
    assert emulator_service.is_system_package('com.google.android.packageinstaller') is True
    
    # Should not filter out non-Google packages
    assert emulator_service.is_system_package('com.example.myapp') is False
    assert emulator_service.is_system_package('com.spotify.music') is False


def test_is_system_package_android_packages(emulator_service):
    """Test system package detection for Android system packages."""
    # Should filter out Android system packages
    assert emulator_service.is_system_package('com.android.systemui') is True
    assert emulator_service.is_system_package('com.android.settings') is True
    assert emulator_service.is_system_package('com.android.providers.calendar') is True
    assert emulator_service.is_system_package('android.process.acore') is True
    
    # Should not filter out third-party packages
    assert emulator_service.is_system_package('com.whatsapp') is False
    assert emulator_service.is_system_package('com.facebook.katana') is False


def test_is_system_package_manufacturer_packages(emulator_service):
    """Test system package detection for manufacturer packages."""
    # Should filter out manufacturer system packages
    assert emulator_service.is_system_package('com.samsung.android.messaging') is True
    assert emulator_service.is_system_package('com.qualcomm.qti.workloadclassifier') is True
    assert emulator_service.is_system_package('com.xiaomi.android.launcher') is True
    assert emulator_service.is_system_package('com.oneplus.android.settings') is True
    
    # Should not filter out manufacturer apps that aren't system packages
    assert emulator_service.is_system_package('com.samsung.myapp') is False


def test_is_system_package_exact_matches(emulator_service):
    """Test system package detection for exact matches."""
    # Should filter out exact system matches
    assert emulator_service.is_system_package('system') is True
    assert emulator_service.is_system_package('android') is True
    assert emulator_service.is_system_package('com.android.shell') is True
    assert emulator_service.is_system_package('com.android.externalstorage') is True
    
    # Should not filter out similar but different packages
    assert emulator_service.is_system_package('systemapp') is False
    assert emulator_service.is_system_package('androidapp') is False


def test_is_system_package_edge_cases(emulator_service):
    """Test system package detection edge cases."""
    # Empty string should not be filtered
    assert emulator_service.is_system_package('') is False
    
    # Packages that start with system patterns but are legitimate apps
    assert emulator_service.is_system_package('com.android.mylegitimateapp') is True  # Still filtered due to com.android. pattern
    
    # Case sensitivity
    assert emulator_service.is_system_package('COM.GOOGLE.ANDROID.GMS') is False  # Case sensitive
    assert emulator_service.is_system_package('com.google.android.gms') is True


@pytest.mark.asyncio
async def test_get_installed_third_party_packages_filtering(emulator_service):
    """Test that get_installed_third_party_packages filters correctly."""
    # Mock running processes
    mock_running_processes = {
        'com.example.myapp': 1234,
        'com.google.android.safetycore': 5678,  # Should be filtered out
        'com.whatsapp': 9012,
        'com.android.systemui': 3456,  # Should be filtered out
        'com.spotify.music': 7890
    }
    
    # Mock third-party packages list
    mock_third_party_packages = [
        'com.example.myapp',
        'com.google.android.safetycore',
        'com.whatsapp',
        'com.android.systemui',
        'com.spotify.music'
    ]
    
    # Mock package info
    def mock_get_package_info(device_id, package_name):
        return {
            'name': f"App for {package_name}",
            'version': '1.0.0'
        }
    
    # Set up mocks
    emulator_service._get_running_processes_map = AsyncMock(return_value=mock_running_processes)
    emulator_service._get_third_party_packages_list = AsyncMock(return_value=mock_third_party_packages)
    emulator_service._get_package_rich_info = AsyncMock(side_effect=mock_get_package_info)
    
    # Call the method
    result = await emulator_service.get_installed_third_party_packages('test_device')
    
    # Verify results - should only include non-system running packages
    expected_packages = {'com.example.myapp', 'com.whatsapp', 'com.spotify.music'}
    actual_packages = {app['package'] for app in result}
    
    assert actual_packages == expected_packages
    assert len(result) == 3
    
    # Verify all results are marked as running
    for app in result:
        assert app['is_running'] is True
        assert app['pid'] is not None


@pytest.mark.asyncio
async def test_get_installed_third_party_packages_only_running(emulator_service):
    """Test that only running packages are included."""
    # Mock running processes (missing some packages)
    mock_running_processes = {
        'com.example.runningapp': 1234,
        'com.whatsapp': 9012
    }
    
    # Mock third-party packages list (includes non-running packages)
    mock_third_party_packages = [
        'com.example.runningapp',
        'com.example.notrunningapp',  # Not in running processes
        'com.whatsapp',
        'com.spotify.music'  # Not in running processes
    ]
    
    # Mock package info
    def mock_get_package_info(device_id, package_name):
        return {
            'name': f"App for {package_name}",
            'version': '1.0.0'
        }
    
    # Set up mocks
    emulator_service._get_running_processes_map = AsyncMock(return_value=mock_running_processes)
    emulator_service._get_third_party_packages_list = AsyncMock(return_value=mock_third_party_packages)
    emulator_service._get_package_rich_info = AsyncMock(side_effect=mock_get_package_info)
    
    # Call the method
    result = await emulator_service.get_installed_third_party_packages('test_device')
    
    # Should only include running packages
    expected_packages = {'com.example.runningapp', 'com.whatsapp'}
    actual_packages = {app['package'] for app in result}
    
    assert actual_packages == expected_packages
    assert len(result) == 2


@pytest.mark.asyncio
async def test_get_installed_third_party_packages_error_handling(emulator_service):
    """Test error handling in get_installed_third_party_packages."""
    # Mock methods to raise exceptions
    emulator_service._get_running_processes_map = AsyncMock(side_effect=Exception("Test error"))
    
    # Call the method
    result = await emulator_service.get_installed_third_party_packages('test_device')
    
    # Should return empty list on error
    assert result == []