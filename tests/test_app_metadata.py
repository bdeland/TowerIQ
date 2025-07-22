"""
Tests for app metadata service functionality in EmulatorService.
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


@pytest.mark.asyncio
async def test_get_basic_package_info_success(emulator_service):
    """Test successful basic package info gathering."""
    # Mock dumpsys package output
    mock_output = """
    Package [com.example.app] (12345678):
      userId=10123
      pkg=Package{abcdef com.example.app}
      codePath=/data/app/com.example.app-1
      resourcePath=/data/app/com.example.app-1
      legacyNativeLibraryDir=/data/app/com.example.app-1/lib
      primaryCpuAbi=arm64-v8a
      secondaryCpuAbi=null
      versionCode=42 minSdk=21 targetSdk=30
      versionName=2.1.0
      splits=[base]
      apkSigningVersion=2
      applicationInfo=[0x2be83000]
      flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
      privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE ]
      dataDir=/data/user/0/com.example.app
      supportsScreens=[small, medium, large, xlarge, resizeable, anyDensity]
      usesLibraries:
      usesOptionalLibraries:
      usesLibraryFiles:
      usesOptionalLibraryFiles:
      extractNativeLibs=true
      timeStamp=2023-01-15 10:30:45
      firstInstallTime=2023-01-15 10:30:45
      lastUpdateTime=2023-01-15 10:30:45
      installerPackageName=com.android.vending
      signatures=PackageSignatures{12345678 version:2, signatures:[Signature{abcdef}], past signatures:[]}
      installPermissionsFixed=true installStatus=1
      pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
      application-label:'My Test App'
      application-icon-120:'/data/app/com.example.app-1/base.apk'
    """
    
    # Mock subprocess execution
    mock_process = AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate.return_value = (mock_output.encode(), b'')
    
    emulator_service.adb.shell = AsyncMock()
    
    # Mock asyncio.create_subprocess_exec
    import asyncio
    original_create_subprocess_exec = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = AsyncMock(return_value=mock_process)
    
    try:
        result = await emulator_service._get_basic_package_info('test_device', 'com.example.app')
        
        expected = {
            'name': 'My Test App',
            'version': '2.1.0',
            'version_code': 42,
            'install_time': None,
            'last_update_time': None,
            'is_debuggable': False
        }
        
        assert result['name'] == expected['name']
        assert result['version'] == expected['version']
        assert result['version_code'] == expected['version_code']
        assert result['is_debuggable'] == expected['is_debuggable']
        
    finally:
        # Restore original function
        asyncio.create_subprocess_exec = original_create_subprocess_exec


@pytest.mark.asyncio
async def test_get_basic_package_info_error(emulator_service):
    """Test basic package info with error."""
    # Mock subprocess execution failure
    mock_process = AsyncMock()
    mock_process.returncode = 1
    mock_process.communicate.return_value = (b'', b'error')
    
    import asyncio
    original_create_subprocess_exec = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = AsyncMock(return_value=mock_process)
    
    try:
        result = await emulator_service._get_basic_package_info('test_device', 'com.example.app')
        
        # Should return fallback info
        assert result['name'] == 'com.example.app'
        assert result['version'] == 'Unknown'
        
    finally:
        asyncio.create_subprocess_exec = original_create_subprocess_exec


@pytest.mark.asyncio
async def test_get_app_display_name_from_pm_path(emulator_service):
    """Test getting app display name via pm path method."""
    # Mock pm path command
    mock_pm_process = AsyncMock()
    mock_pm_process.returncode = 0
    mock_pm_process.communicate.return_value = (b'package:/data/app/com.example.app-1/base.apk\n', b'')
    
    # Mock aapt command (will return None in our simplified implementation)
    emulator_service._get_label_from_aapt = AsyncMock(return_value='My App Name')
    
    import asyncio
    original_create_subprocess_exec = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = AsyncMock(return_value=mock_pm_process)
    
    try:
        result = await emulator_service.get_app_display_name('test_device', 'com.example.app')
        assert result == 'My App Name'
        
    finally:
        asyncio.create_subprocess_exec = original_create_subprocess_exec


@pytest.mark.asyncio
async def test_get_app_display_name_fallback_to_dumpsys(emulator_service):
    """Test app display name fallback to dumpsys method."""
    # Mock pm path command failure
    mock_pm_process = AsyncMock()
    mock_pm_process.returncode = 1
    mock_pm_process.communicate.return_value = (b'', b'error')
    
    # Mock dumpsys command success
    mock_dumpsys_process = AsyncMock()
    mock_dumpsys_process.returncode = 0
    mock_dumpsys_process.communicate.return_value = (b'application-label:My Fallback App\n', b'')
    
    call_count = 0
    def mock_subprocess(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return mock_pm_process  # First call (pm path)
        else:
            return mock_dumpsys_process  # Second call (dumpsys)
    
    import asyncio
    original_create_subprocess_exec = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = AsyncMock(side_effect=mock_subprocess)
    
    try:
        result = await emulator_service.get_app_display_name('test_device', 'com.example.app')
        assert result == 'My Fallback App'
        
    finally:
        asyncio.create_subprocess_exec = original_create_subprocess_exec


@pytest.mark.asyncio
async def test_get_app_display_name_final_fallback(emulator_service):
    """Test app display name final fallback to package name."""
    # Mock all methods failing
    mock_process = AsyncMock()
    mock_process.returncode = 1
    mock_process.communicate.return_value = (b'', b'error')
    
    import asyncio
    original_create_subprocess_exec = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = AsyncMock(return_value=mock_process)
    
    try:
        result = await emulator_service.get_app_display_name('test_device', 'com.example.app')
        assert result == 'com.example.app'  # Should fallback to package name
        
    finally:
        asyncio.create_subprocess_exec = original_create_subprocess_exec


@pytest.mark.asyncio
async def test_get_label_from_aapt_success(emulator_service):
    """Test successful label extraction from aapt."""
    mock_output = "application-label:'My AAPT App'"
    
    mock_process = AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate.return_value = (mock_output.encode(), b'')
    
    import asyncio
    original_create_subprocess_exec = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = AsyncMock(return_value=mock_process)
    
    try:
        result = await emulator_service._get_label_from_aapt('test_device', '/data/app/test.apk')
        assert result == 'My AAPT App'
        
    finally:
        asyncio.create_subprocess_exec = original_create_subprocess_exec


@pytest.mark.asyncio
async def test_get_label_from_aapt_failure(emulator_service):
    """Test aapt label extraction failure."""
    mock_process = AsyncMock()
    mock_process.returncode = 1
    mock_process.communicate.return_value = (b'', b'error')
    
    import asyncio
    original_create_subprocess_exec = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = AsyncMock(return_value=mock_process)
    
    try:
        result = await emulator_service._get_label_from_aapt('test_device', '/data/app/test.apk')
        assert result is None
        
    finally:
        asyncio.create_subprocess_exec = original_create_subprocess_exec


@pytest.mark.asyncio
async def test_get_app_metadata_integration(emulator_service):
    """Test complete app metadata gathering integration."""
    # Mock basic package info
    emulator_service._get_basic_package_info = AsyncMock(return_value={
        'name': 'com.example.app',
        'version': '1.0.0',
        'version_code': 1,
        'install_time': None,
        'last_update_time': None,
        'is_debuggable': False
    })
    
    # Mock display name
    emulator_service.get_app_display_name = AsyncMock(return_value='My Enhanced App')
    
    # Mock icon data (returns None in current implementation)
    emulator_service.get_app_icon_data = AsyncMock(return_value=None)
    
    result = await emulator_service.get_app_metadata('test_device', 'com.example.app')
    
    assert result['name'] == 'My Enhanced App'  # Should use display name
    assert result['version'] == '1.0.0'
    assert result['version_code'] == 1
    assert 'icon_data' not in result  # Icon data not added if None


@pytest.mark.asyncio
async def test_get_app_icon_data_not_implemented(emulator_service):
    """Test that icon data extraction returns None (not yet implemented)."""
    result = await emulator_service.get_app_icon_data('test_device', 'com.example.app')
    assert result is None


@pytest.mark.asyncio
async def test_get_package_rich_info_uses_metadata(emulator_service):
    """Test that _get_package_rich_info uses the new metadata service."""
    # Mock the get_app_metadata method
    expected_metadata = {
        'name': 'Test App',
        'version': '2.0.0',
        'version_code': 20
    }
    
    emulator_service.get_app_metadata = AsyncMock(return_value=expected_metadata)
    
    result = await emulator_service._get_package_rich_info('test_device', 'com.example.app')
    
    assert result == expected_metadata
    emulator_service.get_app_metadata.assert_called_once_with('test_device', 'com.example.app')


@pytest.mark.asyncio
async def test_get_package_rich_info_error_handling(emulator_service):
    """Test error handling in _get_package_rich_info."""
    # Mock get_app_metadata to raise an exception
    emulator_service.get_app_metadata = AsyncMock(side_effect=Exception("Test error"))
    
    result = await emulator_service._get_package_rich_info('test_device', 'com.example.app')
    
    # Should return fallback info
    assert result == {'name': 'com.example.app', 'version': 'Unknown'}