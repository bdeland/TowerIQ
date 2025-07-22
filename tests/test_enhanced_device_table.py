"""
Tests for enhanced device table display in ConnectionPanel.
"""

import pytest
from unittest.mock import MagicMock
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from src.tower_iq.gui.connection_page import ConnectionPanel


@pytest.fixture
def mock_session_manager():
    """Create a mock session manager for testing."""
    session_manager = MagicMock()
    session_manager.available_emulators = []
    session_manager.available_processes = []
    session_manager.connected_emulator_serial = None
    session_manager.selected_target_package = None
    session_manager.hook_activation_stage = "idle"
    session_manager.hook_activation_message = ""
    return session_manager


@pytest.fixture
def connection_panel(mock_session_manager):
    """Create a ConnectionPanel instance for testing."""
    # Ensure QApplication exists
    if not QApplication.instance():
        QApplication([])
    
    return ConnectionPanel(mock_session_manager)


def test_device_table_headers(connection_panel):
    """Test that device table has correct headers."""
    headers = []
    for col in range(connection_panel.device_table.columnCount()):
        headers.append(connection_panel.device_table.horizontalHeaderItem(col).text())
    
    expected_headers = ["Serial", "Model", "Android", "Emulator", "Status"]
    assert headers == expected_headers


def test_update_device_table_with_enhanced_data(connection_panel):
    """Test device table population with enhanced device data."""
    # Sample enhanced device data
    enhanced_devices = [
        {
            'serial': 'emulator-5554',
            'model': 'Pixel 5',
            'manufacturer': 'Google',
            'android_version': '13',
            'api_level': 33,
            'architecture': 'arm64-v8a',
            'is_emulator': True,
            'device_name': 'sdk_gphone_arm64',
            'status': 'Online'
        },
        {
            'serial': 'device123',
            'model': 'Galaxy S21',
            'manufacturer': 'Samsung',
            'android_version': '12',
            'api_level': 31,
            'architecture': 'arm64-v8a',
            'is_emulator': False,
            'device_name': 'SM-G991B',
            'status': 'Online'
        }
    ]
    
    # Update the device table
    connection_panel.update_device_table(enhanced_devices)
    
    # Verify table has correct number of rows
    assert connection_panel.device_table.rowCount() == 2
    
    # Verify first device data (emulator)
    assert connection_panel.device_table.item(0, 0).text() == 'emulator-5554'
    assert connection_panel.device_table.item(0, 1).text() == 'Google Pixel 5'
    assert connection_panel.device_table.item(0, 2).text() == '13 (API 33)'
    assert connection_panel.device_table.item(0, 3).text() == 'Android Emulator'
    assert connection_panel.device_table.item(0, 4).text() == 'Online'
    
    # Verify second device data (physical)
    assert connection_panel.device_table.item(1, 0).text() == 'device123'
    assert connection_panel.device_table.item(1, 1).text() == 'Samsung Galaxy S21'
    assert connection_panel.device_table.item(1, 2).text() == '12 (API 31)'
    assert connection_panel.device_table.item(1, 3).text() == 'Physical'
    assert connection_panel.device_table.item(1, 4).text() == 'Online'
    
    # Verify full device data is stored in UserRole
    stored_data = connection_panel.device_table.item(0, 0).data(Qt.ItemDataRole.UserRole)
    assert stored_data == enhanced_devices[0]


def test_update_device_table_with_unknown_data(connection_panel):
    """Test device table with unknown/missing data."""
    devices_with_unknowns = [
        {
            'serial': 'unknown-device',
            'model': 'Unknown',
            'manufacturer': 'Unknown',
            'android_version': 'Unknown',
            'api_level': 0,
            'status': 'Online'
        }
    ]
    
    connection_panel.update_device_table(devices_with_unknowns)
    
    # Verify handling of unknown data
    assert connection_panel.device_table.item(0, 0).text() == 'unknown-device'
    assert connection_panel.device_table.item(0, 1).text() == 'Unknown'
    assert connection_panel.device_table.item(0, 2).text() == 'Unknown'
    assert connection_panel.device_table.item(0, 3).text() == 'Physical'  # Default for unknown
    assert connection_panel.device_table.item(0, 4).text() == 'Online'


def test_update_device_table_manufacturer_in_model(connection_panel):
    """Test that manufacturer is not duplicated if already in model name."""
    devices = [
        {
            'serial': 'test-device',
            'model': 'Samsung Galaxy S21',  # Already contains manufacturer
            'manufacturer': 'Samsung',
            'android_version': '12',
            'api_level': 31,
            'status': 'Online'
        }
    ]
    
    connection_panel.update_device_table(devices)
    
    # Verify manufacturer is not duplicated
    assert connection_panel.device_table.item(0, 1).text() == 'Samsung Galaxy S21'
    assert connection_panel.device_table.item(0, 3).text() == 'Physical'  # Not an emulator


def test_device_table_column_sizing(connection_panel):
    """Test that device table columns are properly configured."""
    header = connection_panel.device_table.horizontalHeader()
    
    # Verify column count (now 5 columns with Emulator added)
    assert connection_panel.device_table.columnCount() == 5
    
    # Verify resize modes are set (we can't easily test the exact modes without Qt internals)
    assert header is not None


def test_device_table_item_properties(connection_panel):
    """Test that device table items have correct properties."""
    devices = [
        {
            'serial': 'test-device',
            'model': 'Test Model',
            'android_version': '11',
            'api_level': 30,
            'status': 'Online'
        }
    ]
    
    connection_panel.update_device_table(devices)
    
    # Check that items are not editable (now 5 columns)
    for col in range(5):
        item = connection_panel.device_table.item(0, col)
        assert not (item.flags() & Qt.ItemFlag.ItemIsEditable)
        
        # Check vertical alignment
        assert item.textAlignment() & Qt.AlignmentFlag.AlignVCenter


def test_emulator_detection_logic(connection_panel):
    """Test that emulator detection logic correctly identifies different emulator types."""
    # Test MuMu emulator
    mumu_device = {
        'serial': 'mumu-device',
        'model': 'MuMu Global',
        'manufacturer': 'MuMu',
        'device_name': 'mumu_device',
        'is_emulator': True,
        'status': 'Online'
    }
    assert connection_panel._detect_emulator_type(mumu_device) == "MuMu"
    
    # Test BlueStacks emulator
    bluestacks_device = {
        'serial': 'bluestacks-device',
        'model': 'BlueStacks',
        'device_name': 'bst_device',
        'is_emulator': True,
        'status': 'Online'
    }
    assert connection_panel._detect_emulator_type(bluestacks_device) == "BlueStacks"
    
    # Test Android SDK emulator
    sdk_device = {
        'serial': 'emulator-5554',
        'model': 'Android SDK built for x86',
        'device_name': 'sdk_gphone_x86',
        'is_emulator': True,
        'status': 'Online'
    }
    assert connection_panel._detect_emulator_type(sdk_device) == "Android Emulator"
    
    # Test physical device
    physical_device = {
        'serial': 'physical-device',
        'model': 'Pixel 5',
        'manufacturer': 'Google',
        'device_name': 'redfin',
        'is_emulator': False,
        'status': 'Online'
    }
    assert connection_panel._detect_emulator_type(physical_device) == "Physical"
    
    # Test unknown emulator type
    unknown_emulator = {
        'serial': 'unknown-emulator',
        'model': 'Some Emulator',
        'device_name': 'unknown_device',
        'is_emulator': True,
        'status': 'Online'
    }
    assert connection_panel._detect_emulator_type(unknown_emulator) == "Emulator"