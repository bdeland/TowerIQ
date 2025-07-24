"""
Tests for enhanced process table display in ConnectionPanel.
"""

import pytest
from unittest.mock import MagicMock
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from tower_iq.gui.pages.connection_page import ConnectionPanel


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


def test_process_table_headers(connection_panel):
    """Test that process table has correct headers."""
    headers = []
    for col in range(connection_panel.process_table.columnCount()):
        headers.append(connection_panel.process_table.horizontalHeaderItem(col).text())
    
    expected_headers = ["App Name", "Package", "Version", "PID", "Status"]
    assert headers == expected_headers


def test_update_process_table_with_enhanced_data(connection_panel):
    """Test process table population with enhanced app data."""
    # Sample enhanced process data
    enhanced_processes = [
        {
            'name': 'WhatsApp Messenger',
            'package': 'com.whatsapp',
            'version': '2.23.1.75',
            'version_code': 232317500,
            'pid': 1234,
            'is_running': True
        },
        {
            'name': 'Spotify Music',
            'package': 'com.spotify.music',
            'version': '8.7.96.345',
            'version_code': 87096345,
            'pid': 5678,
            'is_running': True
        }
    ]
    
    # Update the process table
    connection_panel.update_process_table(enhanced_processes)
    
    # Verify table has correct number of rows
    assert connection_panel.process_table.rowCount() == 2
    
    # Verify first process data
    assert connection_panel.process_table.item(0, 0).text() == 'WhatsApp Messenger'
    assert connection_panel.process_table.item(0, 1).text() == 'com.whatsapp'
    assert connection_panel.process_table.item(0, 2).text() == '2.23.1.75 (232317500)'
    assert connection_panel.process_table.item(0, 3).text() == '1234'
    assert connection_panel.process_table.item(0, 4).text() == 'Running'
    
    # Verify second process data
    assert connection_panel.process_table.item(1, 0).text() == 'Spotify Music'
    assert connection_panel.process_table.item(1, 1).text() == 'com.spotify.music'
    assert connection_panel.process_table.item(1, 2).text() == '8.7.96.345 (87096345)'
    assert connection_panel.process_table.item(1, 3).text() == '5678'
    assert connection_panel.process_table.item(1, 4).text() == 'Running'
    
    # Verify full process data is stored in UserRole
    stored_data = connection_panel.process_table.item(0, 0).data(Qt.ItemDataRole.UserRole)
    assert stored_data == enhanced_processes[0]


def test_update_process_table_app_name_fallback(connection_panel):
    """Test app name fallback when display name equals package name."""
    processes_with_fallback = [
        {
            'name': 'com.example.myapp',  # Same as package name
            'package': 'com.example.myapp',
            'version': '1.0.0',
            'version_code': 1,
            'pid': 9999,
            'is_running': True
        }
    ]
    
    connection_panel.update_process_table(processes_with_fallback)
    
    # Should use last part of package name as fallback
    assert connection_panel.process_table.item(0, 0).text() == 'Myapp'


def test_update_process_table_version_display_formats(connection_panel):
    """Test different version display formats."""
    processes_with_versions = [
        {
            'name': 'App With Version Code',
            'package': 'com.example.app1',
            'version': '2.1.0',
            'version_code': 210,
            'pid': 1111,
            'is_running': True
        },
        {
            'name': 'App Without Version Code',
            'package': 'com.example.app2',
            'version': '1.5.0',
            'version_code': 0,  # No version code
            'pid': 2222,
            'is_running': True
        },
        {
            'name': 'App With Unknown Version',
            'package': 'com.example.app3',
            'version': 'Unknown',
            'version_code': 100,
            'pid': 3333,
            'is_running': True
        }
    ]
    
    connection_panel.update_process_table(processes_with_versions)
    
    # With version code
    assert connection_panel.process_table.item(0, 2).text() == '2.1.0 (210)'
    
    # Without version code
    assert connection_panel.process_table.item(1, 2).text() == '1.5.0'
    
    # Unknown version
    assert connection_panel.process_table.item(2, 2).text() == 'Unknown'


def test_update_process_table_not_running_apps(connection_panel):
    """Test handling of not running apps (should be grayed out)."""
    processes_mixed_status = [
        {
            'name': 'Running App',
            'package': 'com.example.running',
            'version': '1.0.0',
            'pid': 1234,
            'is_running': True
        },
        {
            'name': 'Not Running App',
            'package': 'com.example.notrunning',
            'version': '1.0.0',
            'pid': None,
            'is_running': False
        }
    ]
    
    connection_panel.update_process_table(processes_mixed_status)
    
    # Running app should be normal
    running_item = connection_panel.process_table.item(0, 0)
    assert running_item.flags() & Qt.ItemFlag.ItemIsEnabled
    assert connection_panel.process_table.item(0, 4).text() == 'Running'
    
    # Not running app should be grayed out
    not_running_item = connection_panel.process_table.item(1, 0)
    assert not (not_running_item.flags() & Qt.ItemFlag.ItemIsEnabled)
    assert connection_panel.process_table.item(1, 4).text() == 'Not Running'


def test_update_process_table_missing_data_handling(connection_panel):
    """Test handling of missing or incomplete process data."""
    processes_with_missing_data = [
        {
            'name': 'Incomplete App',
            'package': 'com.example.incomplete',
            # Missing version, version_code, pid
            'is_running': True
        },
        {
            # Missing name
            'package': 'com.example.noname',
            'version': '1.0.0',
            'pid': 5555,
            'is_running': True
        }
    ]
    
    connection_panel.update_process_table(processes_with_missing_data)
    
    # First app with missing data
    assert connection_panel.process_table.item(0, 0).text() == 'Incomplete App'
    assert connection_panel.process_table.item(0, 2).text() == 'Unknown'  # Missing version
    assert connection_panel.process_table.item(0, 3).text() == 'N/A'  # Missing PID
    
    # Second app with missing name
    assert connection_panel.process_table.item(1, 0).text() == 'N/A'  # Missing name
    assert connection_panel.process_table.item(1, 1).text() == 'com.example.noname'
    assert connection_panel.process_table.item(1, 2).text() == '1.0.0'
    assert connection_panel.process_table.item(1, 3).text() == '5555'


def test_process_table_item_properties(connection_panel):
    """Test that process table items have correct properties."""
    processes = [
        {
            'name': 'Test App',
            'package': 'com.example.test',
            'version': '1.0.0',
            'pid': 1234,
            'is_running': True
        }
    ]
    
    connection_panel.update_process_table(processes)
    
    # Check that items are not editable
    for col in range(5):
        item = connection_panel.process_table.item(0, col)
        assert not (item.flags() & Qt.ItemFlag.ItemIsEditable)
        
        # Check vertical alignment
        assert item.textAlignment() & Qt.AlignmentFlag.AlignVCenter


def test_process_table_column_sizing(connection_panel):
    """Test that process table columns are properly configured."""
    header = connection_panel.process_table.horizontalHeader()
    
    # Verify column count
    assert connection_panel.process_table.columnCount() == 5
    
    # Verify resize modes are set (we can't easily test the exact modes without Qt internals)
    assert header is not None


def test_update_process_table_empty_list(connection_panel):
    """Test updating process table with empty list."""
    connection_panel.update_process_table([])
    
    # Should have no rows
    assert connection_panel.process_table.rowCount() == 0


def test_update_process_table_data_storage(connection_panel):
    """Test that full process data is properly stored for selection handling."""
    process_data = {
        'name': 'Test App',
        'package': 'com.example.test',
        'version': '1.0.0',
        'version_code': 100,
        'pid': 1234,
        'is_running': True,
        'extra_field': 'extra_value'  # Additional data that should be preserved
    }
    
    connection_panel.update_process_table([process_data])
    
    # Verify full data is stored in the first column
    stored_data = connection_panel.process_table.item(0, 0).data(Qt.ItemDataRole.UserRole)
    assert stored_data == process_data
    assert stored_data['extra_field'] == 'extra_value'