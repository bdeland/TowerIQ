#!/usr/bin/env python3
"""
Test script for the new connection page with vertical stepper.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt6.QtCore import QTimer

from tower_iq.gui.pages.connection_page import ConnectionPage
from tower_iq.core.session import SessionManager
from tower_iq.core.config import ConfigManager


class MockSessionManager:
    """Mock session manager for testing."""
    
    def __init__(self):
        self.connection_main_state = None
        self.available_emulators = []
        self.available_processes = []
        self.connected_emulator_serial = None
        self.selected_target_pid = None
        self.selected_target_package = None
        self.selected_target_version = None
        self.is_hook_compatible = False
        self._last_error_info = None
        
    def get_last_error_info(self):
        return self._last_error_info
        
    def set_error_info(self, error_info):
        self._last_error_info = error_info


class MockConfigManager:
    """Mock config manager for testing."""
    
    def __init__(self):
        self.config = {}


class TestWindow(QMainWindow):
    """Test window for the connection page."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Connection Page Test")
        self.setGeometry(100, 100, 800, 600)
        
        # Create mock managers
        self.session_manager = MockSessionManager()
        self.config_manager = MockConfigManager()
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create layout
        layout = QVBoxLayout(central_widget)
        
        # Create connection page
        self.connection_page = ConnectionPage(
            session_manager=self.session_manager,
            config_manager=self.config_manager
        )
        layout.addWidget(self.connection_page)
        
        # Connect signals
        self.connection_page.scan_devices_requested.connect(self._on_scan_devices)
        self.connection_page.connect_device_requested.connect(self._on_connect_device)
        self.connection_page.refresh_processes_requested.connect(self._on_refresh_processes)
        self.connection_page.compatible_scripts_requested.connect(self._on_compatible_scripts)
        
        # Simulate some data after a delay
        QTimer.singleShot(1000, self._simulate_data)
        
    def _on_scan_devices(self):
        """Handle device scan request."""
        print("Device scan requested")
        # Simulate device data
        devices = [
            {
                'serial': 'emulator-5554',
                'model': 'Android SDK built for x86',
                'manufacturer': 'Google',
                'android_version': 'Android 11',
                'api_level': 30,
                'is_emulator': True,
                'status': 'Online'
            },
            {
                'serial': 'ABCD1234',
                'model': 'Pixel 6',
                'manufacturer': 'Google',
                'android_version': 'Android 12',
                'api_level': 31,
                'is_emulator': False,
                'status': 'Online'
            }
        ]
        self.session_manager.available_emulators = devices
        # Emit the signal
        if hasattr(self.session_manager, 'available_emulators_changed'):
            self.session_manager.available_emulators_changed.emit(devices)
        
    def _on_connect_device(self, device_serial):
        """Handle device connection request."""
        print(f"Connect to device: {device_serial}")
        # Simulate connection process
        self.session_manager.connection_main_state = "CONNECTING"
        if hasattr(self.session_manager, 'connection_main_state_changed'):
            self.session_manager.connection_main_state_changed.emit("CONNECTING")
            
        # Simulate successful connection after delay
        QTimer.singleShot(2000, self._simulate_connection_success)
        
    def _on_refresh_processes(self):
        """Handle process refresh request."""
        print("Refresh processes requested")
        # Simulate process data
        processes = [
            {
                'name': 'Tower Defense Game',
                'package': 'com.example.towerdefense',
                'version': '1.2.3',
                'version_code': 123,
                'pid': 12345,
                'is_running': True
            },
            {
                'name': 'Settings',
                'package': 'com.android.settings',
                'version': '12.0.0',
                'version_code': 120,
                'pid': 6789,
                'is_running': True
            }
        ]
        self.session_manager.available_processes = processes
        # Emit the signal
        if hasattr(self.session_manager, 'available_processes_changed'):
            self.session_manager.available_processes_changed.emit(processes)
            
    def _on_compatible_scripts(self, package, version):
        """Handle compatible scripts request."""
        print(f"Compatible scripts requested for {package} {version}")
        # Simulate script data
        scripts = [
            {
                'scriptName': 'Tower Defense Hook',
                'fileName': 'tower_defense_hook.js',
                'content': 'console.log("Tower Defense Hook Loaded");\n// Hook implementation here...'
            },
            {
                'scriptName': 'Generic Game Hook',
                'fileName': 'generic_game_hook.js',
                'content': 'console.log("Generic Game Hook Loaded");\n// Generic hook implementation...'
            }
        ]
        self.connection_page.update_compatible_scripts(scripts)
        
    def _simulate_data(self):
        """Simulate initial data loading."""
        self._on_scan_devices()
        
    def _simulate_connection_success(self):
        """Simulate successful connection."""
        self.session_manager.connection_main_state = "CONNECTED"
        self.session_manager.connected_emulator_serial = "emulator-5554"
        if hasattr(self.session_manager, 'connection_main_state_changed'):
            self.session_manager.connection_main_state_changed.emit("CONNECTED")


def main():
    """Main function to run the test."""
    app = QApplication(sys.argv)
    
    # Create and show test window
    window = TestWindow()
    window.show()
    
    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
