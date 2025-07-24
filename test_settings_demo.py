#!/usr/bin/env python3
"""
Test script for the new Windows 11-style settings item cards.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from PyQt6.QtWidgets import QApplication
from qfluentwidgets import FluentWindow, FluentIcon, NavigationItemPosition

from tower_iq.gui.settings_demo_page import SettingsDemoPage


def main():
    """Main function to run the settings demo."""
    app = QApplication(sys.argv)
    
    # Create the main window
    window = FluentWindow()
    window.setWindowTitle("TowerIQ - Settings Demo")
    window.resize(800, 600)
    
    # Create the settings demo page
    demo_page = SettingsDemoPage()
    
    # Add the demo page to the window
    window.addSubInterface(demo_page, FluentIcon.SETTING, 'Settings Demo')
    
    # Show the window
    window.show()
    
    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main() 