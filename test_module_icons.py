#!/usr/bin/env python3
"""
Test script to verify module icons are displaying correctly in the modules table.
"""

import sys
import os
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from tower_iq.gui.pages.modules_page import ModulesPage


def main():
    """Test the modules page with icons."""
    app = QApplication(sys.argv)
    
    # Create main window
    window = QMainWindow()
    window.setWindowTitle("Module Icons Test")
    window.resize(1200, 800)
    
    # Create central widget
    central_widget = QWidget()
    window.setCentralWidget(central_widget)
    
    # Create layout
    layout = QVBoxLayout(central_widget)
    
    # Create modules page
    modules_page = ModulesPage()
    layout.addWidget(modules_page)
    
    # Show window
    window.show()
    
    # Generate some sample modules to test with
    print("Generating sample modules...")
    modules_page._on_generate_modules()
    
    print("Test window opened. Check if module icons appear in the table.")
    print("You should see module icons (frames + icons) to the left of module names.")
    
    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
