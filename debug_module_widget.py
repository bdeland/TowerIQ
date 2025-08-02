#!/usr/bin/env python3
"""
Simple debug test for ModuleViewWidget
"""

import sys
import os
from pathlib import Path

# Add the source directory to the Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel
from PyQt6.QtCore import Qt
from qfluentwidgets import setTheme, Theme

# Import our module components
from tower_iq.core.module_simulator import Module
from tower_iq.gui.utils.module_view_widget import ModuleViewWidget
from tower_iq.gui.stylesheets.stylesheets import get_themed_stylesheet


def main():
    """Simple test to check if ModuleViewWidget displays."""
    app = QApplication(sys.argv)
    setTheme(Theme.DARK)
    
    window = QMainWindow()
    window.setWindowTitle("Simple Module Widget Debug")
    window.resize(600, 400)
    
    # Create central widget
    central_widget = QWidget()
    window.setCentralWidget(central_widget)
    layout = QVBoxLayout(central_widget)
    
    # Add a simple label first to verify basic functionality
    test_label = QLabel("Debug Test - If you see this, basic Qt is working")
    test_label.setStyleSheet("color: white; font-size: 16px; padding: 10px;")
    layout.addWidget(test_label)
    
    try:
        # Create a simple test module (favorited to test overlay)
        test_module = Module(
            guid="debug-test",
            name="Sharp Fortitude",
            module_type="Armor",
            rarity="Mythic",
            level=50,
            substat_enum_ids=[18, 19],
            substat_rarities=["Mythic", "Epic"],  # Different rarities for each substat
            is_favorite=True  # Test favorite overlay
        )
        
        print("✓ Module created successfully")
        
        # Create module widget
        module_widget = ModuleViewWidget(test_module)
        module_widget.setFixedSize(380, 650)
        
        print("✓ ModuleViewWidget created successfully")
        
        # Add to layout
        layout.addWidget(module_widget)
        
        print("✓ Widget added to layout")
        
        # Apply stylesheet
        stylesheet = get_themed_stylesheet()
        window.setStyleSheet(stylesheet)
        
        print("✓ Stylesheet applied")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        
        # Add error label
        error_label = QLabel(f"Error: {str(e)}")
        error_label.setStyleSheet("color: red; font-size: 14px; padding: 10px;")
        layout.addWidget(error_label)
    
    window.show()
    print("✓ Window shown")
    
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())