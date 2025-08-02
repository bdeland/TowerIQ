#!/usr/bin/env python3
"""
Module View Widget Test Script

This is a standalone test script to validate the ModuleViewWidget implementation.
It can be run independently from the main application to test the widget's appearance
and functionality with hardcoded test data.

Usage: python test_module_view_widget.py
"""

import sys
import os
from pathlib import Path

# Add the source directory to the Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QScrollArea, QHBoxLayout
from PyQt6.QtCore import Qt
from qfluentwidgets import setTheme, Theme, FluentWindow, isDarkTheme

# Import our module components
from tower_iq.core.module_simulator import Module
from tower_iq.gui.utils.module_view_widget import ModuleViewWidget
from tower_iq.gui.stylesheets.stylesheets import get_themed_stylesheet


def create_test_modules():
    """Create a variety of test modules to showcase different rarities and types."""
    test_modules = []
    
    # Test Module 1: Mythic Armor with unique effect
    test_modules.append(Module(
        guid="test-001",
        name="Space Displacer",
        module_type="Armor",
        rarity="Mythic",
        level=142,
        substat_enum_ids=[18, 19, 20],  # Health Regen, Defense Percent, Defense Absolute
        substat_rarities=["Mythic", "Epic", "Legendary"],  # Different rarities for each substat
        coins_spent=5250000,
        shards_spent=18500,
        is_equipped=True,
        is_favorite=True
    ))
    
    # Test Module 2: Epic Generator with unique effect
    test_modules.append(Module(
        guid="test-002", 
        name="Galaxy Compressor",
        module_type="Generator",
        rarity="Epic",
        level=45,
        substat_enum_ids=[35, 36, 39],  # Cash Bonus, Cash Per Wave, Free Attack Upgrade
        substat_rarities=["Epic", "Rare", "Common"],  # Different rarities for each substat
        coins_spent=875000,
        shards_spent=2100,
        is_equipped=False,
        is_favorite=True
    ))
    
    # Test Module 3: Legendary Cannon with unique effect
    test_modules.append(Module(
        guid="test-003",
        name="Shrink Ray", 
        module_type="Cannon",
        rarity="LegendaryPlus",
        level=87,
        substat_enum_ids=[1, 2, 3, 6],  # Attack Speed, Critical Chance, Critical Factor, Multishot Chance
        substat_rarities=["Legendary", "Epic", "Rare", "Mythic"],  # Different rarities for each substat
        coins_spent=2150000,
        shards_spent=8750,
        is_equipped=False,
        is_favorite=False
    ))
    
    # Test Module 4: Rare Core module
    test_modules.append(Module(
        guid="test-004",
        name="Magnetic Hook",
        module_type="Core", 
        rarity="Rare",
        level=25,
        substat_enum_ids=[48, 50],  # Chain Lightning Damage, Chain Lightning Chance
        substat_rarities=["Rare", "Common"],  # Different rarities for each substat
        coins_spent=125000,
        shards_spent=450,
        is_equipped=False,
        is_favorite=False
    ))
    
    # Test Module 5: Common Generator for comparison (using an actual unique effect)
    test_modules.append(Module(
        guid="test-005",
        name="Project Funding",
        module_type="Generator",
        rarity="Common",
        level=8,
        substat_enum_ids=[35],  # Cash Bonus
        substat_rarities=["Common"],  # Single substat
        coins_spent=15000,
        shards_spent=0,
        is_equipped=False,
        is_favorite=False
    ))
    
    # Test Module 6: Ancestral tier module
    test_modules.append(Module(
        guid="test-006",
        name="Dimension Core",
        module_type="Core",
        rarity="Ancestral",
        level=195,
        substat_enum_ids=[48, 49, 50],  # Chain Lightning stats
        substat_rarities=["Ancestral", "Mythic", "Legendary"],  # Different rarities for each substat
        coins_spent=15750000,
        shards_spent=45000,
        is_equipped=True,
        is_favorite=True
    ))
    
    return test_modules


class TestMainWindow(QMainWindow):
    """Main window for testing the ModuleViewWidget."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Module View Widget Test")
        self.resize(1200, 800)
        
        # Create central widget with scroll area
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Create scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(False)  # Important: set to False for proper scrolling
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Create scroll content widget
        scroll_content = QWidget()
        scroll_layout = QHBoxLayout(scroll_content)  # Horizontal layout for side-by-side cards
        scroll_layout.setSpacing(20)
        scroll_layout.setContentsMargins(20, 20, 20, 20)
        
        # Create test modules
        test_modules = create_test_modules()
        
        # Add module widgets horizontally
        for i, module in enumerate(test_modules):
            # Create module widget
            module_widget = ModuleViewWidget(module)
            module_widget.setFixedSize(380, 650)  # Fixed size for consistent display
            
            # Add to horizontal layout
            scroll_layout.addWidget(module_widget)
        
        # Add stretch to push cards to the left
        scroll_layout.addStretch()
        
        # Set fixed size for scroll content to enable horizontal scrolling
        total_width = len(test_modules) * 400 + 100  # Give extra space
        scroll_content.setFixedSize(total_width, 700)
        
        # Set up scroll area
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)
        
        # Apply application stylesheet
        self.apply_stylesheet()
    
    def apply_stylesheet(self):
        """Apply the themed stylesheet to the application."""
        try:
            stylesheet = get_themed_stylesheet()
            self.setStyleSheet(stylesheet)
            print("✓ Successfully applied themed stylesheet")
        except Exception as e:
            print(f"⚠ Warning: Could not apply stylesheet: {e}")
    
    def switch_theme(self):
        """Switch between light and dark themes for testing."""
        current_theme = Theme.DARK if isDarkTheme() else Theme.LIGHT
        new_theme = Theme.LIGHT if current_theme == Theme.DARK else Theme.DARK
        setTheme(new_theme)
        self.apply_stylesheet()
        print(f"Switched to {'dark' if new_theme == Theme.DARK else 'light'} theme")


def main():
    """Main function to run the test application."""
    # Create application
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Module View Widget Test")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("TowerIQ")
    
    # Set initial theme (you can change this to test different themes)
    setTheme(Theme.DARK)  # or Theme.LIGHT
    
    # Create and show main window
    window = TestMainWindow()
    
    # Print instructions
    print("="*60)
    print("MODULE VIEW WIDGET TEST")
    print("="*60)
    print("This window displays several test modules with different rarities and types.")
    print("Test features:")
    print("• Different module rarities (Common, Rare, Epic, Legendary, Mythic, Ancestral)")
    print("• Different module types (Armor, Generator, Cannon, Core)")
    print("• Unique effects display")
    print("• Substat rows with rarity pills")
    print("• Level progress bars")
    print("• Theme-aware styling")
    print("\nInstructions:")
    print("• Scroll to see all modules")
    print("• Check that sprites load correctly")
    print("• Verify colors match rarity scheme")
    print("• Test theme switching if implemented")
    print("="*60)
    
    window.show()
    
    # Run application
    exit_code = app.exec()
    print("Test application closed.")
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error running test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)