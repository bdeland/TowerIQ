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
    
    # Test Module 1: Mythic Cannon with unique effect
    test_modules.append({
        'module': Module(
            guid="188797fe-cd0c-4483-ab91-32df38747ce8",
            name="Death Penalty",
            module_type="Cannon",
            rarity="MythicPlus",
            level=94,
            substat_enum_ids=[13, 1, 14],  # Health Regen, Defense Percent, Defense Absolute
            substat_rarities=["Mythic", "Mythic", "Mythic"],  # Different rarities for each substat
            coins_spent=6196440000,
            shards_spent=18388,
            is_equipped=True,
            is_favorite=True
        ),
        'frame_name': 'mf_cannon_mythic_plus',
        'icon_name': 'cannon_epic_2'
    })
    
    # Test Module 2: Legendary Armor with unique effect
    test_modules.append({
        'module': Module(
            guid="test-002", 
            name="Wormhole Redirector",
            module_type="Armor",
            rarity="LegendaryPlus",
            level=90,
            substat_enum_ids=[32, 30, 28],  # Death Penalty, Defense Percent, Defense Absolute
            substat_rarities=["Legendary", "Legendary", "Legendary"],  # Different rarities for each substat
            coins_spent=4796440000,
            shards_spent=15588,
            is_equipped=True,
            is_favorite=True
        ),
        'frame_name': 'mf_armor_legendary_plus',
        'icon_name': 'armor_epic_1'
    })
    
    # Test Module 3: Mythic Generator with unique effect
    test_modules.append({
        'module': Module(
            guid="test-003",
            name="Galaxy Compressor", 
            module_type="Generator",
            rarity="MythicPlus",
            level=92,
            substat_enum_ids=[43, 47, 44],  # Attack Speed, Critical Chance, Critical Factor, Multishot Chance
            substat_rarities=["Mythic", "Mythic", "Mythic"],  # Different rarities for each substat
            coins_spent=2150000,
            shards_spent=8750,
            is_equipped=True,
            is_favorite=True
        ),
        'frame_name': 'mf_core_mythic_plus',
        'icon_name': 'generator_epic_3'
    })
    
    # Test Module 4: Rare Core module
    test_modules.append({
        'module': Module(
            guid="test-004",
            name="Multiverse Nexus",
            module_type="Core", 
            rarity="Rare",
            level=25,
            substat_enum_ids=[56, 64, 70],  # Chain Lightning Damage, Chain Lightning Chance
            substat_rarities=["Legendary", "Legendary", "Legendary"],  # Different rarities for each substat
            coins_spent=125000,
            shards_spent=450,
            is_equipped=True,
            is_favorite=True
        ),
        'frame_name': 'mf_generator_legendary',
        'icon_name': 'core_epic_1'
    })
    
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
        for i, test_data in enumerate(test_modules):
            # Create module widget with frame and icon names
            module_widget = ModuleViewWidget(
                module=test_data['module'],
                frame_name=test_data['frame_name'],
                icon_name=test_data['icon_name']
            )
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