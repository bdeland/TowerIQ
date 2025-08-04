#!/usr/bin/env python3
"""
Modules Page Test Script

This is a standalone test script to validate the Modules Page implementation.
It can be run independently from the main application to test the page's appearance
and functionality with hardcoded test data.

Usage: python test_modules_page.py
"""

import sys
import os
from pathlib import Path

# Add the source directory to the Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, 
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter, QLabel,
    QLineEdit, QComboBox, QListWidget, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from qfluentwidgets import setTheme, Theme, isDarkTheme, TableWidget, BodyLabel, LineEdit, ComboBox, ListWidget

# Import our module components
from tower_iq.core.module_simulator import Module
from tower_iq.gui.utils.module_view_widget import ModuleViewWidget
from tower_iq.gui.stylesheets.stylesheets import get_themed_stylesheet


def create_test_modules():
    """Create a variety of test modules to showcase different rarities and types."""
    test_modules = []
    
    # Test Module 1: Mythic Cannon with unique effect
    test_modules.append(Module(
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
    ))
    
    # Test Module 2: Legendary Armor with unique effect
    test_modules.append(Module(
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
    ))
    
    # Test Module 3: Mythic Generator with unique effect
    test_modules.append(Module(
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
    ))
    
    # Test Module 4: Rare Core module
    test_modules.append(Module(
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
    ))
    
    # Test Module 5: Common Armor
    test_modules.append(Module(
        guid="test-005",
        name="Basic Shield",
        module_type="Armor",
        rarity="Common",
        level=15,
        substat_enum_ids=[1, 2],  # Defense Percent, Defense Absolute
        substat_rarities=["Common", "Common"],
        coins_spent=50000,
        shards_spent=100,
        is_equipped=False,
        is_favorite=False
    ))
    
    # Test Module 6: Epic Cannon
    test_modules.append(Module(
        guid="test-006",
        name="Plasma Cannon",
        module_type="Cannon",
        rarity="Epic",
        level=45,
        substat_enum_ids=[10, 11, 12],  # Attack Speed, Critical Chance, Critical Factor
        substat_rarities=["Epic", "Epic", "Epic"],
        coins_spent=500000,
        shards_spent=2000,
        is_equipped=False,
        is_favorite=True
    ))
    
    return test_modules


def get_frame_name_for_module(module):
    """Get the appropriate frame name based on module type and rarity."""
    rarity_mapping = {
        "Common": "common",
        "Rare": "rare", 
        "Epic": "epic",
        "Legendary": "legendary",
        "LegendaryPlus": "legendary_plus",
        "Mythic": "mythic",
        "MythicPlus": "mythic_plus",
        "Ancestral": "ancestral"
    }
    
    type_mapping = {
        "Armor": "armor",
        "Cannon": "cannon", 
        "Core": "core",
        "Generator": "generator"
    }
    
    rarity = rarity_mapping.get(module.rarity, "common")
    module_type = type_mapping.get(module.module_type, "core")
    
    return f"mf_{module_type}_{rarity}"


def get_icon_name_for_module(module):
    """Get the appropriate icon name based on module type and rarity."""
    rarity_mapping = {
        "Common": "common",
        "Rare": "rare",
        "Epic": "epic", 
        "Legendary": "epic",  # Use epic icons for legendary
        "LegendaryPlus": "epic",
        "Mythic": "epic",
        "MythicPlus": "epic",
        "Ancestral": "epic"
    }
    
    type_mapping = {
        "Armor": "armor",
        "Cannon": "cannon",
        "Core": "core", 
        "Generator": "generator"
    }
    
    rarity = rarity_mapping.get(module.rarity, "common")
    module_type = type_mapping.get(module.module_type, "core")
    
    # For now, use a simple naming convention - in real implementation,
    # you might want to cycle through different icons based on module name hash
    icon_number = hash(module.name) % 4 + 1  # 1-4
    return f"{module_type}_{rarity}_{icon_number}"


def get_display_rarity(rarity: str) -> str:
    """Convert rarity to display format."""
    display_map = {
        'common': 'COMMON',
        'rare': 'RARE',
        'rareplus': 'RARE+',
        'epic': 'EPIC',
        'epicplus': 'EPIC+',
        'legendary': 'LEGENDARY',
        'legendaryplus': 'LEGENDARY+',
        'mythic': 'MYTHIC',
        'mythicplus': 'MYTHIC+',
        'ancestral': 'ANCESTRAL'
    }
    return display_map.get(rarity.lower(), rarity.upper())


def get_rarity_color(rarity: str, is_dark_theme: bool = True) -> str:
    """Get the color for a rarity based on theme."""
    rarity_colors = {
        'common': {'light': '#e4e4e5', 'dark': '#ffffff'},
        'rare': {'light': '#9ff4fe', 'dark': '#47dbff'},
        'epic': {'light': '#ff9afa', 'dark': '#ff4ccf'},
        'legendary': {'light': '#fbb97f', 'dark': '#ff9c3d'},
        'mythic': {'light': '#ff7586', 'dark': '#ff4040'},
        'ancestral': {'light': '#99d1ac', 'dark': '#79f369'}
    }
    
    # Map full rarity names to base rarity for color lookup
    base_rarity_map = {
        'common': 'common',
        'rare': 'rare',
        'rareplus': 'rare',
        'epic': 'epic',
        'epicplus': 'epic',
        'legendary': 'legendary',
        'legendaryplus': 'legendary',
        'mythic': 'mythic',
        'mythicplus': 'mythic',
        'ancestral': 'ancestral'
    }
    
    base_rarity = base_rarity_map.get(rarity.lower(), 'common')
    theme_key = 'dark' if is_dark_theme else 'light'
    return rarity_colors.get(base_rarity, {}).get(theme_key, '#ffffff')


class MultiSelectLineEdit(LineEdit):
    """LineEdit that allows multiple selections via comma-separated input."""
    
    def __init__(self, items, placeholder="All", parent=None):
        super().__init__(parent)
        self.items = items
        self.setPlaceholderText(placeholder)
        
    def get_selected_items(self):
        """Get list of selected items from comma-separated text."""
        current_text = self.text()
        if not current_text:
            return []
        
        # Split by comma and clean up
        selected = [item.strip() for item in current_text.split(',') if item.strip()]
        # Only return items that are in the valid items list
        return [item for item in selected if item in self.items]
    
    def set_selected_items(self, items):
        """Set selected items as comma-separated text."""
        if not items:
            self.setText("")
        else:
            self.setText(", ".join(items))


class ModulesTableWidget(TableWidget):
    """Custom table widget for displaying modules list with filtering."""
    
    module_selected = pyqtSignal(Module)
    
    def __init__(self, modules):
        super().__init__()
        self.modules = modules
        self.filtered_modules = modules.copy()  # Keep track of filtered modules
        self.setup_table()
        self.populate_table()
        
    def setup_table(self):
        """Setup the table structure and headers."""
        # Set column count and headers
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels([
            "Name", "Type", "Rarity", "Level", "Equipped", "Favorite"
        ])
        
        # Set row count
        self.setRowCount(len(self.modules))
        
        # Configure header
        header = self.horizontalHeader()
        if header:
            header.setStretchLastSection(False)
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Name column stretches
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        # Connect selection change signal
        self.itemSelectionChanged.connect(self.on_selection_changed)
        
        # Set selection behavior
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        
        # Make table read-only
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
    def populate_table(self):
        """Populate the table with module data."""
        # Clear existing items
        self.setRowCount(len(self.filtered_modules))
        
        for row, module in enumerate(self.filtered_modules):
            # Name
            name_item = QTableWidgetItem(module.name)
            name_item.setData(Qt.ItemDataRole.UserRole, module)  # Store module reference
            name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make read-only
            self.setItem(row, 0, name_item)
            
            # Type
            type_item = QTableWidgetItem(module.module_type)
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make read-only
            self.setItem(row, 1, type_item)
            
            # Rarity - use display format and apply color
            display_rarity = get_display_rarity(module.rarity)
            rarity_item = QTableWidgetItem(display_rarity)
            rarity_item.setFlags(rarity_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make read-only
            
            # Apply rarity color
            rarity_color = get_rarity_color(module.rarity, isDarkTheme())
            rarity_item.setForeground(QColor(rarity_color))
            
            self.setItem(row, 2, rarity_item)
            
            # Level
            level_item = QTableWidgetItem(str(module.level))
            level_item.setFlags(level_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make read-only
            self.setItem(row, 3, level_item)
            
            # Equipped
            equipped_item = QTableWidgetItem("✓" if module.is_equipped else "")
            equipped_item.setFlags(equipped_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make read-only
            self.setItem(row, 4, equipped_item)
            
            # Favorite
            favorite_item = QTableWidgetItem("★" if module.is_favorite else "")
            favorite_item.setFlags(favorite_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make read-only
            self.setItem(row, 5, favorite_item)
    
    def filter_modules(self, name_filter="", type_filters=None, rarity_filters=None, 
                      level_filter="", equipped_filter="", favorite_filter=""):
        """Filter modules based on criteria."""
        self.filtered_modules = []
        
        # Convert single filters to lists for consistency
        if type_filters is None:
            type_filters = []
        if rarity_filters is None:
            rarity_filters = []
        
        for module in self.modules:
            # Name filter (case-insensitive)
            if name_filter and name_filter.lower() not in module.name.lower():
                continue
                
            # Type filter (multi-select)
            if type_filters and module.module_type not in type_filters:
                continue
                
            # Rarity filter (multi-select)
            if rarity_filters:
                display_rarity = get_display_rarity(module.rarity)
                if display_rarity not in rarity_filters:
                    continue
                    
            # Level filter
            if level_filter and level_filter != "All":
                try:
                    level_value = int(level_filter)
                    if module.level != level_value:
                        continue
                except ValueError:
                    # If not a number, try to match as string
                    if str(module.level) != level_filter:
                        continue
                        
            # Equipped filter
            if equipped_filter and equipped_filter != "All":
                is_equipped = equipped_filter == "Yes"
                if module.is_equipped != is_equipped:
                    continue
                    
            # Favorite filter
            if favorite_filter and favorite_filter != "All":
                is_favorite = favorite_filter == "Yes"
                if module.is_favorite != is_favorite:
                    continue
                    
            self.filtered_modules.append(module)
        
        # Repopulate table with filtered data
        self.populate_table()
        
        # Select first row if available
        if self.filtered_modules and self.rowCount() > 0:
            self.selectRow(0)
    
    def on_selection_changed(self):
        """Handle table selection changes."""
        current_row = self.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_modules):
            selected_module = self.filtered_modules[current_row]
            self.module_selected.emit(selected_module)


class FilterWidget(QWidget):
    """Widget containing filter controls for the modules table."""
    
    def __init__(self, modules_table):
        super().__init__()
        self.modules_table = modules_table
        self.setup_filters()
        
    def setup_filters(self):
        """Setup the filter controls."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 10)
        layout.setSpacing(10)
        
        # Name filter
        name_label = BodyLabel("Name:")
        self.name_filter = LineEdit()
        self.name_filter.setPlaceholderText("Filter by name...")
        self.name_filter.textChanged.connect(self.apply_filters)
        
        # Type filter (multi-select)
        self.type_filter = MultiSelectLineEdit(["Armor", "Cannon", "Core", "Generator"], "All types")
        self.type_filter.textChanged.connect(self.apply_filters)
        
        # Rarity filter (multi-select)
        rarity_items = ["COMMON", "RARE", "RARE+", "EPIC", "EPIC+", 
                       "LEGENDARY", "LEGENDARY+", "MYTHIC", "MYTHIC+", "ANCESTRAL"]
        self.rarity_filter = MultiSelectLineEdit(rarity_items, "All rarities")
        self.rarity_filter.textChanged.connect(self.apply_filters)
        
        # Level filter
        level_label = BodyLabel("Level:")
        self.level_filter = LineEdit()
        self.level_filter.setPlaceholderText("Filter by level...")
        self.level_filter.textChanged.connect(self.apply_filters)
        
        # Equipped filter
        equipped_label = BodyLabel("Equipped:")
        self.equipped_filter = ComboBox()
        self.equipped_filter.addItems(["All", "Yes", "No"])
        self.equipped_filter.currentTextChanged.connect(self.apply_filters)
        
        # Favorite filter
        favorite_label = BodyLabel("Favorite:")
        self.favorite_filter = ComboBox()
        self.favorite_filter.addItems(["All", "Yes", "No"])
        self.favorite_filter.currentTextChanged.connect(self.apply_filters)
        
        # Add widgets to layout
        layout.addWidget(name_label)
        layout.addWidget(self.name_filter)
        
        # Type filter with label
        type_label = BodyLabel("Type:")
        layout.addWidget(type_label)
        layout.addWidget(self.type_filter)
        
        # Rarity filter with label
        rarity_label = BodyLabel("Rarity:")
        layout.addWidget(rarity_label)
        layout.addWidget(self.rarity_filter)
        
        layout.addWidget(level_label)
        layout.addWidget(self.level_filter)
        layout.addWidget(equipped_label)
        layout.addWidget(self.equipped_filter)
        layout.addWidget(favorite_label)
        layout.addWidget(self.favorite_filter)
        layout.addStretch()
        
    def apply_filters(self):
        """Apply all current filters to the table."""
        self.modules_table.filter_modules(
            name_filter=self.name_filter.text(),
            type_filters=self.type_filter.get_selected_items(),
            rarity_filters=self.rarity_filter.get_selected_items(),
            level_filter=self.level_filter.text(),
            equipped_filter=self.equipped_filter.currentText(),
            favorite_filter=self.favorite_filter.currentText()
        )


class TestModulesPage(QMainWindow):
    """Main window for testing the Modules Page."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Modules Page Test")
        self.resize(1400, 900)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Create splitter for resizable left/right panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel - Modules table
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # Table header
        table_header = BodyLabel("Modules List")
        table_header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        left_layout.addWidget(table_header)
        
        # Create modules table
        self.test_modules = create_test_modules()
        self.modules_table = ModulesTableWidget(self.test_modules)
        
        # Create filter widget
        self.filter_widget = FilterWidget(self.modules_table)
        left_layout.addWidget(self.filter_widget)
        
        left_layout.addWidget(self.modules_table)
        
        # Right panel - Module view
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        # Module view header
        self.module_view_header = BodyLabel("Select a module to view details")
        self.module_view_header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        right_layout.addWidget(self.module_view_header)
        
        # Module view widget container
        self.module_view_container = QWidget()
        self.module_view_layout = QVBoxLayout(self.module_view_container)
        self.module_view_layout.setContentsMargins(0, 0, 0, 0)
        self.module_view_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        right_layout.addWidget(self.module_view_container)
        
        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        
        # Set initial splitter sizes (40% left, 60% right)
        splitter.setSizes([560, 840])
        
        # Connect table selection signal
        self.modules_table.module_selected.connect(self.on_module_selected)
        
        # Apply application stylesheet
        self.apply_stylesheet()
        
        # Select first module by default
        if self.test_modules:
            self.modules_table.selectRow(0)
    
    def on_module_selected(self, module):
        """Handle module selection from table."""
        # Update header
        self.module_view_header.setText(f"Module Details: {module.name}")
        
        # Clear existing module view
        for i in reversed(range(self.module_view_layout.count())):
            layout_item = self.module_view_layout.itemAt(i)
            if layout_item:
                child = layout_item.widget()
                if child:
                    child.deleteLater()
        
        # Create new module view widget
        frame_name = get_frame_name_for_module(module)
        icon_name = get_icon_name_for_module(module)
        
        module_widget = ModuleViewWidget(
            module=module,
            frame_name=frame_name,
            icon_name=icon_name
        )
        
        # Add to layout
        self.module_view_layout.addWidget(module_widget)
    
    def apply_stylesheet(self):
        """Apply the themed stylesheet to the application."""
        try:
            stylesheet = get_themed_stylesheet()
            self.setStyleSheet(stylesheet)
            print("✓ Successfully applied themed stylesheet")
        except Exception as e:
            print(f"⚠ Warning: Could not apply stylesheet: {e}")


def main():
    """Main function to run the test application."""
    # Create application
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Modules Page Test")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("TowerIQ")
    
    # Set initial theme (you can change this to test different themes)
    setTheme(Theme.DARK)  # or Theme.LIGHT
    
    # Create and show main window
    window = TestModulesPage()
    
    # Print instructions
    print("="*60)
    print("MODULES PAGE TEST")
    print("="*60)
    print("This window displays a modules page with:")
    print("• Left side: Table showing list of modules")
    print("• Right side: Module view widget for selected module")
    print("• Splitter for resizable panels")
    print("• Different module rarities and types")
    print("\nTest features:")
    print("• Click on different modules in the table")
    print("• Verify module details update on the right")
    print("• Check that sprites load correctly")
    print("• Verify colors match rarity scheme")
    print("• Test resizing the splitter")
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