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
from dataclasses import dataclass
from typing import List, Optional

# Add the source directory to the Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, 
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter, QLabel,
    QLineEdit, QComboBox, QListWidget, QCheckBox, QPushButton, QSpinBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from qfluentwidgets import setTheme, Theme, isDarkTheme, TableWidget, BodyLabel, LineEdit, ComboBox, ListWidget, PushButton, SpinBox

# Import our module components
from tower_iq.core.game_data.modules.module_blueprints import (
    ModuleBlueprint, get_blueprint_by_name, ALL_MODULE_BLUEPRINTS
)
from tower_iq.core.game_data.modules._enums import ModuleType, Rarity, MaxLevel
from tower_iq.core.game_data.modules.module_simulator import ModuleSimulator, GeneratedModule
from tower_iq.gui.utils.module_view_widget import ModuleViewWidget, ModuleDisplayData, SubstatDisplayInfo
from tower_iq.gui.stylesheets.stylesheets import get_themed_stylesheet


@dataclass
class Module:
    """
    Module instance class that represents an actual module with its current state.
    This is what gets displayed in the UI and stored in the database.
    """
    guid: str
    name: str
    module_type: str
    rarity: str
    level: int
    substat_enum_ids: List[int]
    substat_rarities: List[str]
    coins_spent: int
    shards_spent: int
    is_equipped: bool
    is_favorite: bool


def convert_generated_module_to_module(generated_module: GeneratedModule, guid: str) -> Module:
    """Convert a GeneratedModule to a Module for display in the UI."""
    # Convert substats to enum IDs and rarities
    substat_enum_ids = [substat.enum_id for substat in generated_module.substats]
    substat_rarities = [substat.rarity.value for substat in generated_module.substats]
    
    # Generate random level based on rarity (1 to max_level)
    level = 1  # Default level for new modules
    
    # Generate random coins and shards spent (placeholder values)
    coins_spent = 0
    shards_spent = 0
    
    return Module(
        guid=guid,
        name=generated_module.name,
        module_type=generated_module.module_type.value,
        rarity=generated_module.rarity.value,
        level=level,
        substat_enum_ids=substat_enum_ids,
        substat_rarities=substat_rarities,
        coins_spent=coins_spent,
        shards_spent=shards_spent,
        is_equipped=False,
        is_favorite=False
    )


def create_test_modules():
    """Create an empty list of modules."""
    return []





def get_icon_name_for_module(module):
    """Get the appropriate icon name based on module type and rarity using blueprints."""
    # Get the blueprint for this module
    blueprint = get_blueprint_by_name(module.name)
    if blueprint:
        # Use the blueprint's icon name
        return blueprint.icon_name
    
    # If no blueprint found, raise an error to help identify missing data
    raise ValueError(f"No blueprint found for module: {module.name}")


def convert_module_to_display_data(module: Module, generated_module: Optional[GeneratedModule] = None) -> ModuleDisplayData:
    """Convert a Module object to ModuleDisplayData for the widget."""
    # Get the blueprint for this module
    blueprint = get_blueprint_by_name(module.name)
    if not blueprint:
        raise ValueError(f"No blueprint found for module: {module.name}")
    
    # Get max level for this rarity
    rarity_to_maxlevel = {
        'Common': MaxLevel.COMMON.value,
        'Rare': MaxLevel.RARE.value,
        'RarePlus': MaxLevel.RARE_PLUS.value,
        'Epic': MaxLevel.EPIC.value,
        'EpicPlus': MaxLevel.EPIC_PLUS.value,
        'Legendary': MaxLevel.LEGENDARY.value,
        'LegendaryPlus': MaxLevel.LEGENDARY_PLUS.value,
        'Mythic': MaxLevel.MYTHIC.value,
        'MythicPlus': MaxLevel.MYTHIC_PLUS.value,
        'Ancestral': MaxLevel.ANCESTRAL.value,
        'Ancestral1': MaxLevel.ANCESTRAL1.value,
        'Ancestral2': MaxLevel.ANCESTRAL2.value,
        'Ancestral3': MaxLevel.ANCESTRAL3.value,
        'Ancestral4': MaxLevel.ANCESTRAL4.value,
        'Ancestral5': MaxLevel.ANCESTRAL5.value,
    }
    max_level = rarity_to_maxlevel.get(module.rarity, 20)
    
    # Convert substats to display format
    substats = []
    for i, substat_id in enumerate(module.substat_enum_ids):
        if generated_module and i < len(generated_module.substats):
            # Use the actual substat data from the generated module
            gen_substat = generated_module.substats[i]
            substats.append(SubstatDisplayInfo(
                name=gen_substat.name,
                value=gen_substat.value,
                unit=gen_substat.unit,
                rarity=gen_substat.rarity.value,
                enum_id=gen_substat.enum_id
            ))
        else:
            # Fallback to placeholder if we can't find the generated data
            substat_rarity = module.substat_rarities[i] if i < len(module.substat_rarities) else module.rarity
            substats.append(SubstatDisplayInfo(
                name=f"Substat {i+1}",
                value=1.0,  # Placeholder value
                unit="%",
                rarity=substat_rarity,
                enum_id=substat_id
            ))
    
    # Get unique effect text if this is a natural epic
    unique_effect_text = None
    if blueprint.is_natural_epic and blueprint.unique_effect:
        unique_effect_text = f"{blueprint.unique_effect.name}: {blueprint.unique_effect.effect_template}"
    
    return ModuleDisplayData(
        name=module.name,
        module_type=module.module_type,
        rarity=module.rarity,
        level=module.level,
        max_level=max_level,
        is_equipped=module.is_equipped,
        is_favorite=module.is_favorite,
        frame_name=blueprint.frame_pattern,
        icon_name=blueprint.icon_name,
        substats=substats,
        unique_effect_text=unique_effect_text
    )


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
    
    def update_modules(self, new_modules):
        """Update the modules list and refresh the table."""
        self.modules = new_modules
        self.filtered_modules = new_modules.copy()
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
    
    def __init__(self, modules_table, parent_window=None):
        super().__init__()
        self.modules_table = modules_table
        self.parent_window = parent_window  # Reference to the main window
        self.setup_filters()
        
    def setup_filters(self):
        """Setup the filter controls."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 10)
        layout.setSpacing(10)
        
        # Simulation controls row
        sim_layout = QHBoxLayout()
        sim_layout.setSpacing(10)
        
        # Quantity input
        quantity_label = BodyLabel("Quantity:")
        self.quantity_spinbox = SpinBox()
        self.quantity_spinbox.setRange(1, 1000)
        self.quantity_spinbox.setValue(10)
        self.quantity_spinbox.setMinimumWidth(80)
        
        # Simulate button
        self.simulate_button = PushButton("Simulate")
        self.simulate_button.clicked.connect(self.simulate_modules)
        
        sim_layout.addWidget(quantity_label)
        sim_layout.addWidget(self.quantity_spinbox)
        sim_layout.addWidget(self.simulate_button)
        sim_layout.addStretch()
        
        # Filter controls row
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(10)
        
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
        
        # Add widgets to filter layout
        filter_layout.addWidget(name_label)
        filter_layout.addWidget(self.name_filter)
        
        # Type filter with label
        type_label = BodyLabel("Type:")
        filter_layout.addWidget(type_label)
        filter_layout.addWidget(self.type_filter)
        
        # Rarity filter with label
        rarity_label = BodyLabel("Rarity:")
        filter_layout.addWidget(rarity_label)
        filter_layout.addWidget(self.rarity_filter)
        
        filter_layout.addWidget(level_label)
        filter_layout.addWidget(self.level_filter)
        filter_layout.addWidget(equipped_label)
        filter_layout.addWidget(self.equipped_filter)
        filter_layout.addWidget(favorite_label)
        filter_layout.addWidget(self.favorite_filter)
        filter_layout.addStretch()
        
        # Add both layouts to main layout
        layout.addLayout(sim_layout)
        layout.addLayout(filter_layout)
        
    def simulate_modules(self):
        """Simulate the specified number of modules."""
        quantity = self.quantity_spinbox.value()
        
        print(f"\n=== Simulating {quantity} modules ===")
        
        # Create simulator and generate modules
        simulator = ModuleSimulator()
        generated_modules = simulator.simulate_multiple_pulls(quantity)
        
        # Convert to Module objects
        modules = []
        for i, generated_module in enumerate(generated_modules):
            guid = f"simulated-{i+1:04d}"
            module = convert_generated_module_to_module(generated_module, guid)
            modules.append(module)
            
            # Print module details to terminal
            print(f"{i+1:3d}. {module.name} ({module.rarity}) - {module.module_type}")
            for j, substat in enumerate(generated_module.substats):
                print(f"     Substat {j+1}: {substat.name} = {substat.value}{substat.unit} ({substat.rarity.value})")
            if generated_module.has_unique_effect and generated_module.unique_effect:
                print(f"     Unique Effect: {generated_module.unique_effect.name}")
            print()
        
        # Store the generated modules for substat data access
        if self.parent_window:
            self.parent_window.generated_modules = generated_modules
        
        print(f"=== Generated {len(modules)} modules ===")
        
        # Update the modules table
        self.modules_table.update_modules(modules)
        
        # Apply current filters
        self.apply_filters()
        
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
        self.generated_modules = []  # Store generated modules for substat data
        self.modules_table = ModulesTableWidget(self.test_modules)
        
        # Create filter widget
        self.filter_widget = FilterWidget(self.modules_table, self)
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
        
        # No modules initially, so no selection
    
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
        
        # Convert module to display data and create widget
        # We need to find the corresponding generated module to get actual substat data
        generated_module = None
        for gen_module in self.generated_modules:
            if gen_module.name == module.name:
                generated_module = gen_module
                break
        
        module_display_data = convert_module_to_display_data(module, generated_module)
        
        module_widget = ModuleViewWidget(module_data=module_display_data)
        
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
    print("• Module simulation controls")
    print("\nTest features:")
    print("• Enter a quantity and click 'Simulate' to generate modules")
    print("• Click on different modules in the table")
    print("• Verify module details update on the right")
    print("• Check that sprites load correctly")
    print("• Verify colors match rarity scheme")
    print("• Test filtering and resizing the splitter")
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