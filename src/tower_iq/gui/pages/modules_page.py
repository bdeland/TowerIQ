"""
TowerIQ Modules Page

This module provides the modules page widget for the application.
"""

import os
from typing import List, Optional, Dict, Any, cast
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QHeaderView, QTableWidgetItem, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from qfluentwidgets import (
    TableWidget, TableItemDelegate, SearchLineEdit, ComboBox, 
    BodyLabel, CaptionLabel, CardWidget, CheckBox, PushButton
)
from superqt import QLabeledRangeSlider

from ..utils.content_page import ContentPage
from ..utils.module_view_widget import ModuleViewWidget, ModuleDisplayData, SubstatDisplayInfo
from ..stylesheets.stylesheets import RARITY_COLORS

# Import ModuleSimulator and related classes
from ...core.game_data.modules.module_simulator import ModuleSimulator, GeneratedModule
from ...core.game_data.modules.game_data_manager import GameDataManager


class ModuleTableItemDelegate(TableItemDelegate):
    """Custom delegate for module table items with theme-aware styling."""
    
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        # Apply custom styling for specific columns if needed
        if index.column() == 2:  # Rarity column
            rarity = index.data()
            if rarity:
                # Normalize rarity to match RARITY_COLORS keys
                normalized_key = (
                    str(rarity).lower().replace("+", "plus").replace(" ", "").strip()
                )
                color_hex = RARITY_COLORS.get(normalized_key, RARITY_COLORS["common"]["primary"])
                # If the lookup returned a dict (expected), extract primary; if already a str, use directly
                if isinstance(color_hex, dict):
                    color_hex = color_hex.get("primary", RARITY_COLORS["common"]["primary"])
                # Unselected text color
                option.palette.setColor(option.palette.ColorRole.Text, QColor(color_hex))
                # Selected text color should remain the same as unselected
                option.palette.setColor(option.palette.ColorRole.HighlightedText, QColor(color_hex))


class ModulesPage(ContentPage):
    """
    The modules page of the application.

    Features:
    - Filterable and sortable module table
    - Search functionality
    - Type and rarity filters
    - Level range slider
    - Equipped and favorited checkboxes
    - Module preview widget
    """
    
    # Signals
    module_selected = pyqtSignal(dict)  # Emitted when a module is selected in the table
    
    def __init__(self, parent: QWidget | None = None):
        super().__init__(
            title="Modules",
            description="Manage and view your game modules",
            parent=parent
        )
        
        # Initialize ModuleSimulator
        self.data_manager = GameDataManager()
        self.module_simulator = ModuleSimulator(self.data_manager)
        
        # Initialize empty modules list
        self.sample_modules = []
        self.filtered_modules = []
        
        # Initialize UI
        self._init_ui()
        self._setup_connections()
        
    def _init_ui(self):
        """Initialize the user interface."""
        content_container = self.get_content_container()
        
        # Main layout with left and right panels
        main_layout = QHBoxLayout(content_container)
        main_layout.setSpacing(20)
        
        # Left panel: Filters and Table
        left_panel = self._create_left_panel()
        main_layout.addWidget(left_panel, 2)  # Takes 2/3 of the space
        
        # Right panel: Module View
        right_panel = self._create_right_panel()
        main_layout.addWidget(right_panel, 1)  # Takes 1/3 of the space
        
    def _create_left_panel(self) -> QWidget:
        """Create the left panel with filters and table."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(15)
        layout.setContentsMargins(0, 0, 0, 0)  # Remove margins to align with page title
        
        # Filters section
        filters_card = self._create_filters_section()
        layout.addWidget(filters_card)
        
        # Table section
        table_card = self._create_table_section()
        layout.addWidget(table_card, 1)  # Takes remaining space
        
        return panel
        
    def _create_filters_section(self) -> QWidget:
        """Create the filters section with search and filter controls."""
        # Use a simple widget instead of CardWidget to avoid hover effects
        widget = QWidget()
        widget.setObjectName("FiltersSection")
        
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # All filter controls in a single row with wrapping
        filters_widget = QWidget()
        filters_layout = QHBoxLayout(filters_widget)
        filters_layout.setSpacing(20)  # Increased spacing between widgets
        filters_layout.setContentsMargins(0, 0, 30, 0)  # Remove left padding, keep right padding for label cutoff prevention
        
        # Search bar
        search_widget = QWidget()
        search_layout = QVBoxLayout(search_widget)
        search_layout.setContentsMargins(0, 0, 0, 0)
        search_layout.setSpacing(5)
        search_label = CaptionLabel("Search")
        self.search_edit = SearchLineEdit()
        self.search_edit.setPlaceholderText("Search modules...")
        self.search_edit.setObjectName("ModuleSearch")
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_edit)
        filters_layout.addWidget(search_widget)
        
        # Type filter
        type_widget = QWidget()
        type_layout = QVBoxLayout(type_widget)
        type_layout.setContentsMargins(0, 0, 0, 0)
        type_layout.setSpacing(5)
        type_label = CaptionLabel("Type")
        self.type_combo = ComboBox()
        self._populate_type_combo_with_icons()
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.type_combo)
        filters_layout.addWidget(type_widget)
        
        # Rarity filter
        rarity_widget = QWidget()
        rarity_layout = QVBoxLayout(rarity_widget)
        rarity_layout.setContentsMargins(0, 0, 0, 0)
        rarity_layout.setSpacing(5)
        rarity_label = CaptionLabel("Rarity")
        self.rarity_combo = ComboBox()
        self.rarity_combo.addItems([
            "All", "Common", "Rare", "Rare+", "Epic", "Epic+", 
            "Legendary", "Legendary+", "Mythic", "Mythic+", "Ancestral"
        ])
        rarity_layout.addWidget(rarity_label)
        rarity_layout.addWidget(self.rarity_combo)
        filters_layout.addWidget(rarity_widget)
        
        # Level range slider
        level_widget = QWidget()
        level_layout = QVBoxLayout(level_widget)
        level_layout.setContentsMargins(10, 0, 15, 0)  # Add padding to prevent label cutoff
        level_layout.setSpacing(10)
        level_label = CaptionLabel("Level Range")
        self.level_slider = QLabeledRangeSlider()
        self.level_slider.setOrientation(Qt.Orientation.Horizontal)  # type: ignore[arg-type]
        self.level_slider.setRange(0, 300)
        self.level_slider.setValue((0, 300))  # Set range values as tuple
        self.level_slider.setEdgeLabelMode(QLabeledRangeSlider.EdgeLabelMode.NoLabel)  # Remove edge labels
        self.level_slider.setHandleLabelPosition(QLabeledRangeSlider.LabelPosition.LabelsAbove)
        self.level_slider.setObjectName("LevelSlider")
        level_layout.addWidget(level_label)
        level_layout.addWidget(cast(QWidget, self.level_slider))
        filters_layout.addWidget(level_widget)
        
        # Checkboxes
        checkbox_widget = QWidget()
        checkbox_layout = QVBoxLayout(checkbox_widget)
        checkbox_layout.setContentsMargins(0, 0, 10, 0)  # Add right padding to prevent text cutoff
        checkbox_layout.setSpacing(5)
        checkbox_label = CaptionLabel("Filters")
        self.equipped_checkbox = CheckBox("Equipped Only")
        self.favorited_checkbox = CheckBox("Favorited Only")
        checkbox_layout.addWidget(checkbox_label)
        checkbox_layout.addWidget(self.equipped_checkbox)
        checkbox_layout.addWidget(self.favorited_checkbox)
        filters_layout.addWidget(checkbox_widget)
        
        # Add stretch to allow wrapping behavior
        filters_layout.addStretch()
        
        layout.addWidget(filters_widget)
        
        # Generate Sample Modules button
        generate_button = PushButton("Generate Sample Modules")
        generate_button.setObjectName("GenerateModulesButton")
        generate_button.clicked.connect(self._on_generate_modules)
        layout.addWidget(generate_button)
        
        return widget
        
    def _create_table_section(self) -> QWidget:
        """Create the table section with the modules table."""
        # Use a simple widget instead of CardWidget to avoid hover effects
        widget = QWidget()
        widget.setObjectName("TableSection")
        
        layout = QVBoxLayout(widget)
        layout.setSpacing(10)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create table
        self.table = TableWidget()
        self.table.setObjectName("ModulesTable")
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Name", "Type", "Rarity", "Level", "Equipped", "Favorited"
        ])
        
        # Set up table properties
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(TableWidget.SelectionMode.SingleSelection)
        
        # Set up headers
        header = self.table.horizontalHeader()
        if header:
            header.setStretchLastSection(False)
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Name column stretches
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        # Set custom delegate
        self.table.setItemDelegate(ModuleTableItemDelegate(self.table))
        
        layout.addWidget(self.table)
        
        return widget
        
    def _create_right_panel(self) -> QWidget:
        """Create the right panel with the module view widget."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(15)
        
        # Module view widget
        self.module_view = ModuleViewWidget()
        self.module_view.setObjectName("ModuleViewWidget")
        layout.addWidget(self.module_view)
        
        return panel
        
    def _setup_connections(self):
        """Set up signal connections."""
        # Filter connections
        self.search_edit.textChanged.connect(self._apply_filters)
        self.type_combo.currentTextChanged.connect(self._apply_filters)
        self.rarity_combo.currentTextChanged.connect(self._apply_filters)
        self.level_slider.valuesChanged.connect(self._apply_filters)  # QLabeledRangeSlider uses valuesChanged
        self.equipped_checkbox.toggled.connect(self._apply_filters)
        self.favorited_checkbox.toggled.connect(self._apply_filters)
        
        # Table connections
        self.table.itemSelectionChanged.connect(self._on_module_selected)
        
    def _get_module_type_icon(self, module_type: str) -> str:
        """Get the Unicode character for the module type."""
        icon_map = {
            "Core": "⯁",      # Black Diamond
            "Cannon": "⬤",     # Black Circle
            "Generator": "▲",  # Black Triangle
            "Armor": "■"       # Black Square
        }
        return icon_map.get(module_type, icon_map["Core"])
        
    def _create_type_item_with_icon(self, module_type: str) -> QTableWidgetItem:
        """Create a table item with module type icon and text."""
        # Get the Unicode character
        icon_char = self._get_module_type_icon(module_type)
        
        # Create item with icon character and text (more space between icon and text)
        item = QTableWidgetItem(f"{icon_char}  {module_type}")
        return item
        
    def _populate_type_combo_with_icons(self):
        """Populate the type combo box with icons."""
        # Add "All" option first (no icon)
        self.type_combo.addItem("All")
        
        # Add module types with icons
        module_types = ["Armor", "Cannon", "Generator", "Core"]
        for module_type in module_types:
            # Get the Unicode character
            icon_char = self._get_module_type_icon(module_type)
            self.type_combo.addItem(f"{icon_char}  {module_type}")
        
    def _on_generate_modules(self):
        """Generate modules using the ModuleSimulator and update the table."""
        try:
            # Generate 10 modules using simulate_multiple_pulls
            generated_modules = self.module_simulator.simulate_multiple_pulls(10)
            
            # Convert to GUI format and update
            self.sample_modules = []
            for module in generated_modules:
                module_dict = self._convert_generated_module_to_dict(module)
                self.sample_modules.append(module_dict)
            
            # Update filtered modules and table
            self.filtered_modules = self.sample_modules.copy()
            self._populate_table()
            
        except Exception as e:
            print(f"Error generating modules: {e}")
            # Fallback to empty list
            self.sample_modules = []
            self.filtered_modules = []
            self._populate_table()
        
    def _convert_generated_module_to_dict(self, generated_module: GeneratedModule) -> Dict[str, Any]:
        """Convert a GeneratedModule to the format expected by the GUI."""
        # Convert substats to SubstatDisplayInfo format
        substats = []
        for substat in generated_module.substats:
            substats.append(SubstatDisplayInfo(
                name=substat.name,
                value=substat.value,
                unit=substat.unit,
                rarity=substat.rarity.display_name,
                enum_id=substat.enum_id
            ))
        
        # Get unique effect text if available
        unique_effect_text = None
        if generated_module.unique_effect:
            # Get the value for this module's rarity
            effect_value = generated_module.unique_effect.values.get(generated_module.rarity)
            if effect_value is not None:
                # Replace {X} with the actual value and unit
                unit = generated_module.unique_effect.unit
                if unit:
                    # Format the value with unit and proper sign
                    if effect_value > 0:
                        # Add + prefix for positive values
                        if unit == '%':
                            formatted_value = f"+{effect_value}%"
                        elif unit in ['m', 's']:
                            formatted_value = f"+{effect_value}{unit}"
                        else:
                            formatted_value = f"+{effect_value} {unit}"
                    else:
                        # Negative values are already stored as negative, no prefix needed
                        if unit == '%':
                            formatted_value = f"{effect_value}%"
                        elif unit in ['m', 's']:
                            formatted_value = f"{effect_value}{unit}"
                        else:
                            formatted_value = f"{effect_value} {unit}"
                else:
                    # No unit, just format the number with proper sign
                    if effect_value > 0:
                        formatted_value = f"+{effect_value}"
                    else:
                        formatted_value = str(effect_value)
                
                # Replace {X} in the template with the formatted value
                unique_effect_text = generated_module.unique_effect.effect_template.replace("{X}", formatted_value)
            else:
                # Fallback to raw template if no value found for this rarity
                unique_effect_text = generated_module.unique_effect.effect_template
        
        return {
            "name": generated_module.name,
            "type": generated_module.module_type.value,
            "rarity": generated_module.rarity.display_name,
            "level": generated_module.level,
            "max_level": generated_module.max_level,
            "is_equipped": generated_module.is_equipped,
            "is_favorite": generated_module.is_favorite,
            "frame_name": generated_module.frame_pattern,
            "icon_name": generated_module.icon_name,
            "substats": substats,
            "unique_effect_text": unique_effect_text
        }
    

    def _populate_table(self):
        """Populate the table with module data."""
        self.table.setRowCount(len(self.filtered_modules))
        
        for row, module in enumerate(self.filtered_modules):
            # Name
            name_item = QTableWidgetItem(module["name"])
            name_item.setData(Qt.ItemDataRole.UserRole, module)
            self.table.setItem(row, 0, name_item)
            
            # Type with icon
            type_item = self._create_type_item_with_icon(module["type"])
            self.table.setItem(row, 1, type_item)
            
            # Rarity
            rarity_item = QTableWidgetItem(module["rarity"])
            self.table.setItem(row, 2, rarity_item)
            
            # Level
            level_item = QTableWidgetItem(str(module['level']))
            self.table.setItem(row, 3, level_item)
            
            # Equipped
            equipped_item = QTableWidgetItem("✓" if module["is_equipped"] else "")
            equipped_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 4, equipped_item)
            
            # Favorited
            favorited_item = QTableWidgetItem("★" if module["is_favorite"] else "")
            favorited_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 5, favorited_item)
            
    def _apply_filters(self):
        """Apply all active filters to the module list."""
        search_text = self.search_edit.text().lower()
        type_filter = self.type_combo.currentText()
        rarity_filter = self.rarity_combo.currentText()
        level_range = self.level_slider.value()  # Returns tuple (min, max)
        min_level, max_level = level_range
        equipped_only = self.equipped_checkbox.isChecked()
        favorited_only = self.favorited_checkbox.isChecked()
        
        # Filter modules
        self.filtered_modules = []
        for module in self.sample_modules:
            # Search filter
            if search_text and search_text not in module["name"].lower():
                continue
                
            # Type filter (handle icons in text)
            if type_filter != "All":
                # Remove icon from filter text for comparison
                filter_text = type_filter.strip()
                if module["type"] != filter_text:
                    continue
                
            # Rarity filter
            if rarity_filter != "All" and module["rarity"] != rarity_filter:
                continue
                
            # Level filter
            if module["level"] < min_level or module["level"] > max_level:
                continue
                
            # Equipped filter
            if equipped_only and not module["is_equipped"]:
                continue
                
            # Favorited filter
            if favorited_only and not module["is_favorite"]:
                continue
                
            self.filtered_modules.append(module)
            
        # Update table
        self._populate_table()
        
    def _on_module_selected(self):
        """Handle module selection in the table."""
        current_row = self.table.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_modules):
            module_data = self.filtered_modules[current_row]
            
            # Convert to ModuleDisplayData format
            display_data = ModuleDisplayData(
                name=module_data["name"],
                module_type=module_data["type"],
                rarity=module_data["rarity"].lower(),
                level=module_data["level"],
                max_level=module_data["max_level"],
                is_equipped=module_data["is_equipped"],
                is_favorite=module_data["is_favorite"],
                frame_name=module_data["frame_name"],
                icon_name=module_data["icon_name"],
                substats=module_data["substats"],
                unique_effect_text=module_data.get("unique_effect_text")
            )
            
            # Update module view
            self.module_view.set_module_data(display_data)
            
            # Emit signal
            self.module_selected.emit(module_data)
            
    def update_modules_data(self, modules: List[Dict[str, Any]]):
        """Update the modules data from external source."""
        self.sample_modules = modules
        self._apply_filters()
        
    def clear_selection(self):
        """Clear the current table selection."""
        self.table.clearSelection()
        # Create empty module data instead of None
        empty_data = ModuleDisplayData(
            name="",
            module_type="",
            rarity="",
            level=0,
            max_level=200,
            is_equipped=False,
            is_favorite=False,
            frame_name="",
            icon_name="",
            substats=[]
        )
        self.module_view.set_module_data(empty_data) 