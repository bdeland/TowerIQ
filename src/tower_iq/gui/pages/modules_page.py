"""
TowerIQ Modules Page

This module provides the modules page widget for the application.
"""
import os
from typing import List, Optional, Dict, Any, cast
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QHeaderView, QTableWidgetItem, QSizePolicy, QStackedWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QRect, QPoint
from PyQt6.QtGui import QColor, QPixmap, QPainter, QIcon, QImage
from qfluentwidgets import (
    TableWidget, TableItemDelegate, SearchLineEdit, ComboBox, 
    BodyLabel, CaptionLabel, CardWidget, CheckBox, PushButton
)
from qfluentwidgets.components.navigation.pivot import Pivot
from qfluentwidgets import FluentIcon
from superqt import QLabeledRangeSlider
from PIL import Image

from ..utils.content_page import ContentPage
from ..utils.module_view_widget import ModuleViewWidget, ModuleDisplayData, SubstatDisplayInfo
from ..stylesheets.stylesheets import RARITY_COLORS

# Import ModuleSimulator and related classes
from ...core.game_data.modules.module_simulator import ModuleSimulator, GeneratedModule
from ...core.game_data.modules.game_data_manager import GameDataManager


class ModuleTableItemDelegate(TableItemDelegate):
    """Custom delegate for module table items with theme-aware styling and module icons.

    Stores the table's icon size once to avoid dynamic QObject attribute lookups that
    confuse static linters, and sets decoration alignment so icons are centered
    vertically and left-aligned.
    """

    def __init__(self, table: TableWidget):  # type: ignore[name-defined]
        super().__init__(table)
        # Cache the icon size at construction time
        self._decoration_size: QSize = table.iconSize()

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        
        # For the Name column, ensure the icon is sized and aligned correctly.
        if index.column() == 0:
            option.decorationSize = self._decoration_size
            # Ensure proper vertical centering and left alignment
            option.decorationAlignment = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
        
        # Apply custom styling for the Rarity column.
        if index.column() == 2:  # Rarity column
            rarity = index.data()
            if rarity:
                normalized_key = (
                    str(rarity).lower().replace("+", "plus").replace(" ", "").strip()
                )
                color_hex = RARITY_COLORS.get(normalized_key, RARITY_COLORS["common"]["primary"])
                if isinstance(color_hex, dict):
                    color_hex = color_hex.get("primary", RARITY_COLORS["common"]["primary"])
                option.palette.setColor(option.palette.ColorRole.Text, QColor(color_hex))
                option.palette.setColor(option.palette.ColorRole.HighlightedText, QColor(color_hex))


class ModulesTabWidget(QWidget):
    """
    The main modules tab widget containing the original modules functionality.
    """
    
    # Signals
    module_selected = pyqtSignal(dict)  # Emitted when a module is selected in the table
    
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        
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
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Main layout with left and right panels
        main_layout = QHBoxLayout()
        main_layout.setSpacing(20)
        
        # Left panel: Filters and Table
        left_panel = self._create_left_panel()
        main_layout.addWidget(left_panel, 2)  # Takes 2/3 of the space
        
        # Right panel: Module View
        right_panel = self._create_right_panel()
        main_layout.addWidget(right_panel, 1)  # Takes 1/3 of the space
        
        layout.addLayout(main_layout)
        
    def _create_left_panel(self) -> QWidget:
        """Create the left panel with filters and table."""
        panel = QWidget()
        panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
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
        
        # Set size policy to expand and fill available space
        widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
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
        
        # Set size policy to expand and fill available space
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        
        # Set a fixed row height and icon size for consistent layout
        vh = self.table.verticalHeader()
        if vh is not None:
            vh.setDefaultSectionSize(40)  # Increased height for better icon spacing
        self.table.setIconSize(QSize(32, 32))

        # Set up headers
        header = self.table.horizontalHeader()
        if header:
            header.setStretchLastSection(True)  # Make last column stretch to fill remaining space
            # Set fixed widths for all columns except the last one
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Name
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Type
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Rarity
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Level
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Equipped
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Favorited
            
        # Set custom delegate for styling
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
            "unique_effect_text": unique_effect_text,
            # New: formatted main effect text based on module type
            "main_effect_text": self._format_main_effect_text(generated_module)
        }

    def _format_main_effect_text(self, generated_module: GeneratedModule) -> str:
        """Create the display text for the module's main effect.
        For sample generation, the multiplier is fixed at x1.105 as requested.
        """
        # Determine the primary stat name by module type
        type_to_stat = {
            "Generator": "Coin Bonus",
            "Cannon": "Tower Damage",
            "Armor": "Tower Health",
            "Core": "Ultimate Weapon Damage",
        }
        stat_name = type_to_stat.get(generated_module.module_type.value, "")
        # Use module property if present, otherwise the requested fixed sample value
        try:
            multiplier = getattr(generated_module, "main_effect_multiplier", 1.105)
        except Exception:
            multiplier = 1.105
        return f"x{multiplier} {stat_name}" if stat_name else f"x{multiplier}"
    

    def _populate_table(self):
        """Populate the table with module data."""
        self.table.setRowCount(len(self.filtered_modules))
        
        for row, module in enumerate(self.filtered_modules):
            # Name - text + decoration icon (composite of frame + icon)
            name_item = QTableWidgetItem(module["name"])
            # attach full module dict for selection handling
            name_item.setData(Qt.ItemDataRole.UserRole, module)
            
            try:
                sprites_path = os.path.join(os.path.dirname(__file__), "../../../..", "resources", "assets", "sprites")
                sprites_path = os.path.normpath(sprites_path)

                # Final icon size in table
                icon_size = self.table.iconSize()  # QSize(width, height)

                # Load original images using PIL
                frame_path = os.path.join(sprites_path, f"{module['frame_name']}.png")
                icon_path = os.path.join(sprites_path, f"{module['icon_name']}.png")

                frame_img = Image.open(frame_path).convert("RGBA")
                icon_img = Image.open(icon_path).convert("RGBA")

                # Resize using high-quality Lanczos
                frame_resized = frame_img.resize((icon_size.width(), icon_size.height()), Image.Resampling.LANCZOS)

                margin = int(icon_size.width() * 0.22)
                icon_resized = icon_img.resize(
                    (icon_size.width() - 2 * margin, icon_size.height() - 2 * margin),
                    Image.Resampling.LANCZOS
                )

                # Paste icon onto frame (centered)
                frame_resized.paste(icon_resized, (margin, margin), icon_resized)

                # Convert PIL image to QPixmap
                data = frame_resized.tobytes("raw", "RGBA")
                qimage = QImage(data, frame_resized.width, frame_resized.height, QImage.Format.Format_RGBA8888)
                qpixmap = QPixmap.fromImage(qimage)

                name_item.setIcon(QIcon(qpixmap))

            except Exception as e:
                print(f"Error creating icon: {e}")

            
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
                filter_text = type_filter.strip().split("  ")[-1]
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
                unique_effect_text=module_data.get("unique_effect_text"),
                main_effect_text=module_data.get("main_effect_text")
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


class AnalysisTabWidget(QWidget):
    """
    The analysis tab widget for module analysis and statistics.
    """
    
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._init_ui()
        
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header_label = BodyLabel("Module Analysis")
        header_label.setObjectName("AnalysisHeader")
        layout.addWidget(header_label)
        
        # Description
        description_label = CaptionLabel("Analyze your modules for optimal builds and performance insights.")
        layout.addWidget(description_label)
        
        # Placeholder content
        placeholder = CardWidget()
        placeholder_layout = QVBoxLayout(placeholder)
        placeholder_layout.setContentsMargins(24, 24, 24, 24)
        
        placeholder_label = BodyLabel("Module Analysis features coming soon!")
        placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_layout.addWidget(placeholder_label)
        
        layout.addWidget(placeholder)
        layout.addStretch()


class ModulesPage(ContentPage):
    """
    The modules page of the application with tabbed interface.

    Features:
    - Tabbed interface with Modules and Analysis tabs
    - Filterable and sortable module table
    - Search functionality
    - Type and rarity filters
    - Level range slider
    - Equipped and favorited checkboxes
    - Module preview widget
    """
    
    # Signals
    module_selected = pyqtSignal(dict)  # Emitted when a module is selected in the table
    category_navigated = pyqtSignal(str)  # Emits the category name
    
    def __init__(self, parent: QWidget | None = None):
        super().__init__(
            title="Modules",
            description="Manage and analyze your game modules",
            parent=parent
        )
        
        # Initialize UI
        self._init_ui()
        
    def _init_ui(self):
        """Initialize the user interface."""
        content_container = self.get_content_container()
        
        # Main layout
        layout = QVBoxLayout(content_container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)
        
        # Create the Pivot and add it to the container
        self.pivot = self._create_pivot()
        layout.addWidget(self.pivot, 0)  # Add with stretch factor 0 to prevent expansion
        
        # Create the content area with stacked widget
        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("modules_content_stack")
        layout.addWidget(self.content_stack, 1)  # Add with stretch factor 1 to take remaining space
        
        # Create content widgets for each pivot
        self._create_pivot_content()
        
    def _create_pivot(self) -> Pivot:
        """Create the Pivot with modules category navigation."""
        pivot = Pivot()
        pivot.setObjectName("modules_pivot")
        
        # Define modules categories
        categories = [
            {
                'name': 'modules',
                'title': 'Modules',
                'description': 'Browse and manage your modules'
            },
            {
                'name': 'analysis',
                'title': 'Analysis',
                'description': 'Analyze module performance and statistics'
            }
        ]
        
        # Add items to the Pivot
        for category in categories:
            pivot.addItem(
                routeKey=category['name'],
                text=category['title']
            )
        
        # Calculate and set minimum width for each pivot item based on text content
        self._set_pivot_item_widths(pivot)
        
        # Connect the currentItemChanged signal to handle pivot changes
        pivot.currentItemChanged.connect(self._on_pivot_changed)
        
        return pivot
        
    def _create_pivot_content(self):
        """Create content widgets for each pivot."""
        # Create content widgets for each category
        self.modules_tab = ModulesTabWidget(self)
        self.analysis_tab = AnalysisTabWidget(self)
        
        # Connect signals from modules tab
        self.modules_tab.module_selected.connect(self.module_selected.emit)
        
        # Add content widgets to the stacked widget
        self.content_stack.addWidget(self.modules_tab)
        self.content_stack.addWidget(self.analysis_tab)
        
        # Set the first pivot as active
        if self.pivot.items:
            first_key = list(self.pivot.items.keys())[0]
            self.pivot.setCurrentItem(first_key)
        
    def _on_pivot_changed(self, route_key: str):
        """Handle pivot change event."""
        # Find the index of the content widget for this route key
        content_widgets = {
            'modules': 0,
            'analysis': 1
        }
        
        if route_key in content_widgets:
            index = content_widgets[route_key]
            if index < self.content_stack.count():
                # Switch to the corresponding content widget
                self.content_stack.setCurrentIndex(index)
                
                # Emit the category navigation signal
                self.category_navigated.emit(route_key)
    
    def _set_pivot_item_widths(self, pivot: Pivot):
        """Calculate and set minimum width for each pivot item based on text content."""
        from PyQt6.QtGui import QFontMetrics
        from PyQt6.QtCore import QSize
        
        # Get the font metrics to calculate text width
        font = pivot.font()
        font_metrics = QFontMetrics(font)
        
        # Parse the CSS to get actual padding values
        from ..stylesheets import PIVOT_QSS
        import re
        padding_match = re.search(r'padding:\s*(\d+)px\s+(\d+)px', PIVOT_QSS)
        if padding_match:
            top_bottom_padding = int(padding_match.group(1))
            left_right_padding = int(padding_match.group(2))
            total_padding = left_right_padding * 2  # Left + right padding
        else:
            # Fallback if parsing fails
            total_padding = 40
        
        # Set individual minimum width for each pivot item based on its text content
        for route_key, item in pivot.items.items():
            text_width = font_metrics.horizontalAdvance(item.text())
            min_width = text_width + total_padding
            item.setMinimumWidth(min_width)
        
        # Configure the layout to distribute space evenly
        if hasattr(pivot, 'hBoxLayout') and pivot.hBoxLayout:
            # Set stretch factors to make all items equal width
            for route_key, item in pivot.items.items():
                pivot.hBoxLayout.setStretch(pivot.hBoxLayout.indexOf(item), 1)
    
    def get_current_category(self) -> str:
        """Get the currently active category."""
        return self.pivot.currentRouteKey() or ""
    
    def update_modules_data(self, modules: List[Dict[str, Any]]):
        """Update the modules data from external source."""
        self.modules_tab.update_modules_data(modules)
        
    def clear_selection(self):
        """Clear the current table selection."""
        self.modules_tab.clear_selection()