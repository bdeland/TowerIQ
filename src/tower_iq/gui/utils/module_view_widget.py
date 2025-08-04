"""
TowerIQ Module View Widget

A reusable widget to display module information in a card format.
Follows the application's centralized styling approach.
"""

import yaml
import os
from typing import Dict, List, Optional, Any
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QPixmap, QPainter
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel

from qfluentwidgets import ProgressBar, TitleLabel, CaptionLabel, BodyLabel
from ..stylesheets.stylesheets import get_themed_stylesheet


class SubstatRowWidget(QWidget):
    """Widget representing a single substat row with rarity pill and description."""
    
    def __init__(self, substat_text: str, rarity: str, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("SubstatRow")
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(10)

        # Rarity Pill - using BodyLabel for theme consistency
        self.rarity_pill = BodyLabel(rarity.upper())
        self.rarity_pill.setObjectName("RarityPill")
        self.rarity_pill.setProperty("rarity", rarity.lower())
        
        # Effect Text - using BodyLabel for theme consistency
        self.effect_label = BodyLabel(substat_text)
        self.effect_label.setObjectName("SubstatText")

        layout.addWidget(self.rarity_pill)
        layout.addWidget(self.effect_label)
        layout.addStretch()


class LockedSubstatRowWidget(QWidget):
    """Widget representing a locked substat slot."""
    
    def __init__(self, unlock_level: int, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("LockedSubstatRow")
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        
        self.label = BodyLabel(f"Unlocks at Lv. {unlock_level}")
        self.label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.label.setObjectName("LockedText")
        
        layout.addWidget(self.label)


class ModuleViewWidget(QWidget):
    # Favorite icon positioning offsets for different module types
    FAVORITE_ICON_POSITIONS = {
        'Armor': {'x': 22, 'y': 93},
        'Cannon': {'x': 22, 'y': 93}, 
        'Generator': {'x': 22, 'y': 93},
        'Core': {'x': 22, 'y': 93}
    }
    """
    A reusable widget to display a single module's details.
    
    Features:
    - Data-driven UI based on Module object
    - Centralized styling via stylesheets.py
    - Proper frame and icon combination
    - Theme-aware components using QFluentWidgets
    """
    
    def __init__(self, module=None, frame_name=None, icon_name=None, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("ModuleView")
        self.module = None
        self.frame_name = frame_name
        self.icon_name = icon_name
        self.lookup_data = self._load_lookup_data()
        
        # Initialize UI components
        self._init_components()
        self._init_layout()
        
        # Set module data if provided
        if module:
            self.set_module(module)
    
    def _load_lookup_data(self) -> Dict[str, Any]:
        """Load the module lookup data from YAML file."""
        try:
            lookup_path = os.path.join(os.path.dirname(__file__), "../../../..", "resources", "lookups", "module_lookups.yaml")
            lookup_path = os.path.normpath(lookup_path)
            
            with open(lookup_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load lookup data: {e}")
            return {}
    
    def _init_components(self):
        """Initialize all UI components."""
        # Module info
        self.name_label = TitleLabel()
        self.name_label.setObjectName("ModuleName")
        
        self.rarity_label = BodyLabel()
        self.rarity_label.setObjectName("ModuleRarity")
        
        self.main_stat_label = BodyLabel()
        self.main_stat_label.setObjectName("ModuleMainStat")
        
        # Icon container (holds frame, icon, and favorite overlay)
        self.icon_container = QWidget()
        self.icon_container.setFixedSize(128, 128)
        self.icon_container.setObjectName("ModuleIconContainer")
        
        # Main icon label
        self.icon_label = QLabel(self.icon_container)
        self.icon_label.setObjectName("ModuleIcon")
        self.icon_label.setFixedSize(128, 128)
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Favorite overlay label
        self.favorite_label = QLabel(self.icon_container)
        self.favorite_label.setObjectName("ModuleFavorite")
        self.favorite_label.setFixedSize(25, 25)
        self.favorite_label.hide()  # Hidden by default
        
        # Level information
        self.level_label = BodyLabel()
        self.level_label.setObjectName("ModuleLevel")
        
        self.level_progress_bar = ProgressBar()
        self.level_progress_bar.setObjectName("ModuleLevelBar")
        
        # Effects section
        self.effects_label = BodyLabel("Effects")
        self.effects_label.setObjectName("EffectsTitle")
        
        # Container for substats
        self.substats_widget = QWidget()
        self.substats_layout = QVBoxLayout(self.substats_widget)
        self.substats_layout.setContentsMargins(0, 0, 0, 0)
        self.substats_layout.setSpacing(5)
        
        # Unique Effect section
        self.unique_effect_label = BodyLabel("Unique Effect")
        self.unique_effect_label.setObjectName("UniqueEffectTitle")
        
        self.unique_effect_text = BodyLabel()
        self.unique_effect_text.setObjectName("UniqueEffectText")
        self.unique_effect_text.setWordWrap(True)
    
    def _init_layout(self):
        """Initialize the layout structure."""
        main_layout = QVBoxLayout(self)
        main_layout.setObjectName("ModuleMainLayout")
        main_layout.setContentsMargins(20, 15, 20, 20)
        main_layout.setSpacing(15)

        # 1. Icon & Name section
        info_layout = QHBoxLayout()
        info_layout.setSpacing(20)
        
        # Icon container on the left
        info_layout.addWidget(self.icon_container)
        
        # Rarity, name and main stat on the right
        name_layout = QVBoxLayout()
        name_layout.addStretch(1)
        
        # Rarity first
        name_layout.addWidget(self.rarity_label)
        
        # Name second
        name_layout.addWidget(self.name_label)
        
        # Main stat third
        name_layout.addWidget(self.main_stat_label)
        name_layout.addStretch(1)
        info_layout.addLayout(name_layout)
        
        main_layout.addLayout(info_layout)

        # 3. Level section
        level_layout = QVBoxLayout()
        level_layout.setSpacing(5)
        level_layout.addWidget(self.level_label)
        level_layout.addWidget(self.level_progress_bar)
        main_layout.addLayout(level_layout)

        # 4. Effects section
        main_layout.addWidget(self.effects_label)
        main_layout.addWidget(self.substats_widget)
        
        # 5. Unique Effect section
        main_layout.addWidget(self.unique_effect_label)
        main_layout.addWidget(self.unique_effect_text)
        main_layout.addStretch()
    
    def set_module(self, module):
        """Updates the widget to display data from the given module object."""
        self.module = module
        
        if not module:
            return
        
        # Update rarity and styling
        self._update_rarity()
        
        # Update icon and name
        self._update_icon()
        self.name_label.setText(module.name)
        
        # Update main stat (simplified)
        self._update_main_stat()
        
        # Update unique effect
        self._update_unique_effect()
        
        # Update level information
        self._update_level()
        
        # Update substats
        self._update_substats()
    
    def _get_display_rarity(self, rarity: str) -> str:
        """Convert rarity to display format."""
        display_map = {
            'common': 'COMMON',
            'rare': 'RARE   ',
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
    
    def _update_rarity(self):
        """Update rarity display and apply rarity-based styling."""
        if not self.module:
            return
            
        rarity = self.module.rarity
        display_rarity = self._get_display_rarity(rarity)
        self.rarity_label.setText(display_rarity)  # Removed parentheses
        
        # Apply rarity property for styling
        self.setProperty("module_rarity", rarity.lower())
        self.rarity_label.setProperty("rarity", rarity.lower())
        self.name_label.setProperty("rarity", rarity.lower())
        
        # Force style update
        style = self.style()
        if style:
            style.unpolish(self)
            style.polish(self)
        rarity_style = self.rarity_label.style()
        if rarity_style:
            rarity_style.unpolish(self.rarity_label)
            rarity_style.polish(self.rarity_label)
        name_style = self.name_label.style()
        if name_style:
            name_style.unpolish(self.name_label)
            name_style.polish(self.name_label)
    
    def _update_icon(self):
        """Load and combine the frame and icon images using provided filenames."""
        if not self.module:
            return
            
        # Get base sprites path
        sprites_path = os.path.join(os.path.dirname(__file__), "../../../..", "resources", "assets", "sprites")
        sprites_path = os.path.normpath(sprites_path)
        
        # Construct full paths from filenames
        frame_path = os.path.join(sprites_path, f"{self.frame_name}.png") if self.frame_name else None
        icon_path = os.path.join(sprites_path, f"{self.icon_name}.png") if self.icon_name else None
        
        # Load frame
        frame_pixmap = QPixmap(frame_path) if frame_path else QPixmap()
        
        if frame_pixmap.isNull():
            # Fallback: display placeholder
            self.icon_label.setText("?")
            self.icon_label.setStyleSheet("font-size: 48px; color: #666666;")
            return
        
        # Load icon
        icon_pixmap = QPixmap(icon_path) if icon_path else QPixmap()
        
        # Create combined image
        combined_pixmap = QPixmap(frame_pixmap.size())
        combined_pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(combined_pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw frame first
        painter.drawPixmap(0, 0, frame_pixmap)
        
        # Draw icon on top if available
        if not icon_pixmap.isNull():
            # Center the icon within the frame
            x = (frame_pixmap.width() - icon_pixmap.width()) // 2
            y = (frame_pixmap.height() - icon_pixmap.height()) // 2
            painter.drawPixmap(x, y, icon_pixmap)
        
        painter.end()
        
        # Scale and set the combined image with better quality
        # Use device pixel ratio for better quality on high-DPI displays
        target_size = self.icon_label.size()
        device_pixel_ratio = self.devicePixelRatio()
        
        # Calculate size accounting for device pixel ratio
        scaled_size = QSize(
            int(target_size.width() * device_pixel_ratio),
            int(target_size.height() * device_pixel_ratio)
        )
        
        scaled_pixmap = combined_pixmap.scaled(
            scaled_size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation
        )
        
        # Set the device pixel ratio on the pixmap
        scaled_pixmap.setDevicePixelRatio(device_pixel_ratio)
        
        self.icon_label.setPixmap(scaled_pixmap)
        
        # Update favorite overlay if needed
        self._update_favorite_overlay()
    
    def _update_main_stat(self):
        """Update the main stat description (simplified version)."""
        if not self.module:
            return
            
        # Simple main stat display - just show level and type
        main_stat_text = f"Level {self.module.level} {self.module.module_type}"
        self.main_stat_label.setText(main_stat_text)
    
    def _update_unique_effect(self):
        """Update the unique effect description from unique effects."""
        if not self.module or not self.lookup_data:
            return
            
        # Look for unique effect based on module name
        unique_effects = self.lookup_data.get('unique_effects', {})
        
        unique_effect_text = ""
        for effect_id, effect_data in unique_effects.items():
            if effect_data.get('name') == self.module.name:
                effect_template = effect_data.get('effect', '')
                values = effect_data.get('values', {})
                unit = effect_data.get('unit', '')
                
                # Get value for current rarity
                base_rarity = self._get_base_rarity(self.module.rarity)
                value = values.get(base_rarity, '')
                
                if value and effect_template:
                    # Replace {X} with actual value and add unit
                    value_str = f"{value}{unit}" if unit else str(value)
                    unique_effect_text = effect_template.replace('{X}', value_str)
                break
        
        if not unique_effect_text:
            unique_effect_text = "No unique effect"
        
        self.unique_effect_text.setText(unique_effect_text)
    
    def _update_favorite_overlay(self):
        """Update the favorite star overlay if module is favorited."""
        if not self.module:
            return
            
        if self.module.is_favorite:
            # Load favorite icon
            sprites_path = os.path.join(os.path.dirname(__file__), "../../../..", "resources", "assets", "sprites")
            sprites_path = os.path.normpath(sprites_path)
            favorite_path = os.path.join(sprites_path, "favorite.png")
            
            if os.path.exists(favorite_path):
                favorite_pixmap = QPixmap(favorite_path)
                if not favorite_pixmap.isNull():
                    # Scale favorite icon with better quality
                    target_size = self.favorite_label.size()
                    device_pixel_ratio = self.devicePixelRatio()
                    
                    # Calculate size accounting for device pixel ratio
                    scaled_size = QSize(
                        int(target_size.width() * device_pixel_ratio),
                        int(target_size.height() * device_pixel_ratio)
                    )
                    
                    scaled_favorite = favorite_pixmap.scaled(
                        scaled_size,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation
                    )
                    
                    # Set the device pixel ratio on the pixmap
                    scaled_favorite.setDevicePixelRatio(device_pixel_ratio)
                    self.favorite_label.setPixmap(scaled_favorite)
                    
                    # Position the favorite icon based on module type
                    module_type = self.module.module_type
                    pos = self.FAVORITE_ICON_POSITIONS.get(module_type, {'x': 85, 'y': 15})
                    self.favorite_label.move(pos['x'], pos['y'])
                    self.favorite_label.show()
                    return
        else:
            self.favorite_label.hide()
    
    def _update_level(self):
        """Update level display and progress bar."""
        if not self.module or not self.lookup_data:
            return
            
        max_levels = self.lookup_data.get('max_module_level', {})
        max_level = max_levels.get(self.module.rarity, 100)
        
        self.level_label.setText(f"Lv. {self.module.level} / {max_level}")
        
        # Calculate progress percentage
        progress = min(100, int((self.module.level / max_level) * 100))
        self.level_progress_bar.setValue(progress)
    
    def _update_substats(self):
        """Update the substats display."""
        # Clear existing substat widgets
        while self.substats_layout.count():
            child = self.substats_layout.takeAt(0)
            if child:
                widget = child.widget()
                if widget is not None:
                    widget.deleteLater()
        
        if not self.module or not self.lookup_data:
            return
        
        substat_values = self.lookup_data.get('substat_values', {})
        
        # Add current substats
        for i, substat_id in enumerate(self.module.substat_enum_ids):
            substat_data = substat_values.get(substat_id)
            if substat_data:
                # Get the individual substat rarity
                substat_rarity = self.module.substat_rarities[i] if i < len(self.module.substat_rarities) else self.module.rarity
                base_rarity = self._get_base_rarity(substat_rarity)
                values = substat_data.get('values', {})
                value = values.get(base_rarity)
                
                if value is not None:
                    name = substat_data.get('name', '').replace('_', ' ').title()
                    unit = substat_data.get('unit', '')
                    
                    # Format the substat text
                    if unit:
                        if unit == '%':
                            substat_text = f"+{value}% {name}"
                        elif unit in ['m', 's']:
                            if value < 0:
                                substat_text = f"{value}{unit} {name}"
                            else:
                                substat_text = f"+{value}{unit} {name}"
                        elif unit == 'x':
                            substat_text = f"x{value} {name}"
                        else:
                            substat_text = f"+{value} {name} ({unit})"
                    else:
                        substat_text = f"+{value} {name}"
                    
                    row = SubstatRowWidget(substat_text, base_rarity)
                    self.substats_layout.addWidget(row)
        
        # Add locked slots based on rarity
        # Only show locked slots if the module hasn't reached the level to unlock them
        current_substats = len(self.module.substat_enum_ids)
        max_substats = self._get_max_substats_for_rarity(self.module.rarity)
        
        for i in range(current_substats, max_substats):
            # Fixed unlock levels: slot 3=41, slot 4=101, slot 5=141, slot 6=161
            slot_number = i + 1  # Convert 0-based index to 1-based slot number
            unlock_levels = {
                3: 41,   # Slot 3 unlocks at level 41
                4: 101,  # Slot 4 unlocks at level 101
                5: 141,  # Slot 5 unlocks at level 141
                6: 161   # Slot 6 unlocks at level 161
            }
            unlock_level = unlock_levels.get(slot_number, 200)  # Default fallback
            
            # Only show locked slot if module level is below unlock level
            if self.module.level < unlock_level:
                locked_row = LockedSubstatRowWidget(unlock_level)
                self.substats_layout.addWidget(locked_row)
    
    def _get_base_rarity(self, rarity: str) -> str:
        """Convert full rarity name to base rarity for lookup."""
        rarity_map = {
            'common': 'Common',
            'rare': 'Rare',
            'rareplus': 'Rare',
            'epic': 'Epic',
            'epicplus': 'Epic',
            'legendary': 'Legendary',
            'legendaryplus': 'Legendary',
            'mythic': 'Mythic',
            'mythicplus': 'Mythic',
            'ancestral': 'Ancestral'
        }
        return rarity_map.get(rarity.lower(), 'Common')
    
    def _get_max_substats_for_rarity(self, rarity: str) -> int:
        """Get maximum number of substats for a given rarity."""
        # Simplified logic - in reality this might be more complex
        base_rarity = self._get_base_rarity(rarity)
        max_substats = {
            'Common': 1,
            'Rare': 4,
            'Epic': 6,
            'Legendary': 6,
            'Mythic': 6,
            'Ancestral': 6
        }
        return max_substats.get(base_rarity, 2)