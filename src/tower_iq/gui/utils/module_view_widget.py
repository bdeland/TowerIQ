"""
TowerIQ Module View Widget

A reusable widget to display module information in a card format.
Follows the application's centralized styling approach.
"""

import os
from typing import Dict, List, Optional, Any
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QPixmap, QPainter
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel
from dataclasses import dataclass

from qfluentwidgets import ProgressBar, TitleLabel, CaptionLabel, BodyLabel
from ..stylesheets.stylesheets import get_themed_stylesheet


@dataclass
class SubstatDisplayInfo:
    """Information needed to display a substat."""
    name: str
    value: float
    unit: str
    rarity: str
    enum_id: int


@dataclass
class ModuleDisplayData:
    """Complete data needed to display a module."""
    name: str
    module_type: str
    rarity: str
    level: int
    max_level: int
    is_equipped: bool
    is_favorite: bool
    frame_name: str
    icon_name: str
    substats: List[SubstatDisplayInfo]
    unique_effect_text: Optional[str] = None


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
    - Data-driven UI based on ModuleDisplayData object
    - Centralized styling via stylesheets.py
    - Proper frame and icon combination
    - Theme-aware components using QFluentWidgets
    - No knowledge of data sources - pure display component
    """
    
    def __init__(self, module_data: Optional[ModuleDisplayData] = None, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("ModuleView")
        self.module_data = None
        
        # Initialize UI components
        self._init_components()
        self._init_layout()
        
        # Set module data if provided
        if module_data:
            self.set_module_data(module_data)
    
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
        
        info_layout.addStretch()
        main_layout.addLayout(info_layout)
        
        # 2. Level section
        level_layout = QVBoxLayout()
        level_layout.addWidget(self.level_label)
        level_layout.addWidget(self.level_progress_bar)
        main_layout.addLayout(level_layout)
        
        # 3. Effects section
        main_layout.addWidget(self.effects_label)
        main_layout.addWidget(self.substats_widget)
        
        # 4. Unique Effect section (if applicable)
        main_layout.addWidget(self.unique_effect_label)
        main_layout.addWidget(self.unique_effect_text)
        
        main_layout.addStretch()
    
    def set_module_data(self, module_data: ModuleDisplayData):
        """Set the module data to display."""
        self.module_data = module_data
        self._update_display()
    
    def _update_display(self):
        """Update all display elements with current module data."""
        if not self.module_data:
            return
            
        self._update_name()
        self._update_rarity()
        self._update_icon()
        self._update_level()
        self._update_substats()
        self._update_unique_effect()
        self._update_favorite_overlay()
    
    def _update_name(self):
        """Update the module name display."""
        if not self.module_data:
            return
        self.name_label.setText(self.module_data.name)
    
    def _update_rarity(self):
        """Update the rarity display."""
        if not self.module_data:
            return
            
        display_rarity = self._get_display_rarity(self.module_data.rarity)
        self.rarity_label.setText(display_rarity)
    
    def _get_display_rarity(self, rarity: str) -> str:
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
    
    def _update_icon(self):
        """Update the module icon display with frame and icon composition."""
        if not self.module_data:
            return
            
        # Load and display the module icon with frame
        sprites_path = os.path.join(os.path.dirname(__file__), "../../../..", "resources", "assets", "sprites")
        sprites_path = os.path.normpath(sprites_path)
        
        # Create a composite pixmap for frame + icon
        composite_pixmap = QPixmap(128, 128)
        composite_pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(composite_pixmap)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        
        # Load and draw the frame first (background)
        frame_path = os.path.join(sprites_path, f"{self.module_data.frame_name}.png")
        if os.path.exists(frame_path):
            frame_pixmap = QPixmap(frame_path)
            if not frame_pixmap.isNull():
                # Scale frame to fit
                scaled_frame = frame_pixmap.scaled(
                    128, 128,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                painter.drawPixmap(0, 0, scaled_frame)
        
        # Load and draw the icon on top
        icon_path = os.path.join(sprites_path, f"{self.module_data.icon_name}.png")
        if os.path.exists(icon_path):
            icon_pixmap = QPixmap(icon_path)
            if not icon_pixmap.isNull():
                # Scale icon to fit within frame (slightly smaller)
                scaled_icon = icon_pixmap.scaled(
                    96, 96,  # Slightly smaller than frame
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                # Center the icon
                x = (128 - scaled_icon.width()) // 2
                y = (128 - scaled_icon.height()) // 2
                painter.drawPixmap(x, y, scaled_icon)
        
        painter.end()
        
        # Set the composite pixmap to the icon label
        if not composite_pixmap.isNull():
            self.icon_label.setPixmap(composite_pixmap)
        else:
            # Fallback: show text if no images found
            self.icon_label.setText(self.module_data.name[:10])
    
    def _update_level(self):
        """Update level display and progress bar."""
        if not self.module_data:
            return
            
        self.level_label.setText(f"Lv. {self.module_data.level} / {self.module_data.max_level}")
        
        # Calculate progress percentage
        progress = min(100, int((self.module_data.level / self.module_data.max_level) * 100))
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
        
        if not self.module_data:
            return
        
        # Add current substats
        for substat in self.module_data.substats:
            # Format the substat text
            if substat.unit:
                if substat.unit == '%':
                    substat_text = f"+{substat.value}% {substat.name}"
                elif substat.unit in ['m', 's']:
                    if substat.value < 0:
                        substat_text = f"{substat.value}{substat.unit} {substat.name}"
                    else:
                        substat_text = f"+{substat.value}{substat.unit} {substat.name}"
                elif substat.unit == 'x':
                    substat_text = f"+{substat.value}{substat.unit} {substat.name}"
                else:
                    substat_text = f"+{substat.value} {substat.name} ({substat.unit})"
            else:
                substat_text = f"+{substat.value} {substat.name}"
            
            row = SubstatRowWidget(substat_text, substat.rarity)
            self.substats_layout.addWidget(row)
        
        # Add locked slots based on current substat count
        current_substats = len(self.module_data.substats)
        max_substats = self._get_max_substats_for_rarity(self.module_data.rarity)
        
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
            if self.module_data.level < unlock_level:
                locked_row = LockedSubstatRowWidget(unlock_level)
                self.substats_layout.addWidget(locked_row)
    
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
    
    def _update_unique_effect(self):
        """Update the unique effect display."""
        if not self.module_data:
            return
            
        if self.module_data.unique_effect_text:
            self.unique_effect_text.setText(self.module_data.unique_effect_text)
            self.unique_effect_label.show()
            self.unique_effect_text.show()
        else:
            self.unique_effect_label.hide()
            self.unique_effect_text.hide()
    
    def _update_favorite_overlay(self):
        """Update the favorite star overlay if module is favorited."""
        if not self.module_data:
            return
            
        if self.module_data.is_favorite:
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
                    module_type = self.module_data.module_type
                    pos = self.FAVORITE_ICON_POSITIONS.get(module_type, {'x': 85, 'y': 15})
                    self.favorite_label.move(pos['x'], pos['y'])
                    self.favorite_label.show()
                    return
        else:
            self.favorite_label.hide()