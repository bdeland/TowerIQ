"""
Icon Quality Test Window

This script creates a test window to compare icon quality between PyQt and PIL approaches.
Displays icons and frames at various sizes for visual inspection.
"""

import sys
import os
from typing import List, Tuple
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, 
    QLabel, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QPixmap, QPainter, QIcon, QImage
from PIL import Image


class IconQualityTestWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Icon Quality Test - PyQt vs PIL")
        self.setGeometry(100, 100, 1200, 800)
        
        # Get sprites path
        self.sprites_path = os.path.join(os.path.dirname(__file__), "resources", "assets", "sprites")
        if not os.path.exists(self.sprites_path):
            # Try alternative path
            self.sprites_path = os.path.join(os.path.dirname(__file__), "src", "tower_iq", "resources", "assets", "sprites")
        
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create scroll area for content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.addWidget(scroll_area)
        
        # Content widget
        content_widget = QWidget()
        scroll_area.setWidget(content_widget)
        content_layout = QVBoxLayout(content_widget)
        
        # Test sizes
        test_sizes = [128, 64, 48, 32, 24, 16]
        
        # Sample module data for testing
        test_modules = [
            {"name": "Test Module 1", "frame_name": "mf_cannon_epic", "icon_name": "cannon_epic_1"},
            {"name": "Test Module 2", "frame_name": "mf_armor_rare", "icon_name": "armor_rare_1"},
            {"name": "Test Module 3", "frame_name": "mf_core_legendary", "icon_name": "core_legendary_1"},
        ]
        
        # Create test sections
        for i, module in enumerate(test_modules):
            module_section = self.create_module_section(module, test_sizes, i + 1)
            content_layout.addWidget(module_section)
            
            # Add separator
            if i < len(test_modules) - 1:
                separator = QFrame()
                separator.setFrameShape(QFrame.Shape.HLine)
                separator.setFrameShadow(QFrame.Shadow.Sunken)
                content_layout.addWidget(separator)
        
        content_layout.addStretch()
        
    def create_module_section(self, module: dict, test_sizes: List[int], module_num: int) -> QWidget:
        """Create a section for testing one module at various sizes."""
        section = QWidget()
        layout = QVBoxLayout(section)
        
        # Module title
        title = QLabel(f"Module {module_num}: {module['name']}")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # PyQt row
        pyqt_row = self.create_method_row("PyQt Method", module, test_sizes, self.create_pyqt_icon)
        layout.addWidget(pyqt_row)
        
        # PIL row
        pil_row = self.create_method_row("PIL Method", module, test_sizes, self.create_pil_icon)
        layout.addWidget(pil_row)
        
        return section
        
    def create_method_row(self, method_name: str, module: dict, test_sizes: List[int], 
                         icon_creator_func) -> QWidget:
        """Create a row showing one method at various sizes."""
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(20, 5, 20, 5)
        
        # Method label
        method_label = QLabel(method_name)
        method_label.setFixedWidth(100)
        method_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(method_label)
        
        # Create icons at different sizes
        for size in test_sizes:
            try:
                icon = icon_creator_func(module, size)
                if icon:
                    icon_label = QLabel()
                    icon_label.setPixmap(icon)
                    icon_label.setFixedSize(size, size)
                    icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    icon_label.setStyleSheet("border: 1px solid #ccc; background: white;")
                    
                    # Add size label below icon
                    size_widget = QWidget()
                    size_layout = QVBoxLayout(size_widget)
                    size_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    size_layout.setSpacing(2)
                    size_layout.setContentsMargins(0, 0, 0, 0)
                    
                    size_layout.addWidget(icon_label)
                    
                    size_label = QLabel(f"{size}x{size}")
                    size_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    size_label.setStyleSheet("font-size: 10px; color: #666;")
                    size_layout.addWidget(size_label)
                    
                    layout.addWidget(size_widget)
                else:
                    # Add placeholder for failed icon
                    placeholder = QLabel("Failed")
                    placeholder.setFixedSize(size, size)
                    placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    placeholder.setStyleSheet("border: 1px solid #ccc; background: #f0f0f0; color: #999;")
                    layout.addWidget(placeholder)
                    
            except Exception as e:
                # Add error placeholder
                error_label = QLabel(f"Error\n{str(e)[:20]}")
                error_label.setFixedSize(size, size)
                error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                error_label.setStyleSheet("border: 1px solid #ccc; background: #ffe6e6; color: #c00; font-size: 8px;")
                layout.addWidget(error_label)
        
        layout.addStretch()
        return row
        
    def create_pyqt_icon(self, module: dict, size: int) -> QPixmap | None:
        """Create icon using PyQt method (original approach)."""
        try:
            # Load images
            frame_path = os.path.join(self.sprites_path, f"{module['frame_name']}.png")
            icon_path = os.path.join(self.sprites_path, f"{module['icon_name']}.png")
            
            if not os.path.exists(frame_path) or not os.path.exists(icon_path):
                return None
                
            frame_pixmap = QPixmap(frame_path)
            icon_pixmap = QPixmap(icon_path)
            
            # Create composite
            composite = QPixmap(size, size)
            composite.fill(Qt.GlobalColor.transparent)
            
            painter = QPainter(composite)
            painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
            
            # Scale frame to fill entire icon area
            frame_scaled = frame_pixmap.scaled(
                size, size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            
            # Scale inner icon with margin for padding (22% margin)
            margin = int(size * 0.22)
            inner_size = size - 2 * margin
            icon_scaled = icon_pixmap.scaled(
                inner_size, inner_size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            
            # Draw frame and icon
            painter.drawPixmap(0, 0, frame_scaled)
            painter.drawPixmap(margin, margin, icon_scaled)
            painter.end()
            
            return composite
            
        except Exception as e:
            print(f"PyQt icon creation error: {e}")
            return None
            
    def create_pil_icon(self, module: dict, size: int) -> QPixmap | None:
        """Create icon using PIL method (new approach)."""
        try:
            # Load images
            frame_path = os.path.join(self.sprites_path, f"{module['frame_name']}.png")
            icon_path = os.path.join(self.sprites_path, f"{module['icon_name']}.png")
            
            if not os.path.exists(frame_path) or not os.path.exists(icon_path):
                return None
                
            # Load original images using PIL
            frame_img = Image.open(frame_path).convert("RGBA")
            icon_img = Image.open(icon_path).convert("RGBA")
            
            # Resize using high-quality Lanczos
            frame_resized = frame_img.resize((size, size), Image.Resampling.LANCZOS)
            
            margin = int(size * 0.22)
            icon_resized = icon_img.resize(
                (size - 2 * margin, size - 2 * margin),
                Image.Resampling.LANCZOS
            )
            
            # Paste icon onto frame (centered)
            frame_resized.paste(icon_resized, (margin, margin), icon_resized)
            
            # Convert PIL image to QPixmap
            data = frame_resized.tobytes("raw", "RGBA")
            qimage = QImage(data, frame_resized.width, frame_resized.height, QImage.Format.Format_RGBA8888)
            qpixmap = QPixmap.fromImage(qimage)
            
            return qpixmap
            
        except Exception as e:
            print(f"PIL icon creation error: {e}")
            return None


def main():
    """Main function to run the test window."""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the test window
    window = IconQualityTestWindow()
    window.show()
    
    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
