"""
TowerIQ Database Info Card

This module provides the DatabaseInfoCard widget for displaying database statistics.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel
from qfluentwidgets import CardWidget, PrimaryPushButton, BodyLabel, CaptionLabel, FluentIcon

from ..stylesheets import get_themed_stylesheet


class DatabaseInfoCard(CardWidget):
    """Card widget for displaying database statistics and information."""
    
    # Signal emitted when refresh button is clicked
    refresh_clicked = pyqtSignal()
    
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the database info card user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Header with title and refresh button
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(12)
        
        # Title
        title_label = BodyLabel("Database Information")
        title_label.setObjectName("card_title")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        # Refresh button
        self.refresh_button = PrimaryPushButton("Refresh", self)
        self.refresh_button.setIcon(FluentIcon.SYNC)
        self.refresh_button.clicked.connect(self.refresh_clicked.emit)
        header_layout.addWidget(self.refresh_button)
        
        layout.addLayout(header_layout)
        
        # Form layout for database info
        self.form_layout = QFormLayout()
        self.form_layout.setContentsMargins(0, 0, 0, 0)
        self.form_layout.setSpacing(8)
        self.form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        self.form_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        
        # Create info fields
        self._create_info_fields()
        
        layout.addLayout(self.form_layout)
        
        # Apply styling
        self.setStyleSheet(get_themed_stylesheet())
        
    def _create_info_fields(self):
        """Create the database information fields."""
        # File information
        self.file_path_label = CaptionLabel("Not available")
        self.file_size_label = CaptionLabel("Not available")
        self.wal_size_label = CaptionLabel("Not available")
        self.created_date_label = CaptionLabel("Not available")
        self.modified_date_label = CaptionLabel("Not available")
        
        # Database information
        self.sqlite_version_label = CaptionLabel("Not available")
        self.schema_version_label = CaptionLabel("Not available")
        self.connection_status_label = CaptionLabel("Not available")
        self.last_backup_label = CaptionLabel("Not available")
        
        # Row counts
        self.total_rows_label = CaptionLabel("Not available")
        self.runs_count_label = CaptionLabel("Not available")
        self.metrics_count_label = CaptionLabel("Not available")
        self.events_count_label = CaptionLabel("Not available")
        self.logs_count_label = CaptionLabel("Not available")
        
        # Add fields to form layout
        self.form_layout.addRow("File Path:", self.file_path_label)
        self.form_layout.addRow("File Size:", self.file_size_label)
        self.form_layout.addRow("WAL File Size:", self.wal_size_label)
        self.form_layout.addRow("Created Date:", self.created_date_label)
        self.form_layout.addRow("Modified Date:", self.modified_date_label)
        self.form_layout.addRow("SQLite Version:", self.sqlite_version_label)
        self.form_layout.addRow("Schema Version:", self.schema_version_label)
        self.form_layout.addRow("Connection Status:", self.connection_status_label)
        self.form_layout.addRow("Last Backup:", self.last_backup_label)
        self.form_layout.addRow("Total Rows:", self.total_rows_label)
        self.form_layout.addRow("Runs:", self.runs_count_label)
        self.form_layout.addRow("Metrics:", self.metrics_count_label)
        self.form_layout.addRow("Events:", self.events_count_label)
        self.form_layout.addRow("Logs:", self.logs_count_label)
        
    def update_info(self, stats: dict):
        """Update the displayed database information with new statistics."""
        if not stats:
            return
            
        # File information
        self.file_path_label.setText(stats.get('file_path', 'Not available'))
        self.file_size_label.setText(self._format_file_size(stats.get('file_size', 0)))
        self.wal_size_label.setText(self._format_file_size(stats.get('wal_file_size', 0)))
        self.created_date_label.setText(self._format_date(stats.get('created_date', '')))
        self.modified_date_label.setText(self._format_date(stats.get('modified_date', '')))
        
        # Database information
        self.sqlite_version_label.setText(stats.get('sqlite_version', 'Not available'))
        self.schema_version_label.setText(stats.get('schema_version', 'Not available'))
        self.connection_status_label.setText(stats.get('connection_status', 'Not available'))
        self.last_backup_label.setText(self._format_date(stats.get('last_backup_date', '')))
        
        # Row counts
        self.total_rows_label.setText(str(stats.get('total_rows', 0)))
        
        table_rows = stats.get('table_rows', {})
        self.runs_count_label.setText(str(table_rows.get('runs', 0)))
        self.metrics_count_label.setText(str(table_rows.get('metrics', 0)))
        self.events_count_label.setText(str(table_rows.get('events', 0)))
        self.logs_count_label.setText(str(table_rows.get('logs', 0)))
        
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in bytes to human readable format."""
        if size_bytes == 0:
            return "0 B"
        
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def _format_date(self, date_str: str) -> str:
        """Format date string for display."""
        if not date_str:
            return "Not available"
        
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return date_str 