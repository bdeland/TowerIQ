"""
TowerIQ v1.0 - History Page

This module defines the HistoryPage widget for viewing past game session data.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea, 
    QFrame, QPushButton, QSpacerItem, QSizePolicy, QLineEdit, QTableWidget, QTableWidgetItem, QSplitter
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPalette, QColor
from typing import Any

try:
    import pyqtgraph as pg
except ImportError:
    pg = None

try:
    import pandas as pd
except ImportError:
    pd = None

from tower_iq.core.utils import format_currency, format_duration


class HistoryPage(QWidget):
    """
    A placeholder history page for the TowerIQ application.
    
    This widget will eventually display historical game session data,
    but for now serves as a placeholder in the main window's navigation.
    """
    
    def __init__(self, controller: Any) -> None:
        """
        Initialize the history page.
        
        Args:
            controller: The main controller instance
        """
        super().__init__()
        
        self.controller = controller
        self._init_ui()
    
    def _init_ui(self) -> None:
        """Set up the history page UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Page title
        title_label = QLabel("Run History")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #333; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        # Histogram controls
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)
        controls_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        runs_label = QLabel("Number of most recent runs:")
        runs_label.setStyleSheet("color: #333; font-size: 14px;")
        self.runs_input = QLineEdit()
        self.runs_input.setPlaceholderText("(blank = all)")
        self.runs_input.setFixedWidth(120)
        self.runs_input.setStyleSheet("color: #222; background: #fff; border: 1px solid #bbb; border-radius: 5px; padding: 2px 8px; font-size: 14px;")
        controls_layout.addWidget(runs_label)
        controls_layout.addWidget(self.runs_input)
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Histogram and Table area with splitter
        self.splitter = QSplitter()
        self.splitter.setOrientation(Qt.Orientation.Vertical)
        # Histogram area
        if pg is not None:
            self.histogram_widget = pg.PlotWidget(title="CPH Distribution by Tier")
            self.histogram_widget.setLabel('left', 'Coins Per Hour (CPH)')
            self.histogram_widget.setLabel('bottom', 'Tier')
            self.histogram_widget.showGrid(x=False, y=False, alpha=1.0)
            self.histogram_widget.setBackground('#001219')
            self.splitter.addWidget(self.histogram_widget)
        else:
            placeholder = QLabel("Histogram visualization requires pyqtgraph.\nInstall with: pip install pyqtgraph")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #fff; font-style: italic; margin: 20px; background: #001219;")
            self.splitter.addWidget(placeholder)
            self.histogram_widget = None
        # Table area
        self.runs_table = QTableWidget()
        self.runs_table.setColumnCount(0)
        self.runs_table.setRowCount(0)
        self.runs_table.setMinimumHeight(200)
        self.runs_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.runs_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.runs_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        header = self.runs_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
        self.splitter.addWidget(self.runs_table)
        self.splitter.setSizes([300, 300])
        layout.addWidget(self.splitter, stretch=1)
        # Apply dark style and palette to table after construction
        table_style = """
            QTableWidget {
                background-color: #001219;
                color: #fff;
                border: 1px solid #79a2bc;
                gridline-color: #79a2bc;
                selection-background-color: #2a9b8e;
                selection-color: #fff;
            }
            QHeaderView::section {
                background-color: #001219;
                color: #fff;
                border: 1px solid #79a2bc;
            }
            QTableCornerButton::section {
                background-color: #001219;
                border: 1px solid #79a2bc;
            }
            QScrollBar:vertical, QScrollBar:horizontal {
                background: #001219;
                border: 1px solid #79a2bc;
            }
        """
        self.runs_table.setStyleSheet(table_style)
        pal = self.runs_table.palette()
        pal.setColor(QPalette.ColorRole.Base, QColor('#001219'))
        pal.setColor(QPalette.ColorRole.Text, QColor('#ffffff'))
        pal.setColor(QPalette.ColorRole.Window, QColor('#001219'))
        pal.setColor(QPalette.ColorRole.Highlight, QColor('#2a9b8e'))
        pal.setColor(QPalette.ColorRole.HighlightedText, QColor('#ffffff'))
        self.runs_table.setPalette(pal)
        
        layout.addStretch()
        
        # Connect input change
        self.runs_input.textChanged.connect(self.update_histogram)
        # Connect to setup_finished signal
        if hasattr(self.controller, "setup_finished"):
            self.controller.setup_finished.connect(self._on_setup_finished)
        
        self._histogram_labels = []  # Track data labels for histogram
    
    def _on_setup_finished(self, success: bool):
        if success:
            self.update_histogram()
    
    def update_histogram(self):
        if pg is None or self.histogram_widget is None:
            return
        # Remove old data labels
        for label in getattr(self, '_histogram_labels', []):
            self.histogram_widget.removeItem(label)
        self._histogram_labels = []
        # Get user input for number of runs
        text = self.runs_input.text().strip()
        limit = None
        if text.isdigit():
            limit = int(text)
        # Fetch data for histogram (tier, CPH)
        df = self.controller.db_service.get_recent_runs_for_histogram(limit)
        # Fetch all columns for the table
        df_table = self.controller.db_service.get_all_runs(limit)
        # Update histogram
        self.histogram_widget.clear()
        if df is None or df.empty:
            self.histogram_widget.setTitle("No data available")
        else:
            # Group by tier, compute mean CPH for each tier
            # Only include integer tiers
            df_int_tiers = df[df['tier'].apply(lambda t: float(t).is_integer())].copy()
            df_int_tiers['tier'] = df_int_tiers['tier'].astype(int)
            grouped = df_int_tiers.groupby('tier')['CPH'].mean().reset_index()
            x = grouped['tier'].tolist()
            y = grouped['CPH'].tolist()
            if len(x) == 0:
                self.histogram_widget.setTitle("No data available")
                return
            bg = pg.BarGraphItem(x=x, height=y, width=0.8, brush='#9a4dda')  # Violet Pulse
            self.histogram_widget.addItem(bg)
            self.histogram_widget.setTitle("CPH Distribution by Tier")
            self.histogram_widget.setLabel('bottom', 'Tier')
            self.histogram_widget.setLabel('left', 'Coins Per Hour (CPH)')
            # Set x-axis ticks to integer tiers only
            ax = self.histogram_widget.getAxis('bottom')
            ax.setTicks([[(val, str(val)) for val in x]])
            # Set y-axis ticks to evenly spaced values, formatted as currency
            import numpy as np
            ay = self.histogram_widget.getAxis('left')
            if len(y) > 0:
                y_min = 0  # Start from zero for better visuals
                y_max = max(y)
                n_ticks = 6  # Number of ticks you want
                if y_max > 0:
                    ticks = np.linspace(y_min, y_max, n_ticks)
                    y_ticks = [(float(v), format_currency(float(v), symbol="", pad_to_cents=True)) for v in ticks]
                    ay.setTicks([y_ticks])
            # Add data labels above bars
            for xi, yi in zip(x, y):
                label = pg.TextItem(text=format_currency(yi, symbol="", pad_to_cents=True), anchor=(0.5, 0), color='#fff')
                self.histogram_widget.addItem(label)
                label.setPos(xi, yi + max(y) * 0.02 if max(y) > 0 else yi + 1)
                self._histogram_labels.append(label)
        # Update table
        self.update_runs_table(df_table)

    def update_runs_table(self, df):
        if df is None or df.empty:
            self.runs_table.setColumnCount(1)
            self.runs_table.setRowCount(1)
            self.runs_table.setHorizontalHeaderLabels(["No data"])
            self.runs_table.setItem(0, 0, QTableWidgetItem("No runs available"))
            return

        # Column mapping: db column -> (display name, formatter, alignment)
        column_map = {
            'run_id': ("Run ID", None, Qt.AlignmentFlag.AlignCenter),
            'start_time': ("Start Time", 'datetime', Qt.AlignmentFlag.AlignCenter),
            'end_time': ("End Time", 'datetime', Qt.AlignmentFlag.AlignCenter),
            'duration_realtime': ("Real Duration", 'duration', Qt.AlignmentFlag.AlignCenter),
            'duration_gametime': ("Game Duration", 'duration', Qt.AlignmentFlag.AlignCenter),
            'final_wave': ("Final Wave", None, Qt.AlignmentFlag.AlignCenter),
            'coins_earned': ("Coins Earned", 'currency', Qt.AlignmentFlag.AlignRight),
            'CPH': ("CPH", 'currency', Qt.AlignmentFlag.AlignRight),
            'round_cells': ("Cells Earned", 'currency', Qt.AlignmentFlag.AlignRight),
            'round_gems': ("Gems Earned", 'currency', Qt.AlignmentFlag.AlignRight),
            'round_cash': ("Cash Earned", 'currency', Qt.AlignmentFlag.AlignRight),
            'tier': ("Tier", None, Qt.AlignmentFlag.AlignCenter),
        }
        # Remove game_version if present
        df = df.drop(columns=[col for col in ['game_version'] if col in df.columns], errors='ignore')
        # Only keep columns in our map, in the specified order
        display_columns = [col for col in column_map if col in df.columns]
        self.runs_table.setColumnCount(len(display_columns))
        self.runs_table.setRowCount(len(df))
        self.runs_table.setHorizontalHeaderLabels([column_map[col][0] for col in display_columns])

        import locale
        from datetime import datetime
        locale.setlocale(locale.LC_TIME, '')  # Use user's locale
        dt_fmt = '%c'  # Locale-appropriate date and time

        for row in range(len(df)):
            for col_idx, col in enumerate(display_columns):
                value = df.iloc[row][col]
                display_value = value
                align = column_map[col][2]
                # Format as needed
                if column_map[col][1] == 'datetime':
                    # Assume value is UNIX timestamp in seconds or ms
                    try:
                        v = int(value)
                        if v > 1e12:
                            v = v // 1000
                        dt = datetime.fromtimestamp(v)
                        try:
                            display_value = dt.strftime(dt_fmt)
                        except Exception:
                            display_value = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        display_value = str(value)
                elif column_map[col][1] == 'duration':
                    try:
                        display_value = format_duration(float(value))
                    except Exception:
                        display_value = str(value)
                elif column_map[col][1] == 'currency':
                    try:
                        display_value = format_currency(float(value), symbol="", pad_to_cents=True)
                    except Exception:
                        display_value = str(value)
                else:
                    display_value = str(value)
                item = QTableWidgetItem(display_value)
                item.setTextAlignment(align | Qt.AlignmentFlag.AlignVCenter)
                self.runs_table.setItem(row, col_idx, item) 