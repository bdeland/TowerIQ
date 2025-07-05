"""
TowerIQ v1.0 - Dashboard Page

This module defines the DashboardPage widget with a simple coins chart
for displaying cumulative coin values over time.
"""

from typing import TYPE_CHECKING, Any, Dict, List, Optional
import time
from datetime import datetime
import math
import logging

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, 
    QFrame, QScrollArea, QSizePolicy, QStackedLayout, QGraphicsBlurEffect, QToolTip, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSlot, QTimer
from PyQt6.QtGui import QFont, QPalette

from .connection_state_panel import ConnectionStatePanel
from src.tower_iq.core.utils import format_duration, format_currency

try:
    import pyqtgraph as pg
    from pyqtgraph import AxisItem, ViewBox
    try:
        from pyqtgraph import DateAxisItem
    except ImportError:
        DateAxisItem = None
except ImportError:
    pg = None
    DateAxisItem = None

try:
    import pandas as pd
except ImportError:
    pd = None

if TYPE_CHECKING:
    from tower_iq.main_controller import MainController

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class CurrencyAxis(AxisItem):
    def tickStrings(self, values, scale, spacing):
        return [format_currency(value, symbol="", pad_to_cents=False) for value in values]

# Custom DurationAxis for elapsed time (hh:mm:ss) display
if pg is not None:
    class DurationAxis(pg.AxisItem):
        def tickStrings(self, values, scale, spacing):
            # Format as hh:mm:ss from zero
            def fmt(val):
                val = int(val)
                hours, rem = divmod(val, 3600)
                minutes, seconds = divmod(rem, 60)
                if hours > 0:
                    return f"{hours:d}:{minutes:02d}:{seconds:02d}"
                else:
                    return f"{minutes:d}:{seconds:02d}"
            return [fmt(v) for v in values]

        def generateDrawSpecs(self, p):
            # Copied and modified from pyqtgraph.AxisItem.generateDrawSpecs
            # Only draw tick marks where a label is drawn
            specs = super().generateDrawSpecs(p)
            if specs is None:
                return None
            axisSpec, tickSpecs, textSpecs = specs
            # Only keep ticks that have a label (i.e., their position matches a label position)
            label_positions = set()
            for rect, flags, text in textSpecs:
                # rect.x() is the center of the label for horizontal axis
                if self.orientation in ('bottom', 'top'):
                    label_positions.add(rect.center().x())
                else:
                    label_positions.add(rect.center().y())
            # Filter tickSpecs to only those that match a label position (within 1px tolerance)
            filtered_tickSpecs = []
            for pen, p1, p2 in tickSpecs:
                if self.orientation in ('bottom', 'top'):
                    x = p1.x()
                    if any(abs(x - lp) < 1.0 for lp in label_positions):
                        filtered_tickSpecs.append((pen, p1, p2))
                else:
                    y = p1.y()
                    if any(abs(y - lp) < 1.0 for lp in label_positions):
                        filtered_tickSpecs.append((pen, p1, p2))
            return axisSpec, filtered_tickSpecs, textSpecs
else:
    pass  # Do not define DurationAxis if pg is not available

class GraphWidget(QWidget):
    """
    A widget to display a real-time chart using pyqtgraph.
    
    If pyqtgraph is not available, displays a placeholder message.
    """
    
    # This variable controls the threshold for showing scatter points.
    # If the number of visible points in the current x-range is <= this value, points are shown.
    # Increase to show points only at higher zoom levels, decrease to show more often.
    scatter_point_threshold = 10  # <--- EDIT THIS VALUE TO FINE-TUNE
    
    def __init__(self, title: str, y_label: str = "Value", line_color: str = "#9a4dda", scatter_color: str = "#9a4dda", use_wave_axis: bool = False, bar_mode: bool = False) -> None:
        """
        Initialize a graph widget.
        
        Args:
            title: The title of the graph
            y_label: Label for the Y-axis
            line_color: Color for the line in the chart
            scatter_color: Color for the scatter points in the chart
            use_wave_axis: If True, use a standard integer axis for x (for wave charts)
            bar_mode: If True, use pg.BarGraphItem for plotting instead of a line plot
        """
        super().__init__()
        
        self.title = title
        self.y_label = y_label
        self.line_color = line_color
        self.scatter_color = scatter_color
        self.data_x: List[float] = []
        self.data_y: List[float] = []
        self.max_points = 1000  # Maximum number of data points to keep
        self.start_time = None  # Track start time for relative X-axis
        self.use_wave_axis = use_wave_axis
        self.bar_mode = bar_mode
        self._main_layout = QVBoxLayout(self)
        self._main_layout.setContentsMargins(10, 10, 10, 10)
        
        if pg is not None:
            self._init_pyqtgraph()
        else:
            self._init_placeholder()
    
    def _init_pyqtgraph(self) -> None:
        """Initialize the pyqtgraph plot widget."""
        if pg is None:
            return
        pg.setConfigOption('background', '#001219')
        pg.setConfigOption('foreground', '#fff')
        axis_items = {}
        axis_items['left'] = CurrencyAxis('left')
        if self.use_wave_axis:
            axis_items['bottom'] = pg.AxisItem('bottom')
            x_label = 'Wave'
        else:
            try:
                axis_items['bottom'] = DurationAxis('bottom')
            except Exception:
                axis_items['bottom'] = pg.AxisItem('bottom')
            x_label = 'Duration'
        self.plot_widget = pg.PlotWidget(
            title=None,
            axisItems=axis_items
        )
        self.plot_widget.setBackground('#001219')
        self.plot_widget.setLabel('left', "")
        self.plot_widget.setLabel('bottom', x_label)
        self.plot_widget.showGrid(x=False, y=False)
        # Remove minor ticks: only show major ticks with labels
        for axis in ['left', 'bottom']:
            ax = self.plot_widget.getAxis(axis)
            if ax is not None:
                ax.setStyle(maxTickLevel=0, tickLength=-8)
        if self.bar_mode:
            self.bar_item = pg.BarGraphItem(x=[], height=[], width=0.8, brush=pg.mkBrush(self.line_color))
            self.plot_widget.addItem(self.bar_item)
        else:
            self.plot_item = self.plot_widget.plot(
                pen=pg.mkPen(color=self.line_color, width=3)
            )
            self.scatter = pg.ScatterPlotItem(
                pen=pg.mkPen(None),
                brush=pg.mkBrush(self.scatter_color),
                size=8,
                hoverable=True,
                hoverPen=pg.mkPen('w', width=2),
                hoverBrush=pg.mkBrush('w')
            )
            self.scatter.sigHovered.connect(self._on_point_hovered)
            self.plot_widget.addItem(self.scatter)
            self.plot_widget.sigXRangeChanged.connect(self._on_xrange_changed)
        self._main_layout.addWidget(self.plot_widget)
    
    def _init_placeholder(self) -> None:
        """Initialize a placeholder when pyqtgraph is not available."""
        placeholder = QFrame()
        placeholder.setFrameStyle(QFrame.Shape.StyledPanel)
        placeholder.setStyleSheet("""
            QFrame {
                background-color: #f5f5f5;
                /* No border here to avoid inner borders in stat panels */
                border: none;
                border-radius: 5px;
            }
        """)
        
        placeholder_layout = QVBoxLayout(placeholder)
        
        title_label = QLabel(self.title)
        title_font = QFont()
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        message_label = QLabel("Graph visualization requires pyqtgraph\nInstall with: pip install pyqtgraph")
        message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        message_label.setStyleSheet("color: #666; font-style: italic;")
        
        placeholder_layout.addWidget(title_label)
        placeholder_layout.addWidget(message_label)
        
        self._main_layout.addWidget(placeholder)
        
        # Set minimum size
        placeholder.setMinimumSize(400, 300)
    
    def _normalize_timestamp(self, ts):
        # If timestamp is in milliseconds (e.g., > 10^12), convert to seconds
        if ts > 1e12:
            return ts / 1000.0
        return ts

    def _nice_tick_interval(self, data_max, n_ticks=5):
        if data_max == 0:
            return 1
        raw_interval = data_max / (n_ticks - 1)
        magnitude = 10 ** math.floor(math.log10(raw_interval))
        residual = raw_interval / magnitude
        if residual >= 5:
            nice = 5 * magnitude
        elif residual >= 2:
            nice = 2 * magnitude
        else:
            nice = magnitude
        return nice

    def append_data_point(self, x: float, y: float) -> None:
        x = self._normalize_timestamp(x)
        # Set start time on first data point
        if self.start_time is None:
            self.start_time = x
        # For duration axis, x-axis is elapsed seconds from start
        relative_time = x - self.start_time
        # Store as absolute unix timestamp for DateAxisItem, or as duration for DurationAxis
        if DurationAxis is not None:
            plot_x = relative_time
        else:
            plot_x = x
        self.data_x.append(plot_x)
        self.data_y.append(y)
        if len(self.data_x) > self.max_points:
            self.data_x = self.data_x[-self.max_points:]
            self.data_y = self.data_y[-self.max_points:]
        vb = self.plot_widget.getViewBox() if pg is not None else None
        if not getattr(self.parent(), 'autoscale_enabled', True) and vb is not None:
            old_xrange = vb.viewRange()[0]
        else:
            old_xrange = None
        if pg is not None and hasattr(self, 'plot_item'):
            self.plot_item.setData(self.data_x, self.data_y)
        if pg is not None and hasattr(self, 'scatter'):
            spots = [{'pos': (x, y), 'data': y, 'brush': pg.mkBrush(self.scatter_color)} for x, y in zip(self.data_x, self.data_y)]
            self.scatter.setData(spots)
            vb = self.plot_widget.getViewBox()
            if vb is not None:
                xrange = vb.viewRange()[0]
                self._on_xrange_changed(vb, xrange)
        if not getattr(self.parent(), 'autoscale_enabled', True) and old_xrange is not None and vb is not None:
            vb.setXRange(*old_xrange, padding=0)
    
    def _on_xrange_changed(self, view_box, xrange):
        """
        Show scatter points only if the number of visible points is <= scatter_point_threshold.
        """
        x_min, x_max = xrange
        visible_indices = [i for i, x in enumerate(self.data_x) if x_min <= x <= x_max]
        if len(visible_indices) <= self.scatter_point_threshold:
            self.scatter.setVisible(True)
        else:
            self.scatter.setVisible(False)

    def plot_data(self, df, metric_name: str = "value", normalize_x: bool = True, x_col: Optional[str] = None, y_col: Optional[str] = None) -> None:
        """
        Plot data from a pandas DataFrame.
        Args:
            df: pandas DataFrame with 'real_timestamp' and metric column
            metric_name: the name of the metric column to plot
            normalize_x: whether to normalize the x-axis (for time series)
            x_col: column to use for x-axis (overrides default)
            y_col: column to use for y-axis (overrides default)
        """
        if pg is None:
            return
        if df.empty:
            if self.bar_mode and hasattr(self, 'bar_item'):
                self.bar_item.setOpts(x=[], height=[])
            elif hasattr(self, 'plot_item'):
                self.plot_item.setData([], [])
            if hasattr(self, 'scatter'):
                self.scatter.setData([])
            return
        if len(df) > 0:
            df = df.copy()
            if self.use_wave_axis:
                if x_col is None:
                    x_col = 'current_wave'
                if y_col is None:
                    y_col = 'metric_value'
                # Ensure x is int and y is float for bar chart
                self.data_x = [int(x) for x in df[x_col].tolist()]
                self.data_y = [float(y) for y in df[y_col].tolist()]
            else:
                if x_col is None:
                    x_col = 'real_timestamp'
                if y_col is None:
                    y_col = metric_name
                df['real_timestamp'] = df['real_timestamp'].apply(self._normalize_timestamp)
                current_start_time = df['real_timestamp'].min()
                if self.start_time is None:
                    self.start_time = current_start_time
                else:
                    self.start_time = min(self.start_time, current_start_time)
                if DurationAxis is not None:
                    x_vals = (df[x_col] - self.start_time).tolist()
                else:
                    x_vals = df[x_col].tolist()
                values = df[y_col]
                self.data_x = x_vals
                self.data_y = values.tolist()
            if self.bar_mode and hasattr(self, 'bar_item'):
                self.bar_item.setOpts(x=self.data_x, height=self.data_y, width=0.8, brush=pg.mkBrush(self.line_color))
                # Hide line and scatter if present
                if hasattr(self, 'plot_item'):
                    self.plot_item.setData([], [])
                if hasattr(self, 'scatter'):
                    self.scatter.setData([])
            else:
                if hasattr(self, 'plot_item'):
                    self.plot_item.setData(self.data_x, self.data_y)
                if hasattr(self, 'scatter'):
                    spots = [{'pos': (x, y), 'data': y, 'brush': pg.mkBrush(self.scatter_color)} for x, y in zip(self.data_x, self.data_y)]
                    self.scatter.setData(spots)
                vb = self.plot_widget.getViewBox()
                if vb is not None:
                    xrange = vb.viewRange()[0]
                    self._on_xrange_changed(vb, xrange)
    
    def clear_data(self) -> None:
        """Clear all data points from the graph."""
        self.data_x.clear()
        self.data_y.clear()
        self.start_time = None
        
        if pg is not None and hasattr(self, 'plot_item'):
            self.plot_item.clear()
            self.scatter.clear()
            # Do not reset the view, let auto-range handle it

    def _on_point_hovered(self, scatter, points, event):
        for point in points:
            value = point.data()
            QToolTip.showText(event.screenPos().toPoint(), f"Value: {format_currency(value, symbol='', pad_to_cents=False)}")

class DashboardPage(QWidget):
    """
    Simple dashboard page showing only the coins chart.
    """
    
    def __init__(self, controller: "MainController") -> None:
        """
        Initialize the dashboard page.
        
        Args:
            controller: The main controller instance
        """
        super().__init__()
        
        self.controller = controller
        self.graphs: Dict[str, GraphWidget] = {}
        self.autoscale_enabled = True
        self._autoscale_glow_timer = None
        # Create the connection panel
        self.connection_panel = ConnectionStatePanel(self)
        # --- Stat panel labels (init for linter) ---
        self.status_label = QLabel("-")
        self.run_id_label = QLabel("-")
        self.round_start_label = QLabel("-")
        self.tier_label = QLabel("-")
        self.current_wave_label = QLabel("-")
        self.real_time_label = QLabel("-")
        # Set stat value colors
        stat_value_color = "color: #2a9b8e; font-weight: bold;"
        self.run_id_label.setStyleSheet(stat_value_color)
        self.round_start_label.setStyleSheet(stat_value_color)
        self.tier_label.setStyleSheet(stat_value_color)
        self.current_wave_label.setStyleSheet(stat_value_color)
        self.real_time_label.setStyleSheet(stat_value_color)
        # ---
        self._init_ui()
        # QTimer for periodic stat updates
        self._stat_timer = QTimer(self)
        self._stat_timer.timeout.connect(self._update_stats)
        self._stat_timer.start(1000)
        self._last_run_id = None
    
    def _init_ui(self) -> None:
        """
        Set up the layout and create the coins chart.
        """
        # Create the main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Autoscale checkbox (top right)
        autoscale_layout = QHBoxLayout()
        autoscale_layout.addStretch()
        self.autoscale_checkbox = QCheckBox("Autoscale")
        self.autoscale_checkbox.setChecked(True)
        self.autoscale_checkbox.stateChanged.connect(self._on_autoscale_toggled)
        autoscale_layout.addWidget(self.autoscale_checkbox)
        main_layout.addLayout(autoscale_layout)
        
        # Create the dashboard content
        self.dashboard_widget = self._create_dashboard_content()
        main_layout.addWidget(self.dashboard_widget)
        
        # Create the connection overlay widget (initially hidden)
        self.connection_overlay_widget = self._create_connection_overlay()
        self.connection_overlay_widget.hide()
        
        # Add overlay as a child widget with absolute positioning
        self.connection_overlay_widget.setParent(self)
    
    def _create_dashboard_content(self) -> QWidget:
        """Create the main dashboard content widget."""
        dashboard_widget = QWidget()
        main_layout = QVBoxLayout(dashboard_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        dashboard_widget.setStyleSheet("""
            QWidget {
                background-color: #001219;
                color: #fff;
            }
            QLabel {
                color: #fff;
                background-color: transparent;
            }
        """)

        # --- Stat panels: 3x3 grid ---
        stat_grid = QGridLayout()
        stat_grid.setSpacing(20)
        # Status
        self.status_label = QLabel("-")
        self.status_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_title = QLabel("Round Status")
        status_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_frame = QFrame()
        status_frame.setObjectName("statGroupFrame")
        status_frame.setFrameShape(QFrame.Shape.StyledPanel)
        status_frame.setStyleSheet("""
            #statGroupFrame {
                border: 1px solid #888;
                border-radius: 10px;
                background: transparent;
            }
        """)
        status_frame_layout = QVBoxLayout(status_frame)
        status_frame_layout.setContentsMargins(10, 10, 10, 10)
        status_frame_layout.addWidget(status_title)
        status_frame_layout.addWidget(self.status_label)
        stat_grid.addWidget(status_frame, 0, 0)
        # Run ID
        self.run_id_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.run_id_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        run_id_title = QLabel("Run ID")
        run_id_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        run_id_frame = QFrame()
        run_id_frame.setObjectName("statGroupFrame")
        run_id_frame.setFrameShape(QFrame.Shape.StyledPanel)
        run_id_frame.setStyleSheet("""
            #statGroupFrame {
                border: 1px solid #888;
                border-radius: 10px;
                background: transparent;
            }
        """)
        run_id_frame_layout = QVBoxLayout(run_id_frame)
        run_id_frame_layout.setContentsMargins(10, 10, 10, 10)
        run_id_frame_layout.addWidget(run_id_title)
        run_id_frame_layout.addWidget(self.run_id_label)
        stat_grid.addWidget(run_id_frame, 0, 1)
        # Start Time
        self.round_start_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.round_start_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        round_start_title = QLabel("Round Start Time")
        round_start_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        round_start_frame = QFrame()
        round_start_frame.setObjectName("statGroupFrame")
        round_start_frame.setFrameShape(QFrame.Shape.StyledPanel)
        round_start_frame.setStyleSheet("""
            #statGroupFrame {
                border: 1px solid #888;
                border-radius: 10px;
                background: transparent;
            }
        """)
        round_start_frame_layout = QVBoxLayout(round_start_frame)
        round_start_frame_layout.setContentsMargins(10, 10, 10, 10)
        round_start_frame_layout.addWidget(round_start_title)
        round_start_frame_layout.addWidget(self.round_start_label)
        stat_grid.addWidget(round_start_frame, 0, 2)
        # Tier
        self.tier_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.tier_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tier_title = QLabel("Tier")
        tier_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tier_frame = QFrame()
        tier_frame.setObjectName("statGroupFrame")
        tier_frame.setFrameShape(QFrame.Shape.StyledPanel)
        tier_frame.setStyleSheet("""
            #statGroupFrame {
                border: 1px solid #888;
                border-radius: 10px;
                background: transparent;
            }
        """)
        tier_frame_layout = QVBoxLayout(tier_frame)
        tier_frame_layout.setContentsMargins(10, 10, 10, 10)
        tier_frame_layout.addWidget(tier_title)
        tier_frame_layout.addWidget(self.tier_label)
        stat_grid.addWidget(tier_frame, 1, 0)
        # Current Wave
        self.current_wave_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.current_wave_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        current_wave_title = QLabel("Current Wave")
        current_wave_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        current_wave_frame = QFrame()
        current_wave_frame.setObjectName("statGroupFrame")
        current_wave_frame.setFrameShape(QFrame.Shape.StyledPanel)
        current_wave_frame.setStyleSheet("""
            #statGroupFrame {
                border: 1px solid #888;
                border-radius: 10px;
                background: transparent;
            }
        """)
        current_wave_frame_layout = QVBoxLayout(current_wave_frame)
        current_wave_frame_layout.setContentsMargins(10, 10, 10, 10)
        current_wave_frame_layout.addWidget(current_wave_title)
        current_wave_frame_layout.addWidget(self.current_wave_label)
        stat_grid.addWidget(current_wave_frame, 1, 1)
        # Real Time (Duration)
        self.real_time_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.real_time_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.real_time_label.setStyleSheet("color: #2a9b8e;")
        real_time_title = QLabel("Duration")
        real_time_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        real_time_frame = QFrame()
        real_time_frame.setObjectName("statGroupFrame")
        real_time_frame.setFrameShape(QFrame.Shape.StyledPanel)
        real_time_frame.setStyleSheet("""
            #statGroupFrame {
                border: 1px solid #888;
                border-radius: 10px;
                background: transparent;
            }
        """)
        real_time_frame_layout = QVBoxLayout(real_time_frame)
        real_time_frame_layout.setContentsMargins(10, 10, 10, 10)
        real_time_frame_layout.addWidget(real_time_title)
        real_time_frame_layout.addWidget(self.real_time_label)
        stat_grid.addWidget(real_time_frame, 1, 2)
        # Add grid to main layout
        stat_panel_widget = QWidget()
        stat_panel_widget.setLayout(stat_grid)
        stat_panel_widget.setStyleSheet("")
        main_layout.addWidget(stat_panel_widget)
        
        # Create the charts in a 2x2 grid layout instead of 1x4 vertical
        charts_grid = QGridLayout()
        charts_grid.setSpacing(20)
        # Chart titles and widgets
        # Coins chart
        self.coins_chart = GraphWidget("Cumulative Coins Over Time", "Coins", line_color="#FEE8A8", scatter_color="#FEE8A8")
        self.coins_chart.setStyleSheet("")  # Remove border from chart itself
        # Stat panel for coins
        coins_stat_panel = QHBoxLayout()
        coins_stat_panel.setSpacing(8)
        coins_stat_panel.setContentsMargins(0, 0, 0, 0)
        self.coins_total_label = QLabel("Total Coins: -")
        self.coins_total_label.setStyleSheet("color: #FEE8A8; font-weight: bold; background: transparent;")
        self.coins_per_hour_label = QLabel("CPH: -")
        self.coins_per_hour_label.setStyleSheet("color: #FEE8A8; font-weight: bold; background: transparent;")
        coins_stat_panel.addWidget(self.coins_total_label)
        coins_stat_panel.addWidget(self.coins_per_hour_label)
        coins_panel = QWidget()
        coins_panel.setObjectName("chartPanel")
        coins_panel.setStyleSheet("""
            #chartPanel {
                border: 1px solid #FEE8A8;
                border-radius: 10px;
                background: transparent;
            }
        """)
        coins_vbox = QVBoxLayout(coins_panel)
        coins_vbox.setSpacing(4)
        coins_vbox.setContentsMargins(10, 10, 10, 10)
        coins_vbox.addLayout(coins_stat_panel)
        coins_vbox.addWidget(self.coins_chart)
        charts_grid.addWidget(coins_panel, 0, 0)
        # Coins per Wave chart (top right)
        self.wave_coins_chart = GraphWidget("Coins per Wave", "Wave Coins", line_color="#60c86e", scatter_color="#60c86e", use_wave_axis=True, bar_mode=True)
        self.wave_coins_chart.setStyleSheet("")
        wave_coins_title = QLabel("Coins per Wave")
        wave_coins_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        wave_coins_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        wave_coins_title.setStyleSheet("color: #60c86e; margin-bottom: 4px;")
        wave_coins_panel = QWidget()
        wave_coins_panel.setObjectName("chartPanel")
        wave_coins_panel.setStyleSheet("""
            #chartPanel {
                border: 1px solid #888;
                border-radius: 10px;
                background: transparent;
            }
        """)
        wave_coins_vbox = QVBoxLayout(wave_coins_panel)
        wave_coins_vbox.setSpacing(4)
        wave_coins_vbox.setContentsMargins(10, 10, 10, 10)
        wave_coins_vbox.addWidget(wave_coins_title)
        wave_coins_vbox.addWidget(self.wave_coins_chart)
        charts_grid.addWidget(wave_coins_panel, 0, 1)
        self.graphs["wave_coins_timeline"] = self.wave_coins_chart
        # Gems chart
        self.gems_chart = GraphWidget("Cumulative Gems Over Time", "Gems", line_color="#9a4dda", scatter_color="#9a4dda")
        self.gems_chart.setStyleSheet("")
        gems_stat_panel = QHBoxLayout()
        gems_stat_panel.setSpacing(8)
        gems_stat_panel.setContentsMargins(0, 0, 0, 0)
        self.gems_total_label = QLabel("Total Gems: -")
        self.gems_total_label.setStyleSheet("color: #9a4dda; font-weight: bold; background: transparent;")
        self.gems_per_hour_label = QLabel("GPH: -")
        self.gems_per_hour_label.setStyleSheet("color: #9a4dda; font-weight: bold; background: transparent;")
        gems_stat_panel.addWidget(self.gems_total_label)
        gems_stat_panel.addWidget(self.gems_per_hour_label)
        gems_panel = QWidget()
        gems_panel.setObjectName("chartPanel")
        gems_panel.setStyleSheet("""
            #chartPanel {
                border: 1px solid #9a4dda;
                border-radius: 10px;
                background: transparent;
            }
        """)
        gems_vbox = QVBoxLayout(gems_panel)
        gems_vbox.setSpacing(4)
        gems_vbox.setContentsMargins(10, 10, 10, 10)
        gems_vbox.addLayout(gems_stat_panel)
        gems_vbox.addWidget(self.gems_chart)
        charts_grid.addWidget(gems_panel, 1, 0)
        self.graphs["gems_timeline"] = self.gems_chart
        # Cells chart
        self.cells_chart = GraphWidget("Cumulative Cells Over Time", "Cells", line_color="#139b2d", scatter_color="#139b2d")
        self.cells_chart.setStyleSheet("")
        cells_stat_panel = QHBoxLayout()
        cells_stat_panel.setSpacing(8)
        cells_stat_panel.setContentsMargins(0, 0, 0, 0)
        self.cells_total_label = QLabel("Total Cells: -")
        self.cells_total_label.setStyleSheet("color: #139b2d; font-weight: bold; background: transparent;")
        self.cells_per_hour_label = QLabel("Cells Per Hour: -")
        self.cells_per_hour_label.setStyleSheet("color: #139b2d; font-weight: bold; background: transparent;")
        cells_stat_panel.addWidget(self.cells_total_label)
        cells_stat_panel.addWidget(self.cells_per_hour_label)
        cells_panel = QWidget()
        cells_panel.setObjectName("chartPanel")
        cells_panel.setStyleSheet("""
            #chartPanel {
                border: 1px solid #139b2d;
                border-radius: 10px;
                background: transparent;
            }
        """)
        cells_vbox = QVBoxLayout(cells_panel)
        cells_vbox.setSpacing(4)
        cells_vbox.setContentsMargins(10, 10, 10, 10)
        cells_vbox.addLayout(cells_stat_panel)
        cells_vbox.addWidget(self.cells_chart)
        charts_grid.addWidget(cells_panel, 1, 1)
        self.graphs["cells_timeline"] = self.cells_chart
        main_layout.addLayout(charts_grid, 1)
        
        # After all three charts are created, synchronize their x-axes
        if pg is not None:
            vb_coins = self.coins_chart.plot_widget.getViewBox()
            vb_gems = self.gems_chart.plot_widget.getViewBox()
            vb_cells = self.cells_chart.plot_widget.getViewBox()
            # Link all three bidirectionally
            vb_coins.setXLink(vb_gems)
            vb_coins.setXLink(vb_cells)
            vb_gems.setXLink(vb_coins)
            vb_gems.setXLink(vb_cells)
            vb_cells.setXLink(vb_coins)
            vb_cells.setXLink(vb_gems)
            # Connect manual range change to disable autoscale
            for vb in [vb_coins, vb_gems, vb_cells]:
                vb.sigRangeChangedManually.connect(self._on_user_zoom_pan)
        
        return dashboard_widget
    
    def _create_connection_overlay(self) -> QWidget:
        """Create the connection overlay with proper full-screen coverage."""
        overlay_widget = QWidget()
        overlay_widget.setStyleSheet("""
            QWidget {
                background-color: rgba(0, 0, 0, 0.75);
            }
        """)
        
        # Create layout for the connection panel
        overlay_layout = QVBoxLayout(overlay_widget)
        overlay_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        overlay_layout.setContentsMargins(40, 40, 40, 40)
        
        # Add the connection panel
        overlay_layout.addWidget(self.connection_panel)
        
        return overlay_widget
    
    def resizeEvent(self, event):
        """Handle resize event to keep overlay positioned correctly."""
        super().resizeEvent(event)
        
        # Resize the overlay to match the parent size
        if hasattr(self, 'connection_overlay_widget'):
            self.connection_overlay_widget.resize(self.size())
    
    def set_connection_active(self, is_active: bool) -> None:
        """
        Set the connection active state and show/hide the connection panel.
        
        Args:
            is_active: True to show dashboard (connection active), 
                      False to show connection panel (connection inactive)
        """
        if is_active:
            # Hide the connection overlay
            if hasattr(self, 'connection_overlay_widget'):
                self.connection_overlay_widget.hide()
        else:
            # Show the connection overlay
            if hasattr(self, 'connection_overlay_widget'):
                self.connection_overlay_widget.resize(self.size())
                self.connection_overlay_widget.show()
                self.connection_overlay_widget.raise_()  # Bring to front
    
    def _update_stats(self):
        if self.run_id_label is None or self.round_start_label is None:
            return
        session = self.controller.session
        # --- Status panel ---
        if session.is_round_active:
            self.status_label.setText("ACTIVE")
            self.status_label.setStyleSheet("color: #2ecc40; font-weight: bold;")  # Green
        else:
            self.status_label.setText("INACTIVE")
            self.status_label.setStyleSheet("color: #ff4136; font-weight: bold;")  # Red
        # --- Only increment real time if run is active ---
        if not (session.is_emulator_connected and session.is_hook_active and session.is_round_active):
            self.run_id_label.setText("-")
            self.real_time_label.setText("-")
            self.round_start_label.setText("-")
            self.tier_label.setText("-")
            self.current_wave_label.setText("-")
            self._last_run_id = None
            self._last_start_time = None
            return
        # Use current round's run_id if available
        run_id = session.current_round_seed
        run = None
        if run_id is not None:
            run = self.controller.db_service.get_run_by_id(str(run_id))
        # Fallback: use latest run if no current round
        if run is None:
            runs_df = self.controller.db_service.get_all_runs(limit=1)
            if not runs_df.empty:
                run = runs_df.iloc[0].to_dict()
        # Update stat panels from run
        if run is not None:
            run_id_val = run.get("run_id")
            start_time = run.get("start_time")
            # --- RESET CHARTS IF NEW RUN DETECTED ---
            if self._last_run_id != run_id_val:
                if hasattr(self, 'coins_chart'):
                    self.coins_chart.clear_data()
                if hasattr(self, 'gems_chart'):
                    self.gems_chart.clear_data()
                if hasattr(self, 'cells_chart'):
                    self.cells_chart.clear_data()
            self.run_id_label.setText(str(run_id_val) if run_id_val else "-")
            # Tier
            tier_val = run.get("tier")
            self.tier_label.setText(str(tier_val) if tier_val is not None else "-")
            # Start time and duration
            if start_time:
                if self._last_run_id != run_id_val or not hasattr(self, '_last_start_time'):
                    self._last_run_id = run_id_val
                    self._last_start_time = start_time
                now = time.time()
                elapsed = now - (start_time / 1000.0 if start_time > 1e12 else start_time)
                self.real_time_label.setText(format_duration_long(elapsed))
                ts = start_time / 1000.0 if start_time > 1e12 else start_time
                dt_str = datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")
                self.round_start_label.setText(dt_str)
            else:
                self.real_time_label.setText("-")
                self.round_start_label.setText("-")
            # Current Wave (latest from metrics)
            try:
                df = self.controller.db_service.get_run_metrics(str(run_id_val), "round_coins")
                if not df.empty and "real_timestamp" in df.columns:
                    # Get the latest current_wave from the metrics table
                    # But get_run_metrics does not return current_wave, so query directly
                    # Instead, get the latest current_wave from the metrics table for this run
                    if self.controller.db_service.sqlite_conn is not None:
                        query = "SELECT current_wave FROM metrics WHERE run_id = ? ORDER BY real_timestamp DESC LIMIT 1"
                        cursor = self.controller.db_service.sqlite_conn.execute(query, (str(run_id_val),))
                        row = cursor.fetchone()
                        if row is not None:
                            self.current_wave_label.setText(str(row[0]))
                        else:
                            self.current_wave_label.setText("-")
                    else:
                        self.current_wave_label.setText("-")
                else:
                    self.current_wave_label.setText("-")
            except Exception:
                self.current_wave_label.setText("-")
        else:
            self.run_id_label.setText("-")
            self.real_time_label.setText("-")
            self.round_start_label.setText("-")
            self.tier_label.setText("-")
            self.current_wave_label.setText("-")
    
    @pyqtSlot(str, object)
    def update_metric_display(self, metric_name: str, value: Any) -> None:
        """
        Update metric display - for coins, we'll add it to the chart.
        Args:
            metric_name: The name/ID of the metric to update  
            value: The new value for the metric
        """
        # For coins metric, update the chart using the DataFrame from the database (prevents x-axis desync in test mode)
        if metric_name == "round_coins":
            run_id = getattr(self.controller.session, 'current_round_seed', None)
            if run_id is not None:
                df = self.controller.db_service.get_run_metrics(str(run_id), "round_coins")
                if not df.empty:
                    total = df["round_coins"].iloc[-1]
                    elapsed = (df["real_timestamp"].iloc[-1] - df["real_timestamp"].iloc[0]) / 3600 if len(df) > 1 else 0
                    cph = total / elapsed if elapsed > 0 else 0
                    self.coins_total_label.setText(f"Total Coins: {format_currency(total)}")
                    self.coins_per_hour_label.setText(f"CPH: {format_currency(cph)}")
                    self.coins_chart.plot_data(df, metric_name="round_coins", normalize_x=True)
                else:
                    self.coins_total_label.setText("Total Coins: -")
                    self.coins_per_hour_label.setText("CPH: -")
                    self.coins_chart.clear_data()
            else:
                self.coins_total_label.setText("Total Coins: -")
                self.coins_per_hour_label.setText("CPH: -")
                self.coins_chart.clear_data()
        # For gems, update the chart and stat panel if either underlying metric is updated
        if metric_name in ("round_gems_from_blocks_value", "round_gems_from_ads_value"):
            # Trigger a full update of the gems chart and stat panel
            run_id = getattr(self.controller.session, 'current_round_seed', None)
            if run_id is not None:
                df = self.controller.db_service.get_total_gems_over_time(str(run_id))
                if not df.empty:
                    total = df["total_gems"].iloc[-1]
                    elapsed = (df["real_timestamp"].iloc[-1] - df["real_timestamp"].iloc[0]) / 3600 if len(df) > 1 else 0
                    per_hour = total / elapsed if elapsed > 0 else 0
                    self.gems_total_label.setText(f"Total Gems: {format_currency(total)}")
                    self.gems_per_hour_label.setText(f"GPH: {format_currency(per_hour)}")
                    self.gems_chart.plot_data(df, metric_name="total_gems", normalize_x=True, x_col="real_timestamp", y_col="total_gems")
                else:
                    self.gems_total_label.setText("Total Gems: -")
                    self.gems_per_hour_label.setText("GPH: -")
                    self.gems_chart.clear_data()
        # No direct stat panel update here; handled by _update_stats timer
    
    @pyqtSlot(str, object)
    def update_graph(self, graph_name: str, data: object) -> None:
        """
        Update a specific graph with new data.
        Args:
            graph_name: The name/ID of the graph to update
            data: The new data (pandas DataFrame or dict with 'x' and 'y' values)
        """
        if graph_name in self.graphs:
            if graph_name == "coins_timeline":
                run_id = getattr(self.controller.session, 'current_round_seed', None)
                if run_id is not None:
                    df = self.controller.db_service.get_run_metrics(str(run_id), "round_coins")
                    if not df.empty:
                        # Update stat panels
                        total = df["round_coins"].iloc[-1]
                        elapsed = (df["real_timestamp"].iloc[-1] - df["real_timestamp"].iloc[0]) / 3600 if len(df) > 1 else 0
                        per_hour = total / elapsed if elapsed > 0 else 0
                        self.coins_total_label.setText(f"Total Coins: {format_currency(total)}")
                        self.coins_per_hour_label.setText(f"CPH: {format_currency(per_hour)}")
                        self.graphs[graph_name].plot_data(df, metric_name="round_coins", normalize_x=True)
                return
            if graph_name == "gems_timeline":
                run_id = getattr(self.controller.session, 'current_round_seed', None)
                if run_id is not None:
                    df = self.controller.db_service.get_total_gems_over_time(str(run_id))
                    if not df.empty:
                        total = df["total_gems"].iloc[-1]
                        elapsed = (df["real_timestamp"].iloc[-1] - df["real_timestamp"].iloc[0]) / 3600 if len(df) > 1 else 0
                        per_hour = total / elapsed if elapsed > 0 else 0
                        self.gems_total_label.setText(f"Total Gems: {format_currency(total)}")
                        self.gems_per_hour_label.setText(f"GPH: {format_currency(per_hour)}")
                        self.graphs[graph_name].plot_data(df, metric_name="total_gems", normalize_x=True, x_col="real_timestamp", y_col="total_gems")
                    else:
                        self.gems_total_label.setText("Total Gems: -")
                        self.gems_per_hour_label.setText("GPH: -")
                        self.graphs[graph_name].clear_data()
                return
            if graph_name == "cells_timeline":
                run_id = getattr(self.controller.session, 'current_round_seed', None)
                if run_id is not None:
                    df = self.controller.db_service.get_run_metrics(str(run_id), "round_cells")
                    if not df.empty:
                        total = df["round_cells"].iloc[-1]
                        elapsed = (df["real_timestamp"].iloc[-1] - df["real_timestamp"].iloc[0]) / 3600 if len(df) > 1 else 0
                        per_hour = total / elapsed if elapsed > 0 else 0
                        self.cells_total_label.setText(f"Total Cells: {format_currency(total)}")
                        self.cells_per_hour_label.setText(f"Cells Per Hour: {format_currency(per_hour)}")
                        self.graphs[graph_name].plot_data(df, metric_name="round_cells", normalize_x=True)
                return
            if graph_name == "wave_coins_timeline":
                run_id = getattr(self.controller.session, 'current_round_seed', None)
                if run_id is not None:
                    df = self.controller.db_service.get_wave_coins_per_wave(str(run_id))
                    self.graphs[graph_name].plot_data(df, x_col="current_wave", y_col="metric_value", normalize_x=False)
                return
            # Handle pandas DataFrame (new format)
            if pd is not None and hasattr(data, 'empty'):
                metric_name = graph_name.replace('_timeline', '')
                self.graphs[graph_name].plot_data(data, metric_name=metric_name)
            # Handle legacy dict format
            elif isinstance(data, dict):
                x_value = data.get('x', time.time())
                y_value = data.get('y', 0)
                self.graphs[graph_name].append_data_point(x_value, y_value)

    def clear_all_data(self) -> None:
        """Clear all graph data."""
        # Clear the coins chart
        if hasattr(self, 'coins_chart'):
            self.coins_chart.clear_data()
    
    def showEvent(self, event) -> None:
        """Handle the widget show event."""
        super().showEvent(event)
        # Could trigger data refresh here if needed
    
    def hideEvent(self, event) -> None:
        """Handle the widget hide event."""
        super().hideEvent(event)
    
    def _on_autoscale_toggled(self, state):
        self.autoscale_enabled = bool(state)
        charts = [self.coins_chart, self.gems_chart, self.cells_chart, self.wave_coins_chart]
        if self.autoscale_enabled:
            for chart in charts:
                chart.plot_widget.enableAutoRange(axis=ViewBox.XYAxes, enable=True)
        else:
            for chart in charts:
                chart.plot_widget.enableAutoRange(axis=ViewBox.XYAxes, enable=False)
    
    def _on_user_zoom_pan(self, *args, **kwargs):
        if self.autoscale_enabled:
            self.autoscale_checkbox.setChecked(False)
            self.autoscale_enabled = False
            charts = [self.coins_chart, self.gems_chart, self.cells_chart, self.wave_coins_chart]
            for chart in charts:
                chart.plot_widget.enableAutoRange(axis=ViewBox.XYAxes, enable=False)
            self._glow_autoscale_checkbox()
    
    def _glow_autoscale_checkbox(self):
        # Briefly animate the checkbox to indicate autoscale was disabled
        orig_style = self.autoscale_checkbox.styleSheet()
        glow_style = "QCheckBox { background-color: #ffe066; border-radius: 4px; }"
        self.autoscale_checkbox.setStyleSheet(glow_style)
        if self._autoscale_glow_timer is not None:
            self._autoscale_glow_timer.stop()
        self._autoscale_glow_timer = QTimer(self)
        self._autoscale_glow_timer.setSingleShot(True)
        self._autoscale_glow_timer.timeout.connect(lambda: self.autoscale_checkbox.setStyleSheet(orig_style))
        self._autoscale_glow_timer.start(600)

# Helper for duration formatting

def format_duration_long(seconds: float) -> str:
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts) 