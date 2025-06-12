"""
TowerIQ v1.0 - Dashboard Page

This module defines the DashboardPage widget with a simple coins chart
for displaying cumulative coin values over time.
"""

from typing import TYPE_CHECKING, Any, Dict, List
import time

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, 
    QFrame, QScrollArea, QSizePolicy, QStackedLayout, QGraphicsBlurEffect
)
from PyQt6.QtCore import Qt, pyqtSlot, QTimer
from PyQt6.QtGui import QFont, QPalette

from .connection_state_panel import ConnectionStatePanel

try:
    import pyqtgraph as pg
except ImportError:
    pg = None

try:
    import pandas as pd
except ImportError:
    pd = None


class GraphWidget(QWidget):
    """
    A widget to display a real-time chart using pyqtgraph.
    
    If pyqtgraph is not available, displays a placeholder message.
    """
    
    def __init__(self, title: str, y_label: str = "Value") -> None:
        """
        Initialize a graph widget.
        
        Args:
            title: The title of the graph
            y_label: Label for the Y-axis
        """
        super().__init__()
        
        self.title = title
        self.y_label = y_label
        self.data_x: List[float] = []
        self.data_y: List[float] = []
        self.max_points = 1000  # Maximum number of data points to keep
        self.start_time = None  # Track start time for relative X-axis
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        if pg is not None:
            self._init_pyqtgraph()
        else:
            self._init_placeholder()
    
    def _init_pyqtgraph(self) -> None:
        """Initialize the pyqtgraph plot widget."""
        # Set background color
        pg.setConfigOption('background', 'w')
        pg.setConfigOption('foreground', 'k')
        
        # Create plot widget
        self.plot_widget = pg.PlotWidget(title=self.title)
        self.plot_widget.setLabel('left', self.y_label)
        self.plot_widget.setLabel('bottom', 'Time (seconds)')
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        
        # Set Y-axis to start at 0
        self.plot_widget.setYRange(0, 100, padding=0.1)
        
        # Set X-axis to start at 0
        self.plot_widget.setXRange(0, 60, padding=0.1)  # Start with 60 seconds view
        
        # Create plot item
        self.plot_item = self.plot_widget.plot(
            pen=pg.mkPen(color='#2196F3', width=3),
            symbol='o',
            symbolSize=6,
            symbolBrush='#2196F3'
        )
        
        self.layout().addWidget(self.plot_widget)
    
    def _init_placeholder(self) -> None:
        """Initialize a placeholder when pyqtgraph is not available."""
        placeholder = QFrame()
        placeholder.setFrameStyle(QFrame.Shape.StyledPanel)
        placeholder.setStyleSheet("""
            QFrame {
                background-color: #f5f5f5;
                border: 2px dashed #ccc;
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
        
        self.layout().addWidget(placeholder)
        
        # Set minimum size
        placeholder.setMinimumSize(400, 300)
    
    def append_data_point(self, x: float, y: float) -> None:
        """
        Add a new data point to the graph.
        
        Args:
            x: X-axis value (typically timestamp)
            y: Y-axis value
        """
        # Set start time on first data point
        if self.start_time is None:
            self.start_time = x
        
        # Convert to relative time (seconds from start)
        relative_time = x - self.start_time
        
        self.data_x.append(relative_time)
        self.data_y.append(y)
        
        # Limit the number of points to prevent memory issues
        if len(self.data_x) > self.max_points:
            self.data_x = self.data_x[-self.max_points:]
            self.data_y = self.data_y[-self.max_points:]
        
        # Update the plot if pyqtgraph is available
        if pg is not None and hasattr(self, 'plot_item'):
            self.plot_item.setData(self.data_x, self.data_y)
            
            # Auto-scale the view to fit data
            if len(self.data_x) > 1:
                x_max = max(self.data_x)
                y_max = max(self.data_y) if self.data_y else 100
                
                # Set ranges with some padding
                self.plot_widget.setXRange(0, max(x_max * 1.1, 10), padding=0)
                self.plot_widget.setYRange(0, max(y_max * 1.1, 100), padding=0)
    
    def plot_data(self, df) -> None:
        """
        Plot data from a pandas DataFrame.
        
        Args:
            df: pandas DataFrame with 'timestamp' and 'value' columns
        """
        if pg is None or not hasattr(self, 'plot_item'):
            return
        
        if df.empty:
            return
        
        # Convert timestamps to relative time if we have data
        if len(df) > 0:
            if self.start_time is None:
                self.start_time = df['timestamp'].iloc[0]
            
            relative_times = df['timestamp'] - self.start_time
            values = df['value']
            
            # Update our internal data tracking
            self.data_x = relative_times.tolist()
            self.data_y = values.tolist()
            
            # Plot the data
            self.plot_item.setData(self.data_x, self.data_y)
            
            # Auto-scale the view
            if len(self.data_x) > 1:
                x_max = max(self.data_x)
                y_max = max(self.data_y) if self.data_y else 100
                
                self.plot_widget.setXRange(0, max(x_max * 1.1, 10), padding=0)
                self.plot_widget.setYRange(0, max(y_max * 1.1, 100), padding=0)
    
    def clear_data(self) -> None:
        """Clear all data points from the graph."""
        self.data_x.clear()
        self.data_y.clear()
        self.start_time = None
        
        if pg is not None and hasattr(self, 'plot_item'):
            self.plot_item.clear()
            # Reset the view
            self.plot_widget.setXRange(0, 60, padding=0.1)
            self.plot_widget.setYRange(0, 100, padding=0.1)


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
        
        # Create the connection panel
        self.connection_panel = ConnectionStatePanel(self)
        
        self._init_ui()
    
    def _init_ui(self) -> None:
        """
        Set up the layout and create the coins chart.
        """
        # Create the main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
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
        
        # Page title
        title_label = QLabel("Coins Dashboard")
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #333; margin-bottom: 20px;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Create the coins chart
        self.coins_chart = GraphWidget("Cumulative Coins Over Time", "Coins")
        self.graphs["coins_timeline"] = self.coins_chart
        
        # Add chart to layout with full space
        main_layout.addWidget(self.coins_chart, 1)  # Stretch factor 1
        
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
    
    @pyqtSlot(str, object)
    def update_metric_display(self, metric_name: str, value: Any) -> None:
        """
        Update metric display - for coins, we'll add it to the chart.
        
        Args:
            metric_name: The name/ID of the metric to update  
            value: The new value for the metric
        """
        
        # For coins metric, add a point to the chart using current time
        if metric_name == "coins":
            current_time = time.time()
            if hasattr(self, 'coins_chart'):
                self.coins_chart.append_data_point(current_time, float(value))
    
    @pyqtSlot(str, object)
    def update_graph(self, graph_name: str, data: object) -> None:
        """
        Update a specific graph with new data.
        
        Args:
            graph_name: The name/ID of the graph to update
            data: The new data (pandas DataFrame or dict with 'x' and 'y' values)
        """
        if graph_name in self.graphs:
            # Handle pandas DataFrame (new format)
            if pd is not None and hasattr(data, 'empty'):
                self.graphs[graph_name].plot_data(data)
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