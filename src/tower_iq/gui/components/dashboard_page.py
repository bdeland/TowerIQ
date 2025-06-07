"""
TowerIQ v1.0 - Dashboard Page

This module defines the DashboardPage widget and its child components for displaying
live game metrics and graphs in the main application window.
"""

from typing import TYPE_CHECKING, Any, Dict, List
import time

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, 
    QFrame, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSlot, QTimer
from PyQt6.QtGui import QFont, QPalette

try:
    import pyqtgraph as pg
except ImportError:
    pg = None

if TYPE_CHECKING:
    from tower_iq.core.main_controller import MainController


class MetricDisplayWidget(QFrame):
    """
    A reusable component to display a single metric with name and value.
    
    Shows a metric name (e.g., "Coins per Hour") and its current value
    in a nicely formatted card-style widget.
    """
    
    def __init__(self, metric_name: str, unit: str = "", initial_value: Any = 0) -> None:
        """
        Initialize a metric display widget.
        
        Args:
            metric_name: The display name of the metric
            unit: Optional unit string (e.g., "/hour", "%")
            initial_value: Initial value to display
        """
        super().__init__()
        
        self.metric_name = metric_name
        self.unit = unit
        
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 10px;
                margin: 5px;
            }
            QFrame:hover {
                border: 1px solid #4CAF50;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        layout.setContentsMargins(15, 10, 15, 10)
        
        # Metric name label
        self.name_label = QLabel(metric_name)
        name_font = QFont()
        name_font.setPointSize(10)
        name_font.setBold(True)
        self.name_label.setFont(name_font)
        self.name_label.setStyleSheet("color: #666; text-align: center;")
        self.name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Value label
        self.value_label = QLabel(self._format_value(initial_value))
        value_font = QFont()
        value_font.setPointSize(18)
        value_font.setBold(True)
        self.value_label.setFont(value_font)
        self.value_label.setStyleSheet("color: #2196F3; text-align: center;")
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(self.name_label)
        layout.addWidget(self.value_label)
        
        # Set minimum size for consistent appearance
        self.setMinimumSize(150, 80)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    
    def set_value(self, value: Any) -> None:
        """
        Update the displayed value.
        
        Args:
            value: The new value to display
        """
        formatted_value = self._format_value(value)
        self.value_label.setText(formatted_value)
    
    def _format_value(self, value: Any) -> str:
        """
        Format a value for display.
        
        Args:
            value: The value to format
            
        Returns:
            Formatted string representation
        """
        if isinstance(value, (int, float)):
            if value >= 1000000:
                formatted = f"{value/1000000:.1f}M"
            elif value >= 1000:
                formatted = f"{value/1000:.1f}K"
            else:
                formatted = f"{value:.0f}" if isinstance(value, float) and value.is_integer() else f"{value:.1f}"
        else:
            formatted = str(value)
        
        return f"{formatted} {self.unit}".strip()


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
        self.max_points = 100  # Maximum number of data points to keep
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
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
        self.plot_widget.setLabel('bottom', 'Time')
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        
        # Create plot item
        self.plot_item = self.plot_widget.plot(
            pen=pg.mkPen(color='#2196F3', width=2),
            symbol='o',
            symbolSize=4,
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
        placeholder.setMinimumSize(300, 200)
    
    def append_data_point(self, x: float, y: float) -> None:
        """
        Add a new data point to the graph.
        
        Args:
            x: X-axis value (typically timestamp)
            y: Y-axis value
        """
        self.data_x.append(x)
        self.data_y.append(y)
        
        # Limit the number of points to prevent memory issues
        if len(self.data_x) > self.max_points:
            self.data_x = self.data_x[-self.max_points:]
            self.data_y = self.data_y[-self.max_points:]
        
        # Update the plot if pyqtgraph is available
        if pg is not None and hasattr(self, 'plot_item'):
            self.plot_item.setData(self.data_x, self.data_y)
    
    def clear_data(self) -> None:
        """Clear all data points from the graph."""
        self.data_x.clear()
        self.data_y.clear()
        
        if pg is not None and hasattr(self, 'plot_item'):
            self.plot_item.clear()


class DashboardPage(QWidget):
    """
    The primary view for displaying live game metrics and graphs.
    
    This widget is placed inside the MainWindow's QStackedWidget and shows
    all current game metrics, charts, and real-time data.
    """
    
    def __init__(self, controller: "MainController") -> None:
        """
        Initialize the dashboard page.
        
        Args:
            controller: The main controller instance
        """
        super().__init__()
        
        self.controller = controller
        self.metrics: Dict[str, MetricDisplayWidget] = {}
        self.graphs: Dict[str, GraphWidget] = {}
        
        self._init_ui()
        self._setup_demo_timer()  # For demonstration purposes
    
    def _init_ui(self) -> None:
        """
        Set up the layout and create all child display widgets.
        
        Creates a grid layout with metric cards at the top and graphs below.
        """
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Page title
        title_label = QLabel("Dashboard")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #333; margin-bottom: 10px;")
        main_layout.addWidget(title_label)
        
        # Create scroll area for the content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(20)
        
        # Metrics section
        metrics_label = QLabel("Current Metrics")
        metrics_font = QFont()
        metrics_font.setPointSize(14)
        metrics_font.setBold(True)
        metrics_label.setFont(metrics_font)
        metrics_label.setStyleSheet("color: #555; margin-bottom: 5px;")
        content_layout.addWidget(metrics_label)
        
        # Metrics grid
        metrics_frame = QFrame()
        metrics_layout = QGridLayout(metrics_frame)
        metrics_layout.setSpacing(10)
        
        # Create metric display widgets
        metric_configs = [
            ("coins_per_hour", "Coins per Hour", "/hr"),
            ("total_coins", "Total Coins", ""),
            ("efficiency", "Efficiency", "%"),
            ("uptime", "Uptime", "min"),
            ("level_progress", "Level Progress", "%"),
            ("session_duration", "Session Duration", "min")
        ]
        
        row, col = 0, 0
        for metric_id, metric_name, unit in metric_configs:
            metric_widget = MetricDisplayWidget(metric_name, unit)
            self.metrics[metric_id] = metric_widget
            metrics_layout.addWidget(metric_widget, row, col)
            
            col += 1
            if col >= 3:  # 3 columns
                col = 0
                row += 1
        
        content_layout.addWidget(metrics_frame)
        
        # Graphs section
        graphs_label = QLabel("Performance Graphs")
        graphs_label.setFont(metrics_font)
        graphs_label.setStyleSheet("color: #555; margin-bottom: 5px; margin-top: 20px;")
        content_layout.addWidget(graphs_label)
        
        # Graphs container
        graphs_frame = QFrame()
        graphs_layout = QGridLayout(graphs_frame)
        graphs_layout.setSpacing(15)
        
        # Create graph widgets
        graph_configs = [
            ("coins_timeline", "Coins Over Time", "Coins"),
            ("efficiency_timeline", "Efficiency Over Time", "Efficiency %")
        ]
        
        for i, (graph_id, title, y_label) in enumerate(graph_configs):
            graph_widget = GraphWidget(title, y_label)
            self.graphs[graph_id] = graph_widget
            graphs_layout.addWidget(graph_widget, i // 2, i % 2)
        
        content_layout.addWidget(graphs_frame)
        content_layout.addStretch()  # Push content to top
        
        scroll_area.setWidget(content_widget)
        main_layout.addWidget(scroll_area)
    
    def _setup_demo_timer(self) -> None:
        """
        Set up a timer for demonstration purposes.
        
        This simulates live data updates to test the UI components.
        In the actual implementation, this would be replaced by real
        data from the controller.
        """
        self.demo_timer = QTimer()
        self.demo_timer.timeout.connect(self._update_demo_data)
        self.demo_timer.start(2000)  # Update every 2 seconds
        
        self.demo_counter = 0
    
    def _update_demo_data(self) -> None:
        """Update demo data for testing purposes."""
        import random
        
        self.demo_counter += 1
        current_time = time.time()
        
        # Update metrics with random demo data
        demo_values = {
            "coins_per_hour": 1200 + random.randint(-100, 100),
            "total_coins": 45000 + self.demo_counter * 50,
            "efficiency": 85 + random.randint(-5, 15),
            "uptime": self.demo_counter * 2,
            "level_progress": min(99, self.demo_counter * 3),
            "session_duration": self.demo_counter * 2
        }
        
        for metric_id, value in demo_values.items():
            if metric_id in self.metrics:
                self.metrics[metric_id].set_value(value)
        
        # Update graphs
        if "coins_timeline" in self.graphs:
            self.graphs["coins_timeline"].append_data_point(
                current_time, demo_values["total_coins"]
            )
        
        if "efficiency_timeline" in self.graphs:
            self.graphs["efficiency_timeline"].append_data_point(
                current_time, demo_values["efficiency"]
            )
    
    @pyqtSlot(str, object)
    def update_metric_display(self, metric_name: str, value: Any) -> None:
        """
        Update a specific metric display.
        
        This slot receives signals from the MainController with new metric values.
        
        Args:
            metric_name: The name/ID of the metric to update
            value: The new value for the metric
        """
        if metric_name in self.metrics:
            self.metrics[metric_name].set_value(value)
    
    @pyqtSlot(str, object)
    def update_graph(self, graph_name: str, data: object) -> None:
        """
        Update a specific graph with new data.
        
        This slot receives new data points for graphs from the MainController.
        
        Args:
            graph_name: The name/ID of the graph to update
            data: The new data (should contain 'x' and 'y' values)
        """
        if graph_name in self.graphs and isinstance(data, dict):
            x_value = data.get('x', time.time())
            y_value = data.get('y', 0)
            self.graphs[graph_name].append_data_point(x_value, y_value)
    
    def clear_all_data(self) -> None:
        """Clear all metrics and graph data."""
        # Reset all metrics to zero
        for metric_widget in self.metrics.values():
            metric_widget.set_value(0)
        
        # Clear all graph data
        for graph_widget in self.graphs.values():
            graph_widget.clear_data()
    
    def showEvent(self, event) -> None:
        """Handle the widget show event."""
        super().showEvent(event)
        # Could trigger data refresh here if needed
    
    def hideEvent(self, event) -> None:
        """Handle the widget hide event."""
        super().hideEvent(event)
        # Could pause updates here if needed 