// ============================================================================
// IMPORTS - External libraries and internal utilities
// ============================================================================
import React, { useEffect, useState, useRef } from 'react';
// Material-UI components for UI elements (buttons, dialogs, menus, etc.)
import { 
  Box, 
  Typography, 
  CircularProgress, 
  Alert, 
  IconButton, 
  MenuItem, 
  MenuList,
  ListItemIcon, 
  ListItemText,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Tooltip,
  Drawer,
  Divider,
  Paper,
  Chip
} from '@mui/material';
// Material-UI icons for various actions (menu, fullscreen, edit, etc.)
import { 
  MoreVert as MoreVertIcon,
  Visibility as ViewIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Fullscreen as FullscreenIcon,
  FullscreenExit as FullscreenExitIcon,
  ArrowBack as ArrowBackIcon,
  SettingsBackupRestore as SettingsBackupRestoreIcon,
  BugReport as BugReportIcon
} from '@mui/icons-material';
// ECharts React wrapper for rendering charts
import ReactECharts from 'echarts-for-react';
// Internal imports for dashboard context, navigation, and utilities
import { DashboardPanel } from '../contexts/DashboardContext';
import { useNavigate } from 'react-router-dom';
import { useDashboardVariable } from '../contexts/DashboardVariableContext';
import { useDeveloper } from '../contexts/DeveloperContext';
import { applyTransformations } from '../services/transformationService';
import { grafanaToECharts, mergeWithEChartsOption } from '../utils/grafanaToECharts';
import { API_CONFIG } from '../config/environment';
import { getCategoricalColor } from '../utils/colorPalette';
import { formatCurrency, formatNumber } from '../utils/formattingUtils';
import DebugDrawer from './DebugDrawer';

// ============================================================================
// TYPE DEFINITIONS - Props and data structures
// ============================================================================

/**
 * Props interface for the DashboardPanelView component
 * Defines all the properties that can be passed to customize panel behavior
 */
interface DashboardPanelViewProps {
  panel: DashboardPanel;                    // The panel configuration and data
  data?: any[];                            // Pre-fetched data to use instead of fetching
  error?: string;                          // Error message from data fetching
  loading?: boolean;                       // External loading state from parent dashboard
  onClick?: () => void;                    // Callback when panel is clicked (edit mode)
  isEditMode?: boolean;                    // Whether panel is in edit mode
  showMenu?: boolean;                      // Whether to show the context menu button
  showFullscreen?: boolean;                // Whether to show the fullscreen button
  onDelete?: (panelId: string) => void;    // Callback when panel is deleted
  onEdit?: (panelId: string) => void;      // Callback when panel is edited
  onDataFetched?: (data: any[]) => void;   // Callback when data is fetched
  onFullscreenToggle?: (panelId: string) => void; // Callback for fullscreen toggle
}

/**
 * Interface for query results from the backend
 * Contains the data array and optional error message
 */
interface QueryResult {
  data: any[];
  error?: string;
}

// ============================================================================
// UTILITY FUNCTIONS - Helper functions for data processing
// ============================================================================

/**
 * Maps tier numbers to consistent colors using the standardized color palette
 * Used for bar charts that display tier-based data (like game tiers)
 * @param tier - The tier number to get color for
 * @param availableTiers - Array of all available tiers in the data
 * @returns CSS color string for the tier
 */
const getTierColor = (tier: number, availableTiers: number[]): string => {
  // Find the index of this tier in the sorted available tiers array
  const sortedTiers = [...availableTiers].sort((a, b) => a - b);
  const tierIndex = sortedTiers.indexOf(tier);
  
  // Use categorical colors in order for maximum contrast
  return getCategoricalColor(tierIndex >= 0 ? tierIndex : 0);
};

// ============================================================================
// MAIN COMPONENT - DashboardPanelViewComponent
// ============================================================================

/**
 * Main dashboard panel component that renders different types of charts and data visualizations
 * Supports multiple chart types: stat, timeseries, bar, pie, table, treemap, calendar
 * Includes drilldown functionality, fullscreen mode, and context menus
 */
const DashboardPanelViewComponent: React.FC<DashboardPanelViewProps> = ({ 
  panel, 
  data,
  error: externalError,
  loading: externalLoading = false,
  onClick, 
  isEditMode = false,
  showMenu = true,
  showFullscreen = false,
  onDelete,
  onEdit,
  onDataFetched,
  onFullscreenToggle
}) => {
  // ============================================================================
  // HOOKS AND STATE MANAGEMENT
  // ============================================================================
  
  const navigate = useNavigate(); // React Router navigation hook
  const { isDevMode } = useDeveloper(); // Developer mode context
  
  // Core data and loading states
  const [queryResult, setQueryResult] = useState<QueryResult>({ data: [] }); // Query results from backend
  const [internalLoading, setInternalLoading] = useState(false); // Internal loading state for data fetching
  const [error, setError] = useState<string | null>(null); // Error state for failed operations
  
  // Combined loading state: external (from dashboard) OR internal (from panel)
  const loading = externalLoading || internalLoading;
  
  // Debounced loading state to prevent rapid flashing
  const [debouncedLoading, setDebouncedLoading] = useState(false);
  
  // Effect to debounce loading state changes
  useEffect(() => {
    if (loading) {
      // Show loading immediately when it starts
      setDebouncedLoading(true);
    } else {
      // Add small delay when hiding to prevent flashing
      const timer = setTimeout(() => {
        setDebouncedLoading(false);
      }, 100); // 100ms delay
      
      return () => clearTimeout(timer);
    }
  }, [loading]);
  const chartRef = useRef<ReactECharts>(null); // Reference to ECharts instance
  const dataFetchedRef = useRef<boolean>(false); // Prevents duplicate data fetching
  
  // UI interaction states
  const [menuOpen, setMenuOpen] = useState(false); // Context menu visibility
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false); // Delete confirmation dialog
  const [debugDrawerOpen, setDebugDrawerOpen] = useState(false); // Debug drawer visibility
  
  // Drilldown functionality states
  const [isDrilldown, setIsDrilldown] = useState(false); // Whether currently in drilldown mode
  const [originalOption, setOriginalOption] = useState<any>(null); // Original chart config for back navigation
  const [drilldownData, setDrilldownData] = useState<any[]>([]); // Data for drilldown view
  
  // Calendar-specific drilldown states (hierarchical navigation)
  const [calendarDrilldownLevel, setCalendarDrilldownLevel] = useState<number>(0); // Current drill level
  const [calendarDrilldownStack, setCalendarDrilldownStack] = useState<any[]>([]); // Navigation stack
  
  // Performance optimization refs (for zoom/pan operations)
  const zoomUpdateTimeoutRef = useRef<NodeJS.Timeout | null>(null); // Debounced zoom updates
  const lastZoomStateRef = useRef<{start: number, end: number} | null>(null); // Last zoom state
  
  // Chart interaction state
  const [isChartModified, setIsChartModified] = useState(false); // Whether chart has been zoomed/panned
  


  // ============================================================================
  // DATA FETCHING FUNCTIONS
  // ============================================================================

  /**
   * Fetches data from the backend API based on the panel's SQL query
   * Handles loading states, errors, and placeholder queries
   * Called when panel needs fresh data (not using pre-fetched data)
   */
  const fetchPanelData = async () => {
    if (!panel.query) {
      setError('No query defined for panel');
      return;
    }

    // Don't fetch if query contains placeholders - should use pre-fetched data
    if (panel.query.includes('${')) {
      console.log('DashboardPanelView: Skipping fetch for query with placeholders:', panel.query);
      // Set loading state instead of error for placeholders
      setInternalLoading(true);
      setError(null);
      return;
    }

    setInternalLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query: panel.query }),
      });

      if (!response.ok) {
        throw new Error(`Query failed: ${response.statusText}`);
      }

      const result = await response.json();
      const data = result.data || [];
      setQueryResult({ data });
      
      // Call the callback to provide data to parent component
      if (onDataFetched) {
        onDataFetched(data);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch panel data';
      setError(errorMessage);
      console.error('Error fetching panel data:', err);
    } finally {
      setInternalLoading(false);
    }
  };

  // ============================================================================
  // DRILLDOWN FUNCTIONALITY
  // ============================================================================

  /**
   * Handles standard drilldown functionality (clicking on chart elements)
   * Used for bar charts and other chart types where clicking shows detailed data
   * @param runNumber - The run number or data index that was clicked
   */
  const handleDrilldown = async (runNumber: number) => {
    if (!panel.echartsOption.drilldown) return;
    
    setInternalLoading(true);
    try {
      // Store original option for back navigation
      if (!originalOption) {
        setOriginalOption(getTransformedEChartsOption());
      }
      
      // Replace placeholders in drilldown query
      let drilldownQuery = panel.echartsOption.drilldown.query;
      drilldownQuery = drilldownQuery.replace(/{run_number}/g, runNumber.toString());
      
      // Handle tier_filter replacement - remove the placeholder and any trailing WHERE clause
      drilldownQuery = drilldownQuery.replace(/\$\{tier_filter\}/g, '');
      
      // Remove trailing semicolon to prevent issues with backend LIMIT addition
      drilldownQuery = drilldownQuery.trim().replace(/;+$/, '');
      
      // Debug: Log the processed query
      console.log('Drilldown query being sent:', drilldownQuery);
      
      // Fetch drilldown data
      const response = await fetch(`${API_CONFIG.BASE_URL}/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: drilldownQuery })
      });
      
      if (!response.ok) {
        // Try to get the error details from the response
        let errorMessage = `HTTP error! status: ${response.status}`;
        try {
          const errorData = await response.json();
          errorMessage += ` - ${errorData.detail || errorData.message || 'Unknown error'}`;
        } catch (e) {
          // If we can't parse the error response, use the status text
          errorMessage += ` - ${response.statusText}`;
        }
        throw new Error(errorMessage);
      }
      
      const result = await response.json();
      console.log('Drilldown data received:', result.data);
      setDrilldownData(result.data || []);
      setIsDrilldown(true);
      
    } catch (err) {
      console.error('Drilldown fetch error:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch drilldown data');
    } finally {
      setInternalLoading(false);
    }
  };

  /**
   * Handles calendar hierarchical drilldown functionality
   * Used for calendar heatmaps where clicking on dates drills down to more detailed views
   * Supports multiple levels: year -> quarter -> month -> week -> day -> hour
   * @param params - ECharts click event parameters containing the clicked date
   */
  const handleCalendarDrilldown = async (params: any) => {
    if (!panel.echartsOption.drilldown?.enabled || panel.echartsOption.drilldown.type !== 'calendar_hierarchical') return;
    
    const drilldownConfig = panel.echartsOption.drilldown;
    const levels = drilldownConfig.levels;
    
    if (!levels || calendarDrilldownLevel >= levels.length - 1) return;
    
    setInternalLoading(true);
    try {
      // Store original option for back navigation on first drill
      if (!originalOption) {
        setOriginalOption(getTransformedEChartsOption());
      }
      
      // Determine what was clicked and extract date information
      let drillParams: any = {};
      const clickedDate = new Date(params.data[0]);
      
      // Determine next drill level and extract parameters
      const nextLevel = levels[calendarDrilldownLevel + 1];
      let drilldownQuery = nextLevel.query;
      
      // Extract date components for parameter replacement
      const year = clickedDate.getFullYear();
      const month = String(clickedDate.getMonth() + 1).padStart(2, '0');
      const quarter = Math.ceil((clickedDate.getMonth() + 1) / 3);
      const date = params.data[0]; // YYYY-MM-DD format
      
      // Calculate week boundaries
      const weekStart = new Date(clickedDate);
      weekStart.setDate(clickedDate.getDate() - clickedDate.getDay());
      const weekEnd = new Date(weekStart);
      weekEnd.setDate(weekStart.getDate() + 6);
      
      const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                         'July', 'August', 'September', 'October', 'November', 'December'];
      
      // Replace placeholders in query
      drillParams = {
        year: year.toString(),
        quarter: quarter.toString(),
        month: month,
        month_name: monthNames[clickedDate.getMonth()],
        date: date,
        week_start: weekStart.toISOString().split('T')[0],
        week_end: weekEnd.toISOString().split('T')[0]
      };
      
      // Replace all placeholders
      Object.keys(drillParams).forEach(key => {
        const regex = new RegExp(`{${key}}`, 'g');
        drilldownQuery = drilldownQuery.replace(regex, drillParams[key]);
      });
      
      // Handle tier_filter replacement
      drilldownQuery = drilldownQuery.replace(/\$\{tier_filter\}/g, '');
      drilldownQuery = drilldownQuery.trim().replace(/;+$/, '');
      
      console.log('Calendar drilldown query being sent:', drilldownQuery);
      console.log('Drill parameters:', drillParams);
      
      // Fetch drilldown data
      const response = await fetch(`${API_CONFIG.BASE_URL}/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: drilldownQuery })
      });
      
      if (!response.ok) {
        let errorMessage = `HTTP error! status: ${response.status}`;
        try {
          const errorData = await response.json();
          errorMessage += ` - ${errorData.detail || errorData.message || 'Unknown error'}`;
        } catch (e) {
          errorMessage += ` - ${response.statusText}`;
        }
        throw new Error(errorMessage);
      }
      
      const result = await response.json();
      console.log('Calendar drilldown data received:', result.data);
      
      // Store current state in the stack
      setCalendarDrilldownStack(prev => [...prev, {
        level: calendarDrilldownLevel,
        data: drilldownData.length > 0 ? drilldownData : queryResult.data,
        params: drillParams,
        title: panel.title
      }]);
      
      setDrilldownData(result.data || []);
      setCalendarDrilldownLevel(prev => prev + 1);
      setIsDrilldown(true);
      
    } catch (err) {
      console.error('Calendar drilldown fetch error:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch calendar drilldown data');
    } finally {
      setInternalLoading(false);
    }
  };
  
  // ============================================================================
  // NAVIGATION AND RESET FUNCTIONS
  // ============================================================================

  /**
   * Returns to the original chart view, clearing all drilldown state
   * Resets all drilldown-related state variables and clears performance optimization refs
   */
  const handleBackToOriginal = () => {
    setIsDrilldown(false);
    setDrilldownData([]);
    setOriginalOption(null);
    setIsChartModified(false);
    
    // Reset calendar drilldown state
    setCalendarDrilldownLevel(0);
    setCalendarDrilldownStack([]);
    
    // Clear any pending zoom updates
    if (zoomUpdateTimeoutRef.current) {
      clearTimeout(zoomUpdateTimeoutRef.current);
      zoomUpdateTimeoutRef.current = null;
    }
    lastZoomStateRef.current = null;
  };

  /**
   * Handles back navigation in calendar hierarchical drilldown
   * Pops the last state from the navigation stack and restores the previous view
   */
  const handleCalendarDrilldownBack = () => {
    if (calendarDrilldownStack.length === 0) {
      handleBackToOriginal();
      return;
    }
    
    const previousState = calendarDrilldownStack[calendarDrilldownStack.length - 1];
    setCalendarDrilldownStack(prev => prev.slice(0, -1));
    setCalendarDrilldownLevel(previousState.level);
    setDrilldownData(previousState.data);
    
    // If we're back to the original level, exit drilldown mode
    if (previousState.level === 0) {
      setIsDrilldown(false);
      setOriginalOption(null);
    }
  };
  
  /**
   * Resets chart zoom and pan to default state
   * Used when the reset button is clicked in drilldown mode
   */
  const handleChartReset = () => {
    if (chartRef.current) {
      const chartInstance = chartRef.current.getEchartsInstance();
      
      // Reset dataZoom to default state
      chartInstance.dispatchAction({
        type: 'dataZoom',
        start: 0,
        end: 100
      });
      
      setIsChartModified(false);
      lastZoomStateRef.current = { start: 0, end: 100 };
    }
  };
  
  // ============================================================================
  // EFFECTS AND EVENT HANDLERS
  // ============================================================================

  /**
   * Cleanup effect - clears timeouts when component unmounts
   * Prevents memory leaks from pending zoom update timeouts
   */
  useEffect(() => {
    return () => {
      if (zoomUpdateTimeoutRef.current) {
        clearTimeout(zoomUpdateTimeoutRef.current);
      }
    };
  }, []);
  
  /**
   * Chart event handlers for ECharts interactions
   * Handles click events for drilldown and zoom events for performance optimization
   */
  const onChartEvents = {
    click: (params: any) => {
      if (panel.echartsOption.drilldown?.enabled && params.componentType === 'series') {
        // Check if this is a calendar hierarchical drilldown
        if (panel.echartsOption.drilldown.type === 'calendar_hierarchical' && panel.type === 'calendar') {
          handleCalendarDrilldown(params);
        } else {
          // Standard drilldown (for bar charts, etc.)
          const runNumber = params.dataIndex + 1; // Assuming 1-based indexing
          handleDrilldown(runNumber);
        }
      }
    },
    /**
     * Handles zoom/pan events for performance optimization
     * Dynamically shows/hides chart symbols based on data density
     * Debounces updates to prevent excessive calculations
     */
    datazoom: (_params: any) => {
      // Handle zoom events for dynamic point visibility with performance optimizations
      if (!isDrilldown || !chartRef.current || drilldownData.length === 0) {
        return; // Early exit if not applicable
      }
      
      // Clear any existing timeout
      if (zoomUpdateTimeoutRef.current) {
        clearTimeout(zoomUpdateTimeoutRef.current);
      }
      
      // Debounce the zoom updates to avoid excessive calculations
      zoomUpdateTimeoutRef.current = setTimeout(() => {
        const chartInstance = chartRef.current?.getEchartsInstance();
        if (!chartInstance) return;
        
        const option = chartInstance.getOption();
        const dataZoomOption = option.dataZoom;
        let startPercent = 0;
        let endPercent = 100;
        
        if (dataZoomOption && Array.isArray(dataZoomOption) && dataZoomOption.length > 0) {
          const zoom = dataZoomOption[0];
          startPercent = Math.round((zoom.start || 0) * 10) / 10; // Round to 1 decimal
          endPercent = Math.round((zoom.end || 100) * 10) / 10;
        }
        
        // Check if zoom state actually changed (avoid redundant updates)
        const lastZoom = lastZoomStateRef.current;
        if (lastZoom && lastZoom.start === startPercent && lastZoom.end === endPercent) {
          return; // No change, skip update
        }
        lastZoomStateRef.current = { start: startPercent, end: endPercent };
        
        // Update chart modified state
        const isDefaultZoom = startPercent === 0 && endPercent === 100;
        setIsChartModified(!isDefaultZoom);
        
        const visibleRatio = (endPercent - startPercent) / 100;
        const totalPoints = drilldownData.length;
        const visiblePointCount = Math.ceil(totalPoints * visibleRatio);
        const maxPointsForSymbols = 50;
        
        // Only calculate Y-axis range if we're actually zoomed in
        let yAxisMin = null;
        let yAxisMax = null;
        
        if (startPercent !== 0 || endPercent !== 100) {
          // Efficient Y-range calculation using pre-sorted data assumption
          const startIndex = Math.floor((startPercent / 100) * totalPoints);
          const endIndex = Math.min(Math.ceil((endPercent / 100) * totalPoints), totalPoints);
          
          // Use reduce for better performance than forEach
          const yRange = drilldownData.slice(startIndex, endIndex).reduce(
            (acc, point) => {
              const y = point.y_value;
              return {
                min: Math.min(acc.min, y),
                max: Math.max(acc.max, y)
              };
            },
            { min: Number.MAX_VALUE, max: Number.MIN_VALUE }
          );
          
          const padding = (yRange.max - yRange.min) * 0.1;
          yAxisMin = Math.max(0, yRange.min - padding);
          yAxisMax = yRange.max + padding;
        }
        
        // Batch all option updates into a single setOption call
        const updates: any = {};
        
        // Update series symbol
        if (option.series && Array.isArray(option.series) && option.series.length > 0) {
          updates.series = [{
            ...option.series[0],
            symbol: visiblePointCount <= maxPointsForSymbols ? 'circle' : 'none',
            symbolSize: visiblePointCount <= maxPointsForSymbols ? 4 : 0
          }];
        }
        
        // Update Y-axis
        if (option.yAxis && Array.isArray(option.yAxis) && option.yAxis.length > 0) {
          updates.yAxis = [{
            ...option.yAxis[0],
            min: yAxisMin,
            max: yAxisMax
          }];
        }
        
        // Single chart update for better performance
        chartInstance.setOption(updates, false);
        
      }, 100); // 100ms debounce
    }
  };

  // ============================================================================
  // CHART CONFIGURATION AND DATA TRANSFORMATION
  // ============================================================================

  /**
   * Transforms data based on panel type and returns ECharts configuration
   * This is the core function that converts raw data into chart-ready format
   * Handles different chart types: stat, timeseries, bar, pie, table, treemap, calendar
   * Also manages drilldown chart configurations
   */
  const getTransformedEChartsOption = () => {
    // If in drilldown mode, return drilldown chart option
    if (isDrilldown && panel.echartsOption.drilldown) {
      const drilldownOption = { ...panel.echartsOption.drilldown.echartsOption };
      
      // Apply consistent grid configuration with smart spacing
      if (!drilldownOption.grid) {
        drilldownOption.grid = {};
      }
      drilldownOption.grid = {
        ...drilldownOption.grid,
        left: '0%',     // Minimal space for y-axis labels
        right: '2%',    // Minimal space for right side (no legend or right elements)
        top: '2%',      // Minimal space for top (no title in drilldown)
        bottom: '5%',   // Space for x-axis labels only (no slider needed)
        containLabel: true // Ensure labels are contained within the grid
      };
      
      // Ensure tooltips and other elements don't overflow
      if (!drilldownOption.tooltip) {
        drilldownOption.tooltip = {};
      }
      drilldownOption.tooltip = {
        ...drilldownOption.tooltip,
        confine: true, // Prevent tooltip from overflowing the chart container
        position: 'inside' // Keep tooltips within chart bounds
      };
      
      // Ensure axis labels don't overflow
      if (drilldownOption.xAxis) {
        drilldownOption.xAxis = {
          ...drilldownOption.xAxis,
          axisLabel: {
            ...drilldownOption.xAxis.axisLabel,
            overflow: 'truncate', // Truncate long labels
            width: 60, // Limit label width
            rotate: 0 // Keep labels horizontal
          }
        };
      }
      
      if (drilldownOption.yAxis) {
        drilldownOption.yAxis = {
          ...drilldownOption.yAxis,
          axisLabel: {
            ...drilldownOption.yAxis.axisLabel,
            overflow: 'truncate', // Truncate long currency labels
            width: 80 // Limit Y-axis label width
          }
        };
      }
      
      // Configure dataZoom to hide slider but keep inside zoom functionality
      if (drilldownOption.dataZoom) {
        drilldownOption.dataZoom = drilldownOption.dataZoom.map((zoom: any) => {
          if (zoom.type === 'slider') {
            // Hide the slider but keep inside zoom
            return {
              type: 'inside',
              xAxisIndex: zoom.xAxisIndex || 0,
              filterMode: zoom.filterMode || 'none'
            };
          }
          return zoom; // Keep inside zoom as-is
        });
      }
      
      // Update chart with drilldown data
      if (drilldownData.length > 0) {
        // For value-type x-axis (like wave numbers), we need coordinate pairs [x, y]
        const coordinateData = drilldownData.map(row => [row.x_value, row.y_value]);
        
        if (drilldownOption.series && drilldownOption.series[0]) {
          drilldownOption.series[0].data = coordinateData;
          
          // Dynamic point visibility based on data density
          const dataPointCount = coordinateData.length;
          const maxPointsForSymbols = 50; // Threshold for showing individual points - more restrictive
          
          // Initial symbol configuration - start hidden for large datasets
          console.log(`📊 Initial chart setup: ${dataPointCount} points, threshold: ${maxPointsForSymbols}`);
          
          if (dataPointCount > maxPointsForSymbols) {
            // Too many points - start with symbols hidden
            console.log('📊 Initial: Hiding symbols (too many points)');
            drilldownOption.series[0].symbol = 'none';
            drilldownOption.series[0].symbolSize = 0;
          } else {
            // Few enough points - always show symbols
            console.log('📊 Initial: Showing symbols (few enough points)');
            drilldownOption.series[0].symbol = 'circle';
            drilldownOption.series[0].symbolSize = 4;
          }
          
          // Ensure smooth line and good performance
          drilldownOption.series[0].smooth = true;
          drilldownOption.series[0].lineStyle = { width: 1 };
          
          // Add emphasis for better interaction
          drilldownOption.series[0].emphasis = {
            focus: 'series',
            scale: true,
            lineStyle: { width: 1 }
          };
        }
        
        // Don't set xAxis.data for value-type axes - it's only for category axes
      }
      
      return drilldownOption;
    }
    
    const baseOption = { ...panel.echartsOption };
    
    // Remove title to prevent "Panel 1" from showing in chart
    delete baseOption.title;
    
    // Ensure grid configuration is present for consistent chart rendering
    if (!baseOption.grid) {
      baseOption.grid = {};
    }
    baseOption.grid = {
      ...baseOption.grid,
      left: '2%',     // Minimal space for y-axis labels
      right: '2%',    // Minimal space for right-side elements
      top: '2%',      // Minimal space for top labels/titles
      bottom: '2%',   // Minimal space for x-axis labels
      containLabel: true // Ensure labels are contained within the grid
    };
    
    // Ensure tooltips and other elements don't overflow
    if (!baseOption.tooltip) {
      baseOption.tooltip = {};
    }
    baseOption.tooltip = {
      ...baseOption.tooltip,
      confine: true // Prevent tooltip from overflowing the chart container
    };
    
    // Ensure legend doesn't overflow
    if (baseOption.legend) {
      baseOption.legend = {
        ...baseOption.legend,
        confine: true // Prevent legend from overflowing the chart container
      };
    }
    
    if (!queryResult.data || queryResult.data.length === 0) {
      return baseOption;
    }

    // If panel has transformations, use the new transformation service
    if (panel.transformations && panel.transformations.length > 0) {
      console.log('🔧 Applying transformations:', panel.transformations);
      console.log('📊 Original data:', queryResult.data);
      
      try {
        // Apply transformations using the transformation service
        const transformedDataFrames = applyTransformations(queryResult.data, panel.transformations);
        console.log('📈 Transformed DataFrames:', transformedDataFrames);
        
        // Convert transformed DataFrames to ECharts format
        const echartsData = grafanaToECharts(transformedDataFrames, panel.type);
        console.log('📉 ECharts data:', echartsData);
        
        // Merge with existing ECharts option
        const mergedOption = mergeWithEChartsOption(echartsData, baseOption, panel.type);
        console.log('🎯 Final merged option:', mergedOption);
        
        return mergedOption;
      } catch (error) {
        console.error('❌ Error applying transformations:', error);
        // Fall through to legacy transformation logic
      }
    }

    /**
     * Helper function to intelligently map data columns to chart axes
     * Auto-detects appropriate columns for x-axis, y-axis, and labels
     * Falls back to manual column mapping if provided in panel config
     */
    const getColumnMapping = (data: any[]) => {
      if (data.length === 0) return { xAxis: null, yAxis: null, label: null };
      
      const firstRow = data[0];
      const columns = Object.keys(firstRow);
      
      // Debug logging
      if (import.meta.env.DEV) {
        console.log('Chart data structure:', {
          firstRow,
          columns,
          dataLength: data.length
        });
      }
      
      // Try to find appropriate columns for different chart types
      const mapping: any = {};
      
      // Use manual column mapping if provided, otherwise auto-detect
      if (panel.columnMapping?.xAxis) {
        mapping.xAxis = panel.columnMapping.xAxis;
      } else {
        // For x-axis (categories/labels/dates)
        mapping.xAxis = columns.find(col => 
          ['category', 'name', 'label', 'title', 'id', 'type', 'date', 'time', 'timestamp'].includes(col.toLowerCase())
        ) || columns[0];
      }
      
      if (panel.columnMapping?.yAxis) {
        mapping.yAxis = panel.columnMapping.yAxis;
      } else {
        // For y-axis (values)
        mapping.yAxis = columns.find(col => 
          ['value', 'count', 'amount', 'number', 'score', 'total', 'coins', 'total_coins'].includes(col.toLowerCase())
        ) || columns[1] || columns[0];
      }
      
      // For labels (pie charts)
      if (panel.columnMapping?.label) {
        mapping.label = panel.columnMapping.label;
      } else {
        mapping.label = mapping.xAxis;
      }
      
      if (import.meta.env.DEV) {
        console.log('Column mapping:', mapping);
      }
      
      return mapping;
    };

    // ============================================================================
    // CHART TYPE SPECIFIC DATA TRANSFORMATION
    // ============================================================================
    
    switch (panel.type) {
      case 'stat': {
        // STAT PANEL: Displays a single value (like total coins, database size, etc.)
        const mapping = getColumnMapping(queryResult.data);
        const value = queryResult.data[0]?.[mapping.yAxis] || 0;
        if (baseOption.graphic && baseOption.graphic[0]) {
          // Check if this is a database health dashboard or contains count/size data
          const isDatabaseHealth = panel.title.toLowerCase().includes('total') || 
                                 panel.title.toLowerCase().includes('database') ||
                                 panel.title.toLowerCase().includes('size') ||
                                 panel.title.toLowerCase().includes('count') ||
                                 panel.title.toLowerCase().includes('avg') ||
                                 mapping.yAxis?.includes('total') ||
                                 mapping.yAxis?.includes('count') ||
                                 mapping.yAxis?.includes('size') ||
                                 mapping.yAxis?.includes('formatted');
          
          // Format the value appropriately
          let formattedValue: string;
          if (isDatabaseHealth && typeof value === 'string' && value.includes(' ')) {
            // If it's already formatted (like "15.2 MB"), use as-is
            formattedValue = value;
          } else if (isDatabaseHealth && typeof value === 'number') {
            // Check if this is a count-based stat that should be shown as integer
            const isCountStat = panel.title.toLowerCase().includes('total runs') ||
                               panel.title.toLowerCase().includes('total metrics') ||
                               panel.title.toLowerCase().includes('total events') ||
                               mapping.yAxis?.includes('total_runs') ||
                               mapping.yAxis?.includes('total_metrics') ||
                               mapping.yAxis?.includes('total_events') ||
                               mapping.yAxis?.includes('total_count');
            
            if (isCountStat) {
              // Format as integer for count stats
              formattedValue = formatNumber(value, 0);
            } else if (panel.title.toLowerCase().includes('avg')) {
              // Format with exactly 1 decimal for averages
              formattedValue = formatNumber(value, 1);
            } else {
              // Default formatting for other database stats
              formattedValue = formatNumber(value, 1);
            }
          } else if (typeof value === 'number') {
            // Use currency formatting for game-related stats
            formattedValue = formatCurrency(value, 1);
          } else {
            // Fallback to string conversion
            formattedValue = String(value);
          }
          
          baseOption.graphic[0].style.text = formattedValue;
        }
        return baseOption;
      }

      case 'timeseries': {
        // TIMESERIES PANEL: Line chart showing data over time
        const mapping = getColumnMapping(queryResult.data);
        const timeData = queryResult.data.map(row => [
          new Date(row[mapping.xAxis]).getTime(),
          row[mapping.yAxis]
        ]);
        
        if (baseOption.series && baseOption.series[0]) {
          baseOption.series[0].data = timeData;
        }
        return baseOption;
      }

      case 'bar': {
        // BAR CHART PANEL: Vertical bars showing categorical data (supports tier coloring)
        const mapping = getColumnMapping(queryResult.data);
        const categories = queryResult.data.map(row => row[mapping.xAxis]);
        
        // Check if we have tier data for color mapping
        const hasTierData = queryResult.data.length > 0 && 'tier' in queryResult.data[0];
        
        let chartData;
        if (hasTierData) {
          // Get all unique tiers from the data for proper color mapping
          const availableTiers = [...new Set(queryResult.data.map(row => row.tier))].filter(tier => tier != null);
          
          // Create data objects with tier information for color mapping
          chartData = queryResult.data.map(row => ({
            value: row[mapping.yAxis],
            tier: row.tier,
            itemStyle: {
              color: getTierColor(row.tier, availableTiers),
              borderColor: 'var(--tiq-border-primary)',
              borderWidth: 1
            }
          }));
        } else {
          // Simple values array for regular bar charts
          chartData = queryResult.data.map(row => row[mapping.yAxis]);
        }
        
        return {
          ...baseOption,
          xAxis: { ...baseOption.xAxis, data: categories },
          series: [{
            ...baseOption.series?.[0],
            type: 'bar',
            data: chartData
          }]
        };
      }

      case 'pie': {
        // PIE CHART PANEL: Circular chart showing proportional data
        const mapping = getColumnMapping(queryResult.data);
        const pieData = queryResult.data.map(row => ({
          name: row[mapping.label],
          value: row[mapping.yAxis]
        }));
        
        return {
          ...baseOption,
          series: [{
            ...baseOption.series?.[0],
            type: 'pie',
            data: pieData
          }]
        };
      }

      case 'table': {
        // TABLE PANEL: Data table (rendered separately, not using ECharts)
        return baseOption;
      }

      case 'treemap': {
        // TREEMAP PANEL: Hierarchical data visualization with nested rectangles
        const mapping = getColumnMapping(queryResult.data);
        if (import.meta.env.DEV) {
          console.log('🌳 Processing treemap data:', queryResult.data);
        }
        if (import.meta.env.DEV) {
          console.log('🌳 Column mapping:', mapping);
        }
        
        if (!queryResult.data || queryResult.data.length === 0) {
          if (import.meta.env.DEV) {
            console.log('🌳 No data available for treemap');
          }
          return {
            ...baseOption,
            series: [{
              ...baseOption.series?.[0],
              type: 'treemap',
              data: []
            }]
          };
        }
        
        // Transform data to treemap format: {name: string, value: number}
        // For treemap, we want the label/name as the name and the value as the size
        const treemapData = queryResult.data.map(row => {
          const name = row[mapping.label] || row[mapping.xAxis] || 'Unknown';
          const value = Number(row[mapping.yAxis]) || 0;
          // Row processing happens silently unless in dev mode
          return {
            name: name,
            value: value
          };
        }).filter(item => item.value > 0); // Filter out zero values
        
        if (import.meta.env.DEV) {
          console.log('🌳 Processed treemap data:', treemapData);
        }
        
        return {
          ...baseOption,
          series: [{
            ...baseOption.series?.[0],
            type: 'treemap',
            data: treemapData
          }]
        };
      }

      case 'calendar': {
        // CALENDAR PANEL: Heatmap showing data over calendar dates (supports hierarchical drilldown)
        if (import.meta.env.DEV) {
          console.log('📅 Processing calendar data:', queryResult.data);
        }
        
        // Check if we're in calendar drilldown mode and if it's the final level (day -> hourly bar chart)
        if (isDrilldown && panel.echartsOption.drilldown?.type === 'calendar_hierarchical') {
          const drilldownConfig = panel.echartsOption.drilldown;
          const currentLevel = drilldownConfig.levels[calendarDrilldownLevel];
          
          // If this level should be a bar chart (like hourly data), transform accordingly
          if (currentLevel?.chartType === 'bar') {
            const mapping = getColumnMapping(drilldownData);
            const barData = drilldownData.map(row => ({
              name: row[mapping.xAxis],
              value: Number(row[mapping.yAxis]) || 0
            }));
            
            return {
              ...baseOption,
              xAxis: {
                type: 'category',
                data: barData.map(item => item.name),
                name: 'Hour',
                nameLocation: 'middle',
                nameGap: 30
              },
              yAxis: {
                type: 'value',
                name: 'Coins',
                nameLocation: 'middle',
                nameGap: 50,
                axisLabel: {
                  formatter: (value: number) => formatCurrency(value, 0)
                }
              },
              series: [{
                type: 'bar',
                data: barData.map(item => item.value),
                itemStyle: {
                  color: 'var(--tiq-brand-primary)'
                }
              }],
              tooltip: {
                trigger: 'axis',
                formatter: (params: any) => {
                  const data = params[0];
                  const formattedValue = formatCurrency(data.value, 0);
                  return `${data.axisValue}<br/>Coins: ${formattedValue}`;
                }
              }
            };
          }
        }
        
        const dataToProcess = isDrilldown && drilldownData.length > 0 ? drilldownData : queryResult.data;
        
        if (!dataToProcess || dataToProcess.length === 0) {
          if (import.meta.env.DEV) {
            console.log('📅 No data available for calendar');
          }
          return {
            ...baseOption,
            calendar: {
              ...baseOption.calendar,
              range: [new Date().getFullYear()]
            },
            visualMap: {
              ...baseOption.visualMap,
              min: 0,
              max: 100
            },
            series: [{
              ...baseOption.series?.[0],
              type: 'heatmap',
              coordinateSystem: 'calendar',
              data: []
            }]
          };
        }
        
        const mapping = getColumnMapping(dataToProcess);
        if (import.meta.env.DEV) {
          console.log('📅 Column mapping:', mapping);
          console.log('📅 Sample data row:', dataToProcess[0]);
        }
        
        // Calendar data should be in format [[date, value], [date, value], ...]
        const calendarData = dataToProcess
          .filter(row => row[mapping.xAxis] && row[mapping.yAxis] != null)
          .map(row => {
            // Ensure date is in YYYY-MM-DD format
            const dateStr = row[mapping.xAxis];
            const value = Number(row[mapping.yAxis]) || 0;
            return [dateStr, value];
          });
        
        if (import.meta.env.DEV) {
          console.log('📅 Processed calendar data:', calendarData);
        }
        
        if (calendarData.length === 0) {
          if (import.meta.env.DEV) {
            console.log('📅 No valid data points after processing');
          }
          return {
            ...baseOption,
            calendar: {
              ...baseOption.calendar,
              range: [new Date().getFullYear()]
            },
            visualMap: {
              ...baseOption.visualMap,
              min: 0,
              max: 100
            },
            series: [{
              ...baseOption.series?.[0],
              type: 'heatmap',
              coordinateSystem: 'calendar',
              data: []
            }]
          };
        }
        
        // Get date range from data for calendar configuration
        const dates = calendarData.map(([dateStr]) => new Date(dateStr));
        const validDates = dates.filter(d => !isNaN(d.getTime()));
        
        if (validDates.length === 0) {
          if (import.meta.env.DEV) {
            console.log('📅 No valid dates found');
          }
          return {
            ...baseOption,
            calendar: {
              ...baseOption.calendar,
              range: [new Date().getFullYear()]
            },
            visualMap: {
              ...baseOption.visualMap,
              min: 0,
              max: 100
            },
            series: [{
              ...baseOption.series?.[0],
              type: 'heatmap',
              coordinateSystem: 'calendar',
              data: []
            }]
          };
        }
        
        const minDate = new Date(Math.min(...validDates.map(d => d.getTime())));
        const maxDate = new Date(Math.max(...validDates.map(d => d.getTime())));
        
        // Get min/max values for visualMap
        const values = calendarData.map(([, value]) => value).filter(v => v != null && !isNaN(v));
        const minValue = values.length > 0 ? Math.min(...values) : 0;
        const maxValue = values.length > 0 ? Math.max(...values) : 100;
        
        // Determine calendar range based on drilldown level
        let calendarRange;
        if (isDrilldown && panel.echartsOption.drilldown?.type === 'calendar_hierarchical') {
          const drilldownConfig = panel.echartsOption.drilldown;
          const currentLevel = drilldownConfig.levels[calendarDrilldownLevel];
          
          switch (currentLevel?.range) {
            case 'quarter':
            case 'month':
            case 'week':
              // For focused ranges, show the specific time period
              calendarRange = minDate.getFullYear() === maxDate.getFullYear() 
                ? minDate.getFullYear() 
                : [minDate.getFullYear(), maxDate.getFullYear()];
              break;
            case 'year':
            default:
              calendarRange = minDate.getFullYear() === maxDate.getFullYear() 
                ? minDate.getFullYear() 
                : [minDate.getFullYear(), maxDate.getFullYear()];
              break;
          }
        } else {
          calendarRange = minDate.getFullYear() === maxDate.getFullYear() 
            ? minDate.getFullYear() 
            : [minDate.getFullYear(), maxDate.getFullYear()];
        }
        
        if (import.meta.env.DEV) {
          console.log('📅 Final configuration:', {
            dateRange: calendarRange,
            valueRange: [minValue, maxValue],
            dataPoints: calendarData.length,
            drilldownLevel: calendarDrilldownLevel
          });
        }
        
        return {
          ...baseOption,
          calendar: {
            ...baseOption.calendar,
            range: calendarRange
          },
          visualMap: {
            ...baseOption.visualMap,
            min: minValue,
            max: maxValue
          },
          series: [{
            ...baseOption.series?.[0],
            type: 'heatmap',
            coordinateSystem: 'calendar',
            data: calendarData
          }]
        };
      }

      default:
        return baseOption;
    }
  };

  // ============================================================================
  // USEEFFECT HOOKS - Data fetching and UI interactions
  // ============================================================================

  /**
   * Effect: Fetch data when panel changes, but only if not already fetched
   * Uses pre-fetched data if available, otherwise fetches from API
   */
  useEffect(() => {
    if (!dataFetchedRef.current) {
      // Use pre-fetched data if available, otherwise fetch from API
      if (data) {
        setQueryResult({ data });
        if (onDataFetched) {
          onDataFetched(data);
        }
      } else {
        fetchPanelData();
      }
      dataFetchedRef.current = true;
    }
  }, [panel.query, data]);

  /**
   * Effect: Reset dataFetchedRef when data prop changes
   * Handles updates to pre-fetched data
   */
  useEffect(() => {
    if (data) {
      setQueryResult({ data });
      setError(null); // Clear any placeholder-related errors
      setInternalLoading(false); // Ensure loading state is cleared
      if (onDataFetched) {
        onDataFetched(data);
      }
    }
  }, [data, onDataFetched]);

  /**
   * Effect: Re-render chart when data or echartsOption changes
   * Updates the ECharts instance with new configuration
   */
  useEffect(() => {
    if (chartRef.current) {
      const chart = chartRef.current.getEchartsInstance();
      const option = getTransformedEChartsOption();
      // Use smooth updates instead of force re-render to prevent flashing
      chart.setOption(option, false);
    }
  }, [queryResult, panel.echartsOption]);

  /**
   * Effect: Close menu when clicking outside
   * Handles click-outside behavior for the context menu
   */
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      // Check if the click is outside the menu and not on the menu button
      const target = event.target as Element;
      const menuButton = document.getElementById(`panel-menu-button-${panel.id}`);
      const menuElement = document.getElementById(`panel-menu-${panel.id}`);
      
      if (menuOpen && 
          !menuButton?.contains(target) && 
          !menuElement?.contains(target)) {
        setMenuOpen(false);
      }
    };

    if (menuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [menuOpen, panel.id]);



  // ============================================================================
  // UI EVENT HANDLERS - Menu, navigation, and interaction handlers
  // ============================================================================

  /**
   * Handles clicking the menu button (three dots)
   * Toggles menu visibility and prevents event bubbling
   */
  const handleMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    event.stopPropagation(); // Prevent panel click when clicking menu
    setMenuOpen(!menuOpen); // Toggle menu state
  };

  /**
   * Closes the context menu
   */
  const handleMenuClose = () => {
    setMenuOpen(false);
  };

  /**
   * Handles clicking on the panel itself
   * In edit mode, triggers the onClick callback
   * Always closes the menu if it's open
   */
  const handlePanelClick = () => {
    if (isEditMode && onClick) {
      onClick();
    }
    // Close menu if clicking outside the menu area
    if (menuOpen) {
      setMenuOpen(false);
    }
  };

  /**
   * Handles "View" menu item - navigates to fullscreen panel view
   */
  const handleView = () => {
    handleMenuClose();
    // Get dashboard ID from current URL or context
    const pathSegments = window.location.pathname.split('/').filter(Boolean);
    const dashboardIndex = pathSegments.findIndex(segment => segment === 'dashboard' || segment === 'dashboards');
    const dashboardId = dashboardIndex !== -1 && pathSegments[dashboardIndex + 1] ? pathSegments[dashboardIndex + 1] : null;
    
    // Get current dashboard variables if available
    let variablesParam = '';
    try {
      // Try to access dashboard variables from context
      const dashboardVariableContext = useDashboardVariable();
      if (dashboardVariableContext.selectedValues) {
        const variables = encodeURIComponent(JSON.stringify(dashboardVariableContext.selectedValues));
        variablesParam = `?variables=${variables}`;
      }
    } catch (error) {
      // Dashboard variable context not available, continue without variables
      console.log('Dashboard variables not available for fullscreen view');
    }
    
    if (dashboardId) {
      navigate(`/dashboards/${dashboardId}/panels/${panel.id}/view${variablesParam}`);
    } else {
      // Fallback to old URL structure if dashboard ID not found
      navigate(`/panels/${panel.id}/view${variablesParam}`);
    }
  };

  /**
   * Handles "Edit" menu item - navigates to panel edit page
   */
  const handleEdit = () => {
    handleMenuClose();
    if (onEdit) {
      onEdit(panel.id);
    } else {
      // Get dashboard ID from current URL or context
      const pathSegments = window.location.pathname.split('/').filter(Boolean);
      const dashboardIndex = pathSegments.findIndex(segment => segment === 'dashboard' || segment === 'dashboards');
      const dashboardId = dashboardIndex !== -1 && pathSegments[dashboardIndex + 1] ? pathSegments[dashboardIndex + 1] : null;
      
      if (dashboardId) {
        navigate(`/dashboards/${dashboardId}/panels/${panel.id}/edit`);
      } else {
        // Fallback to old URL structure if dashboard ID not found
        navigate(`/panels/${panel.id}/edit`);
      }
    }
  };

  /**
   * Handles "Remove" menu item - opens delete confirmation dialog
   */
  const handleRemove = () => {
    handleMenuClose();
    setDeleteDialogOpen(true);
  };

  /**
   * Confirms panel deletion
   */
  const handleDeleteConfirm = () => {
    setDeleteDialogOpen(false);
    if (onDelete) {
      onDelete(panel.id);
    }
  };

  /**
   * Cancels panel deletion
   */
  const handleDeleteCancel = () => {
    setDeleteDialogOpen(false);
  };

  /**
   * Handles opening the debug drawer
   */
  const handleDebugClick = () => {
    setDebugDrawerOpen(true);
  };

  /**
   * Handles closing the debug drawer
   */
  const handleDebugDrawerClose = () => {
    setDebugDrawerOpen(false);
  };

  /**
   * Toggles fullscreen mode for the panel
   * Detects current state and navigates accordingly
   */
  const handleFullscreenToggle = () => {
    // Check if we're already in fullscreen mode (PanelViewPage)
    const isInFullscreen = window.location.pathname.includes('/panels/') && window.location.pathname.includes('/view');
    
    if (isInFullscreen) {
      // We're in fullscreen mode, exit by going back to dashboard
      if (onFullscreenToggle) {
        onFullscreenToggle(panel.id);
      }
    } else {
      // We're in dashboard mode, enter fullscreen by navigating to PanelViewPage
      const pathSegments = window.location.pathname.split('/').filter(Boolean);
      const dashboardIndex = pathSegments.findIndex(segment => segment === 'dashboard' || segment === 'dashboards');
      const dashboardId = dashboardIndex !== -1 && pathSegments[dashboardIndex + 1] ? pathSegments[dashboardIndex + 1] : null;
      
      // Get current dashboard variables if available
      let variablesParam = '';
      try {
        // Try to access dashboard variables from context
        const dashboardVariableContext = useDashboardVariable();
        if (dashboardVariableContext.selectedValues) {
          const variables = encodeURIComponent(JSON.stringify(dashboardVariableContext.selectedValues));
          variablesParam = `?variables=${variables}`;
        }
      } catch (error) {
        // Dashboard variable context not available, continue without variables
        console.log('Dashboard variables not available for fullscreen view');
      }
      
      if (dashboardId) {
        navigate(`/dashboards/${dashboardId}/panels/${panel.id}/view${variablesParam}`);
      } else {
        // Fallback to old URL structure if dashboard ID not found
        navigate(`/panels/${panel.id}/view${variablesParam}`);
      }
    }
  };

  // ============================================================================
  // UI COMPONENTS - Panel header, menu, and content rendering
  // ============================================================================

  /**
   * Panel Header Component
   * Contains the panel title, drilldown navigation, and action buttons
   * Shows breadcrumbs for calendar drilldowns and back/reset buttons
   */
  const PanelHeader = () => (
    <Box 
      sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: (showMenu || showFullscreen) ? 'space-between' : 'flex-start',
        paddingLeft: '8px',
        paddingRight: (showMenu || showFullscreen) ? '0px' : '8px',
        paddingTop: '4px',
        paddingBottom: '4px',
        backgroundColor: 'background.paper',
        minHeight: '28px',
        maxHeight: '28px',
        borderTopLeftRadius: 'inherit',
        borderTopRightRadius: 'inherit',
        position: 'relative', // Ensure proper positioning context
        '&:hover .fullscreen-button': {
          opacity: 1,
          visibility: 'visible'
        }
      }}
    >
      {isDrilldown && (
        <IconButton 
          size="small" 
          onClick={panel.echartsOption.drilldown?.type === 'calendar_hierarchical' 
            ? handleCalendarDrilldownBack 
            : handleBackToOriginal}
          sx={{ mr: 1 }}
          aria-label="Back"
        >
          <ArrowBackIcon fontSize="small" />
        </IconButton>
      )}
      
      {/* Breadcrumb navigation for calendar hierarchical drilldowns */}
      {isDrilldown && panel.echartsOption.drilldown?.type === 'calendar_hierarchical' ? (
        <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'nowrap', gap: 0.5, overflow: 'hidden' }}>
          <Tooltip title={panel.title} arrow placement="top">
            <Typography 
              variant="subtitle2" 
              sx={{ 
                fontWeight: 500, 
                color: 'text.primary',
                fontSize: '0.875rem',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                maxWidth: '200px',
                '&:hover': { textDecoration: 'underline' }
              }}
              onClick={handleBackToOriginal}
            >
              {panel.title}
            </Typography>
          </Tooltip>
          {calendarDrilldownStack.map((stackItem, index) => {
            const drilldownConfig = panel.echartsOption.drilldown;
            const level = drilldownConfig.levels[stackItem.level + 1];
            let breadcrumbText = level?.title || 'Drill Level';
            
            // Replace placeholders with actual values
            Object.keys(stackItem.params || {}).forEach(key => {
              const regex = new RegExp(`{${key}}`, 'g');
              breadcrumbText = breadcrumbText.replace(regex, stackItem.params[key]);
            });
            
            return (
              <React.Fragment key={index}>
                <Typography variant="subtitle2" sx={{ color: 'text.secondary', fontSize: '0.875rem' }}>
                  →
                </Typography>
                <Tooltip title={breadcrumbText} arrow placement="top">
                  <Typography 
                    variant="subtitle2" 
                    sx={{ 
                      fontWeight: index === calendarDrilldownStack.length - 1 ? 500 : 400,
                      color: index === calendarDrilldownStack.length - 1 ? 'text.primary' : 'text.secondary',
                      fontSize: '0.875rem',
                      cursor: index === calendarDrilldownStack.length - 1 ? 'default' : 'pointer',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      maxWidth: '150px',
                      '&:hover': index !== calendarDrilldownStack.length - 1 ? { textDecoration: 'underline' } : {}
                    }}
                    onClick={() => {
                      if (index !== calendarDrilldownStack.length - 1) {
                        // Navigate back to this level
                        const targetLevel = index + 1;
                        setCalendarDrilldownStack(prev => prev.slice(0, targetLevel));
                        setCalendarDrilldownLevel(stackItem.level + 1);
                        setDrilldownData(stackItem.data);
                      }
                    }}
                  >
                    {breadcrumbText}
                  </Typography>
                </Tooltip>
              </React.Fragment>
            );
          })}
          {calendarDrilldownLevel < (panel.echartsOption.drilldown.levels?.length || 0) && (
            <>
              <Typography variant="subtitle2" sx={{ color: 'text.secondary', fontSize: '0.875rem' }}>
                →
              </Typography>
              <Tooltip 
                title={(() => {
                  const currentLevel = panel.echartsOption.drilldown.levels[calendarDrilldownLevel];
                  const lastStack = calendarDrilldownStack[calendarDrilldownStack.length - 1];
                  let currentTitle = currentLevel?.title || 'Current Level';
                  
                  if (lastStack?.params) {
                    Object.keys(lastStack.params).forEach(key => {
                      const regex = new RegExp(`{${key}}`, 'g');
                      currentTitle = currentTitle.replace(regex, lastStack.params[key]);
                    });
                  }
                  
                  return currentTitle;
                })()}
                arrow
                placement="top"
              >
                <Typography 
                  variant="subtitle2" 
                  sx={{ 
                    fontWeight: 500, 
                    color: 'text.primary',
                    fontSize: '0.875rem',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    maxWidth: '150px'
                  }}
                >
                  {(() => {
                    const currentLevel = panel.echartsOption.drilldown.levels[calendarDrilldownLevel];
                    const lastStack = calendarDrilldownStack[calendarDrilldownStack.length - 1];
                    let currentTitle = currentLevel?.title || 'Current Level';
                    
                    if (lastStack?.params) {
                      Object.keys(lastStack.params).forEach(key => {
                        const regex = new RegExp(`{${key}}`, 'g');
                        currentTitle = currentTitle.replace(regex, lastStack.params[key]);
                      });
                    }
                    
                    return currentTitle;
                  })()}
                </Typography>
              </Tooltip>
            </>
          )}
        </Box>
      ) : (
        <Tooltip 
          title={isDrilldown && panel.echartsOption.drilldown 
            ? panel.echartsOption.drilldown.title.replace('{run_number}', 'Selected Run')
            : panel.title
          }
          arrow
          placement="top"
        >
          <Typography 
            variant="subtitle2" 
            sx={{ 
              fontWeight: 500, 
              color: 'text.primary',
              fontSize: '0.875rem',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              maxWidth: '100%',
              display: 'block'
            }}
          >
            {isDrilldown && panel.echartsOption.drilldown 
              ? panel.echartsOption.drilldown.title.replace('{run_number}', 'Selected Run')
              : panel.title
            }
          </Typography>
        </Tooltip>
      )}
      
      {/* Reset button - only show when chart is modified and in drilldown mode */}
      {isDrilldown && isChartModified && (
        <IconButton
          size="small"
          onClick={handleChartReset}
          aria-label="Reset zoom and pan"
          sx={{ 
            padding: '4px',
            color: 'text.secondary',
            borderRadius: 0.25,
            ml: 'auto', // Push to the right
            mr: (isDevMode || showFullscreen) ? 0.5 : 0, // Small margin if debug or fullscreen button follows
            '&:hover': {
              backgroundColor: 'action.hover',
              color: 'text.primary'
            }
          }}
        >
          <SettingsBackupRestoreIcon fontSize="small" />
        </IconButton>
      )}
      
      {/* Debug button - only show in development mode */}
      {isDevMode && (
        <IconButton
          size="small"
          onClick={handleDebugClick}
          aria-label="Debug panel"
          sx={{ 
            padding: '4px',
            color: 'text.secondary',
            borderRadius: 0.25,
            ml: (!isDrilldown || !isChartModified) ? 'auto' : 0, // Push to the right if no reset button
            mr: showFullscreen ? 0.5 : 0, // Small margin if fullscreen button follows
            '&:hover': {
              backgroundColor: 'action.hover',
              color: 'text.primary'
            }
          }}
        >
          <BugReportIcon fontSize="small" />
        </IconButton>
      )}
      
      {showFullscreen ? (
        <IconButton
          id={`panel-fullscreen-button-${panel.id}`}
          className="fullscreen-button"
          size="small"
          onClick={handleFullscreenToggle}
          aria-label={window.location.pathname.includes('/panels/') && window.location.pathname.includes('/view') ? "Exit fullscreen" : "Enter fullscreen"}
          sx={{ 
            padding: '4px',
            color: 'text.secondary',
            borderRadius: 0.25, // Rectangle shape instead of circle
            position: 'relative', // Ensure proper positioning context
            opacity: 0,
            visibility: 'hidden',
            transition: 'opacity 0.2s ease, visibility 0.2s ease',
            '&:hover': {
              backgroundColor: 'action.hover',
              color: 'text.primary'
            }
          }}
        >
          {window.location.pathname.includes('/panels/') && window.location.pathname.includes('/view') ? 
            <FullscreenExitIcon fontSize="small" /> : 
            <FullscreenIcon fontSize="small" />
          }
        </IconButton>
      ) : showMenu && (
        <IconButton
          id={`panel-menu-button-${panel.id}`}
          size="small"
          onClick={handleMenuClick}
          aria-controls={menuOpen ? `panel-menu-${panel.id}` : undefined}
          aria-haspopup="true"
          aria-expanded={menuOpen ? 'true' : undefined}
          sx={{ 
            padding: '4px',
            color: 'text.secondary',
            borderRadius: 0.25, // Rectangle shape instead of circle
            position: 'relative', // Ensure proper positioning context
            '&:hover': {
              backgroundColor: 'action.hover',
              color: 'text.primary'
            }
          }}
        >
          <MoreVertIcon fontSize="small" />
        </IconButton>
      )}
    </Box>
  );

  /**
   * Context Menu Component
   * Dropdown menu with View, Edit, and Remove options
   * Includes delete confirmation dialog
   */
  const ContextMenu = () => (
    <>
             {showMenu && menuOpen && (
         <Box
           id={`panel-menu-${panel.id}`}
           onClick={(e) => e.stopPropagation()} // Prevent closing when clicking inside menu
           sx={{
             position: 'absolute',
             top: '28px', // Position below the header
             right: '0px',
             zIndex: 1000,
             minWidth: 140,
             backgroundColor: 'background.paper',
             boxShadow: '0px 4px 16px rgba(0,0,0,0.3)',
             border: '1px solid',
             borderColor: 'divider',
             borderRadius: 0.25,
             overflow: 'hidden'
           }}
         >
                  <MenuList
            autoFocusItem={menuOpen}
            id={`panel-menu-list-${panel.id}`}
            aria-labelledby={`panel-menu-button-${panel.id}`}
          >
            <MenuItem 
              onClick={handleView} 
              sx={{ 
                fontSize: '0.875rem',
                color: 'text.primary',
                '&:hover': {
                  backgroundColor: 'action.hover'
                }
              }}
            >
              <ListItemIcon sx={{ minWidth: '32px', color: 'text.secondary' }}>
                <ViewIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primary="View" />
            </MenuItem>
            <MenuItem 
              onClick={handleEdit} 
              sx={{ 
                fontSize: '0.875rem',
                color: 'text.primary',
                '&:hover': {
                  backgroundColor: 'action.hover'
                }
              }}
            >
              <ListItemIcon sx={{ minWidth: '32px', color: 'text.secondary' }}>
                <EditIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primary="Edit" />
            </MenuItem>
            <MenuItem 
              onClick={handleRemove} 
              sx={{ 
                fontSize: '0.875rem', 
                color: 'error.main',
                '&:hover': {
                  backgroundColor: 'action.hover'
                }
              }}
            >
              <ListItemIcon sx={{ minWidth: '32px' }}>
                <DeleteIcon fontSize="small" color="error" />
              </ListItemIcon>
              <ListItemText primary="Remove" />
            </MenuItem>
          </MenuList>
        </Box>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={handleDeleteCancel}>
        <DialogTitle>Are you sure?</DialogTitle>
        <DialogContent>
          <Typography>
            This will permanently delete the panel "{panel.title}". This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteCancel} color="inherit">
            Cancel
          </Button>
          <Button onClick={handleDeleteConfirm} color="error" variant="contained">
            Delete panel {panel.title}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );


  /**
   * Renders panel content based on type and state
   * Handles loading states, errors, and different chart types
   * Returns appropriate UI for tables vs charts
   */
  const renderPanelContent = () => {
    // Loading state is now handled with overlay instead of replacing content
    
    // Check for external error first, then internal error
    const displayError = externalError || error;
    if (displayError) {
      return (
        <Box p={2} display="flex" justifyContent="center" alignItems="center" height="100%">
          <Alert 
            severity="error" 
            sx={{ 
              width: '100%', 
              maxWidth: '400px',
              '& .MuiAlert-message': {
                fontSize: '0.875rem',
                lineHeight: 1.4
              }
            }}
          >
            <strong>Failed to load data</strong>
            <br />
            {displayError.includes('CORS') 
              ? 'Backend server is not running. Please start the server using start_toweriq.py'
              : displayError
            }
          </Alert>
        </Box>
      );
    }

    // TABLE CONTENT: Custom HTML table rendering (not using ECharts)
    if (panel.type === 'table') {
      return (
        <Box sx={{ overflowX: 'auto', flex: 1 }}>
          <table style={{ 
            width: '100%', 
            borderCollapse: 'collapse',
            backgroundColor: 'transparent'
          }}>
            <thead>
              <tr>
                {queryResult.data.length > 0 && Object.keys(queryResult.data[0]).map(key => (
                  <th key={key} style={{ 
                    border: '1px solid var(--tiq-border-primary)', 
                    backgroundColor: 'var(--tiq-action-hover)',
                    fontSize: '12px',
                    color: 'var(--tiq-text-primary)',
                    fontWeight: 500
                  }}>
                    {key}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {queryResult.data.map((row, index) => (
                <tr key={index}>
                  {Object.values(row).map((value, colIndex) => (
                    <td key={colIndex} style={{ 
                      border: '1px solid var(--tiq-border-primary)', 
                      fontSize: '11px',
                      color: 'var(--tiq-text-primary)',
                      backgroundColor: index % 2 === 0 ? 'transparent' : 'var(--tiq-action-hover)'
                    }}>
                      {String(value)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </Box>
      );
    }

    // CHART CONTENT: ECharts rendering for all chart types (timeseries, bar, pie, stat, etc.)
    return (
      <Box sx={{ 
        height: '100%', 
        width: '100%',
        overflow: 'hidden', // Ensure chart elements don't overflow the container
        position: 'relative' // Enable absolute positioning for loading overlay
      }}>
        <ReactECharts
          ref={chartRef}
          option={getTransformedEChartsOption()}
          style={{ 
            height: '100%', 
            width: '100%',
            opacity: debouncedLoading ? 0.3 : 1, // Dim the chart when loading
            transition: 'opacity 0.3s ease-in-out' // Smooth transition
          }}
          notMerge={true}
          lazyUpdate={true}
          onEvents={onChartEvents}
        />
        
        {/* Loading overlay with centered CircularProgress - always rendered for smooth transitions */}
        <Box
          sx={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            backgroundColor: 'rgba(255, 255, 255, 0.1)', // Subtle overlay background
            zIndex: 1000, // Ensure it's above the chart
            pointerEvents: 'none', // Allow interactions with chart when not loading
            opacity: debouncedLoading ? 1 : 0, // Fade in/out based on debounced loading state
            visibility: debouncedLoading ? 'visible' : 'hidden', // Hide completely when not loading
            transition: 'opacity 0.3s ease-in-out, visibility 0.3s ease-in-out' // Smooth fade transition
          }}
        >
          <CircularProgress 
            sx={{ 
              color: 'primary.main',
              width: '40px !important',
              height: '40px !important',
              opacity: debouncedLoading ? 1 : 0, // Also fade the spinner itself
              transition: 'opacity 0.2s ease-in-out' // Slightly faster spinner transition
            }} 
          />
        </Box>
      </Box>
    );
  };

  // ============================================================================
  // MAIN RENDER - Unified panel container with header and content
  // ============================================================================

  /**
   * Main panel container that combines header, content, and context menu
   * Handles panel styling, hover effects, and click interactions
   */
  return (
    <Box
      sx={{
        width: '100%',
        height: '100%',
        borderRadius: 0.25,
        cursor: isEditMode ? 'pointer' : 'default',
        backgroundColor: 'rgba(225, 139, 61, 0.1)', // Using brand.secondary with opacity
        borderBottom: 'none', // Remove bottom border since PanelHeader provides it
        '&:hover': isEditMode ? { 
          boxShadow: '0 2px 8px rgba(225, 139, 61, 0.2)' // Using brand.secondary for hover
        } : {
          boxShadow: '0 1px 3px rgba(0, 0, 0, 0.12)'
        },
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden', // Ensure clean rounded corners
        position: 'relative'
      }}
      onClick={handlePanelClick}
    >
      <PanelHeader />
      
      <Box sx={{ 
        flex: 1, 
        backgroundColor: 'background.paper',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        minHeight: 0,
        overflow: 'hidden',
        borderBottomLeftRadius: 'inherit',
        borderBottomRightRadius: 'inherit',
        padding: '8px' // Consistent margin between content and panel boundaries
      }}>
        {renderPanelContent()}
      </Box>

      <ContextMenu />
      <DebugDrawer 
        open={debugDrawerOpen}
        onClose={handleDebugDrawerClose}
        panel={panel}
        queryResult={queryResult}
        loading={loading}
        error={error}
      />
    </Box>
  );
};

// ============================================================================
// COMPONENT EXPORT - Memoized component for performance optimization
// ============================================================================

/**
 * Memoized version of DashboardPanelViewComponent
 * Prevents unnecessary re-renders when props haven't changed
 * Improves performance in dashboard grids with many panels
 */
const DashboardPanelView = React.memo(DashboardPanelViewComponent);

export default DashboardPanelView;
