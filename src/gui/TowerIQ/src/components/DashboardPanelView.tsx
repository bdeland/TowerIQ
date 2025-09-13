import React, { useEffect, useState, useRef } from 'react';
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
  Button
} from '@mui/material';
import { 
  MoreVert as MoreVertIcon,
  Visibility as ViewIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Fullscreen as FullscreenIcon,
  FullscreenExit as FullscreenExitIcon
} from '@mui/icons-material';
import ReactECharts from 'echarts-for-react';
import { DashboardPanel } from '../contexts/DashboardContext';
import { useNavigate } from 'react-router-dom';
import { applyTransformations } from '../services/transformationService';
import { grafanaToECharts, mergeWithEChartsOption } from '../utils/grafanaToECharts';

interface DashboardPanelViewProps {
  panel: DashboardPanel;
  onClick?: () => void;
  isEditMode?: boolean;
  showMenu?: boolean;
  showFullscreen?: boolean;
  onDelete?: (panelId: string) => void;
  onEdit?: (panelId: string) => void;
  onDataFetched?: (data: any[]) => void;
  onFullscreenToggle?: (panelId: string) => void;
}

interface QueryResult {
  data: any[];
  error?: string;
}

const DashboardPanelViewComponent: React.FC<DashboardPanelViewProps> = ({ 
  panel, 
  onClick, 
  isEditMode = false,
  showMenu = true,
  showFullscreen = false,
  onDelete,
  onEdit,
  onDataFetched,
  onFullscreenToggle
}) => {
  const navigate = useNavigate();
  const [queryResult, setQueryResult] = useState<QueryResult>({ data: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const chartRef = useRef<ReactECharts>(null);
  const dataFetchedRef = useRef<boolean>(false);
  
  // Menu state
  const [menuOpen, setMenuOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  


  // Fetch data from backend based on panel query
  const fetchPanelData = async () => {
    if (!panel.query) {
      setError('No query defined for panel');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('http://localhost:8000/api/query', {
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
      setLoading(false);
    }
  };

  // Transform data based on panel type and update ECharts option
  const getTransformedEChartsOption = () => {
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

    // Helper function to intelligently map data columns
    const getColumnMapping = (data: any[]) => {
      if (data.length === 0) return { xAxis: null, yAxis: null, label: null };
      
      const firstRow = data[0];
      const columns = Object.keys(firstRow);
      
      // Debug logging
      console.log('Chart data structure:', {
        firstRow,
        columns,
        dataLength: data.length
      });
      
      // Try to find appropriate columns for different chart types
      const mapping: any = {};
      
      // Use manual column mapping if provided, otherwise auto-detect
      if (panel.columnMapping?.xAxis) {
        mapping.xAxis = panel.columnMapping.xAxis;
      } else {
        // For x-axis (categories/labels)
        mapping.xAxis = columns.find(col => 
          ['category', 'name', 'label', 'title', 'id', 'type'].includes(col.toLowerCase())
        ) || columns[0];
      }
      
      if (panel.columnMapping?.yAxis) {
        mapping.yAxis = panel.columnMapping.yAxis;
      } else {
        // For y-axis (values)
        mapping.yAxis = columns.find(col => 
          ['value', 'count', 'amount', 'number', 'score', 'total'].includes(col.toLowerCase())
        ) || columns[1] || columns[0];
      }
      
      // For labels (pie charts)
      if (panel.columnMapping?.label) {
        mapping.label = panel.columnMapping.label;
      } else {
        mapping.label = mapping.xAxis;
      }
      
      console.log('Column mapping:', mapping);
      
      return mapping;
    };

    switch (panel.type) {
      case 'stat': {
        // For stat panels, display the first value
        const mapping = getColumnMapping(queryResult.data);
        const value = queryResult.data[0]?.[mapping.yAxis] || 0;
        if (baseOption.graphic && baseOption.graphic[0]) {
          baseOption.graphic[0].style.text = String(value);
        }
        return baseOption;
      }

      case 'timeseries': {
        // For timeseries, transform data to ECharts format
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
        // For bar charts
        const mapping = getColumnMapping(queryResult.data);
        const categories = queryResult.data.map(row => row[mapping.xAxis]);
        const values = queryResult.data.map(row => row[mapping.yAxis]);
        
        return {
          ...baseOption,
          xAxis: { ...baseOption.xAxis, data: categories },
          series: [{
            ...baseOption.series?.[0],
            type: 'bar',
            data: values
          }]
        };
      }

      case 'pie': {
        // For pie charts
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
        // For tables, we'll use a custom approach since ECharts doesn't have native table support
        // Return the base option and handle table rendering separately
        return baseOption;
      }

      default:
        return baseOption;
    }
  };

  // Fetch data when panel changes, but only if not already fetched
  useEffect(() => {
    if (!dataFetchedRef.current) {
      fetchPanelData();
      dataFetchedRef.current = true;
    }
  }, [panel.query]);

  // Re-render chart when data or echartsOption changes
  useEffect(() => {
    if (chartRef.current) {
      const chart = chartRef.current.getEchartsInstance();
      const option = getTransformedEChartsOption();
      chart.setOption(option, true);
    }
  }, [queryResult, panel.echartsOption]);

  // Close menu when clicking outside
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



  // Menu handlers
  const handleMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    event.stopPropagation(); // Prevent panel click when clicking menu
    setMenuOpen(!menuOpen); // Toggle menu state
  };

  const handleMenuClose = () => {
    setMenuOpen(false);
  };

  // Close menu when clicking outside
  const handlePanelClick = () => {
    if (isEditMode && onClick) {
      onClick();
    }
    // Close menu if clicking outside the menu area
    if (menuOpen) {
      setMenuOpen(false);
    }
  };

  const handleView = () => {
    handleMenuClose();
    // Get dashboard ID from current URL or context
    const pathSegments = window.location.pathname.split('/').filter(Boolean);
    const dashboardIndex = pathSegments.findIndex(segment => segment === 'dashboard' || segment === 'dashboards');
    const dashboardId = dashboardIndex !== -1 && pathSegments[dashboardIndex + 1] ? pathSegments[dashboardIndex + 1] : null;
    
    if (dashboardId) {
      navigate(`/dashboard/${dashboardId}/panels/${panel.id}/view`);
    } else {
      // Fallback to old URL structure if dashboard ID not found
      navigate(`/panels/${panel.id}/view`);
    }
  };

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
        navigate(`/dashboard/${dashboardId}/panels/${panel.id}/edit`);
      } else {
        // Fallback to old URL structure if dashboard ID not found
        navigate(`/panels/${panel.id}/edit`);
      }
    }
  };

  const handleRemove = () => {
    handleMenuClose();
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = () => {
    setDeleteDialogOpen(false);
    if (onDelete) {
      onDelete(panel.id);
    }
  };

  const handleDeleteCancel = () => {
    setDeleteDialogOpen(false);
  };

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
      
      if (dashboardId) {
        navigate(`/dashboard/${dashboardId}/panels/${panel.id}/view`);
      } else {
        // Fallback to old URL structure if dashboard ID not found
        navigate(`/panels/${panel.id}/view`);
      }
    }
  };

  // Panel Header Component
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
        borderBottom: '1px solid',
        borderBottomColor: 'divider',
        backgroundColor: 'background.paper',
        minHeight: '28px',
        maxHeight: '28px',
        borderTopLeftRadius: 'inherit',
        borderTopRightRadius: 'inherit',
        position: 'relative' // Ensure proper positioning context
      }}
    >
      <Typography 
        variant="subtitle2" 
        sx={{ 
          fontWeight: 500, 
          color: 'text.primary',
          fontSize: '0.875rem'
        }}
      >
        {panel.title}
      </Typography>
      {showFullscreen ? (
        <IconButton
          id={`panel-fullscreen-button-${panel.id}`}
          size="small"
          onClick={handleFullscreenToggle}
          aria-label={window.location.pathname.includes('/panels/') && window.location.pathname.includes('/view') ? "Exit fullscreen" : "Enter fullscreen"}
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

  // Context Menu
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

  // Render panel content based on type
  const renderPanelContent = () => {
    if (loading) {
      return (
        <Box display="flex" justifyContent="center" alignItems="center" height="100%">
          <CircularProgress sx={{ color: 'primary.main' }} />
        </Box>
      );
    }
    
    if (error) {
      return (
        <Box p={2}>
          <Alert severity="error">
            {error}
          </Alert>
        </Box>
      );
    }

    // Table content
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
                    border: '1px solid var(--mui-palette-divider)', 
                    backgroundColor: 'var(--mui-palette-action-hover)',
                    fontSize: '12px',
                    color: 'var(--mui-palette-text-primary)',
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
                      border: '1px solid var(--mui-palette-divider)', 
                      fontSize: '11px',
                      color: 'var(--mui-palette-text-primary)',
                      backgroundColor: index % 2 === 0 ? 'transparent' : 'var(--mui-palette-action-hover)'
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

    // Chart content (for timeseries, bar, pie, stat, etc.)
    return (
      <Box sx={{ 
        height: '100%', 
        width: '100%',
        overflow: 'hidden' // Ensure chart elements don't overflow the container
      }}>
        <ReactECharts
          ref={chartRef}
          option={getTransformedEChartsOption()}
          style={{ height: '100%', width: '100%' }}
          notMerge={true}
          lazyUpdate={true}
        />
      </Box>
    );
  };

  // Unified panel container
  return (
    <Box
      sx={{
        width: '100%',
        height: '100%',
        border: isEditMode ? '1px solid' : '1px solid',
        borderColor: isEditMode ? 'divider' : 'divider',
        borderRadius: 0.25,
        cursor: isEditMode ? 'pointer' : 'default',
        backgroundColor: 'background.paper',
        '&:hover': isEditMode ? { 
          borderColor: 'primary.light',
          boxShadow: '0 2px 8px rgba(247, 149, 32, 0.2)'
        } : {
          boxShadow: '0 1px 3px rgba(0, 0, 0, 0.12)'
        },
        display: 'flex',
        flexDirection: 'column',
        overflow: 'visible', // Allow rounded corners to be visible
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
        borderRadius: 'inherit',
        padding: '10px' // Consistent margin between content and panel boundaries
      }}>
        {renderPanelContent()}
      </Box>

      <ContextMenu />
    </Box>
  );
};

const DashboardPanelView = React.memo(DashboardPanelViewComponent);

export default DashboardPanelView;
