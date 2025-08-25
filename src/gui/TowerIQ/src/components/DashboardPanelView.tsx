import React, { useEffect, useState, useRef } from 'react';
import { 
  Box, 
  Typography, 
  CircularProgress, 
  Alert, 
  IconButton, 
  Popover, 
  MenuItem, 
  MenuList,
  ListItemIcon, 
  ListItemText,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Paper
} from '@mui/material';
import { 
  MoreVert as MoreVertIcon,
  Visibility as ViewIcon,
  Edit as EditIcon,
  Delete as DeleteIcon
} from '@mui/icons-material';
import ReactECharts from 'echarts-for-react';
import { DashboardPanel } from '../contexts/DashboardContext';
import { useNavigate } from 'react-router-dom';

interface DashboardPanelViewProps {
  panel: DashboardPanel;
  onClick?: () => void;
  isEditMode?: boolean;
  onDelete?: (panelId: string) => void;
  onEdit?: (panelId: string) => void;
}

interface QueryResult {
  data: any[];
  error?: string;
}

const DashboardPanelView: React.FC<DashboardPanelViewProps> = ({ 
  panel, 
  onClick, 
  isEditMode = false,
  onDelete,
  onEdit
}) => {
  const navigate = useNavigate();
  const [queryResult, setQueryResult] = useState<QueryResult>({ data: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const chartRef = useRef<ReactECharts>(null);
  
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
      setQueryResult({ data: result.data || [] });
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
    
    if (!queryResult.data || queryResult.data.length === 0) {
      return baseOption;
    }

    switch (panel.type) {
      case 'stat': {
        // For stat panels, display the first value
        const value = queryResult.data[0]?.value || 0;
        if (baseOption.graphic && baseOption.graphic[0]) {
          baseOption.graphic[0].style.text = String(value);
        }
        return baseOption;
      }

      case 'timeseries': {
        // For timeseries, transform data to ECharts format
        const timeData = queryResult.data.map(row => [
          new Date(row.timestamp).getTime(),
          row.value
        ]);
        
        if (baseOption.series && baseOption.series[0]) {
          baseOption.series[0].data = timeData;
        }
        return baseOption;
      }

      case 'bar': {
        // For bar charts
        const categories = queryResult.data.map(row => row.category || row.name);
        const values = queryResult.data.map(row => row.value);
        
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
        const pieData = queryResult.data.map(row => ({
          name: row.name || row.category,
          value: row.value
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

  // Fetch data when panel changes
  useEffect(() => {
    fetchPanelData();
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
  const handlePanelClick = (event: React.MouseEvent) => {
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
    navigate(`/panels/${panel.id}/view`);
  };

  const handleEdit = () => {
    handleMenuClose();
    if (onEdit) {
      onEdit(panel.id);
    } else {
      navigate(`/panels/${panel.id}/edit`);
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

  // Panel Header Component
  const PanelHeader = () => (
    <Box 
      sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        paddingLeft: '8px',
        paddingRight: '0px',
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
    </Box>
  );

  // Context Menu
  const ContextMenu = () => (
    <>
             {menuOpen && (
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
        <Box sx={{ overflowX: 'auto', flex: 1, padding: 1 }}>
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
                    padding: '8px', 
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
                      padding: '8px',
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
      <ReactECharts
        ref={chartRef}
        option={getTransformedEChartsOption()}
        style={{ height: '100%', width: '100%' }}
        notMerge={true}
        lazyUpdate={true}
      />
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
        overflow: 'visible', // Change from 'hidden' to 'visible' to allow popover to show
        position: 'relative' // Add relative positioning for resize handle
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
        minHeight: 0
      }}>
        {renderPanelContent()}
      </Box>

      <ContextMenu />
    </Box>
  );
};

export default DashboardPanelView;
