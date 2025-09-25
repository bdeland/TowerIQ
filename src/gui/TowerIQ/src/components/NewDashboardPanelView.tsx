import React, { useMemo, useState, useCallback, useEffect, useRef } from 'react';
import {
  Card,
  CardHeader,
  CardContent,
  IconButton,
  Typography,
  Box,
  Alert,
  CircularProgress,
  Tooltip,
  Menu,
  MenuItem,
  Divider,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Fullscreen as FullscreenIcon,
  FullscreenExit as FullscreenExitIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  MoreVert as MoreVertIcon,
  BugReport as BugReportIcon,
} from '@mui/icons-material';
import ReactECharts from 'echarts-for-react';
import { Panel } from '../domain/dashboard/Panel';
import { Dashboard } from '../domain/dashboard/Dashboard';
import type { PanelState } from '../hooks/useDashboard';
import type { EChartsOption } from 'echarts';
import { useDeveloper } from '../contexts/DeveloperContext';
import SkeletonOverlay from './skeletons/SkeletonOverlay';
import { ChartType } from './skeletons/ChartSkeleton';

interface NewDashboardPanelViewProps {
  panel: Panel;
  state: PanelState;
  dashboard: Dashboard;
  onRefresh: () => void;
  onFullscreenToggle?: () => void;
  onEdit?: () => void;
  onDelete?: () => void;
  isFullscreen?: boolean;
  showDebugInfo?: boolean;
}

/**
 * Maps panel visualization type to skeleton chart type
 */
const mapVisualizationTypeToSkeletonType = (panel: Panel): ChartType => {
  const config = panel.getConfig();
  const vizType = config.visualization.type;
  const chartType = config.visualization.chartType;
  
  if (vizType === 'table') return 'table';
  if (vizType === 'stat') return 'stat';
  if (vizType === 'chart') {
    switch (chartType) {
      case 'bar':
        return 'bar';
      case 'line':
        return 'line';
      case 'pie':
        return 'pie';
      case 'timeseries':
        return 'timeseries';
      case 'calendar':
        return 'calendar';
      case 'treemap':
        return 'treemap';
      case 'heatmap':
        return 'calendar'; // Use calendar skeleton for heatmaps
      case 'ridgeline':
        return 'ridgeline';
      default:
        return 'bar';
    }
  }
  
  return 'bar'; // Default fallback
};

export const NewDashboardPanelView: React.FC<NewDashboardPanelViewProps> = ({
  panel,
  state,
  dashboard,
  onRefresh,
  onFullscreenToggle,
  onEdit,
  onDelete,
  isFullscreen = false,
  showDebugInfo = false,
}) => {
  const { isDevMode, minPanelLoadingMs } = useDeveloper();
  const [menuAnchorEl, setMenuAnchorEl] = useState<null | HTMLElement>(null);
  const [debugDrawerOpen, setDebugDrawerOpen] = useState(false);

  // Generate ECharts options from panel and data
  const echartsOptions = useMemo((): EChartsOption | null => {
    if (state.status !== 'loaded') {
      return null;
    }

    try {
      return panel.getEChartsOptions();
    } catch (error) {
      console.error('Error generating ECharts options:', error);
      return null;
    }
  }, [panel, state]);

  // Handle menu actions
  const handleMenuOpen = useCallback((event: React.MouseEvent<HTMLElement>) => {
    setMenuAnchorEl(event.currentTarget);
  }, []);

  const handleMenuClose = useCallback(() => {
    setMenuAnchorEl(null);
  }, []);

  const handleEdit = useCallback(() => {
    handleMenuClose();
    onEdit?.();
  }, [onEdit, handleMenuClose]);

  const handleDelete = useCallback(() => {
    handleMenuClose();
    if (window.confirm(`Are you sure you want to delete the panel "${panel.title}"?`)) {
      onDelete?.();
    }
  }, [onDelete, panel.title, handleMenuClose]);

  const handleDebugToggle = useCallback(() => {
    setDebugDrawerOpen(prev => !prev);
  }, []);

  const isLoading = state.status === 'loading';
  const [debouncedLoading, setDebouncedLoading] = useState(isLoading);
  const loadingStartRef = useRef<number | null>(null);
  const loadingDelayTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const forceSkeletonOnly = isDevMode && minPanelLoadingMs === 0;
  const effectiveLoading = forceSkeletonOnly || debouncedLoading;

  // Chart skeleton type based on panel configuration
  useEffect(() => {
    const baseDelay = 100;

    if (loadingDelayTimeoutRef.current) {
      clearTimeout(loadingDelayTimeoutRef.current);
      loadingDelayTimeoutRef.current = null;
    }

    if (isLoading) {
      setDebouncedLoading(true);
      if (loadingStartRef.current === null) {
        loadingStartRef.current = performance.now();
      }
    } else {
      const enforcedDelay = isDevMode ? minPanelLoadingMs : 0;

      if (isDevMode && enforcedDelay === 0) {
        setDebouncedLoading(true);
        loadingStartRef.current = null;
      } else {
        const elapsed = loadingStartRef.current !== null ? performance.now() - loadingStartRef.current : 0;
        loadingStartRef.current = null;

        const minimumVisibleDuration = Math.max(enforcedDelay, baseDelay);
        const remaining = Math.max(minimumVisibleDuration - elapsed, baseDelay);

        loadingDelayTimeoutRef.current = setTimeout(() => {
          setDebouncedLoading(false);
          loadingDelayTimeoutRef.current = null;
        }, remaining);
      }
    }

    return () => {
      if (loadingDelayTimeoutRef.current) {
        clearTimeout(loadingDelayTimeoutRef.current);
        loadingDelayTimeoutRef.current = null;
      }
    };
  }, [isLoading, isDevMode, minPanelLoadingMs]);
  const skeletonType = useMemo(() => {
    return mapVisualizationTypeToSkeletonType(panel);
  }, [panel]);

  // Error display component
  const ErrorDisplay = useMemo(() => {
    if (state.status !== 'error' || !state.error) return null;

    return (
      <Alert 
        severity="error" 
        action={
          <IconButton size="small" onClick={onRefresh}>
            <RefreshIcon />
          </IconButton>
        }
      >
        <Typography variant="body2">
          Failed to load panel data: {state.error.message}
        </Typography>
      </Alert>
    );
  }, [state.status, state.error, onRefresh]);

  // Chart component with skeleton overlay
  const ChartComponent = useMemo(() => {
    return (
      <SkeletonOverlay
        isLoading={effectiveLoading}
        chartType={skeletonType}
        width="100%"
        height={isFullscreen ? 'calc(100vh - 120px)' : '300px'}
      >
        {forceSkeletonOnly ? (
          <Box sx={{ height: isFullscreen ? 'calc(100vh - 120px)' : '300px', width: '100%' }} />
        ) : (
          <ReactECharts
            option={echartsOptions || {}} // Provide empty option when loading
            style={{ 
              height: isFullscreen ? 'calc(100vh - 120px)' : '300px',
              width: '100%'
            }}
            opts={{ renderer: 'canvas' }}
            notMerge={true}
            lazyUpdate={true}
          />
        )}
      </SkeletonOverlay>
    );
  }, [effectiveLoading, echartsOptions, forceSkeletonOnly, isFullscreen, skeletonType, state.status]);

  return (
    <>
      <Card
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
          border: '1px solid',
          borderColor: 'divider',
          backgroundColor: 'background.paper',
          ...(isFullscreen && {
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            zIndex: 9999,
            borderRadius: 0,
          })
        }}
      >

        {/* Panel header */}
        <CardHeader
          title={
            <Tooltip title={panel.title}>
              <Typography
                variant="h6"
                component="div"
                sx={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: '200px',
                }}
              >
                {panel.title}
              </Typography>
            </Tooltip>
          }
          action={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              {/* Debug button (dev mode only) */}
              {isDevMode && (
                <Tooltip title="Debug Panel">
                  <IconButton size="small" onClick={handleDebugToggle}>
                    <BugReportIcon />
                  </IconButton>
                </Tooltip>
              )}

              {/* Refresh button */}
              <Tooltip title="Refresh">
                <IconButton size="small" onClick={onRefresh}>
                  <RefreshIcon />
                </IconButton>
              </Tooltip>

              {/* Fullscreen toggle */}
              {onFullscreenToggle && (
                <Tooltip title={isFullscreen ? "Exit Fullscreen" : "Fullscreen"}>
                  <IconButton size="small" onClick={onFullscreenToggle}>
                    {isFullscreen ? <FullscreenExitIcon /> : <FullscreenIcon />}
                  </IconButton>
                </Tooltip>
              )}

              {/* Panel menu */}
              {(onEdit || onDelete) && (
                <>
                  <Tooltip title="Panel Options">
                    <IconButton size="small" onClick={handleMenuOpen}>
                      <MoreVertIcon />
                    </IconButton>
                  </Tooltip>
                  
                  <Menu
                    anchorEl={menuAnchorEl}
                    open={Boolean(menuAnchorEl)}
                    onClose={handleMenuClose}
                    anchorOrigin={{
                      vertical: 'bottom',
                      horizontal: 'right',
                    }}
                    transformOrigin={{
                      vertical: 'top',
                      horizontal: 'right',
                    }}
                  >
                    {onEdit && (
                      <MenuItem onClick={handleEdit}>
                        <EditIcon sx={{ mr: 1 }} />
                        Edit Panel
                      </MenuItem>
                    )}
                    
                    {onEdit && onDelete && <Divider />}
                    
                    {onDelete && (
                      <MenuItem onClick={handleDelete} sx={{ color: 'error.main' }}>
                        <DeleteIcon sx={{ mr: 1 }} />
                        Delete Panel
                      </MenuItem>
                    )}
                  </Menu>
                </>
              )}
            </Box>
          }
          sx={{
            pb: 1,
            borderBottom: '1px solid',
            borderColor: 'divider',
          }}
        />

        {/* Panel content */}
        <CardContent sx={{ 
          flex: 1, 
          display: 'flex', 
          flexDirection: 'column',
          p: 1,
          '&:last-child': { pb: 1 }
        }}>
          {/* Error state */}
          {ErrorDisplay}

          {/* Empty state */}
          {state.status === 'idle' && (
            <Box sx={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              height: '200px',
              color: 'text.secondary'
            }}>
              <Typography variant="body2">
                Click refresh to load data
              </Typography>
            </Box>
          )}

          {/* Chart display */}
          {state.status === 'loaded' && ChartComponent}

          {/* No data state */}
          {state.status === 'loaded' && (!state.data || state.data.data.length === 0) && (
            <Box sx={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              height: '200px',
              color: 'text.secondary'
            }}>
              <Typography variant="body2">
                No data available
              </Typography>
            </Box>
          )}
        </CardContent>

        {/* Panel metadata footer (dev mode only) */}
        {isDevMode && (
          <Box sx={{ 
            px: 2, 
            py: 1, 
            borderTop: '1px solid',
            borderColor: 'divider',
            backgroundColor: 'background.default',
            fontSize: '0.75rem',
            color: 'text.secondary'
          }}>
            Panel ID: {panel.id} | Type: {panel.type} | Status: {state.status}
            {state.lastUpdated > 0 && ` | Updated: ${new Date(state.lastUpdated).toLocaleTimeString()}`}
          </Box>
        )}
      </Card>

      {/* Debug drawer */}
      {debugDrawerOpen && (
        <PanelDebugDrawer
          panel={panel}
          state={state}
          dashboard={dashboard}
          onClose={() => setDebugDrawerOpen(false)}
        />
      )}
    </>
  );
};

// Debug drawer component for development
interface PanelDebugDrawerProps {
  panel: Panel;
  state: PanelState;
  dashboard: Dashboard;
  onClose: () => void;
}

const PanelDebugDrawer: React.FC<PanelDebugDrawerProps> = ({
  panel,
  state,
  dashboard,
  onClose,
}) => {
  const variables = dashboard.variables.getValues();
  const originalQuery = panel.query.query;
  const composedQuery = dashboard.variables.getComposedQuery(originalQuery);

  return (
    <Box
      sx={{
        position: 'fixed',
        top: 0,
        right: 0,
        width: '400px',
        height: '100vh',
        backgroundColor: 'background.paper',
        borderLeft: '1px solid',
        borderColor: 'divider',
        zIndex: 10000,
        overflow: 'auto',
        p: 2,
      }}
    >
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">Panel Debug Info</Typography>
        <IconButton onClick={onClose}>
          ×
        </IconButton>
      </Box>

      <Box sx={{ mb: 2 }}>
        <Typography variant="subtitle2" gutterBottom>Panel Info</Typography>
        <Typography variant="body2">ID: {panel.id}</Typography>
        <Typography variant="body2">Title: {panel.title}</Typography>
        <Typography variant="body2">Type: {panel.type}</Typography>
        <Typography variant="body2">Status: {state.status}</Typography>
      </Box>

      <Box sx={{ mb: 2 }}>
        <Typography variant="subtitle2" gutterBottom>Variables</Typography>
        <pre style={{ fontSize: '0.75rem', overflow: 'auto' }}>
          {JSON.stringify(variables, null, 2)}
        </pre>
      </Box>

      <Box sx={{ mb: 2 }}>
        <Typography variant="subtitle2" gutterBottom>Original Query</Typography>
        <pre style={{ fontSize: '0.75rem', overflow: 'auto', backgroundColor: '#f5f5f5', padding: '8px' }}>
          {originalQuery}
        </pre>
      </Box>

      <Box sx={{ mb: 2 }}>
        <Typography variant="subtitle2" gutterBottom>Composed Query</Typography>
        <pre style={{ fontSize: '0.75rem', overflow: 'auto', backgroundColor: '#f5f5f5', padding: '8px' }}>
          {composedQuery}
        </pre>
      </Box>

      {state.data && (
        <Box>
          <Typography variant="subtitle2" gutterBottom>Data Preview</Typography>
          <pre style={{ fontSize: '0.75rem', overflow: 'auto' }}>
            {JSON.stringify(state.data.data.slice(0, 3), null, 2)}
            {state.data.data.length > 3 && `\n... and ${state.data.data.length - 3} more rows`}
          </pre>
        </Box>
      )}
    </Box>
  );
};








