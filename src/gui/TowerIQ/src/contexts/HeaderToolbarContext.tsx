import React, {
  createContext,
  useContext,
  useMemo,
  ReactNode,
} from 'react';
import { useLocation, useParams } from 'react-router-dom';
import {
  Box,
  Button,
  Typography,
  CircularProgress,
  FormControl,
  Select,
  Checkbox,
  Chip,
  IconButton,
  MenuItem,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { useDashboard } from './DashboardContext';
import { useDashboardVariable } from './DashboardVariableContext';
import { API_CONFIG } from '../config/environment';

interface RenderItem {
  id: string;
  node: ReactNode;
}

interface HeaderToolbarContextValue {
  secondaryLeft: RenderItem[];
  secondaryRight: RenderItem[];
}

const HeaderToolbarContext = createContext<HeaderToolbarContextValue | undefined>(undefined);

export const HeaderToolbarProvider = ({ children }: { children: ReactNode }) => {
  const location = useLocation();
  const params = useParams();
  const { currentDashboard } = useDashboard();

  const { secondaryLeft, secondaryRight } = useMemo(() => {
    const pathname = location.pathname;
    const leftItems: RenderItem[] = [];
    const rightItems: RenderItem[] = [];
    
    // Route-specific toolbar configurations
    if (pathname === '/database-health') {
      leftItems.push({
        id: 'database-health',
        node: <DatabaseHealthToolbar key="database-health" />
      });
    }
    
    if (pathname.startsWith('/dashboard/') || pathname.startsWith('/dashboards/')) {
      const dashboardId = params.id;
      
      // Database health dashboard via generic dashboard route
      if (dashboardId === 'database-health-dashboard') {
        leftItems.push({
          id: 'database-health',
          node: <DatabaseHealthToolbar key="database-health" />
        });
      }
      // Dashboard variables for default dashboards with variables  
      else if (currentDashboard?.is_default && currentDashboard?.variables && currentDashboard.variables.length > 0) {
        leftItems.push({
          id: 'dashboard-variables',
          node: <DashboardVariablesToolbar key="dashboard-variables" />
        });
      }
      
      // Dashboard edit controls (this would need more context from DashboardEditContext)
      // We'll keep this simpler for now
    }
    
    return { secondaryLeft: leftItems, secondaryRight: rightItems };
  }, [location.pathname, params, currentDashboard]);

  const value = useMemo(() => ({
    secondaryLeft,
    secondaryRight,
  }), [secondaryLeft, secondaryRight]);

  return (
    <HeaderToolbarContext.Provider value={value}>
      {children}
    </HeaderToolbarContext.Provider>
  );
};

export const useHeaderToolbar = () => {
  const context = useContext(HeaderToolbarContext);
  if (!context) {
    throw new Error('useHeaderToolbar must be used within a HeaderToolbarProvider');
  }
  return context;
};

// Individual toolbar components
function DatabaseHealthToolbar() {
  const [isRefreshingDb, setIsRefreshingDb] = React.useState(false);
  const [lastDbUpdate, setLastDbUpdate] = React.useState<string | null>(null);

  const fetchLastMetricsTimestamp = React.useCallback(async () => {
    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}/api/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
        },
        body: JSON.stringify({
          query: `SELECT MAX(timestamp) as latest_timestamp FROM db_metrics LIMIT 1`,
        }),
      });

      if (response.ok) {
        const result = await response.json();
        if (result.data && result.data.length > 0 && result.data[0].latest_timestamp) {
          const timestamp = new Date(result.data[0].latest_timestamp * 1000).toISOString();
          setLastDbUpdate(timestamp);
        } else {
          setLastDbUpdate(new Date().toISOString());
        }
      } else {
        console.error('Query failed with status:', response.status);
      }
    } catch (error) {
      console.error('Failed to fetch metrics timestamp:', error);
    }
  }, []);

  const handleRefreshDbStats = React.useCallback(async () => {
    try {
      setIsRefreshingDb(true);

      const metricsResponse = await fetch(`${API_CONFIG.BASE_URL}/v1/database/collect-metrics`, {
        method: 'POST',
      });

      if (!metricsResponse.ok) {
        throw new Error(`Failed to collect metrics: HTTP ${metricsResponse.status}`);
      }

      await new Promise(resolve => setTimeout(resolve, 500));
      await fetchLastMetricsTimestamp();

      // Always dispatch the event when on database health page
      window.dispatchEvent(new CustomEvent('database-metrics-updated'));
    } catch (error) {
      console.error('Failed to refresh database stats:', error);
    } finally {
      setIsRefreshingDb(false);
    }
  }, [fetchLastMetricsTimestamp]);

  React.useEffect(() => {
    // Always fetch metrics timestamp when component mounts (since this only renders on database health page)
    fetchLastMetricsTimestamp();
  }, [fetchLastMetricsTimestamp]);

  return (
    <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
      <Typography
        variant="body2"
        sx={{
          color: 'text.secondary',
          fontSize: '0.75rem',
          mr: 1,
        }}
      >
        Last Updated: {lastDbUpdate ? new Date(lastDbUpdate).toLocaleString() : 'Never'}
      </Typography>
      <Button
        variant="outlined"
        size="small"
        startIcon={isRefreshingDb ? <CircularProgress size={14} /> : <RefreshIcon sx={{ fontSize: '16px' }} />}
        onClick={handleRefreshDbStats}
        disabled={isRefreshingDb}
        sx={{
          color: 'text.primary',
          borderColor: 'divider',
          height: '30px',
          fontSize: '0.75rem',
          padding: '0 12px',
          '&:hover': {
            borderColor: 'text.primary',
            backgroundColor: 'action.hover',
          },
        }}
      >
        {isRefreshingDb ? 'Refreshing...' : 'Refresh DB Stats'}
      </Button>
    </Box>
  );
}

function DashboardVariablesToolbar() {
  const { currentDashboard } = useDashboard();
  
  let dashboardVariableContext: ReturnType<typeof useDashboardVariable> | null = null;
  try {
    dashboardVariableContext = useDashboardVariable();
  } catch (error) {
    dashboardVariableContext = null;
  }

  if (!dashboardVariableContext || !currentDashboard?.variables || currentDashboard.variables.length === 0) {
    return null;
  }

  const { selectedValues, options, isLoading, updateVariable } = dashboardVariableContext;

  return (
    <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
      {currentDashboard.variables.map(variable => {
        const selectedValue = selectedValues[variable.name];
        const variableOptions = options[variable.name] || [];

        const clearAllSelections = (event: React.MouseEvent) => {
          event.stopPropagation();
          updateVariable(variable.name, []);
        };

        let displayValue = '';
        let renderValue: React.ReactNode = null;

        if (variable.type === 'multiselect' && Array.isArray(selectedValue)) {
          const nonAllSelections = selectedValue.filter(v => v !== 'all');

          if (selectedValue.includes('all') || selectedValue.length === 0) {
            displayValue = 'All';
            renderValue = <span style={{ color: '#e0e0e0', fontSize: '0.75rem' }}>All</span>;
          } else {
            displayValue = `Selected (${nonAllSelections.length})`;
            renderValue = (
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, alignItems: 'center', maxWidth: '120px', overflow: 'hidden' }}>
                {nonAllSelections
                  .sort((a, b) => {
                    const numA = Number(a);
                    const numB = Number(b);
                    if (!isNaN(numA) && !isNaN(numB)) {
                      return numA - numB;
                    }
                    return String(a).localeCompare(String(b));
                  })
                  .slice(0, 3)
                  .map(value => {
                    const option = variableOptions.find(opt => opt.value === value);
                    return (
                      <Chip
                        key={value}
                        label={option?.label || value}
                        size="small"
                        sx={{
                          height: '18px',
                          fontSize: '0.8rem',
                          backgroundColor: '#22252b',
                          color: '#e0e0e0',
                          borderRadius: '2px',
                          '& .MuiChip-label': {
                            px: 0.75,
                          },
                        }}
                      />
                    );
                  })}
                {nonAllSelections.length > 3 && (
                  <span style={{ color: '#e0e0e0', fontSize: '0.65rem' }}>+{nonAllSelections.length - 3}</span>
                )}
              </Box>
            );
          }
        } else {
          const option = variableOptions.find(opt => opt.value === selectedValue);
          displayValue = option?.label || selectedValue || 'All';
          renderValue = <span style={{ color: 'var(--tiq-text-primary)', fontSize: '0.75rem' }}>{displayValue}</span>;
        }

        return (
          <Box key={variable.name} sx={{ display: 'flex', alignItems: 'center' }}>
            <Box
              sx={{
                backgroundColor: 'var(--tiq-bg-paper)',
                color: 'var(--tiq-text-primary)',
                px: 1.5,
                py: 0.5,
                fontSize: '0.8rem',
                fontWeight: 500,
                borderRadius: '2px 0 0 2px',
                border: '1px solid var(--tiq-border-primary)',
                minHeight: '30px',
                display: 'flex',
                alignItems: 'center',
              }}
            >
              {variable.label}
            </Box>

            <Box sx={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <FormControl size="small" disabled={isLoading}>
                <Select
                  multiple={variable.type === 'multiselect'}
                  value={selectedValue || (variable.type === 'multiselect' ? [] : '')}
                  onChange={event => updateVariable(variable.name, event.target.value)}
                  displayEmpty
                  renderValue={() => renderValue}
                  sx={{
                    minWidth: variable.type === 'multiselect' ? 140 : 80,
                    height: '30px',
                    backgroundColor: '#111217',
                    color: '#e0e0e0',
                    borderRadius: variable.type === 'multiselect' ? '0' : '0 2px 2px 0',
                    '& .MuiOutlinedInput-notchedOutline': {
                      border: '1px solid #404040',
                      borderLeft: 'none',
                      borderRight: variable.type === 'multiselect' ? 'none' : '1px solid #404040',
                    },
                    '& .MuiSelect-select': {
                      py: 0.5,
                      px: 1,
                      fontSize: '0.75rem',
                      display: 'flex',
                      alignItems: 'center',
                    },
                    '& .MuiSvgIcon-root': {
                      color: '#e0e0e0',
                      fontSize: '16px',
                    },
                    '&:hover .MuiOutlinedInput-notchedOutline': {
                      borderColor: '#555',
                    },
                    '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                      borderColor: '#1f77b4',
                      borderWidth: '1px',
                    },
                  }}
                  MenuProps={{
                    PaperProps: {
                      sx: {
                        backgroundColor: '#2e3136',
                        border: '1px solid #404040',
                        '& .MuiMenuItem-root': {
                          color: '#e0e0e0',
                          fontSize: '0.75rem',
                          minHeight: '32px',
                          py: 0.5,
                          px: 1,
                          '&:hover': {
                            backgroundColor: '#404040',
                          },
                          '&.Mui-selected': {
                            backgroundColor: 'transparent',
                            '&:hover': {
                              backgroundColor: '#404040',
                            },
                          },
                        },
                      },
                    },
                  }}
                >
                  {variableOptions.map(option => (
                    <MenuItem key={option.value} value={option.value}>
                      {variable.type === 'multiselect' && (
                        <Checkbox
                          checked={
                            Array.isArray(selectedValue) &&
                            (selectedValue.includes(option.value) ||
                              (option.value === 'all' && selectedValue.includes('all')))
                          }
                          size="small"
                          sx={{
                            color: 'var(--tiq-text-primary)',
                            p: 0.25,
                            '&.Mui-checked': {
                              color: 'var(--tiq-brand-primary)',
                            },
                            '& .MuiSvgIcon-root': {
                              fontSize: '12px',
                            },
                            mr: 0.75,
                          }}
                        />
                      )}
                      {option.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              {variable.type === 'multiselect' && (
                <IconButton
                  size="small"
                  onClick={clearAllSelections}
                  disabled={!Array.isArray(selectedValue) || selectedValue.length === 0}
                  sx={{
                    width: '30px',
                    height: '30px',
                    backgroundColor: 'var(--tiq-border-primary)',
                    borderRadius: '0 2px 2px 0',
                    border: '1px solid var(--tiq-border-primary)',
                    color: 'var(--tiq-text-primary)',
                    '&:hover': {
                      backgroundColor: 'var(--tiq-border-interactive)',
                      borderColor: 'var(--tiq-border-interactive)',
                    },
                    '&:disabled': {
                      backgroundColor: 'var(--tiq-border-primary)',
                      color: 'var(--tiq-text-disabled)',
                    },
                  }}
                >
                  <CloseIcon sx={{ fontSize: '14px' }} />
                </IconButton>
              )}
            </Box>
          </Box>
        );
      })}
    </Box>
  );
}
