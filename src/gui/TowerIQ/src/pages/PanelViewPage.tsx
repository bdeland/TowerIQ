import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { 
  Box, 
  Button, 
  Alert, 
  CircularProgress
} from '@mui/material';
import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import { useDashboardVariable } from '../contexts/DashboardVariableContext';
import DashboardPanelView from '../components/DashboardPanelView';
import { defaultDashboard } from '../config/defaultDashboard';
import { databaseHealthDashboard } from '../config/databaseHealthDashboard';
import { liveRunTrackingDashboard } from '../config/liveRunTrackingDashboard';
import { composeQuery } from '../utils/queryComposer';
import { API_CONFIG } from '../config/environment';

export function PanelViewPage() {
  const { panelId, dashboardId } = useParams<{ panelId: string; dashboardId: string }>();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { fetchDashboard, loading, error, currentDashboard } = useDashboard();
  
  const [panel, setPanel] = useState<DashboardPanel | null>(null);
  const [dashboard, setDashboard] = useState<any>(null);
  const [panelData, setPanelData] = useState<any[]>([]);
  const [isLoadingData, setIsLoadingData] = useState(false);
  const lastSelectedValuesRef = useRef<string>('');

  // Get dashboard variables if available
  let selectedValues = {};
  try {
    if (currentDashboard?.variables && currentDashboard.variables.length > 0) {
      const dashboardVariableContext = useDashboardVariable();
      selectedValues = dashboardVariableContext.selectedValues;
    }
  } catch (error) {
    // Dashboard variable context not available, use empty values
    selectedValues = {};
  }

  useEffect(() => {
    const loadPanel = async () => {
      if (!panelId || !dashboardId) {
        return;
      }

      try {
        let foundDashboard = null;

        // Check if this is a special hardcoded dashboard
        if (dashboardId === 'default-dashboard') {
          console.log('PanelViewPage - Loading hardcoded default dashboard');
          foundDashboard = defaultDashboard;
        } else if (dashboardId === 'live-run-tracking-dashboard') {
          console.log('PanelViewPage - Loading hardcoded live run tracking dashboard');
          foundDashboard = liveRunTrackingDashboard;
        } else if (dashboardId === 'database-health-dashboard') {
          console.log('PanelViewPage - Loading hardcoded database health dashboard');
          foundDashboard = databaseHealthDashboard;
        } else {
          // For other dashboards, fetch from backend
          foundDashboard = await fetchDashboard(dashboardId);
        }

        if (!foundDashboard) {
          console.error(`Dashboard with ID "${dashboardId}" not found`);
          return;
        }

        // Find the panel within that dashboard
        const foundPanel = foundDashboard.config?.panels?.find((p: DashboardPanel) => p.id === panelId);
        if (foundPanel) {
          console.log('PanelViewPage - Found panel:', foundPanel);
          console.log('PanelViewPage - Panel query:', foundPanel.query);
          
          // Get variables from URL parameters
          const variablesParam = searchParams.get('variables');
          let variables = {};
          if (variablesParam) {
            try {
              variables = JSON.parse(decodeURIComponent(variablesParam));
            } catch (error) {
              console.error('Failed to parse variables from URL:', error);
            }
          }
          
          // Don't compose the query here - let the variable change effect handle it
          // This ensures we always have the original query with placeholders
          setPanel(foundPanel);
          setDashboard(foundDashboard);
        } else {
          console.error(`Panel with ID "${panelId}" not found in dashboard "${foundDashboard.title}"`);
        }
      } catch (err) {
        console.error('Error loading panel:', err);
      }
    };

    loadPanel();
  }, [panelId, dashboardId, fetchDashboard, searchParams]);

  // Effect to refetch panel data when variables change
  useEffect(() => {
    const fetchPanelData = async () => {
      if (!panel || !panel.query || isLoadingData) {
        return;
      }

      // Create a stable string representation of selectedValues to prevent infinite loops
      const selectedValuesString = JSON.stringify(selectedValues);
      
      // Only fetch if the selected values have actually changed
      if (selectedValuesString === lastSelectedValuesRef.current) {
        return;
      }
      
      lastSelectedValuesRef.current = selectedValuesString;
      setIsLoadingData(true);
      
      try {
        const finalQuery = composeQuery(panel.query, selectedValues);
        console.log('PanelViewPage - Original query:', panel.query);
        console.log('PanelViewPage - Selected values:', selectedValues);
        console.log('PanelViewPage - Final query:', finalQuery);
        
        const response = await fetch(`${API_CONFIG.BASE_URL}/query`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: finalQuery }),
        });
        
        if (!response.ok) {
          throw new Error(`Query failed: ${response.statusText}`);
        }
        
        const result = await response.json();
        setPanelData(result.data || []);
      } catch (error) {
        console.error('Failed to fetch panel data:', error);
        setPanelData([]);
      } finally {
        setIsLoadingData(false);
      }
    };

    fetchPanelData();
  }, [panel, selectedValues]);

  const handleEdit = () => {
    navigate(`/dashboard/${dashboardId}/panels/${panelId}/edit`);
  };

  const handleBackToDashboard = () => {
    if (dashboard) {
      navigate(`/dashboard/${dashboard.id}`);
    } else {
      navigate('/dashboards');
    }
  };

  const handleFullscreenToggle = () => {
    // Exit fullscreen by going back to dashboard
    handleBackToDashboard();
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error || !panel) {
    return (
      <Box sx={{ padding: 3 }}>
        <Alert severity="error" sx={{ mb: 2 }}>
          {error || 'Panel not found'}
        </Alert>
        <Button
          variant="outlined"
          onClick={() => navigate('/dashboards')}
        >
          Back to Dashboards
        </Button>
      </Box>
    );
  }

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Panel Content - Full Screen with 8px margins */}
      <Box sx={{ flex: 1, padding: '8px' }} data-content-container="true">
        <Box sx={{ height: '100%', width: '100%' }}>
          <DashboardPanelView 
            panel={panel}
            data={panelData}
            isEditMode={false}
            showFullscreen={true}
            onEdit={handleEdit}
            onDelete={() => {
              // Navigate back to dashboard after delete
              handleBackToDashboard();
            }}
            onFullscreenToggle={handleFullscreenToggle}
          />
        </Box>
      </Box>
    </Box>
  );
}
