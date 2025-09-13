import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  Box, 
  Button, 
  Alert, 
  CircularProgress
} from '@mui/material';
import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import DashboardPanelView from '../components/DashboardPanelView';

export function PanelViewPage() {
  const { panelId, dashboardId } = useParams<{ panelId: string; dashboardId: string }>();
  const navigate = useNavigate();
  const { fetchDashboard, loading, error } = useDashboard();
  
  const [panel, setPanel] = useState<DashboardPanel | null>(null);
  const [dashboard, setDashboard] = useState<any>(null);

  useEffect(() => {
    const loadPanel = async () => {
      if (!panelId || !dashboardId) {
        return;
      }

      try {
        // Fetch only the specific dashboard instead of all dashboards
        const foundDashboard = await fetchDashboard(dashboardId);
        if (!foundDashboard) {
          return;
        }

        // Find the panel within that dashboard
        const foundPanel = foundDashboard.config?.panels?.find((p: DashboardPanel) => p.id === panelId);
        if (foundPanel) {
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
  }, [panelId, dashboardId, fetchDashboard]);

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
