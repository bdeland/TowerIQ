import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  Box, 
  Typography, 
  Button, 
  Alert, 
  CircularProgress,
  IconButton,
  Link
} from '@mui/material';
import { 
  ArrowBack as ArrowBackIcon,
  Edit as EditIcon
} from '@mui/icons-material';
import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import DashboardPanelView from '../components/DashboardPanelView';
import { Breadcrumbs } from '../components/Breadcrumbs';

export function PanelViewPage() {
  const { panelId, dashboardId } = useParams<{ panelId: string; dashboardId: string }>();
  const navigate = useNavigate();
  const { dashboards, fetchDashboards } = useDashboard();
  
  const [panel, setPanel] = useState<DashboardPanel | null>(null);
  const [dashboard, setDashboard] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const findPanel = async () => {
      if (!panelId || !dashboardId) {
        setError('Panel ID or Dashboard ID not provided');
        setLoading(false);
        return;
      }

      try {
        // If dashboards are not loaded, fetch them
        if (dashboards.length === 0) {
          await fetchDashboards();
        }

        // Find the specific dashboard first
        const foundDashboard = dashboards.find(dash => dash.id === dashboardId);
        if (!foundDashboard) {
          setError(`Dashboard with ID "${dashboardId}" not found`);
          setLoading(false);
          return;
        }

        // Find the panel within that dashboard
        const foundPanel = foundDashboard.config?.panels?.find((p: DashboardPanel) => p.id === panelId);
        if (foundPanel) {
          setPanel(foundPanel);
          setDashboard(foundDashboard);
        } else {
          setError(`Panel with ID "${panelId}" not found in dashboard "${foundDashboard.title}"`);
        }
      } catch (err) {
        setError('Failed to load panel');
        console.error('Error finding panel:', err);
      } finally {
        setLoading(false);
      }
    };

    findPanel();
  }, [panelId, dashboardId, dashboards, fetchDashboards]);

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
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/dashboards')}
        >
          Back to Dashboards
        </Button>
      </Box>
    );
  }

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <Box 
        sx={{ 
          padding: 2, 
          borderBottom: '1px solid #e0e0e0',
          backgroundColor: '#fafafa'
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <IconButton onClick={handleBackToDashboard} size="small">
              <ArrowBackIcon />
            </IconButton>
            <Typography variant="h5" component="h1">
              {panel.title}
            </Typography>
          </Box>
          
          <Button
            variant="contained"
            startIcon={<EditIcon />}
            onClick={handleEdit}
            size="small"
          >
            Edit Panel
          </Button>
        </Box>
        
        {/* Breadcrumbs */}
        <Box sx={{ ml: 5 }}>
          <Breadcrumbs />
        </Box>
      </Box>

      {/* Panel Content */}
      <Box sx={{ flex: 1, padding: 2 }}>
        <Box sx={{ height: '100%', maxHeight: 'calc(100vh - 140px)' }}>
          <DashboardPanelView 
            panel={panel}
            isEditMode={false}
            onEdit={handleEdit}
            onDelete={() => {
              // Navigate back to dashboard after delete
              handleBackToDashboard();
            }}
          />
        </Box>
      </Box>
    </Box>
  );
}
