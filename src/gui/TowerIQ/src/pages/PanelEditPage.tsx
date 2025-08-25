import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  Box, 
  Typography, 
  Button, 
  Alert, 
  CircularProgress,
  IconButton,
  Breadcrumbs,
  Link,
  Grid,
  Paper
} from '@mui/material';
import { 
  ArrowBack as ArrowBackIcon,
  Save as SaveIcon,
  Visibility as ViewIcon,
  Home as HomeIcon
} from '@mui/icons-material';
import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import DashboardPanelView from '../components/DashboardPanelView';
import PanelEditorDrawer from '../components/PanelEditorDrawer';

export function PanelEditPage() {
  const { panelId } = useParams<{ panelId: string }>();
  const navigate = useNavigate();
  const { dashboards, fetchDashboards, updateDashboard } = useDashboard();
  
  const [panel, setPanel] = useState<DashboardPanel | null>(null);
  const [dashboard, setDashboard] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const findPanel = async () => {
      if (!panelId) {
        setError('Panel ID not provided');
        setLoading(false);
        return;
      }

      try {
        // If dashboards are not loaded, fetch them
        if (dashboards.length === 0) {
          await fetchDashboards();
        }

        // Find the panel across all dashboards
        let foundPanel: DashboardPanel | null = null;
        let foundDashboard: any = null;

        for (const dash of dashboards) {
          const panelInDash = dash.config?.panels?.find((p: DashboardPanel) => p.id === panelId);
          if (panelInDash) {
            foundPanel = { ...panelInDash }; // Create a copy for editing
            foundDashboard = dash;
            break;
          }
        }

        if (foundPanel && foundDashboard) {
          setPanel(foundPanel);
          setDashboard(foundDashboard);
        } else {
          setError(`Panel with ID "${panelId}" not found`);
        }
      } catch (err) {
        setError('Failed to load panel');
        console.error('Error finding panel:', err);
      } finally {
        setLoading(false);
      }
    };

    findPanel();
  }, [panelId, dashboards, fetchDashboards]);

  const handleUpdatePanel = (updatedPanel: DashboardPanel) => {
    setPanel(updatedPanel);
  };

  const handleSave = async () => {
    if (!panel || !dashboard) return;

    setSaving(true);
    try {
      // Update the panel in the dashboard's panels array
      const updatedPanels = dashboard.config.panels.map((p: DashboardPanel) =>
        p.id === panel.id ? panel : p
      );

      const updatedConfig = {
        ...dashboard.config,
        panels: updatedPanels
      };

      const success = await updateDashboard(dashboard.id, { config: updatedConfig });
      if (success) {
        navigate(`/panels/${panelId}/view`);
      } else {
        setError('Failed to save panel changes');
      }
    } catch (err) {
      setError('Error saving panel changes');
      console.error('Error saving panel:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleView = () => {
    navigate(`/panels/${panelId}/view`);
  };

  const handleBackToDashboard = () => {
    if (dashboard) {
      navigate(`/dashboards/${dashboard.id}`);
    } else {
      navigate('/dashboards');
    }
  };

  const handleDeletePanel = async (panelId: string) => {
    if (!dashboard) return;

    setSaving(true);
    try {
      // Remove the panel from the dashboard's panels array
      const updatedPanels = dashboard.config.panels.filter((p: DashboardPanel) => p.id !== panelId);

      const updatedConfig = {
        ...dashboard.config,
        panels: updatedPanels
      };

      const success = await updateDashboard(dashboard.id, { config: updatedConfig });
      if (success) {
        navigate(`/dashboards/${dashboard.id}`);
      } else {
        setError('Failed to delete panel');
      }
    } catch (err) {
      setError('Error deleting panel');
      console.error('Error deleting panel:', err);
    } finally {
      setSaving(false);
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
              Edit: {panel.title}
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              startIcon={<ViewIcon />}
              onClick={handleView}
              disabled={saving}
              size="small"
            >
              View Panel
            </Button>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSave}
              disabled={saving}
              size="small"
            >
              {saving ? 'Saving...' : 'Save Changes'}
            </Button>
          </Box>
        </Box>
        
        {/* Breadcrumbs */}
        <Breadcrumbs aria-label="breadcrumb" sx={{ ml: 5 }}>
          <Link 
            color="inherit" 
            href="/dashboards" 
            onClick={(e) => {
              e.preventDefault();
              navigate('/dashboards');
            }}
            sx={{ display: 'flex', alignItems: 'center', textDecoration: 'none' }}
          >
            <HomeIcon sx={{ mr: 0.5 }} fontSize="inherit" />
            Dashboards
          </Link>
          {dashboard && (
            <Link
              color="inherit"
              href={`/dashboards/${dashboard.id}`}
              onClick={(e) => {
                e.preventDefault();
                navigate(`/dashboards/${dashboard.id}`);
              }}
              sx={{ textDecoration: 'none' }}
            >
              {dashboard.title}
            </Link>
          )}
          <Link
            color="inherit"
            href={`/panels/${panelId}/view`}
            onClick={(e) => {
              e.preventDefault();
              navigate(`/panels/${panelId}/view`);
            }}
            sx={{ textDecoration: 'none' }}
          >
            {panel.title}
          </Link>
          <Typography color="text.primary">Edit</Typography>
        </Breadcrumbs>

        {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {error}
          </Alert>
        )}
      </Box>

      {/* Content */}
      <Box sx={{ flex: 1, display: 'flex' }}>
        {/* Panel Preview */}
        <Box sx={{ flex: 1, padding: 2 }}>
          <Paper sx={{ height: '100%', maxHeight: 'calc(100vh - 140px)' }} elevation={1}>
            <DashboardPanelView 
              panel={panel}
              isEditMode={false}
              onEdit={() => {}} // Disable edit menu in edit mode
              onDelete={handleDeletePanel}
            />
          </Paper>
        </Box>

        {/* Panel Editor - Always Open */}
        <Box sx={{ width: 400, borderLeft: '1px solid #e0e0e0' }}>
          <PanelEditorDrawer
            open={true}
            panel={panel}
            onClose={() => {}} // Disable close in dedicated edit page
            onUpdatePanel={handleUpdatePanel}
            onDeletePanel={handleDeletePanel}
            standalone={true}
          />
        </Box>
      </Box>
    </Box>
  );
}
