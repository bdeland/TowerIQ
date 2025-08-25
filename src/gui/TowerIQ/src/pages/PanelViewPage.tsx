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
  Link
} from '@mui/material';
import { 
  ArrowBack as ArrowBackIcon,
  Edit as EditIcon,
  Home as HomeIcon
} from '@mui/icons-material';
import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import DashboardPanelView from '../components/DashboardPanelView';

export function PanelViewPage() {
  const { panelId } = useParams<{ panelId: string }>();
  const navigate = useNavigate();
  const { dashboards, fetchDashboards } = useDashboard();
  
  const [panel, setPanel] = useState<DashboardPanel | null>(null);
  const [dashboard, setDashboard] = useState<any>(null);
  const [loading, setLoading] = useState(true);
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
            foundPanel = panelInDash;
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

  const handleEdit = () => {
    navigate(`/panels/${panelId}/edit`);
  };

  const handleBackToDashboard = () => {
    if (dashboard) {
      navigate(`/dashboards/${dashboard.id}`);
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
          <Typography color="text.primary">{panel.title}</Typography>
        </Breadcrumbs>
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
