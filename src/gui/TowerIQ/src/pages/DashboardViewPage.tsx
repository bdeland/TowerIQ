import { Box, Typography, Button, Alert, CircularProgress } from '@mui/material';
import { Add as AddIcon } from '@mui/icons-material';
import { Responsive, WidthProvider, Layout } from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useDashboard, Dashboard, DashboardPanel } from '../contexts/DashboardContext';

const ResponsiveGridLayout = WidthProvider(Responsive);

export function DashboardViewPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { fetchDashboard, currentDashboard, setCurrentDashboard, loading, error, clearError } = useDashboard();
  
  const [panels, setPanels] = useState<DashboardPanel[]>([]);
  const [panelCounter, setPanelCounter] = useState(1);

  // Debug logging
  useEffect(() => {
    console.log('DashboardViewPage - Current dashboard:', currentDashboard);
    console.log('DashboardViewPage - Current dashboard title:', currentDashboard?.title);
  }, [currentDashboard]);

  useEffect(() => {
    const loadDashboard = async () => {
      if (id && (!currentDashboard || currentDashboard.id !== id)) {
        console.log('DashboardViewPage - Loading dashboard with ID:', id);
        const dashboard = await fetchDashboard(id);
        if (dashboard) {
          console.log('DashboardViewPage - Setting current dashboard:', dashboard.title);
          setCurrentDashboard(dashboard);
          setPanels(dashboard.config.panels || []);
          setPanelCounter((dashboard.config.panels?.length || 0) + 1);
        } else {
          // Dashboard not found, redirect to dashboards list
          navigate('/dashboards');
        }
      }
    };

    loadDashboard();
  }, [id, navigate]); // Removed fetchDashboard and setCurrentDashboard from dependencies

  const addPanel = () => {
    const newPanel: DashboardPanel = {
      id: `panel-${panelCounter}`,
      type: 'stat',
      title: `Panel ${panelCounter}`,
      gridPos: {
        x: (panels.length * 4) % 12,
        y: Math.floor(panels.length / 3) * 2,
        w: 4,
        h: 2
      },
      options: {}
    };
    
    console.log('Adding new panel:', newPanel);
    setPanels([...panels, newPanel]);
    setPanelCounter(panelCounter + 1);
  };

  const onLayoutChange = (layout: Layout[]) => {
    console.log('Layout changed:', layout);
    // Update panel positions when layout changes
    const updatedPanels = panels.map(panel => {
      const layoutItem = layout.find(item => item.i === panel.id);
      if (layoutItem) {
        return {
          ...panel,
          gridPos: {
            x: layoutItem.x,
            y: layoutItem.y,
            w: layoutItem.w,
            h: layoutItem.h
          }
        };
      }
      return panel;
    });
    setPanels(updatedPanels);
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ padding: 3 }}>
        <Alert severity="error" onClose={clearError}>
          {error}
        </Alert>
      </Box>
    );
  }

  if (!currentDashboard) {
    return (
      <Box sx={{ padding: 3 }}>
        <Typography>Dashboard not found.</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ padding: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', mb: 3 }}>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={addPanel}
          sx={{ minWidth: 120 }}
        >
          Add Panel
        </Button>
      </Box>
      
      <Box sx={{ mt: 2 }}>
        <ResponsiveGridLayout
          className="layout"
          layouts={{ lg: panels.map(panel => ({
            i: panel.id,
            x: panel.gridPos.x,
            y: panel.gridPos.y,
            w: panel.gridPos.w,
            h: panel.gridPos.h
          })) }}
          breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
          cols={{ lg: 12, md: 10, sm: 6, xs: 4, xxs: 2 }}
          rowHeight={100}
          margin={[8, 8]}
          onLayoutChange={onLayoutChange}
          isDraggable={true}
          isResizable={true}
        >
          {panels.map((panel) => (
            <Box
              key={panel.id}
              sx={{
                backgroundColor: 'background.paper',
                border: '1px solid',
                borderColor: 'divider',
                borderRadius: 1,
                p: 2,
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center',
                textAlign: 'center',
                boxShadow: 1,
                '&:hover': {
                  boxShadow: 2,
                  borderColor: 'primary.main'
                }
              }}
            >
              <Typography variant="h6" gutterBottom>
                {panel.title}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Type: {panel.type}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Drag to move • Resize corners to adjust
              </Typography>
            </Box>
          ))}
        </ResponsiveGridLayout>
      </Box>
    </Box>
  );
}
