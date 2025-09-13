import { Box, Typography, Alert, CircularProgress } from '@mui/material';
import { useEffect, useState } from 'react';
import { DashboardGrid } from '../components/DashboardGrid';
import { useDashboard, DashboardPanel, Dashboard } from '../contexts/DashboardContext';

export function DefaultDashboardPage() {
  const { getDefaultDashboard, createDashboard, setDefaultDashboard, loading, error, clearError, setCurrentDashboard } = useDashboard();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [panels, setPanels] = useState<DashboardPanel[]>([]);

  useEffect(() => {
    const loadDefault = async () => {
      let d = await getDefaultDashboard();
      if (!d) {
        // Create a minimal template dashboard if none exists
        const templatePanels: DashboardPanel[] = [
          {
            id: 'panel-1',
            type: 'stat',
            title: 'Welcome',
            gridPos: { x: 0, y: 0, w: 4, h: 2 },
            query: "SELECT 'Ready' AS value",
            echartsOption: {
              tooltip: { show: false },
              graphic: [{
                type: 'text',
                left: 'center',
                top: 'center',
                style: { text: '', fontSize: 28, fontWeight: 'bold' }
              }]
            }
          }
        ];
        const created = await createDashboard({
          title: 'TowerIQ Overview',
          description: 'Default pre-written dashboard',
          config: { panels: templatePanels, time: { from: 'now-1h', to: 'now' }, refresh: '30s' },
          tags: ['default']
        });
        if (created) {
          await setDefaultDashboard(created.id);
          d = created as Dashboard;
        }
      }

      if (d) {
        setDashboard(d);
        setCurrentDashboard(d);
        setPanels(d.config?.panels || []);
      } else {
        setDashboard(null);
        setPanels([]);
      }
    };
    loadDefault();
  }, [getDefaultDashboard, createDashboard, setDefaultDashboard, setCurrentDashboard]);


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

  if (!dashboard) {
    return (
      <Box sx={{ padding: 3 }}>
        <Typography>No dashboard available.</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ padding: '8px 8px 8px 8px', border: '2px solid red' }} data-content-container="true">
      <Box sx={{ mt: 0 }}>
        <DashboardGrid
          panels={panels}
          isEditMode={false}
          isEditable={false} // Default dashboard is always read-only
          showMenu={false} // Explicitly disable panel menus for read-only experience
          showFullscreen={true}
          dashboardId={dashboard?.id}
        />
      </Box>
    </Box>
  );
}


