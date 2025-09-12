import { Box, Typography, Alert, CircularProgress } from '@mui/material';
import { Responsive, WidthProvider } from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import { useEffect, useState } from 'react';
import DashboardPanelView from '../components/DashboardPanelView';
import { useDashboard, DashboardPanel, Dashboard } from '../contexts/DashboardContext';

const ResponsiveGridLayout = WidthProvider(Responsive);

export function DefaultDashboardPage() {
  const { getDefaultDashboard, createDashboard, setDefaultDashboard, loading, error, clearError, setCurrentDashboard } = useDashboard();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [panels, setPanels] = useState<DashboardPanel[]>([]);
  const [fullscreenPanelId, setFullscreenPanelId] = useState<string | null>(null);

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

  const handleFullscreenToggle = (panelId: string) => {
    setFullscreenPanelId(fullscreenPanelId === panelId ? null : panelId);
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

  if (!dashboard) {
    return (
      <Box sx={{ padding: 3 }}>
        <Typography>No dashboard available.</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ padding: '8px 8px 8px 8px' }}>
      <Box sx={{ mt: 0 }}>
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
          containerPadding={[0, 0]}
          isDraggable={false}
          isResizable={false}
        >
          {panels.map((panel) => (
            <div key={panel.id} style={{ height: '100%' }}>
              <DashboardPanelView 
                panel={panel}
                isEditMode={false}
                showMenu={false}
                showFullscreen={true}
                onFullscreenToggle={handleFullscreenToggle}
              />
            </div>
          ))}
        </ResponsiveGridLayout>
      </Box>
    </Box>
  );
}


