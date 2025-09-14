import { Box, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { DashboardGrid } from '../components/DashboardGrid';
import { useDashboard, DashboardPanel, Dashboard } from '../contexts/DashboardContext';
import { defaultDashboard } from '../config/defaultDashboard';

export function DefaultDashboardPage() {
  const { setCurrentDashboard } = useDashboard();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [panels, setPanels] = useState<DashboardPanel[]>([]);

  useEffect(() => {
    // Set the dashboard from the hardcoded configuration.
    const d = defaultDashboard;
    setDashboard(d);
    setCurrentDashboard(d);
    setPanels(d.config?.panels || []);
  }, [setCurrentDashboard]);


  if (!dashboard) {
    return (
      <Box sx={{ padding: 3 }}>
        <Typography>Loading Default Dashboard...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ padding: '8px 8px 8px 8px' }} data-content-container="true">
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


