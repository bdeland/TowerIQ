import { Box, Typography } from '@mui/material';
import React, { useEffect, useState } from 'react';
import { useDashboard } from '../contexts/DashboardContext';
import { DashboardGrid } from '../components/DashboardGrid';
import { liveRunTrackingDashboard } from '../config/liveRunTrackingDashboard';
import { useDashboardData } from '../hooks/useDashboardData';

function LiveRunTrackingDashboardContent() {
  const { setCurrentDashboard } = useDashboard();
  const [panels, setPanels] = useState(liveRunTrackingDashboard.config.panels || []);

  const dashboard = liveRunTrackingDashboard;

  // Use the new dashboard data hook
  const { panelData, loading: isLoading, errors } = useDashboardData(
    panels,
    {}, // No variables for live run tracking dashboard
    {
      enabled: true,
      onError: (errors) => {
        console.error('Live run tracking dashboard data fetch errors:', errors);
      }
    }
  );

  useEffect(() => {
    setCurrentDashboard(dashboard);
    setPanels(dashboard.config.panels || []);
  }, [setCurrentDashboard, dashboard]);

  // Convert Map to Record for DashboardGrid compatibility
  const panelDataRecord = React.useMemo(() => {
    const record: Record<string, any[]> = {};
    panelData.forEach((result, panelId) => {
      record[panelId] = result.data;
    });
    return record;
  }, [panelData]);

  return (
    <Box sx={{ padding: '8px' }} data-content-container="true">
      <DashboardGrid
        panels={panels}
        panelData={panelDataRecord}
        isEditMode={false}
        isEditable={false} // Live run tracking dashboard is always read-only
        showMenu={false} // Explicitly disable panel menus for read-only experience
        showFullscreen={true}
        dashboardId={dashboard?.id}
      />
    </Box>
  );
}

export function LiveRunTrackingDashboardPage() {
  return <LiveRunTrackingDashboardContent />;
}