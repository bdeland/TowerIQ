import { Box, Typography } from '@mui/material';
import React, { useEffect, useState } from 'react';
import { DashboardGrid } from '../components/DashboardGrid';
import { useDashboard, DashboardPanel, Dashboard } from '../contexts/DashboardContext';
import { defaultDashboard } from '../config/defaultDashboard';
import { useDashboardVariable } from '../contexts/DashboardVariableContext';
import { useDashboardData } from '../hooks/useDashboardData';

// Create a new component to contain the logic, so it can be wrapped by the provider
function DefaultDashboardContent() {
  const { setCurrentDashboard } = useDashboard();
  const { selectedValues } = useDashboardVariable();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [panels, setPanels] = useState<DashboardPanel[]>([]);

  // Use the new dashboard data hook
  const { panelData, loading: isLoading, errors } = useDashboardData(
    panels,
    selectedValues,
    {
      enabled: !!dashboard,
      onError: (errors) => {
        console.error('Dashboard data fetch errors:', errors);
      }
    }
  );

  useEffect(() => {
    const d = defaultDashboard;
    setDashboard(d);
    setCurrentDashboard(d);
    setPanels(d.config?.panels || []);
  }, [setCurrentDashboard]);

  // Convert Map to Record for DashboardGrid compatibility
  const panelDataRecord = React.useMemo(() => {
    const record: Record<string, any[]> = {};
    panelData.forEach((result, panelId) => {
      record[panelId] = result.data;
    });
    return record;
  }, [panelData]);

  if (!dashboard) {
    return <Typography sx={{ padding: 3 }}>Loading Default Dashboard...</Typography>;
  }

  return (
    <Box data-content-container="true">
      <DashboardGrid
        panels={panels}
        panelData={panelDataRecord} // Pass the dynamic data here
        isLoading={isLoading}
        isEditMode={false}
        isEditable={false} // Default dashboard is always read-only
        showMenu={false} // Explicitly disable panel menus for read-only experience
        showFullscreen={true}
        dashboardId={dashboard?.id}
      />
    </Box>
  );
}

// The main export - no need for provider wrapping since App.tsx handles it
export function DefaultDashboardPage() {
  return <DefaultDashboardContent />;
}


