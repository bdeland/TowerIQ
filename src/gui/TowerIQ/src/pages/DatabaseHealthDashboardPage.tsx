import { Box, Typography } from '@mui/material';
import React, { useEffect, useState } from 'react';
import { DashboardGrid } from '../components/DashboardGrid';
import { useDashboard, DashboardPanel, Dashboard } from '../contexts/DashboardContext';
import { databaseHealthDashboard } from '../config/databaseHealthDashboard';
import { DashboardVariableProvider, useDashboardVariable } from '../contexts/DashboardVariableContext';
import { useDashboardData } from '../hooks/useDashboardData';

// Create a new component to contain the logic, so it can be wrapped by the provider
function DatabaseHealthDashboardContent() {
  const { setCurrentDashboard } = useDashboard();
  const { selectedValues } = useDashboardVariable();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [panels, setPanels] = useState<DashboardPanel[]>([]);

  // Use the new dashboard data hook
  const { panelData, loading: isLoading, errors, refetch } = useDashboardData(
    panels,
    selectedValues,
    {
      enabled: !!dashboard,
      onError: (errors) => {
        console.error('Database health dashboard data fetch errors:', errors);
      }
    }
  );

  useEffect(() => {
    const d = databaseHealthDashboard;
    setDashboard(d);
    setCurrentDashboard(d);
    setPanels(d.config?.panels || []);
  }, [setCurrentDashboard]);

  // Add event listener for database metrics updates
  useEffect(() => {
    const handleDatabaseMetricsUpdate = () => {
      console.log('Database metrics updated, refreshing database health dashboard panels...');
      // Clear cache and refetch data
      refetch();
    };

    // Listen for custom events that indicate database metrics have been updated
    window.addEventListener('databaseMetricsUpdated', handleDatabaseMetricsUpdate);

    return () => {
      window.removeEventListener('databaseMetricsUpdated', handleDatabaseMetricsUpdate);
    };
  }, [refetch]);

  // Convert Map to Record for DashboardGrid compatibility
  const panelDataRecord = React.useMemo(() => {
    const record: Record<string, any[]> = {};
    panelData.forEach((result, panelId) => {
      record[panelId] = result.data;
    });
    return record;
  }, [panelData]);

  if (!dashboard) {
    return <Typography sx={{ padding: 3 }}>Loading Database Health Dashboard...</Typography>;
  }

  return (
    <Box data-content-container="true">
      <DashboardGrid
        panels={panels}
        panelData={panelDataRecord} // Pass the dynamic data here
        isEditMode={false}
        isEditable={false} // Database health dashboard is always read-only
        showMenu={false} // Explicitly disable panel menus for read-only experience
        showFullscreen={true}
        dashboardId={dashboard?.id}
      />
    </Box>
  );
}

// The main export - no need for provider wrapping since App.tsx handles it
export function DatabaseHealthDashboardPage() {
  return <DatabaseHealthDashboardContent />;
}