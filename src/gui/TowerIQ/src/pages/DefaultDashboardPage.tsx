import { Box, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { DashboardGrid } from '../components/DashboardGrid';
import { useDashboard, DashboardPanel, Dashboard } from '../contexts/DashboardContext';
import { defaultDashboard } from '../config/defaultDashboard';
import { DashboardVariableProvider, useDashboardVariable } from '../contexts/DashboardVariableContext';
import { composeQuery } from '../utils/queryComposer';
import { API_CONFIG } from '../config/environment';

// Create a new component to contain the logic, so it can be wrapped by the provider
function DefaultDashboardContent() {
  const { setCurrentDashboard } = useDashboard();
  const { selectedValues } = useDashboardVariable();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [panels, setPanels] = useState<DashboardPanel[]>([]);
  const [panelData, setPanelData] = useState<Record<string, any[]>>({});

  useEffect(() => {
    const d = defaultDashboard;
    setDashboard(d);
    setCurrentDashboard(d);
    setPanels(d.config?.panels || []);
  }, [setCurrentDashboard]);

  useEffect(() => {
    if (!dashboard) return;

    const fetchAllPanelData = async () => {
      for (const panel of panels) {
        if (panel.query) {
          const finalQuery = composeQuery(panel.query, selectedValues);
          try {
            const response = await fetch(`${API_CONFIG.BASE_URL}/query`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ query: finalQuery }),
            });
            
            if (!response.ok) {
              throw new Error(`Query failed: ${response.statusText}`);
            }
            
            const result = await response.json();
            setPanelData(prev => ({ ...prev, [panel.id]: result.data }));
          } catch (error) {
            console.error(`Failed to fetch data for panel ${panel.title}:`, error);
            setPanelData(prev => ({ ...prev, [panel.id]: [] })); // Set empty data on error
          }
        }
      }
    };

    fetchAllPanelData();
  }, [selectedValues, dashboard, panels]);

  if (!dashboard) {
    return <Typography sx={{ padding: 3 }}>Loading Default Dashboard...</Typography>;
  }

  return (
    <Box sx={{ padding: '8px' }} data-content-container="true">
      <DashboardGrid
        panels={panels}
        panelData={panelData} // Pass the dynamic data here
        isEditMode={false}
        isEditable={false} // Default dashboard is always read-only
        showMenu={false} // Explicitly disable panel menus for read-only experience
        showFullscreen={true}
        dashboardId={dashboard?.id}
      />
    </Box>
  );
}

// The main export is now the provider wrapping the content
export function DefaultDashboardPage() {
  return (
    <DashboardVariableProvider>
      <DefaultDashboardContent />
    </DashboardVariableProvider>
  );
}


