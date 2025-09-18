import { Box, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { DashboardGrid } from '../components/DashboardGrid';
import { useDashboard, DashboardPanel, Dashboard } from '../contexts/DashboardContext';
import { databaseHealthDashboard } from '../config/databaseHealthDashboard';
import { DashboardVariableProvider, useDashboardVariable } from '../contexts/DashboardVariableContext';
import { composeQuery } from '../utils/queryComposer';
import { API_CONFIG } from '../config/environment';

// Create a new component to contain the logic, so it can be wrapped by the provider
function DatabaseHealthDashboardContent() {
  const { setCurrentDashboard } = useDashboard();
  const { selectedValues } = useDashboardVariable();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [panels, setPanels] = useState<DashboardPanel[]>([]);
  const [panelData, setPanelData] = useState<Record<string, any[]>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [lastPanelIds, setLastPanelIds] = useState<string>('');
  const [forceRefresh, setForceRefresh] = useState(0);
  const [lastForceRefresh, setLastForceRefresh] = useState(0);

  useEffect(() => {
    const d = databaseHealthDashboard;
    setDashboard(d);
    setCurrentDashboard(d);
    setPanels(d.config?.panels || []);
  }, [setCurrentDashboard]);

  useEffect(() => {
    if (!dashboard) return;

    const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
    
    // Create a stable identifier for the current panels to prevent infinite loops
    const currentPanelIds = panels.map(p => p.id).sort().join(',');
    const selectedValuesString = JSON.stringify(selectedValues);
    
    // Only fetch if panels have changed or selectedValues have changed, and we're not already loading
    // Or if forceRefresh has been triggered
    if (isLoading || (currentPanelIds === lastPanelIds && forceRefresh === lastForceRefresh)) {
      return;
    }

    const fetchAllPanelData = async () => {
      setIsLoading(true);
      setLastPanelIds(currentPanelIds);
      
      // Update lastForceRefresh to prevent infinite loops
      setLastForceRefresh(forceRefresh);
      
      // Don't reset panel data to avoid flickering - update incrementally instead
      
      // Process panels in batches to avoid overwhelming the server
      const BATCH_SIZE = 2; // Reduced batch size to be more conservative
      const DELAY_BETWEEN_BATCHES = 300; // Increased delay between batches
      const DELAY_BETWEEN_REQUESTS = 150; // Increased delay between individual requests
      
      const panelsWithQueries = panels.filter(panel => panel.query);
      
      try {
        for (let i = 0; i < panelsWithQueries.length; i += BATCH_SIZE) {
          const batch = panelsWithQueries.slice(i, i + BATCH_SIZE);
          
          // Process each panel in the batch with a small delay between requests
          for (const panel of batch) {
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
            
            // Small delay between individual requests to prevent overwhelming
            if (batch.indexOf(panel) < batch.length - 1) {
              await delay(DELAY_BETWEEN_REQUESTS);
            }
          }
          
          // Delay between batches (except for the last batch)
          if (i + BATCH_SIZE < panelsWithQueries.length) {
            await delay(DELAY_BETWEEN_BATCHES);
          }
        }
      } finally {
        setIsLoading(false);
      }
    };

    fetchAllPanelData();
  }, [selectedValues, dashboard, panels, isLoading, lastPanelIds, forceRefresh, lastForceRefresh]);

  // Add event listener for database metrics updates
  useEffect(() => {
    const handleDatabaseMetricsUpdate = () => {
      console.log('Database metrics updated, refreshing database health dashboard panels...');
      // Use a timestamp to ensure uniqueness and avoid infinite loops
      setForceRefresh(Date.now());
    };

    window.addEventListener('database-metrics-updated', handleDatabaseMetricsUpdate);
    
    return () => {
      window.removeEventListener('database-metrics-updated', handleDatabaseMetricsUpdate);
    };
  }, []);

  if (!dashboard) {
    return <Typography sx={{ padding: 3 }}>Loading Database Health Dashboard...</Typography>;
  }

  return (
    <Box sx={{ padding: '8px' }} data-content-container="true">
      <DashboardGrid
        panels={panels}
        panelData={panelData} // Pass the dynamic data here
        isEditMode={false}
        isEditable={false} // Database health dashboard is always read-only
        showMenu={false} // Explicitly disable panel menus for read-only experience
        showFullscreen={true}
        dashboardId={dashboard?.id}
      />
    </Box>
  );
}

// The main export is now the provider wrapping the content
export function DatabaseHealthDashboardPage() {
  return (
    <DashboardVariableProvider>
      <DatabaseHealthDashboardContent />
    </DashboardVariableProvider>
  );
}
