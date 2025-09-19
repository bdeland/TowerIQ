import { Box, Typography } from '@mui/material';
import { useState, useEffect } from 'react';
import { useDashboard } from '../contexts/DashboardContext';
import { DashboardGrid } from '../components/DashboardGrid';
import { liveRunTrackingDashboard } from '../config/liveRunTrackingDashboard';
import { composeQuery } from '../utils/queryComposer';
import { API_CONFIG } from '../config/environment';

function LiveRunTrackingDashboardContent() {
  const { setCurrentDashboard } = useDashboard();
  const [panelData, setPanelData] = useState<Record<string, any[]>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [lastPanelIds, setLastPanelIds] = useState<string>('');

  const dashboard = liveRunTrackingDashboard;
  const panels = dashboard.config.panels || [];

  useEffect(() => {
    setCurrentDashboard(dashboard);
  }, [setCurrentDashboard]);

  useEffect(() => {
    const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
    
    // Constants for batching
    const BATCH_SIZE = 3;
    const DELAY_BETWEEN_REQUESTS = 100; // 100ms between individual requests
    const DELAY_BETWEEN_BATCHES = 300; // 300ms between batches

    const currentPanelIds = panels.map(p => p.id).join(',');
    if (currentPanelIds === lastPanelIds && isLoading) {
      return; // Skip if already loading the same panels
    }

    const fetchAllPanelData = async () => {
      setIsLoading(true);
      setLastPanelIds(currentPanelIds);

      // No variables for live run tracking dashboard
      const selectedValues = {};
      
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
    
    // Set up auto-refresh every 5 seconds for live data
    const refreshInterval = setInterval(fetchAllPanelData, 5000);
    
    return () => clearInterval(refreshInterval);
  }, [panels, isLoading, lastPanelIds]);

  if (!dashboard) {
    return <Typography sx={{ padding: 3 }}>Loading Live Run Tracking Dashboard...</Typography>;
  }

  return (
    <Box sx={{ padding: '8px' }} data-content-container="true">
      <DashboardGrid
        panels={panels}
        panelData={panelData}
        isEditMode={false}
        isEditable={false}
        showMenu={false}
        showFullscreen={false}
        onLayoutChange={() => {}}
        onPanelClick={() => {}}
        onPanelDelete={() => {}}
        onPanelFullscreenToggle={() => {}}
      />
    </Box>
  );
}

export function LiveRunTrackingDashboardPage() {
  return <LiveRunTrackingDashboardContent />;
}
