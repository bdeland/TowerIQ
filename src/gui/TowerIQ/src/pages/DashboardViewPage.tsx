import { Box, Typography, Alert, CircularProgress } from '@mui/material';
// Removed react-grid-layout import as we're now using native CSS Grid
import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import { useDashboardEdit } from '../contexts/DashboardEditContext';
import PanelEditorDrawer from '../components/PanelEditorDrawer';
import { DashboardGrid } from '../components/DashboardGrid';
import { generateUUID } from '../utils/uuid';
import { featureFlags } from '../config/featureFlags';
import { defaultDashboard } from '../config/defaultDashboard';
import { databaseHealthDashboard } from '../config/databaseHealthDashboard';
import { DashboardVariableProvider, useDashboardVariable } from '../contexts/DashboardVariableContext';
import { composeQuery } from '../utils/queryComposer';
import { API_CONFIG } from '../config/environment';
import { useDeveloper } from '../contexts/DeveloperContext';

// Component that handles default dashboard with dynamic data fetching
function DefaultDashboardContent({ panels, currentDashboard, isEditMode, selectedPanelId, onLayoutChange, onPanelClick, onPanelDelete, onUpdatePanel, onDeletePanel, getSelectedPanel }: {
  panels: DashboardPanel[];
  currentDashboard: any;
  isEditMode: boolean;
  selectedPanelId: string | null;
  onLayoutChange: (panels: DashboardPanel[]) => void;
  onPanelClick: (panelId: string) => void;
  onPanelDelete: (panelId: string) => void;
  onUpdatePanel: (panel: DashboardPanel) => void;
  onDeletePanel: (panelId: string) => void;
  getSelectedPanel: () => DashboardPanel | null;
}) {
  const { isDevMode } = useDeveloper();
  const [panelData, setPanelData] = useState<Record<string, any[]>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [lastPanelIds, setLastPanelIds] = useState<string>('');

  // Only use dashboard variables if the dashboard has them
  let selectedValues = {};
  try {
    if (currentDashboard?.variables && currentDashboard.variables.length > 0) {
      const dashboardVariableContext = useDashboardVariable();
      selectedValues = dashboardVariableContext.selectedValues;
    }
  } catch (error) {
    // Dashboard variable context not available, use empty values
    selectedValues = {};
  }

  useEffect(() => {
    const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
    
    // Create a stable identifier for the current panels to prevent infinite loops
    const currentPanelIds = panels.map(p => p.id).sort().join(',');
    const selectedValuesString = JSON.stringify(selectedValues);
    
    // Only fetch if panels have changed or selectedValues have changed, and we're not already loading
    if (isLoading || currentPanelIds === lastPanelIds) {
      return;
    }
    
    const fetchAllPanelData = async () => {
      setIsLoading(true);
      setLastPanelIds(currentPanelIds);
      
      // Reset panel data when starting fresh fetch
      setPanelData({});
      
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
              setPanelData(prev => ({ ...prev, [panel.id]: [] }));
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
  }, [selectedValues, panels, isLoading, lastPanelIds]);

  return (
    <Box sx={{ padding: '8px 8px 8px 8px', border: isDevMode ? '2px solid red' : 'none' }} data-content-container="true">
      <Box sx={{ mt: 0 }}>
        <DashboardGrid
          panels={panels}
          panelData={panelData}
          isEditMode={isEditMode}
          isEditable={featureFlags.enableAdHocDashboards}
          showMenu={featureFlags.enableAdHocDashboards && !currentDashboard?.is_default}
          showFullscreen={currentDashboard?.is_default || false}
          dashboardId={currentDashboard?.id}
          onLayoutChange={onLayoutChange}
          onPanelClick={onPanelClick}
          onPanelDelete={onPanelDelete}
        />
      </Box>

      {/* Panel Editor Drawer */}
      <PanelEditorDrawer
        open={selectedPanelId !== null}
        panel={getSelectedPanel()}
        onClose={() => setSelectedPanelId(null)}
        onUpdatePanel={onUpdatePanel}
        onDeletePanel={onDeletePanel}
      />
    </Box>
  );
}

export function DashboardViewPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { fetchDashboard, currentDashboard, setCurrentDashboard, updateDashboard, createDashboard, fetchDashboards, loading, error, clearError } = useDashboard();
  const { isDevMode } = useDeveloper();
  const { 
    setIsDashboardPage, 
    setIsEditMode: setContextEditMode, 
    setSaving: setContextSaving, 
    setEditHandlers 
  } = useDashboardEdit();
  
  const [panels, setPanels] = useState<DashboardPanel[]>([]);
  const [isEditMode, setIsEditMode] = useState(false);
  const [originalPanels, setOriginalPanels] = useState<DashboardPanel[]>([]);
  const [selectedPanelId, setSelectedPanelId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Handler functions for dashboard edit context
  const handleEditModeToggle = useCallback(() => {
    if (!featureFlags.enableAdHocDashboards) return; // Prevent entering edit mode
    if (id === 'default-dashboard' || id === 'database-health-dashboard') return; // Prevent editing system dashboards
    if (isEditMode) {
      setIsEditMode(false);
      setSelectedPanelId(null);
      // Reset panels to original state on cancel
      setPanels(originalPanels);
    } else {
      setIsEditMode(true);
      setOriginalPanels([...panels]);
    }
  }, [isEditMode, originalPanels, panels, id]);

  const handleAddVisualization = useCallback(() => {
    // Call addPanel function (will be defined later)
    const newPanel: DashboardPanel = {
      id: generateUUID(),
      type: 'stat',
      title: `New Panel`,
      gridPos: {
        x: (panels.length * 4) % 12,
        y: Math.floor(panels.length / 3) * 2,
        w: 4,
        h: 2
      },
      query: "SELECT 'Sample Data' as value",
      echartsOption: {
        tooltip: { show: false },
        graphic: [{
          type: 'text',
          left: 'center',
          top: 'center',
          style: {
            text: 'New Panel',
            fontSize: 24,
            fontWeight: 'bold',
            fill: '#333'
          }
        }]
      }
    };
    
    console.log('Adding new panel:', newPanel);
    setPanels([...panels, newPanel]);
  }, [panels]);

  const handleAddRow = useCallback(() => {
    console.log('Add Row clicked');
    // TODO: Implement row functionality
  }, []);

  const handlePastePanel = useCallback(() => {
    console.log('Paste Panel clicked');
    // TODO: Implement paste panel functionality
  }, []);

  const handleSave = useCallback(async () => {
    if (!currentDashboard || !id) return;
    
    // Prevent saving changes to the default dashboard
    if (id === 'default-dashboard') {
      console.log('DashboardViewPage - Cannot save changes to default dashboard');
      return;
    }
    
    setSaving(true);
    try {
      console.log('DashboardViewPage - Saving dashboard with panels:', panels);
      const updatedConfig = { ...currentDashboard.config, panels };
      const updatedDashboard = await updateDashboard(id, { config: updatedConfig });
      
      if (updatedDashboard) {
        console.log('DashboardViewPage - Dashboard saved successfully:', updatedDashboard);
        setOriginalPanels([...panels]); // Update original panels after save
        setIsEditMode(false); // Exit edit mode after save
      } else {
        console.error('DashboardViewPage - Failed to save dashboard');
      }
    } catch (error) {
      console.error('DashboardViewPage - Error saving dashboard:', error);
    } finally {
      setSaving(false);
    }
  }, [currentDashboard, id, panels, updateDashboard]);

  const handleSaveAsCopy = useCallback(async () => {
    if (!currentDashboard) return;
    
    setSaving(true);
    try {
      console.log('DashboardViewPage - Saving dashboard as copy with panels:', panels);
      
      // Create a new dashboard with " - Copy" appended to the name
      const copyConfig = { 
        ...currentDashboard.config, 
        panels: panels.map(panel => ({
          ...panel,
          id: generateUUID() // Generate new UUID for each panel
        }))
      };
      
      const copyDashboardRequest = {
        title: `${currentDashboard.title} - Copy`,
        description: currentDashboard.description || '',
        config: copyConfig,
        tags: currentDashboard.tags || []
      };
      
      console.log('DashboardViewPage - Creating dashboard copy with data:', copyDashboardRequest);
      
      // Create the copy using the dashboard context
      const newDashboard = await createDashboard(copyDashboardRequest);
      
      if (newDashboard) {
        console.log('DashboardViewPage - Dashboard copy created successfully:', newDashboard);
        
        // Refresh the dashboard list so the copy appears
        await fetchDashboards();
        
        // Navigate to the new dashboard
        navigate(`/dashboard/${newDashboard.id}`);
      } else {
        console.error('DashboardViewPage - Failed to create dashboard copy');
      }
    } catch (error) {
      console.error('DashboardViewPage - Error creating dashboard copy:', error);
    } finally {
      setSaving(false);
    }
  }, [currentDashboard, panels, navigate, createDashboard, fetchDashboards]);

  // Set up dashboard edit context with error handling
  useEffect(() => {
    try {
      setIsDashboardPage(true);
      
      return () => {
        setIsDashboardPage(false);
      };
    } catch (error) {
      console.error('Error setting up dashboard edit context:', error);
    }
  }, [setIsDashboardPage]);

  // Set handlers separately to avoid dependency issues
  useEffect(() => {
    try {
      setEditHandlers({
        onEditToggle: handleEditModeToggle,
        onAddVisualization: handleAddVisualization,
        onAddRow: handleAddRow,
        onPastePanel: handlePastePanel,
        onSave: handleSave,
        onSaveAsCopy: handleSaveAsCopy,
      });
    } catch (error) {
      console.error('Error setting edit handlers:', error);
    }
  }, [setEditHandlers, handleEditModeToggle, handleAddVisualization, handleAddRow, handlePastePanel, handleSave, handleSaveAsCopy]);

  // Sync edit mode with context
  useEffect(() => {
    try {
      setContextEditMode(isEditMode);
    } catch (error) {
      console.error('Error syncing edit mode:', error);
    }
  }, [isEditMode, setContextEditMode]);

  // Sync saving state with context
  useEffect(() => {
    try {
      setContextSaving(saving);
    } catch (error) {
      console.error('Error syncing saving state:', error);
    }
  }, [saving, setContextSaving]);

  // Debug logging
  useEffect(() => {
    console.log('DashboardViewPage - Current dashboard:', currentDashboard);
    console.log('DashboardViewPage - Current dashboard title:', currentDashboard?.title);
  }, [currentDashboard]);

  useEffect(() => {
    const loadDashboard = async () => {
      if (id) {
        console.log('DashboardViewPage - Loading dashboard with ID:', id);
        
        // Check if this is the default dashboard
        if (id === 'default-dashboard') {
          console.log('DashboardViewPage - Loading hardcoded default dashboard');
          const dashboard = defaultDashboard;
          setCurrentDashboard(dashboard);
          setPanels(dashboard.config.panels || []);
          setIsEditMode(false);
          setSelectedPanelId(null);
          setOriginalPanels(dashboard.config.panels || []);
          return;
        }
        
        // Check if this is the database health dashboard
        if (id === 'database-health-dashboard') {
          console.log('DashboardViewPage - Loading hardcoded database health dashboard');
          const dashboard = databaseHealthDashboard;
          setCurrentDashboard(dashboard);
          setPanels(dashboard.config.panels || []);
          setIsEditMode(false);
          setSelectedPanelId(null);
          setOriginalPanels(dashboard.config.panels || []);
          return;
        }
        
        // For other dashboards, fetch from backend
        const dashboard = await fetchDashboard(id);
        if (dashboard) {
          console.log('DashboardViewPage - Setting current dashboard:', dashboard.title);
          console.log('DashboardViewPage - Dashboard panels:', dashboard.config.panels);
          setCurrentDashboard(dashboard);
          setPanels(dashboard.config.panels || []);
          // Reset edit mode and selection when loading
          setIsEditMode(false);
          setSelectedPanelId(null);
          setOriginalPanels(dashboard.config.panels || []);
        } else {
          // Dashboard not found, redirect to dashboards list
          navigate('/dashboards');
        }
      }
    };

    loadDashboard();
  }, [id, fetchDashboard, setCurrentDashboard, navigate]);

  // addPanel functionality moved to handleAddVisualization

  const onLayoutChange = (updatedPanels: DashboardPanel[]) => {
    console.log('Layout changed:', updatedPanels);
    // Only update panel positions when in edit mode
    if (isEditMode) {
      setPanels(updatedPanels);
    }
  };



  // handleSave function moved to the top with other handlers

  const handlePanelClick = (panelId: string) => {
    if (isEditMode) {
      setSelectedPanelId(selectedPanelId === panelId ? null : panelId);
    }
  };

  const handleUpdatePanel = (updatedPanel: DashboardPanel) => {
    const updatedPanels = panels.map(p => 
      p.id === updatedPanel.id ? updatedPanel : p
    );
    setPanels(updatedPanels);
  };

  const handleDeletePanel = (panelId: string) => {
    const updatedPanels = panels.filter(p => p.id !== panelId);
    setPanels(updatedPanels);
    setSelectedPanelId(null);
  };

  const getSelectedPanel = () => {
    return selectedPanelId ? panels.find(p => p.id === selectedPanelId) || null : null;
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

  const dashboardContent = (
    <Box sx={{ padding: '8px 8px 8px 8px', border: isDevMode ? '2px solid red' : 'none' }} data-content-container="true">
      <Box sx={{ mt: 0 }}>
        <DashboardGrid
          panels={panels}
          isEditMode={isEditMode}
          isEditable={featureFlags.enableAdHocDashboards}
          showMenu={featureFlags.enableAdHocDashboards && !currentDashboard?.is_default}
          showFullscreen={currentDashboard?.is_default || false}
          dashboardId={currentDashboard?.id}
          onLayoutChange={onLayoutChange}
          onPanelClick={handlePanelClick}
          onPanelDelete={handleDeletePanel}
        />
      </Box>

      {/* Panel Editor Drawer */}
      <PanelEditorDrawer
        open={selectedPanelId !== null}
        panel={getSelectedPanel()}
        onClose={() => setSelectedPanelId(null)}
        onUpdatePanel={handleUpdatePanel}
        onDeletePanel={handleDeletePanel}
      />
    </Box>
  );

  // Use DefaultDashboardContent for default dashboards (handles variables conditionally)
  if (currentDashboard?.is_default) {
    return (
      <DefaultDashboardContent
        panels={panels}
        currentDashboard={currentDashboard}
        isEditMode={isEditMode}
        selectedPanelId={selectedPanelId}
        onLayoutChange={onLayoutChange}
        onPanelClick={handlePanelClick}
        onPanelDelete={handleDeletePanel}
        onUpdatePanel={handleUpdatePanel}
        onDeletePanel={handleDeletePanel}
        getSelectedPanel={getSelectedPanel}
      />
    );
  }

  return dashboardContent;
}
