import { Box, Typography, Alert, CircularProgress } from '@mui/material';
import { Responsive, WidthProvider, Layout } from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import { useDashboardEdit } from '../contexts/DashboardEditContext';
import DashboardPanelView from '../components/DashboardPanelView';
import PanelEditorDrawer from '../components/PanelEditorDrawer';

const ResponsiveGridLayout = WidthProvider(Responsive);

export function DashboardViewPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { fetchDashboard, currentDashboard, setCurrentDashboard, updateDashboard, loading, error, clearError } = useDashboard();
  const { 
    setIsDashboardPage, 
    setIsEditMode: setContextEditMode, 
    setSaving: setContextSaving, 
    setEditHandlers 
  } = useDashboardEdit();
  
  const [panels, setPanels] = useState<DashboardPanel[]>([]);
  const [panelCounter, setPanelCounter] = useState(1);
  const [isEditMode, setIsEditMode] = useState(false);
  const [originalPanels, setOriginalPanels] = useState<DashboardPanel[]>([]);
  const [selectedPanelId, setSelectedPanelId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Handler functions for dashboard edit context
  const handleEditModeToggle = useCallback(() => {
    if (isEditMode) {
      setIsEditMode(false);
      setSelectedPanelId(null);
      // Reset panels to original state on cancel
      setPanels(originalPanels);
    } else {
      setIsEditMode(true);
      setOriginalPanels([...panels]);
    }
  }, [isEditMode, originalPanels, panels]);

  const handleAddVisualization = useCallback(() => {
    // Call addPanel function (will be defined later)
    const newPanel: DashboardPanel = {
      id: `panel-${panelCounter}`,
      type: 'stat',
      title: `Panel ${panelCounter}`,
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
    setPanelCounter(panelCounter + 1);
  }, [panels, panelCounter]);

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
      });
    } catch (error) {
      console.error('Error setting edit handlers:', error);
    }
  }, [setEditHandlers, handleEditModeToggle, handleAddVisualization, handleAddRow, handlePastePanel, handleSave]);

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
        const dashboard = await fetchDashboard(id);
        if (dashboard) {
          console.log('DashboardViewPage - Setting current dashboard:', dashboard.title);
          console.log('DashboardViewPage - Dashboard panels:', dashboard.config.panels);
          setCurrentDashboard(dashboard);
          setPanels(dashboard.config.panels || []);
          setPanelCounter((dashboard.config.panels?.length || 0) + 1);
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

  const onLayoutChange = (layout: Layout[]) => {
    console.log('Layout changed:', layout);
    // Only update panel positions when in edit mode
    if (isEditMode) {
      const updatedPanels = panels.map(panel => {
        const layoutItem = layout.find(item => item.i === panel.id);
        if (layoutItem) {
          return {
            ...panel,
            gridPos: {
              x: layoutItem.x,
              y: layoutItem.y,
              w: layoutItem.w,
              h: layoutItem.h
            }
          };
        }
        return panel;
      });
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

  return (
    <Box sx={{ padding: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4" component="h1">
          {currentDashboard.title}
        </Typography>
      </Box>
      
      <Box sx={{ mt: 2 }}>
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
          onLayoutChange={onLayoutChange}
          isDraggable={isEditMode}
          isResizable={isEditMode}
        >
          {panels.map((panel) => (
            <div key={panel.id} style={{ height: '100%' }}>
              <DashboardPanelView 
                panel={panel} 
                isEditMode={isEditMode}
                onClick={() => handlePanelClick(panel.id)}
                onDelete={handleDeletePanel}
                onEdit={(panelId) => setSelectedPanelId(panelId)}
              />
            </div>
          ))}
        </ResponsiveGridLayout>
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
}
