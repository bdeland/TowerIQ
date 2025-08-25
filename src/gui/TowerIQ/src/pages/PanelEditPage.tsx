import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  Box, 
  Alert, 
  CircularProgress,
  Paper,
  Tabs,
  Tab
} from '@mui/material';

import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import DashboardPanelView from '../components/DashboardPanelView';
import PanelEditorDrawer from '../components/PanelEditorDrawer';

export function PanelEditPage() {
  const { panelId } = useParams<{ panelId: string }>();
  const navigate = useNavigate();
  const { dashboards, fetchDashboards, updateDashboard } = useDashboard();
  
  const [panel, setPanel] = useState<DashboardPanel | null>(null);
  const [dashboard, setDashboard] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [drawerWidth, setDrawerWidth] = useState(400);
  const [isDragging, setIsDragging] = useState(false);
  const [tabbedSectionHeight, setTabbedSectionHeight] = useState(300);
  const [isDraggingHorizontal, setIsDraggingHorizontal] = useState(false);
  const [activeTab, setActiveTab] = useState(0);

  useEffect(() => {
    const findPanel = async () => {
      if (!panelId) {
        setError('Panel ID not provided');
        setLoading(false);
        return;
      }

      try {
        // If dashboards are not loaded, fetch them
        if (dashboards.length === 0) {
          await fetchDashboards();
        }

        // Find the panel across all dashboards
        let foundPanel: DashboardPanel | null = null;
        let foundDashboard: any = null;

        for (const dash of dashboards) {
          const panelInDash = dash.config?.panels?.find((p: DashboardPanel) => p.id === panelId);
          if (panelInDash) {
            foundPanel = { ...panelInDash }; // Create a copy for editing
            foundDashboard = dash;
            break;
          }
        }

        if (foundPanel && foundDashboard) {
          setPanel(foundPanel);
          setDashboard(foundDashboard);
        } else {
          setError(`Panel with ID "${panelId}" not found`);
        }
      } catch (err) {
        setError('Failed to load panel');
        console.error('Error finding panel:', err);
      } finally {
        setLoading(false);
      }
    };

    findPanel();
  }, [panelId, dashboards, fetchDashboards]);

  const handleUpdatePanel = (updatedPanel: DashboardPanel) => {
    setPanel(updatedPanel);
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleHorizontalMouseDown = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsDraggingHorizontal(true);
  };

  const handleMouseMove = (e: MouseEvent) => {
    if (!isDragging) return;
    
    const newWidth = window.innerWidth - e.clientX;
    const minWidth = 300;
    const maxWidth = window.innerWidth * 0.8;
    
    if (newWidth >= minWidth && newWidth <= maxWidth) {
      setDrawerWidth(newWidth);
    }
  };

  const handleHorizontalMouseMove = (e: MouseEvent) => {
    if (!isDraggingHorizontal) return;
    
    const newHeight = window.innerHeight - e.clientY;
    const minHeight = 200;
    const maxHeight = window.innerHeight * 0.7;
    
    if (newHeight >= minHeight && newHeight <= maxHeight) {
      setTabbedSectionHeight(newHeight);
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
    setIsDraggingHorizontal(false);
  };

  useEffect(() => {
    if (isDragging || isDraggingHorizontal) {
      document.addEventListener('mousemove', isDragging ? handleMouseMove : handleHorizontalMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      
      return () => {
        document.removeEventListener('mousemove', isDragging ? handleMouseMove : handleHorizontalMouseMove);
        document.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [isDragging, isDraggingHorizontal]);

  const handleSave = async () => {
    if (!panel || !dashboard) return;

    setSaving(true);
    try {
      // Update the panel in the dashboard's panels array
      const updatedPanels = dashboard.config.panels.map((p: DashboardPanel) =>
        p.id === panel.id ? panel : p
      );

      const updatedConfig = {
        ...dashboard.config,
        panels: updatedPanels
      };

      const success = await updateDashboard(dashboard.id, { config: updatedConfig });
      if (success) {
        navigate(`/panels/${panelId}/view`);
      } else {
        setError('Failed to save panel changes');
      }
    } catch (err) {
      setError('Error saving panel changes');
      console.error('Error saving panel:', err);
    } finally {
      setSaving(false);
    }
  };



  const handleDeletePanel = async (panelId: string) => {
    if (!dashboard) return;

    setSaving(true);
    try {
      // Remove the panel from the dashboard's panels array
      const updatedPanels = dashboard.config.panels.filter((p: DashboardPanel) => p.id !== panelId);

      const updatedConfig = {
        ...dashboard.config,
        panels: updatedPanels
      };

      const success = await updateDashboard(dashboard.id, { config: updatedConfig });
      if (success) {
        navigate(`/dashboards/${dashboard.id}`);
      } else {
        setError('Failed to delete panel');
      }
    } catch (err) {
      setError('Error deleting panel');
      console.error('Error deleting panel:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error || !panel) {
    return (
      <Box sx={{ padding: 3 }}>
        <Alert severity="error">
          {error || 'Panel not found'}
        </Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ 
      height: '100vh', 
      display: 'flex', 
      overflow: 'hidden',
      margin: 0,
      padding: 0
    }}>
      {/* Content */}
      <Box sx={{ 
        flex: 1, 
        display: 'flex', 
        flexDirection: 'column', 
        overflow: 'hidden',
        margin: 0,
        padding: 0
      }}>
        {/* Panel Preview */}
        <Box sx={{ 
          flex: 1, 
          minHeight: 0, 
          overflow: 'hidden', 
          padding: 2,
          margin: 0
        }}>
          <Paper sx={{ height: '100%', overflow: 'visible' }} elevation={1}>
            <DashboardPanelView 
              panel={panel}
              isEditMode={false}
              onEdit={() => {}} // Disable edit menu in edit mode
              onDelete={handleDeletePanel}
            />
          </Paper>
        </Box>

        {/* Horizontal Resizable Splitter */}
        <Box
          sx={{
            height: '1px',
            backgroundColor: 'divider',
            cursor: 'row-resize',
            position: 'relative',
            flexShrink: 0,
            zIndex: 10,
            transition: 'background-color 0.2s ease',
            margin: 0,
            '&:hover': {
              backgroundColor: 'primary.main',
            },
            '&::before': {
              content: '""',
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              width: '25%',
              height: '4px',
              backgroundColor: isDraggingHorizontal ? 'primary.main' : 'divider',
              borderRadius: '4px',
              cursor: 'row-resize',
              transition: 'background-color 0.2s ease',
            },
            '&:hover::before': {
              backgroundColor: 'primary.main',
            },
            '&::after': {
              content: '""',
              position: 'absolute',
              top: '-8px',
              left: 0,
              right: 0,
              bottom: '-8px',
              cursor: 'row-resize',
            }
          }}
          onMouseDown={handleHorizontalMouseDown}
        />

        {/* Tabbed Section */}
        <Box sx={{ 
          height: tabbedSectionHeight, 
          display: 'flex', 
          flexDirection: 'column',
          flexShrink: 0,
          overflow: 'hidden',
          margin: 0
        }}>
          <Tabs 
            value={activeTab} 
            onChange={handleTabChange}
            sx={{ 
              borderBottom: 1, 
              borderColor: 'divider',
              backgroundColor: 'background.paper',
              margin: 0
            }}
          >
            <Tab label="Tab 1" />
            <Tab label="Tab 2" />
            <Tab label="Tab 3" />
          </Tabs>
          
          <Box sx={{ 
            flex: 1, 
            overflow: 'auto',
            padding: 2,
            backgroundColor: 'background.paper',
            margin: 0
          }}>
            {activeTab === 0 && (
              <Box>
                <h3>Tab 1 Content</h3>
                <p>This is the content for tab 1. You can add any components or content here.</p>
                {/* Add your tab 1 content here */}
              </Box>
            )}
            {activeTab === 1 && (
              <Box>
                <h3>Tab 2 Content</h3>
                <p>This is the content for tab 2. You can add any components or content here.</p>
                {/* Add your tab 2 content here */}
              </Box>
            )}
            {activeTab === 2 && (
              <Box>
                <h3>Tab 3 Content</h3>
                <p>This is the content for tab 3. You can add any components or content here.</p>
                {/* Add your tab 3 content here */}
              </Box>
            )}
          </Box>
        </Box>
      </Box>

      {/* Resizable Splitter */}
      <Box
        sx={{
          width: '1px',
          backgroundColor: 'divider',
          cursor: 'col-resize',
          position: 'relative',
          flexShrink: 0,
          zIndex: 10,
          transition: 'background-color 0.2s ease',
          margin: 0,
          '&:hover': {
            backgroundColor: 'primary.main',
          },
          '&::before': {
            content: '""',
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: '4px',
            height: '25%',
            backgroundColor: isDragging ? 'primary.main' : 'divider',
            borderRadius: '4px',
            cursor: 'col-resize',
            transition: 'background-color 0.2s ease',
          },
          '&:hover::before': {
            backgroundColor: 'primary.main',
          },
          '&::after': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: '-8px',
            right: '-8px',
            bottom: 0,
            cursor: 'col-resize',
          }
        }}
        onMouseDown={handleMouseDown}
      />

      {/* Panel Editor - Always Open */}
      <Box sx={{ 
        width: drawerWidth, 
        flexShrink: 0,
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        margin: 0
      }}>
        <PanelEditorDrawer
          open={true}
          panel={panel}
          onClose={() => {}} // Disable close in dedicated edit page
          onUpdatePanel={handleUpdatePanel}
          onDeletePanel={handleDeletePanel}
          standalone={true}
        />
      </Box>
    </Box>
  );
}
