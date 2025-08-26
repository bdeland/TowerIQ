import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  Box, 
  Alert, 
  CircularProgress,
  Paper,
  Tabs,
  Tab,
  TextField,
  Button,
  Card,
  CardContent,
  CardActions,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Typography,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  DragIndicator as DragIndicatorIcon,
  VisibilityOff as VisibilityOffIcon,
  Visibility as VisibilityIcon,
  ContentCopy as ContentCopyIcon
} from '@mui/icons-material';

import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import DashboardPanelView from '../components/DashboardPanelView';
import PanelEditorDrawer from '../components/PanelEditorDrawer';

export function PanelEditPage() {
  const { panelId, dashboardId } = useParams<{ panelId: string; dashboardId: string }>();
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
  const [queryError, setQueryError] = useState<string | null>(null);
  const [queries, setQueries] = useState<Array<{ id: string; query: string; name: string; visible: boolean }>>([]);
  const [editingQueryId, setEditingQueryId] = useState<string | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [queryToDelete, setQueryToDelete] = useState<string | null>(null);

  useEffect(() => {
    const findPanel = async () => {
      if (!panelId || !dashboardId) {
        setError('Panel ID or Dashboard ID not provided');
        setLoading(false);
        return;
      }

      try {
        // If dashboards are not loaded, fetch them
        if (dashboards.length === 0) {
          await fetchDashboards();
        }

        // Find the specific dashboard first
        const foundDashboard = dashboards.find(dash => dash.id === dashboardId);
        if (!foundDashboard) {
          setError(`Dashboard with ID "${dashboardId}" not found`);
          setLoading(false);
          return;
        }

                 // Find the panel within that dashboard
         const foundPanel = foundDashboard.config?.panels?.find((p: DashboardPanel) => p.id === panelId);
         if (foundPanel) {
           setPanel({ ...foundPanel }); // Create a copy for editing
           setDashboard(foundDashboard);
           
                       // Initialize queries from panel
            if (foundPanel.options?.queryData && foundPanel.options.queryData.length > 0) {
              // Load saved query data with names and ensure visible property exists
              const queriesWithVisibility = foundPanel.options.queryData.map((q: any) => ({
                ...q,
                visible: q.visible !== undefined ? q.visible : true
              }));
              setQueries(queriesWithVisibility);
            } else if (foundPanel.query) {
              // Fallback to single query with default name
              setQueries([{ id: '1', query: foundPanel.query, name: 'A', visible: true }]);
            } else {
              // Default empty query
              setQueries([{ id: '1', query: '', name: 'A', visible: true }]);
            }
         } else {
           setError(`Panel with ID "${panelId}" not found in dashboard "${foundDashboard.title}"`);
         }
      } catch (err) {
        setError('Failed to load panel');
        console.error('Error finding panel:', err);
      } finally {
        setLoading(false);
      }
    };

    findPanel();
  }, [panelId, dashboardId, dashboards, fetchDashboards]);

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
      // Update the panel with query data including names
      const updatedPanel = {
        ...panel,
        query: queries[0]?.query || '',
        options: {
          ...panel.options,
          queryData: queries // Store all query data including names
        }
      };

      // Update the panel in the dashboard's panels array
      const updatedPanels = dashboard.config.panels.map((p: DashboardPanel) =>
        p.id === panel.id ? updatedPanel : p
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

  const handleQueryTest = async (queryText: string) => {
    if (!queryText.trim()) {
      setQueryError('Query cannot be empty');
      return;
    }

    setQueryError(null);
    try {
      const response = await fetch('http://localhost:8000/api/query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query: queryText }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Query failed');
      }

      const result = await response.json();
      setQueryError(`✓ Query successful! Returned ${result.rowCount} rows.`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Query test failed';
      setQueryError(errorMessage);
    }
  };

  const handleAddQuery = () => {
    const newId = (queries.length + 1).toString();
    const newQuery = { id: newId, query: '', name: String.fromCharCode(64 + queries.length + 1), visible: true }; // A, B, C, D...
    setQueries([...queries, newQuery]);
  };

  const handleDeleteQuery = (id: string) => {
    handleDeleteQueryConfirm(id);
  };

  const handleQueryChange = (id: string, query: string) => {
    const updatedQueries = queries.map(q => 
      q.id === id ? { ...q, query } : q
    );
    setQueries(updatedQueries);
    
    // Update panel query with the first query (assuming single query for now)
    if (panel && updatedQueries.length > 0) {
      const updatedPanel = { ...panel, query: updatedQueries[0].query };
      setPanel(updatedPanel);
    }
  };

  const handleQueryNameChange = (id: string, name: string) => {
    const updatedQueries = queries.map(q => 
      q.id === id ? { ...q, name } : q
    );
    setQueries(updatedQueries);
  };

  const handleStartEditing = (id: string) => {
    setEditingQueryId(id);
  };

  const handleFinishEditing = (id: string, newName: string) => {
    const updatedQueries = queries.map(q => 
      q.id === id ? { ...q, name: newName } : q
    );
    setQueries(updatedQueries);
    setEditingQueryId(null);
  };

  const handleCancelEditing = () => {
    setEditingQueryId(null);
  };

  const handleToggleVisibility = (id: string) => {
    const updatedQueries = queries.map(q => 
      q.id === id ? { ...q, visible: !q.visible } : q
    );
    setQueries(updatedQueries);
  };

  const handleDuplicateQuery = (id: string) => {
    const queryToDuplicate = queries.find(q => q.id === id);
    if (queryToDuplicate) {
      const newId = (queries.length + 1).toString();
      const newQuery = { 
        ...queryToDuplicate, 
        id: newId, 
        name: queryToDuplicate.name + ' Copy',
        visible: true 
      };
      setQueries([...queries, newQuery]);
    }
  };

  const handleDeleteQueryConfirm = (id: string) => {
    setQueryToDelete(id);
    setDeleteDialogOpen(true);
  };

  const handleDeleteQueryConfirmed = () => {
    if (queryToDelete) {
      const updatedQueries = queries.filter(q => q.id !== queryToDelete);
      
      if (updatedQueries.length > 0) {
        // Renumber queries alphabetically
        const renumberedQueries = updatedQueries.map((q, index) => ({
          ...q,
          name: String.fromCharCode(65 + index) // A, B, C, D...
        }));
        
        setQueries(renumberedQueries);
        
        // Update panel query with the first remaining query
        if (panel) {
          const updatedPanel = { ...panel, query: renumberedQueries[0].query };
          setPanel(updatedPanel);
        }
      } else {
        // All queries deleted, set empty state
        setQueries([]);
        if (panel) {
          const updatedPanel = { ...panel, query: '' };
          setPanel(updatedPanel);
        }
      }
    }
    setDeleteDialogOpen(false);
    setQueryToDelete(null);
  };

  const handleDeleteQueryCancel = () => {
    setDeleteDialogOpen(false);
    setQueryToDelete(null);
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
            <Tab label="Data Query" />
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
                <Typography variant="h6" sx={{ mb: 2 }}>Data Queries</Typography>
                
                                 {/* Query Cards */}
                 {queries.length === 0 ? (
                   <Box sx={{ 
                     display: 'flex', 
                     justifyContent: 'center', 
                     alignItems: 'center', 
                     py: 2,
                     border: '2px dashed',
                     borderColor: 'divider',
                     borderRadius: 2,
                     backgroundColor: 'background.default'
                   }}>
                     <Typography variant="body2" color="text.secondary">
                       No queries defined. Click "Add Query" to get started.
                     </Typography>
                   </Box>
                 ) : (
                   queries.map((queryItem, index) => (
                                           <Accordion key={queryItem.id} sx={{ mb: 0, borderRadius: 2, '& .MuiAccordionSummary-root': { height: '15px !important' } }}>
                                               <AccordionSummary 
                          expandIcon={<ExpandMoreIcon />}
                          sx={{ 
                            flexDirection: 'row-reverse',
                            py: 0.5,
                            '& .MuiAccordionSummary-expandIconWrapper': {
                              transform: 'rotate(0deg)',
                              marginLeft: 0,
                              marginRight: 'auto'
                            },
                            '& .MuiAccordionSummary-expandIconWrapper.Mui-expanded': {
                              transform: 'rotate(180deg)'
                            }
                          }}
                        >
                                                   <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', ml: 1 }}>
                            {editingQueryId === queryItem.id ? (
                              <TextField
                                size="small"
                                value={queryItem.name}
                                onChange={(e) => handleQueryNameChange(queryItem.id, e.target.value)}
                                onBlur={() => handleFinishEditing(queryItem.id, queryItem.name)}
                                onKeyPress={(e) => {
                                  if (e.key === 'Enter') {
                                    handleFinishEditing(queryItem.id, queryItem.name);
                                  } else if (e.key === 'Escape') {
                                    handleCancelEditing();
                                  }
                                }}
                                autoFocus
                                onClick={(e) => e.stopPropagation()}
                                sx={{ width: 200 }}
                              />
                            ) : (
                              <Box
                                sx={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: 1,
                                  padding: '0px 8px',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  border: '1px dashed transparent',
                                  '&:hover': {
                                    border: '1px dashed #666',
                                    backgroundColor: 'rgba(255, 255, 255, 0.04)',
                                  },
                                }}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleStartEditing(queryItem.id);
                                }}
                              >
                                <Typography
                                  sx={{
                                    color: 'primary.main',
                                    fontSize: '0.875rem',
                                    fontWeight: 500,
                                  }}
                                >
                                  {queryItem.name}
                                </Typography>
                                <EditIcon
                                  sx={{
                                    fontSize: '0.875rem',
                                    color: '#666',
                                    opacity: 0,
                                    transition: 'opacity 0.2s ease',
                                    '.MuiBox-root:hover &': {
                                      opacity: 1,
                                    },
                                  }}
                                />
                              </Box>
                            )}
                                                       <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                              <Tooltip title="Duplicate query">
                                <IconButton
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleDuplicateQuery(queryItem.id);
                                  }}
                                >
                                  <ContentCopyIcon sx={{ fontSize: '18px' }} />
                                </IconButton>
                              </Tooltip>
                              
                              <Tooltip title={queryItem.visible ? "Hide Response" : "Show Response"}>
                                <IconButton
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleToggleVisibility(queryItem.id);
                                  }}
                                >
                                  {queryItem.visible ? <VisibilityIcon sx={{ fontSize: '18px' }} /> : <VisibilityOffIcon sx={{ fontSize: '18px' }} />}
                                </IconButton>
                              </Tooltip>
                              
                              <Tooltip title="Delete query">
                                <IconButton
                                  color="error"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleDeleteQuery(queryItem.id);
                                  }}
                                >
                                  <DeleteIcon sx={{ fontSize: '18px' }} />
                                </IconButton>
                              </Tooltip>
                              
                              <Tooltip title="Drag and drop to reorder queries">
                                <IconButton
                                  sx={{ cursor: 'grab', '&:active': { cursor: 'grabbing' } }}
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  <DragIndicatorIcon sx={{ fontSize: '18px' }} />
                                </IconButton>
                              </Tooltip>
                            </Box>
                         </Box>
                       </AccordionSummary>
                                                                                           <AccordionDetails sx={{ py: 0.5 }}>
                         <Box sx={{ width: '100%' }}>
                                                                                 <TextField
                              fullWidth
                              multiline
                              rows={2}
                              value={queryItem.query}
                              onChange={(e) => handleQueryChange(queryItem.id, e.target.value)}
                              placeholder="SELECT * FROM metrics WHERE..."
                              sx={{ mb: 0.5 }}
                            />
                                                                                 <Button
                              variant="outlined"
                              fullWidth
                              onClick={() => handleQueryTest(queryItem.query)}
                              disabled={!queryItem.query.trim()}
                              sx={{ mb: 0.5 }}
                            >
                            Test Query
                          </Button>
                        </Box>
                                             </AccordionDetails>
                     </Accordion>
                   ))
                 )}
                
                {/* Add Query Button */}
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={handleAddQuery}
                  sx={{ mt: 2 }}
                >
                  Add Query
                </Button>
                
                {/* Query Error Display */}
                {queryError && (
                  <Alert severity={queryError.startsWith('✓') ? 'success' : 'error'} sx={{ mt: 2 }}>
                    {queryError}
                  </Alert>
                )}
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

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={handleDeleteQueryCancel}
        aria-labelledby="delete-dialog-title"
        aria-describedby="delete-dialog-description"
      >
        <DialogTitle id="delete-dialog-title">
          Delete Query
        </DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete this query? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteQueryCancel} color="primary">
            Cancel
          </Button>
          <Button onClick={handleDeleteQueryConfirmed} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
