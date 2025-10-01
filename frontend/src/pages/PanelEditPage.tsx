import React, { useState, useEffect, useCallback } from 'react';
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
  ContentCopy as ContentCopyIcon,
  Code as CodeIcon,
  AutoFixHigh as AutoFixHighIcon
} from '@mui/icons-material';
import { Editor } from '@monaco-editor/react';
import { format } from 'sql-formatter';
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  DragEndEvent,
} from '@dnd-kit/core';

import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import {
  useSortable,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';

import { useDashboard, DashboardPanel } from '../contexts/DashboardContext';
import { useDashboardEdit } from '../contexts/DashboardEditContext';
import DashboardPanelView from '../components/DashboardPanelView';
import PanelEditorDrawer from '../components/PanelEditorDrawer';
import TransformationsEditor from '../components/TransformationsEditor';
import { generateUUID } from '../utils/uuid';
import { API_CONFIG } from '../config/environment';

// Sortable Query Accordion Component
interface SortableQueryAccordionProps {
  queryItem: { id: string; query: string; name: string; visible: boolean };
  index: number;
  editingQueryId: string | null;
  onStartEditing: (id: string) => void;
  onFinishEditing: (id: string, name: string) => void;
  onCancelEditing: () => void;
  onQueryNameChange: (id: string, name: string) => void;
  onQueryChange: (id: string, query: string) => void;
  onToggleVisibility: (id: string) => void;
  onDeleteQuery: (id: string) => void;
  onDuplicateQuery: (id: string) => void;
  onFormatQuery: (id: string) => void;
  onQueryTest: (query: string) => void;
}

function SortableQueryAccordion({
  queryItem,
  index,
  editingQueryId,
  onStartEditing,
  onFinishEditing,
  onCancelEditing,
  onQueryNameChange,
  onQueryChange,
  onToggleVisibility,
  onDeleteQuery,
  onDuplicateQuery,
  onFormatQuery,
  onQueryTest
}: SortableQueryAccordionProps) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ 
    id: queryItem.id,
  });

  const style = {
    transform: isDragging 
      ? `translate3d(0, ${transform?.y || 0}px, 0)` 
      : CSS.Transform.toString(transform),
    transition: isDragging ? 'none' : 'transform 100ms ease',
    opacity: isDragging ? 0.5 : 1,
  };

  return (
    <div ref={setNodeRef} style={style}>
                                         <Accordion sx={{ 
           mb: 0, 
           borderRadius: '12px',
           border: '1px solid',
           borderColor: 'divider',
           boxShadow: 'none',
           position: 'relative',
           zIndex: 1,
          '& .MuiAccordion-root': {
            boxShadow: 'none'
          },
          '& .MuiAccordionSummary-root': { 
            height: '30px !important',
            minHeight: '30px !important',
            padding: '0 !important'
          },
          '& .MuiAccordionSummary-content': {
            margin: '0 !important',
            padding: '0 !important'
          },
          '&:hover': {
            backgroundColor: 'transparent'
          }
        }}>
                 <AccordionSummary 
           expandIcon={<ExpandMoreIcon sx={{ fontSize: '16px' }} />}
           sx={{ 
             flexDirection: 'row-reverse',
             py: 0,
             px: 6,
             borderRadius: '4px',
             '& .MuiAccordionSummary-expandIconWrapper': {
               transform: 'rotate(0deg)',
               marginLeft: 1,
               marginRight: 'auto'
             },
             '& .MuiAccordionSummary-expandIconWrapper.Mui-expanded': {
               transform: 'rotate(180deg)'
             },
             '&.Mui-expanded': {
               borderBottom: '1px solid',
               borderColor: 'divider'
             }
           }}
         >
                     <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', ml: 0.5, py: 0.25 }}>
            {editingQueryId === queryItem.id ? (
              <TextField
                size="small"
                value={queryItem.name}
                onChange={(e) => onQueryNameChange(queryItem.id, e.target.value)}
                onBlur={() => onFinishEditing(queryItem.id, queryItem.name)}
                onKeyPress={(e) => {
                  if (e.key === 'Enter') {
                    onFinishEditing(queryItem.id, queryItem.name);
                  } else if (e.key === 'Escape') {
                    onCancelEditing();
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
                   gap: 0.5,
                   padding: '0px 6px',
                   borderRadius: '4px',
                   cursor: 'pointer',
                   border: '1px dashed transparent',
                   '&:hover': {
                     border: '1px dashed #666',
                     backgroundColor: 'rgba(255, 255, 255, 0.04)',
                     '& .edit-icon': {
                       opacity: 1,
                     },
                   },
                 }}
                onClick={(e) => {
                  e.stopPropagation();
                  onStartEditing(queryItem.id);
                }}
              >
                                 <Typography
                   sx={{
                     color: 'primary.main',
                     fontSize: '0.75rem',
                     fontWeight: 'bold',
                   }}
                 >
                  {queryItem.name}
                </Typography>
                                 <EditIcon
                   className="edit-icon"
                   sx={{
                     fontSize: '12px',
                     color: '#666',
                     opacity: 0,
                     transition: 'opacity 0.1s ease',
                   }}
                 />
              </Box>
            )}
            
                         <Box sx={{ display: 'flex', alignItems: 'center', gap: 0 }}>
               <Tooltip title="Format query">
                 <IconButton
                   onClick={(e) => {
                     e.stopPropagation();
                     onFormatQuery(queryItem.id);
                   }}
                   disabled={!queryItem.query.trim()}
                 >
                   <AutoFixHighIcon sx={{ fontSize: '14px' }} />
                 </IconButton>
               </Tooltip>
               
               <Tooltip title="Duplicate query">
                 <IconButton
                   onClick={(e) => {
                     e.stopPropagation();
                     onDuplicateQuery(queryItem.id);
                   }}
                 >
                   <ContentCopyIcon sx={{ fontSize: '14px' }} />
                 </IconButton>
               </Tooltip>
               
               <Tooltip title={queryItem.visible ? "Hide Response" : "Show Response"}>
                 <IconButton
                   onClick={(e) => {
                     e.stopPropagation();
                     onToggleVisibility(queryItem.id);
                   }}
                 >
                   {queryItem.visible ? <VisibilityIcon sx={{ fontSize: '14px' }} /> : <VisibilityOffIcon sx={{ fontSize: '14px' }} />}
                 </IconButton>
               </Tooltip>
               
               <Tooltip title="Delete query">
                 <IconButton
                   color="error"
                   onClick={(e) => {
                     e.stopPropagation();
                     onDeleteQuery(queryItem.id);
                   }}
                 >
                   <DeleteIcon sx={{ fontSize: '14px' }} />
                 </IconButton>
               </Tooltip>
               
               <Tooltip title="Drag and drop to reorder queries">
                 <IconButton
                   {...attributes}
                   {...listeners}
                   sx={{ cursor: 'grab', '&:active': { cursor: 'grabbing' } }}
                   onClick={(e) => e.stopPropagation()}
                 >
                   <DragIndicatorIcon sx={{ fontSize: '14px' }} />
                 </IconButton>
               </Tooltip>
             </Box>
          </Box>
        </AccordionSummary>
        
                 <AccordionDetails sx={{ 
           py: 1, 
           px: 1,
           borderRadius: '0 0 4px 4px',
           overflow: 'hidden'
         }}>
          <Box sx={{ width: '100%' }}>
                         <Box sx={{ 
                           mb: 0, 
                           ml: 0, 
                           mr: 0, 
                           border: '1px solid', 
                           borderColor: 'divider', 
                           borderRadius: '4px', 
                           overflow: 'hidden',
                           '& .monaco-editor': {
                             borderRadius: '4px',
                           },
                           '& .monaco-editor .overflow-guard': {
                             borderRadius: '4px',
                           }
                         }}>
               <Editor
                 height="150px"
                 language="sql"
                 theme="vs-dark"
                 value={queryItem.query}
                 onChange={(value) => onQueryChange(queryItem.id, value || '')}
                 options={{
                   minimap: { enabled: false },
                   scrollBeyondLastLine: false,
                   fontSize: 12,
                   wordWrap: 'on',
                   automaticLayout: true,
                   placeholder: 'SELECT * FROM metrics WHERE...',
                 }}
               />
             </Box>
          </Box>
        </AccordionDetails>
      </Accordion>
    </div>
  );
}

export function PanelEditPage() {
  const { panelId, dashboardId } = useParams<{ panelId: string; dashboardId: string }>();
  const navigate = useNavigate();
  const { dashboards, fetchDashboards, updateDashboard } = useDashboard();
  const { 
    setIsPanelEditPage, 
    setSaving, 
    setHasUnsavedChanges, 
    setPanelEditHandlers 
  } = useDashboardEdit();
  
  const [panel, setPanel] = useState<DashboardPanel | null>(null);
  const [originalPanel, setOriginalPanel] = useState<DashboardPanel | null>(null);
  const [dashboard, setDashboard] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setLocalSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [drawerWidth, setDrawerWidth] = useState(400);
  const [isDragging, setIsDragging] = useState(false);
  const [tabbedSectionHeight, setTabbedSectionHeight] = useState(300);
  const [isDraggingHorizontal, setIsDraggingHorizontal] = useState(false);
  const [activeTab, setActiveTab] = useState(0);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [queries, setQueries] = useState<Array<{ id: string; query: string; name: string; visible: boolean }>>([]);
  const [originalQueries, setOriginalQueries] = useState<Array<{ id: string; query: string; name: string; visible: boolean }>>([]);
  const [editingQueryId, setEditingQueryId] = useState<string | null>(null);
  const [panelData, setPanelData] = useState<any[]>([]);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [queryToDelete, setQueryToDelete] = useState<string | null>(null);
  const [discardDialogOpen, setDiscardDialogOpen] = useState(false);
  const [unsavedChangesDialogOpen, setUnsavedChangesDialogOpen] = useState(false);

  // Drag and drop sensors
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  );

  // Update saving state in context
  useEffect(() => {
    setSaving(saving);
  }, [saving, setSaving]);

  const checkForChanges = useCallback(() => {
    if (!panel || !originalPanel) return false;
    
    // Check panel properties
    const panelChanged = JSON.stringify(panel) !== JSON.stringify(originalPanel);
    
    // Check queries
    const queriesChanged = JSON.stringify(queries) !== JSON.stringify(originalQueries);
    
    return panelChanged || queriesChanged;
  }, [panel, originalPanel, queries, originalQueries]);

  // Check for changes and update context
  useEffect(() => {
    if (panel && originalPanel) {
      const hasChanges = checkForChanges();
      setHasUnsavedChanges(hasChanges);
    }
  }, [panel, queries, originalPanel, originalQueries, checkForChanges, setHasUnsavedChanges]);

  const handleBackToDashboard = useCallback(() => {
    if (checkForChanges()) {
      setUnsavedChangesDialogOpen(true);
    } else {
      navigate(`/dashboards/${dashboardId}`);
    }
  }, [checkForChanges, navigate, dashboardId]);

  const handleDiscardChanges = useCallback(() => {
    setDiscardDialogOpen(true);
  }, []);

  const handleDiscardConfirmed = useCallback(() => {
    if (originalPanel) {
      setPanel({ ...originalPanel });
    }
    if (originalQueries) {
      setQueries([...originalQueries]);
    }
    setDiscardDialogOpen(false);
  }, [originalPanel, originalQueries]);

  const handleDiscardCancel = useCallback(() => {
    setDiscardDialogOpen(false);
  }, []);

  const handleSavePanelChanges = useCallback(async () => {
    if (!panel || !dashboard) return;

    setLocalSaving(true);
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
        // Update original state to reflect saved state
        setOriginalPanel({ ...updatedPanel });
        setOriginalQueries([...queries]);
        // Don't navigate away - stay on the edit page
      } else {
        setError('Failed to save panel changes');
      }
    } catch (err) {
      setError('Error saving panel changes');
      console.error('Error saving panel:', err);
    } finally {
      setLocalSaving(false);
    }
  }, [panel, dashboard, queries, updateDashboard, navigate, panelId]);

  const handleUnsavedChangesSave = useCallback(() => {
    setUnsavedChangesDialogOpen(false);
    handleSavePanelChanges();
  }, [handleSavePanelChanges]);

  const handleUnsavedChangesDiscard = useCallback(() => {
    setUnsavedChangesDialogOpen(false);
    navigate(`/dashboards/${dashboardId}`);
  }, [navigate, dashboardId]);

  const handleUnsavedChangesCancel = useCallback(() => {
    setUnsavedChangesDialogOpen(false);
  }, []);

  // Set up panel edit context
  useEffect(() => {
    setIsPanelEditPage(true);
    
    // Set up panel edit handlers
    setPanelEditHandlers({
      onBackToDashboard: handleBackToDashboard,
      onDiscardChanges: handleDiscardChanges,
      onSavePanelChanges: handleSavePanelChanges
    });

    return () => {
      setIsPanelEditPage(false);
    };
  }, [setIsPanelEditPage, setPanelEditHandlers, handleBackToDashboard, handleDiscardChanges, handleSavePanelChanges]);

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
           const panelCopy = { ...foundPanel }; // Create a copy for editing
           setPanel(panelCopy);
           setOriginalPanel({ ...foundPanel }); // Store original for change tracking
           setDashboard(foundDashboard);
           
                       // Initialize queries from panel
            if (foundPanel.options?.queryData && foundPanel.options.queryData.length > 0) {
              // Load saved query data with names and ensure visible property exists
              const queriesWithVisibility = foundPanel.options.queryData.map((q: any) => ({
                ...q,
                visible: q.visible !== undefined ? q.visible : true
              }));
              setQueries(queriesWithVisibility);
              setOriginalQueries([...queriesWithVisibility]);
            } else if (foundPanel.query) {
              // Fallback to single query with default name
              const defaultQuery = { id: '1', query: foundPanel.query, name: 'A', visible: true };
              setQueries([defaultQuery]);
              setOriginalQueries([defaultQuery]);
            } else {
              // Default empty query
              const emptyQuery = { id: '1', query: '', name: 'A', visible: true };
              setQueries([emptyQuery]);
              setOriginalQueries([emptyQuery]);
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

  const handleDeletePanel = async (panelId: string) => {
    if (!dashboard) return;

    setLocalSaving(true);
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
      setLocalSaving(false);
    }
  };

  const handleQueryTest = async (queryText: string) => {
    if (!queryText.trim()) {
      setQueryError('Query cannot be empty');
      return;
    }

    setQueryError(null);
    try {
      const response = await fetch(API_CONFIG.QUERY_PREVIEW_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query: queryText }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Query preview failed');
      }

      const result = await response.json();
      if (result.status === 'success') {
        setQueryError(`✓ ${result.message}`);
      } else {
        setQueryError(result.message);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Query preview failed';
      setQueryError(errorMessage);
    }
  };

  const handleFormatQuery = (queryId: string) => {
    const queryItem = queries.find(q => q.id === queryId);
    if (queryItem && queryItem.query.trim()) {
      try {
        const formattedQuery = format(queryItem.query, {
          language: 'sql',
          keywordCase: 'upper',
          linesBetweenQueries: 2,
        });
        
        const updatedQueries = queries.map(q => 
          q.id === queryId ? { ...q, query: formattedQuery } : q
        );
        setQueries(updatedQueries);
        
        // Update panel query with the first query (assuming single query for now)
        if (panel && updatedQueries.length > 0) {
          const updatedPanel = { ...panel, query: updatedQueries[0].query };
          setPanel(updatedPanel);
        }
      } catch (error) {
        setQueryError('Failed to format query. Please check syntax.');
      }
    }
  };

  // Handle drag end for reordering queries
  const handleDragEnd = useCallback((event: DragEndEvent) => {
    const { active, over } = event;

    if (active.id !== over?.id) {
      const oldIndex = queries.findIndex((_, index) => queries[index].id === active.id);
      const newIndex = queries.findIndex((_, index) => queries[index].id === over?.id);

      if (oldIndex !== -1 && newIndex !== -1) {
        // Immediately update the queries array to prevent intermediate transitions
        const updatedQueries = arrayMove(queries, oldIndex, newIndex);
        setQueries(updatedQueries);
        
        // Update panel query with the first query after reordering
        if (panel && updatedQueries.length > 0) {
          const updatedPanel = { ...panel, query: updatedQueries[0].query };
          setPanel(updatedPanel);
        }
      }
    }
  }, [queries, panel]);

  const handleAddQuery = () => {
    const newId = generateUUID();
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
      const newId = generateUUID();
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

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
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
              onDataFetched={setPanelData}
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
            <Tab label="Transform" />
            <Tab label="Tab 3" />
          </Tabs>
          
                     <Box sx={{ 
             flex: 1, 
             overflow: 'auto',
             overflowX: 'hidden', // Prevent horizontal scrolling
             padding: 2,
             backgroundColor: 'background.paper',
             margin: 0,
             '&::-webkit-scrollbar': {
               display: 'none'
             },
             scrollbarWidth: 'none',
             msOverflowStyle: 'none'
           }}>
            {activeTab === 0 && (
              <Box>
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
                   <DndContext
                     sensors={sensors}
                     collisionDetection={closestCenter}
                     onDragEnd={handleDragEnd}

                   >
                     <SortableContext
                       items={queries.map(query => query.id)}
                       strategy={verticalListSortingStrategy}
                     >
                       {queries.map((queryItem, index) => (
                         <SortableQueryAccordion
                           key={queryItem.id}
                           queryItem={queryItem}
                           index={index}
                           editingQueryId={editingQueryId}
                           onStartEditing={handleStartEditing}
                           onFinishEditing={handleFinishEditing}
                           onCancelEditing={handleCancelEditing}
                           onQueryNameChange={handleQueryNameChange}
                           onQueryChange={handleQueryChange}
                           onToggleVisibility={handleToggleVisibility}
                           onDeleteQuery={handleDeleteQuery}
                           onDuplicateQuery={handleDuplicateQuery}
                           onFormatQuery={handleFormatQuery}
                           onQueryTest={handleQueryTest}
                         />
                       ))}
                     </SortableContext>
                   </DndContext>
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
              <Box sx={{ height: '100%', overflow: 'auto' }}>
                {panel ? (
                  <TransformationsEditor
                    panel={panel}
                    onPanelUpdate={setPanel}
                    panelData={panelData}
                  />
                ) : (
                  <Typography>Loading panel configuration...</Typography>
                )}
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

      {/* Discard Changes Confirmation Dialog */}
      <Dialog
        open={discardDialogOpen}
        onClose={handleDiscardCancel}
        aria-labelledby="discard-dialog-title"
        aria-describedby="discard-dialog-description"
      >
        <DialogTitle id="discard-dialog-title">
          Discard Changes
        </DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to discard all changes? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDiscardCancel} color="primary">
            Cancel
          </Button>
          <Button onClick={handleDiscardConfirmed} color="error" variant="contained">
            Discard
          </Button>
        </DialogActions>
      </Dialog>

      {/* Unsaved Changes Dialog */}
      <Dialog
        open={unsavedChangesDialogOpen}
        onClose={handleUnsavedChangesCancel}
        aria-labelledby="unsaved-dialog-title"
        aria-describedby="unsaved-dialog-description"
      >
        <DialogTitle id="unsaved-dialog-title">
          Unsaved Changes
        </DialogTitle>
        <DialogContent>
          <Typography>
            You have unsaved changes. Would you like to save them before leaving?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleUnsavedChangesDiscard} color="primary">
            Don't Save
          </Button>
          <Button onClick={handleUnsavedChangesCancel} color="primary">
            Cancel
          </Button>
          <Button onClick={handleUnsavedChangesSave} color="primary" variant="contained">
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
