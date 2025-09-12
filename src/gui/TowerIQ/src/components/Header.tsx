import React from 'react';
import { AppBar, Toolbar, Box, IconButton, Button, Menu, MenuItem, ListItemIcon, ListItemText, Tooltip } from '@mui/material';
import { 
  Menu as MenuIcon,
  KeyboardArrowDown as ArrowDownIcon,
  BarChart as VisualizationIcon,
  ViewHeadline as RowIcon,
  ContentPaste as PasteIcon,
  Save as SaveIcon,
  SaveAs as SaveAsIcon,
  ArrowBack as ArrowBackIcon,
  Undo as UndoIcon
} from '@mui/icons-material';
import { Breadcrumbs } from './Breadcrumbs';
import { SearchBar } from './SearchBar';
import { useDashboardEdit } from '../contexts/DashboardEditContext';
import { useDashboard } from '../contexts/DashboardContext';

interface HeaderProps {
  sidebarDocked: boolean;
  sidebarHidden: boolean;
  onSidebarToggle: () => void;
  layoutStyles: {
    appBar: any;
  };
  layout: {
    appBarHeight: number;
    border: string;
  };
  listItemIconStyles: any;
}

export function Header({ 
  sidebarDocked, 
  sidebarHidden, 
  onSidebarToggle, 
  layoutStyles, 
  layout, 
  listItemIconStyles
}: HeaderProps) {
  // Safely get dashboard edit context with error handling
  let dashboardEditContext;
  try {
    dashboardEditContext = useDashboardEdit();
  } catch (error) {
    console.error('Error accessing dashboard edit context:', error);
    dashboardEditContext = {
      isDashboardPage: false,
      isEditMode: false,
      isPanelEditPage: false,
      saving: false,
      hasUnsavedChanges: false,
      onEditToggle: undefined,
      onAddVisualization: undefined,
      onAddRow: undefined,
      onPastePanel: undefined,
      onSave: undefined,
      onSaveAsCopy: undefined,
      onBackToDashboard: undefined,
      onDiscardChanges: undefined,
      onSavePanelChanges: undefined
    };
  }

  // Safely get dashboard context with error handling
  let dashboardContext;
  try {
    dashboardContext = useDashboard();
  } catch (error) {
    console.error('Error accessing dashboard context:', error);
    dashboardContext = {
      currentDashboard: null
    };
  }
  
  const {
    isDashboardPage,
    isEditMode,
    isPanelEditPage,
    saving,
    hasUnsavedChanges,
    onEditToggle,
    onAddVisualization,
    onAddRow,
    onPastePanel,
    onSave,
    onSaveAsCopy,
    onBackToDashboard,
    onDiscardChanges,
    onSavePanelChanges
  } = dashboardEditContext;

  const { currentDashboard } = dashboardContext;
  
  const [addMenuAnchor, setAddMenuAnchor] = React.useState<null | HTMLElement>(null);
  const [saveMenuAnchor, setSaveMenuAnchor] = React.useState<null | HTMLElement>(null);

  const handleAddMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    setAddMenuAnchor(event.currentTarget);
  };

  const handleAddMenuClose = () => {
    setAddMenuAnchor(null);
  };

  const handleAddVisualization = () => {
    if (onAddVisualization) {
      onAddVisualization();
    }
    handleAddMenuClose();
  };

  const handleAddRow = () => {
    if (onAddRow) {
      onAddRow();
    }
    handleAddMenuClose();
  };

  const handlePastePanel = () => {
    if (onPastePanel) {
      onPastePanel();
    }
    handleAddMenuClose();
  };

  const handleSaveMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    setSaveMenuAnchor(event.currentTarget);
  };

  const handleSaveMenuClose = () => {
    setSaveMenuAnchor(null);
  };

  const handleSave = () => {
    if (onSave) {
      onSave();
    }
    handleSaveMenuClose();
  };

  const handleSaveAsCopy = () => {
    if (onSaveAsCopy) {
      onSaveAsCopy();
    }
    handleSaveMenuClose();
  };

  return (
    <AppBar position="fixed" sx={{ ...layoutStyles.appBar, backgroundColor: 'background.paper' }}>
      {/* First Toolbar */}
             <Toolbar sx={{ 
         minHeight: `${layout.appBarHeight}px !important`, 
         maxHeight: `${layout.appBarHeight}px !important`,
         borderTop: layout.border,
         borderBottom: layout.border,
         boxSizing: 'border-box',
         padding: '0 16px',
         display: 'flex',
         alignItems: 'center',
         justifyContent: 'space-between'
       }}>
                 {/* Left side */}
         <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
           <IconButton
             edge="start"
             color="inherit"
             aria-label="menu"
             onClick={onSidebarToggle}
             sx={{ 
               color: 'text.primary',
               display: sidebarDocked ? (sidebarHidden ? 'block' : 'none') : 'block',
               '&:hover': {
                 backgroundColor: 'action.hover'
               }
             }}
           >
             <MenuIcon />
           </IconButton>
           
           <Breadcrumbs />
         </Box>

        {/* Right side */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SearchBar />
        </Box>
      </Toolbar>

      {/* Second Toolbar */}
      <Toolbar sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        borderBottom: layout.border, // Add bottom border to second toolbar
        boxSizing: 'border-box',
        minHeight: `${layout.appBarHeight}px !important`,
        maxHeight: `${layout.appBarHeight}px !important`,
        padding: '0 16px',
        }}>
        {/* Dashboard Edit Controls - Grafana Style */}
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', width: '100%' }}>
          {/* All buttons right-aligned */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {isPanelEditPage && (
              <>
                <Button
                  variant="outlined"
                  startIcon={<ArrowBackIcon sx={{ fontSize: '16px' }} />}
                  onClick={onBackToDashboard}
                  disabled={saving}
                  size="small"
                  sx={{
                    color: 'text.primary',
                    borderColor: 'divider',
                    height: '32px',
                    fontSize: '0.75rem',
                    padding: '0 12px',
                    '&:hover': {
                      borderColor: 'text.primary',
                      backgroundColor: 'action.hover'
                    }
                  }}
                >
                  Back to Dashboard
                </Button>
                <Tooltip title={hasUnsavedChanges ? "Discard all changes" : "No changes to discard"}>
                  <span>
                    <Button
                      variant="outlined"
                      startIcon={<UndoIcon sx={{ fontSize: '16px' }} />}
                      onClick={onDiscardChanges}
                      disabled={saving || !hasUnsavedChanges}
                      size="small"
                      sx={{
                        color: 'text.primary',
                        borderColor: 'divider',
                        height: '32px',
                        fontSize: '0.75rem',
                        padding: '0 12px',
                        '&:hover': {
                          borderColor: 'text.primary',
                          backgroundColor: 'action.hover'
                        }
                      }}
                    >
                      Discard Changes
                    </Button>
                  </span>
                </Tooltip>
                <Tooltip title={hasUnsavedChanges ? "Save panel changes" : "No changes to save"}>
                  <span>
                    <Button
                      variant="contained"
                      startIcon={<SaveIcon sx={{ fontSize: '16px' }} />}
                      onClick={onSavePanelChanges}
                      disabled={saving || !hasUnsavedChanges}
                      size="small"
                      sx={{
                        backgroundColor: '#28a745', // Green for save
                        height: '32px',
                        fontSize: '0.75rem',
                        padding: '0 12px',
                        '&:hover': {
                          backgroundColor: '#218838',
                        },
                        '&:disabled': {
                          backgroundColor: '#6c757d',
                          color: '#adb5bd'
                        }
                      }}
                    >
                      {saving ? 'Saving...' : 'Save Changes'}
                    </Button>
                  </span>
                </Tooltip>
              </>
            )}
            {isDashboardPage && isEditMode && !isPanelEditPage && (
              <>
                <Button
                  variant="contained"
                  onClick={handleAddMenuClick}
                  endIcon={<ArrowDownIcon />}
                  disabled={saving}
                  size="small"
                  sx={{
                    backgroundColor: '#1f77b4', // Grafana blue
                    '&:hover': {
                      backgroundColor: '#1565c0',
                    }
                  }}
                >
                  Add
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  sx={{
                    color: 'text.primary',
                    borderColor: 'divider',
                    '&:hover': {
                      borderColor: 'text.primary',
                      backgroundColor: 'action.hover'
                    }
                  }}
                >
                  Settings
                </Button>
                <Button
                  variant="outlined"
                  onClick={onEditToggle}
                  disabled={saving}
                  size="small"
                  sx={{
                    color: 'text.primary',
                    borderColor: 'divider',
                    '&:hover': {
                      borderColor: 'text.primary',
                      backgroundColor: 'action.hover'
                    }
                  }}
                >
                  Exit edit
                </Button>
                <Button
                  variant="contained"
                  onClick={handleSaveMenuClick}
                  disabled={saving}
                  size="small"
                  endIcon={<ArrowDownIcon />}
                  sx={{
                    backgroundColor: '#28a745', // Green for save
                    '&:hover': {
                      backgroundColor: '#218838',
                    }
                  }}
                >
                  {saving ? 'Saving...' : 'Save dashboard'}
                </Button>
              </>
            )}
            {isDashboardPage && !isEditMode && !isPanelEditPage && !currentDashboard?.is_default && (
              <Button
                variant="contained"
                onClick={onEditToggle}
                size="small"
                sx={{
                  backgroundColor: '#1f77b4', // Grafana blue
                  '&:hover': {
                    backgroundColor: '#1565c0',
                  }
                }}
              >
                Edit
              </Button>
            )}
          </Box>

          {/* Add Menu */}
          <Menu
            anchorEl={addMenuAnchor}
            open={Boolean(addMenuAnchor)}
            onClose={handleAddMenuClose}
            slotProps={{
              paper: {
                sx: {
                  backgroundColor: 'background.paper',
                  border: '1px solid',
                  borderColor: 'divider'
                }
              }
            }}
          >
            <MenuItem onClick={handleAddVisualization}>
              <ListItemIcon>
                <VisualizationIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primary="Visualization" />
            </MenuItem>
            <MenuItem onClick={handleAddRow}>
              <ListItemIcon>
                <RowIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primary="Row" />
            </MenuItem>
            <MenuItem onClick={handlePastePanel}>
              <ListItemIcon>
                <PasteIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primary="Paste Panel" />
            </MenuItem>
          </Menu>

          {/* Save Menu */}
          <Menu
            anchorEl={saveMenuAnchor}
            open={Boolean(saveMenuAnchor)}
            onClose={handleSaveMenuClose}
            slotProps={{
              paper: {
                sx: {
                  backgroundColor: 'background.paper',
                  border: '1px solid',
                  borderColor: 'divider'
                }
              }
            }}
          >
            <MenuItem onClick={handleSave}>
              <ListItemIcon>
                <SaveIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primary="Save" />
            </MenuItem>
            <MenuItem onClick={handleSaveAsCopy}>
              <ListItemIcon>
                <SaveAsIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primary="Save as copy" />
            </MenuItem>
          </Menu>
        </Box>
      </Toolbar>
    </AppBar>
  );
}
