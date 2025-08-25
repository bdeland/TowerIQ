import React from 'react';
import { AppBar, Toolbar, Box, IconButton, Button, Menu, MenuItem, ListItemIcon, ListItemText } from '@mui/material';
import { 
  Menu as MenuIcon,
  KeyboardArrowDown as ArrowDownIcon,
  BarChart as VisualizationIcon,
  ViewHeadline as RowIcon,
  ContentPaste as PasteIcon,
  Save as SaveIcon,
  SaveAs as SaveAsIcon
} from '@mui/icons-material';
import { Breadcrumbs } from './Breadcrumbs';
import { SearchBar } from './SearchBar';
import { useDashboardEdit } from '../contexts/DashboardEditContext';

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
      saving: false,
      onEditToggle: undefined,
      onAddVisualization: undefined,
      onAddRow: undefined,
      onPastePanel: undefined,
      onSave: undefined,
      onSaveAsCopy: undefined
    };
  }
  
  const {
    isDashboardPage,
    isEditMode,
    saving,
    onEditToggle,
    onAddVisualization,
    onAddRow,
    onPastePanel,
    onSave,
    onSaveAsCopy
  } = dashboardEditContext;
  
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
    } else {
      console.log('Save dashboard clicked - no handler available');
    }
    handleSaveMenuClose();
  };

  const handleSaveAsCopy = () => {
    if (onSaveAsCopy) {
      onSaveAsCopy();
    } else {
      console.log('Save as copy clicked - no handler available');
    }
    handleSaveMenuClose();
  };
  return (
    <AppBar
      position="fixed"
      sx={{
        ...layoutStyles.appBar,
        // Match sidebar: exactly 80px total with top/bottom borders, no internal border
        borderTop: layout.border,
        borderBottom: layout.border,
        height: `${layout.appBarHeight * 2}px`, // Exactly 80px total
        minHeight: `${layout.appBarHeight * 2}px`,
        maxHeight: `${layout.appBarHeight * 2}px`,
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column',
        padding: 0,
        '& .MuiToolbar-root': {
          // Default height for toolbars without internal borders
          minHeight: `${layout.appBarHeight}px`,
          height: `${layout.appBarHeight}px`,
          maxHeight: `${layout.appBarHeight}px`,
          paddingLeft: 1,
          paddingRight: 1.5,
          paddingTop: 0,
          paddingBottom: 0,
          boxSizing: 'border-box',
          borderRight: layout.border, // Add right border to all toolbars
          flex: 'none', // Prevent flex growing/shrinking
        }
      }}
    >
      {/* First Toolbar */}
      <Toolbar sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        borderBottom: layout.border,
        boxSizing: 'border-box',
      }}>
        {/* Main Menu Toggle Icon - Show when not docked or when docked and hidden */}
        <IconButton
          aria-label="toggle sidebar"
          onClick={onSidebarToggle}
          sx={{ 
            ...listItemIconStyles,
            display: sidebarDocked ? (sidebarHidden ? 'block' : 'none') : 'block',
            color: 'text.primary', // Explicitly set color to match theme
            marginLeft: '-8px', // Compensate for Toolbar's left padding
            '&:hover': {
              backgroundColor: 'rgba(255, 255, 255, 0.04)',
            }
          }}
        >
          <MenuIcon />
        </IconButton>

        {/* Breadcrumbs */}
        <Box sx={{ flexGrow: 1, display: 'flex', alignItems: 'center' }}>
          <Breadcrumbs />
        </Box>

        {/* Search Bar - Pushed to the right */}
        <Box sx={{ 
          marginLeft: 'auto',
          margin: 0,
          padding: 0,
          marginRight: 0,
          paddingRight: 0,
        }}>
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
        }}>
        {/* Dashboard Edit Controls - Grafana Style */}
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', width: '100%' }}>
          {/* All buttons right-aligned */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {isDashboardPage && isEditMode && (
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
            {isDashboardPage && !isEditMode && (
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
