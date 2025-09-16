import React from 'react';
import { AppBar, Toolbar, Box, IconButton, Button, Menu, MenuItem, ListItemIcon, ListItemText, Tooltip, FormControl, Select, Checkbox, Chip } from '@mui/material';
import { 
  Menu as MenuIcon,
  KeyboardArrowDown as ArrowDownIcon,
  BarChart as VisualizationIcon,
  ViewHeadline as RowIcon,
  ContentPaste as PasteIcon,
  Save as SaveIcon,
  SaveAs as SaveAsIcon,
  ArrowBack as ArrowBackIcon,
  Undo as UndoIcon,
  Close as CloseIcon
} from '@mui/icons-material';
import { Breadcrumbs } from './Breadcrumbs';
import { SearchBar } from './SearchBar';
import { useDashboardEdit } from '../contexts/DashboardEditContext';
import { useDashboard } from '../contexts/DashboardContext';
import { useDashboardVariable } from '../contexts/DashboardVariableContext';

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
}

export function Header({ 
  sidebarDocked, 
  sidebarHidden, 
  onSidebarToggle, 
  layoutStyles, 
  layout
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

  // Safely get dashboard variable context with error handling
  let dashboardVariableContext;
  try {
    dashboardVariableContext = useDashboardVariable();
  } catch (error) {
    // Context is not available, which is fine for non-default dashboards
    dashboardVariableContext = null;
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
        padding: '0px 16px 0 16px',
        }}>
        {/* Dashboard Variables - Grafana Style */}
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
          {currentDashboard?.is_default && currentDashboard.variables && dashboardVariableContext && 
            currentDashboard.variables.map(variable => {
              const selectedValue = dashboardVariableContext.selectedValues[variable.name];
              const options = dashboardVariableContext.options[variable.name] || [];
              

              // Helper function to clear all selections
              const clearAllSelections = (event: React.MouseEvent) => {
                event.stopPropagation(); // Prevent dropdown from opening
                dashboardVariableContext.updateVariable(variable.name, []);
              };

              // Get display value for selected option(s)
              let displayValue = '';
              let renderValue = null;
              
              if (variable.type === 'multiselect' && Array.isArray(selectedValue)) {
                const nonAllSelections = selectedValue.filter(v => v !== 'all');
                
                if (selectedValue.includes('all') || selectedValue.length === 0) {
                  displayValue = 'All';
                  renderValue = <span style={{ color: '#e0e0e0', fontSize: '0.75rem' }}>All</span>;
                } else {
                  displayValue = `Selected (${nonAllSelections.length})`;
                  renderValue = (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, alignItems: 'center', maxWidth: '120px', overflow: 'hidden' }}>
                      {nonAllSelections.sort((a, b) => {
                        // Sort numerically if both are numbers, otherwise sort as strings
                        const numA = Number(a);
                        const numB = Number(b);
                        if (!isNaN(numA) && !isNaN(numB)) {
                          return numA - numB;
                        }
                        return String(a).localeCompare(String(b));
                      }).slice(0, 3).map((value) => {
                        const option = options.find(opt => opt.value === value);
                        return (
                          <Chip
                            key={value}
                            label={option?.label || value}
                            size="small"
                            sx={{
                              height: '18px',
                              fontSize: '0.8rem',
                              backgroundColor: '#22252b',
                              color: '#e0e0e0',
                              borderRadius: '2px',
                              '& .MuiChip-label': {
                                px: 0.75,
                              },
                            }}
                          />
                        );
                      })}
                      {nonAllSelections.length > 3 && (
                        <span style={{ color: '#e0e0e0', fontSize: '0.65rem' }}>
                          +{nonAllSelections.length - 3}
                        </span>
                      )}
                    </Box>
                  );
                }
              } else {
                const option = options.find(opt => opt.value === selectedValue);
                displayValue = option?.label || selectedValue || 'All';
                renderValue = <span style={{ color: '#e0e0e0', fontSize: '0.75rem' }}>{displayValue}</span>;
              }

              return (
                <Box key={variable.name} sx={{ display: 'flex', alignItems: 'center' }}>
                  {/* Variable Label */}
                  <Box sx={{
                    backgroundColor: '#181b1f',
                    color: '#e0e0e0',
                    px: 1.5,
                    py: 0.5,
                    fontSize: '0.8rem',
                    fontWeight: 500,
                    borderRadius: '2px 0 0 2px',
                    border: '1px solid #404040',
                    minHeight: '30px',
                    display: 'flex',
                    alignItems: 'center',
                  }}>
                    {variable.label}
                  </Box>
                  
                  {/* Variable Value Selector */}
                  <Box sx={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                    <FormControl size="small" disabled={dashboardVariableContext.isLoading}>
                      <Select
                        multiple={variable.type === 'multiselect'}
                        value={selectedValue || (variable.type === 'multiselect' ? [] : '')}
                        onChange={(e) => dashboardVariableContext.updateVariable(variable.name, e.target.value)}
                        displayEmpty
                        renderValue={() => renderValue}
                        sx={{
                          minWidth: variable.type === 'multiselect' ? 140 : 80,
                          height: '30px',
                          backgroundColor: '#111217',
                          color: '#e0e0e0',
                          borderRadius: variable.type === 'multiselect' ? '0' : '0 2px 2px 0',
                          '& .MuiOutlinedInput-notchedOutline': {
                            border: '1px solid #404040',
                            borderLeft: 'none',
                            borderRight: variable.type === 'multiselect' ? 'none' : '1px solid #404040',
                          },
                          '& .MuiSelect-select': {
                            py: 0.5,
                            px: 1,
                            fontSize: '0.75rem',
                            display: 'flex',
                            alignItems: 'center',
                          },
                          '& .MuiSvgIcon-root': {
                            color: '#e0e0e0',
                            fontSize: '16px',
                          },
                          '&:hover .MuiOutlinedInput-notchedOutline': {
                            borderColor: '#555',
                          },
                          '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                            borderColor: '#1f77b4',
                            borderWidth: '1px',
                          },
                        }}
                      MenuProps={{
                        PaperProps: {
                          sx: {
                            backgroundColor: '#2e3136',
                            border: '1px solid #404040',
                            '& .MuiMenuItem-root': {
                              color: '#e0e0e0',
                              fontSize: '0.75rem',
                              minHeight: '32px',
                              py: 0.5,
                              px: 1,
                              '&:hover': {
                                backgroundColor: '#404040',
                              },
                              '&.Mui-selected': {
                                backgroundColor: 'transparent',
                                '&:hover': {
                                  backgroundColor: '#404040',
                                },
                              },
                            },
                          },
                        },
                      }}
                    >
                      {options.map(option => (
                        <MenuItem key={option.value} value={option.value}>
                          {variable.type === 'multiselect' && (
                            <Checkbox
                              checked={Array.isArray(selectedValue) && (selectedValue.includes(option.value) || (option.value === 'all' && selectedValue.includes('all')))}
                              size="small"
                              sx={{
                                color: '#e0e0e0',
                                p: 0.25,
                                '&.Mui-checked': {
                                  color: '#1f77b4',
                                },
                                '& .MuiSvgIcon-root': {
                                  fontSize: '12px',
                                },
                                mr: 0.75,
                              }}
                            />
                          )}
                          {option.label}
                        </MenuItem>
                      ))}
                    </Select>
                    </FormControl>
                    
                    {/* Clear button for multiselect */}
                    {variable.type === 'multiselect' && (
                      <IconButton
                        size="small"
                        onClick={clearAllSelections}
                        disabled={!Array.isArray(selectedValue) || selectedValue.length === 0}
                        sx={{
                          width: '30px',
                          height: '30px',
                          backgroundColor: '#404040',
                          borderRadius: '0 2px 2px 0',
                          border: '1px solid #404040',
                          color: '#e0e0e0',
                          '&:hover': {
                            backgroundColor: '#555',
                            borderColor: '#555',
                          },
                          '&:disabled': {
                            backgroundColor: '#404040',
                            color: '#666',
                          },
                        }}
                      >
                        <CloseIcon sx={{ fontSize: '14px' }} />
                      </IconButton>
                    )}
                  </Box>
                </Box>
              );
            })
          }
        </Box>

        {/* Dashboard Edit Controls - Grafana Style */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {/* All buttons right-aligned */}
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
      </Toolbar>

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
    </AppBar>
  );
}
