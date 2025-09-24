import React, { useState, useCallback } from 'react';
import { 
  Box, 
  Typography, 
  IconButton, 
  Tooltip,
  Chip,
  Button,
  Menu,
  MenuItem,
  Divider
} from '@mui/material';
import { 
  Refresh as RefreshIcon,
  Edit as EditIcon,
  Save as SaveIcon,
  Cancel as CancelIcon,
  Settings as SettingsIcon,
  MoreVert as MoreVertIcon
} from '@mui/icons-material';
import { Dashboard } from '../domain/dashboard/Dashboard';
import { NewDashboardVariableControls } from './NewDashboardVariableControls';
import type { VariableValues } from '../hooks/useDashboard';

interface NewDashboardHeaderProps {
  dashboard: Dashboard;
  variables: VariableValues;
  onVariableChange: (name: string, value: any) => void;
  onRefresh: () => Promise<void>;
  isEditMode?: boolean;
  onEditModeToggle?: () => void;
  onSave?: () => Promise<void>;
  onCancel?: () => void;
  isDevMode?: boolean;
  isSaving?: boolean;
}

export const NewDashboardHeader: React.FC<NewDashboardHeaderProps> = ({
  dashboard,
  variables,
  onVariableChange,
  onRefresh,
  isEditMode = false,
  onEditModeToggle,
  onSave,
  onCancel,
  isDevMode = false,
  isSaving = false,
}) => {
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [menuAnchorEl, setMenuAnchorEl] = useState<null | HTMLElement>(null);

  const handleRefresh = useCallback(async () => {
    setIsRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setIsRefreshing(false);
    }
  }, [onRefresh]);

  const handleMenuOpen = useCallback((event: React.MouseEvent<HTMLElement>) => {
    setMenuAnchorEl(event.currentTarget);
  }, []);

  const handleMenuClose = useCallback(() => {
    setMenuAnchorEl(null);
  }, []);

  const handleEditToggle = useCallback(() => {
    handleMenuClose();
    onEditModeToggle?.();
  }, [onEditModeToggle, handleMenuClose]);

  const handleSave = useCallback(async () => {
    if (onSave) {
      await onSave();
    }
  }, [onSave]);

  const hasVariables = dashboard.variables.definitions.size > 0;

  return (
    <Box sx={{ 
      mb: 2, 
      pb: 2, 
      borderBottom: '1px solid',
      borderColor: 'divider'
    }}>
      {/* Primary Header */}
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        mb: hasVariables ? 2 : 0
      }}>
        {/* Left side - Title and metadata */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="h4" component="h1">
            {dashboard.metadata.title}
          </Typography>
          
          {dashboard.metadata.description && (
            <Typography variant="body2" color="text.secondary">
              {dashboard.metadata.description}
            </Typography>
          )}
          
          {/* Dashboard metadata chips */}
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Chip 
              label={`${dashboard.panels.size} panels`} 
              size="small" 
              variant="outlined" 
            />
            
            {dashboard.metadata.tags && dashboard.metadata.tags.length > 0 && (
              dashboard.metadata.tags.map(tag => (
                <Chip 
                  key={tag}
                  label={tag} 
                  size="small" 
                  color="primary"
                  variant="outlined" 
                />
              ))
            )}
            
            {isEditMode && (
              <Chip 
                label="Edit Mode" 
                size="small" 
                color="warning"
                variant="filled"
              />
            )}
            
            {isDevMode && (
              <Chip 
                label="Dev Mode" 
                size="small" 
                color="info"
                variant="outlined"
              />
            )}
          </Box>
        </Box>

        {/* Right side - Actions */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {/* Edit mode controls */}
          {isEditMode && onSave && onCancel && (
            <>
              <Button
                variant="outlined"
                startIcon={<CancelIcon />}
                onClick={onCancel}
                disabled={isSaving}
              >
                Cancel
              </Button>
              <Button
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={handleSave}
                disabled={isSaving}
              >
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </>
          )}
          
          {/* Refresh button */}
          <Tooltip title="Refresh Dashboard">
            <IconButton 
              onClick={handleRefresh}
              disabled={isRefreshing}
              color="primary"
            >
              <RefreshIcon sx={{ 
                ...(isRefreshing && {
                  animation: 'spin 1s linear infinite',
                  '@keyframes spin': {
                    '0%': { transform: 'rotate(0deg)' },
                    '100%': { transform: 'rotate(360deg)' },
                  }
                })
              }} />
            </IconButton>
          </Tooltip>

          {/* Dashboard menu */}
          <Tooltip title="Dashboard Options">
            <IconButton onClick={handleMenuOpen}>
              <MoreVertIcon />
            </IconButton>
          </Tooltip>
          
          <Menu
            anchorEl={menuAnchorEl}
            open={Boolean(menuAnchorEl)}
            onClose={handleMenuClose}
            anchorOrigin={{
              vertical: 'bottom',
              horizontal: 'right',
            }}
            transformOrigin={{
              vertical: 'top',
              horizontal: 'right',
            }}
          >
            {onEditModeToggle && (
              <MenuItem onClick={handleEditToggle}>
                <EditIcon sx={{ mr: 1 }} />
                {isEditMode ? 'Exit Edit Mode' : 'Edit Dashboard'}
              </MenuItem>
            )}
            
            <MenuItem onClick={handleMenuClose}>
              <SettingsIcon sx={{ mr: 1 }} />
              Dashboard Settings
            </MenuItem>
            
            <Divider />
            
            <MenuItem onClick={handleMenuClose} disabled>
              Export Dashboard
            </MenuItem>
            
            <MenuItem onClick={handleMenuClose} disabled>
              Duplicate Dashboard
            </MenuItem>
          </Menu>
        </Box>
      </Box>

      {/* Secondary Header - Variables */}
      {hasVariables && (
        <Box sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 2,
          p: 2,
          backgroundColor: 'background.paper',
          borderRadius: 1,
          border: '1px solid',
          borderColor: 'divider'
        }}>
          <Typography variant="subtitle2" color="text.secondary" sx={{ minWidth: 'fit-content' }}>
            Filters:
          </Typography>
          
          <NewDashboardVariableControls
            variables={dashboard.variables}
            selectedValues={variables}
            onChange={onVariableChange}
          />
        </Box>
      )}
    </Box>
  );
};
