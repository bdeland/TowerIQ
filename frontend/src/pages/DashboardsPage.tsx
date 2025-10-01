import { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  Button, 
  IconButton, 
  Dialog, 
  DialogTitle, 
  DialogContent, 
  DialogActions, 
  TextField,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Checkbox,
  Chip,
  Autocomplete,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  CircularProgress
} from '@mui/material';
import { 
  Dashboard as DashboardIcon, 
  Add as AddIcon, 
  Delete as DeleteIcon, 
  ContentCopy as DuplicateIcon,
  Edit as EditIcon,
  LocalOffer as TagIcon,
  FilterList as FilterIcon,
  Star as StarIcon,
  StarBorder as StarBorderIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useDashboard, Dashboard, DashboardCreateRequest } from '../contexts/DashboardContext';
import { generateUUID } from '../utils/uuid';
import { featureFlags } from '../config/featureFlags';
import { ConfirmationDialog } from '../components/ConfirmationDialog';
import { defaultDashboard } from '../config/defaultDashboard';
import { databaseHealthDashboard } from '../config/databaseHealthDashboard';
import { liveRunTrackingDashboard } from '../config/liveRunTrackingDashboard';

export function DashboardsPage() {
  const navigate = useNavigate();
  const { 
    dashboards, 
    loading, 
    error, 
    createDashboard, 
    deleteDashboard, 
    setDefaultDashboard,
    clearError 
  } = useDashboard();

  const [openCreateDialog, setOpenCreateDialog] = useState(false);
  const [openDeleteDialog, setOpenDeleteDialog] = useState(false);
  const [openEditTagsDialog, setOpenEditTagsDialog] = useState(false);
  const [dashboardToDelete, setDashboardToDelete] = useState<Dashboard | null>(null);
  const [dashboardToEditTags, setDashboardToEditTags] = useState<Dashboard | null>(null);
  const [newDashboardName, setNewDashboardName] = useState('');
  const [newDashboardDescription, setNewDashboardDescription] = useState('');
  const [newDashboardTags, setNewDashboardTags] = useState<string[]>([]);
  const [editingTags, setEditingTags] = useState<string[]>([]);
  const [selectedDashboards, setSelectedDashboards] = useState<string[]>([]);
  const [tagFilter, setTagFilter] = useState<string>('all');

  // Combine database dashboards with the hardcoded dashboards
  const allDashboards = [liveRunTrackingDashboard, defaultDashboard, databaseHealthDashboard, ...dashboards];

  // Get all unique tags from all dashboards
  const allTags = Array.from(new Set(allDashboards.flatMap(d => d.tags))).sort();

  // Filter dashboards based on tag filter
  const filteredDashboards = tagFilter === 'all' 
    ? allDashboards 
    : allDashboards.filter(d => d.tags.includes(tagFilter));

  const handleCreateDashboard = async () => {
    if (newDashboardName.trim()) {
      const dashboardData: DashboardCreateRequest = {
        title: newDashboardName.trim(),
        description: newDashboardDescription.trim(),
        config: {
          panels: [
            {
              id: generateUUID(),
              type: 'stat',
              title: 'Quick Stats',
              gridPos: { x: 0, y: 0, w: 4, h: 2 },
              query: 'SELECT COUNT(*) as count FROM system_stats',
              echartsOption: {},
              options: {}
            },
            {
              id: generateUUID(),
              type: 'timeseries',
              title: 'Recent Activity',
              gridPos: { x: 4, y: 0, w: 4, h: 2 },
              query: 'SELECT timestamp, value FROM activity_log ORDER BY timestamp DESC LIMIT 100',
              echartsOption: {},
              options: {}
            },
            {
              id: generateUUID(),
              type: 'table',
              title: 'System Status',
              gridPos: { x: 8, y: 0, w: 4, h: 2 },
              query: 'SELECT * FROM system_status',
              echartsOption: {},
              options: {}
            }
          ]
        },
        tags: newDashboardTags
      };
      
      const newDashboard = await createDashboard(dashboardData);
      if (newDashboard) {
        setNewDashboardName('');
        setNewDashboardDescription('');
        setNewDashboardTags([]);
        setOpenCreateDialog(false);
      }
    }
  };

  const handleDeleteDashboard = (dashboard: Dashboard) => {
    // Prevent deleting the default dashboard and database health dashboard
    if (dashboard.id === 'default-dashboard' || dashboard.id === 'database-health-dashboard') {
      console.log('Cannot delete system dashboards');
      return;
    }
    setDashboardToDelete(dashboard);
    setOpenDeleteDialog(true);
  };

  const confirmDeleteDashboard = async () => {
    if (dashboardToDelete) {
      const success = await deleteDashboard(dashboardToDelete.id);
      if (success) {
        // Remove from selected dashboards if it was selected
        setSelectedDashboards(prev => prev.filter(id => id !== dashboardToDelete.id));
        setDashboardToDelete(null);
        setOpenDeleteDialog(false);
      }
    }
  };

  const handleDuplicateDashboard = async (dashboard: Dashboard) => {
    const dashboardData: DashboardCreateRequest = {
      title: `${dashboard.title} (Copy)`,
      description: dashboard.description,
      config: {
        ...dashboard.config,
        panels: dashboard.config.panels.map(panel => ({
          ...panel,
          id: generateUUID() // Generate new UUID for each panel
        }))
      },
      tags: [...dashboard.tags]
    };
    
    await createDashboard(dashboardData);
  };

  const handleViewDashboard = (dashboard: Dashboard) => {
            navigate(`/dashboards/${dashboard.id}`);
  };

  const handleEditTags = (dashboard: Dashboard) => {
    setDashboardToEditTags(dashboard);
    setEditingTags([...dashboard.tags]);
    setOpenEditTagsDialog(true);
  };

  const handleSaveTags = async () => {
    if (dashboardToEditTags) {
      // For now, we'll need to implement updateDashboard in the context
      // This is a placeholder for the tag update functionality
      setDashboardToEditTags(null);
      setEditingTags([]);
      setOpenEditTagsDialog(false);
    }
  };

  const handleSetDefault = async (dashboard: Dashboard) => {
    // Prevent setting default for the hardcoded dashboards
    if (dashboard.id === 'default-dashboard' || dashboard.id === 'database-health-dashboard' || dashboard.id === 'live-run-tracking-dashboard') {
      console.log('System dashboards cannot be set as default');
      return;
    }
    await setDefaultDashboard(dashboard.id);
  };

  // Selection handlers
  const handleSelectAll = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.checked) {
      const allIds = filteredDashboards.map(dashboard => dashboard.id);
      setSelectedDashboards(allIds);
    } else {
      setSelectedDashboards([]);
    }
  };

  const handleSelectDashboard = (dashboardId: string) => {
    setSelectedDashboards(prev => {
      if (prev.includes(dashboardId)) {
        return prev.filter(id => id !== dashboardId);
      } else {
        return [...prev, dashboardId];
      }
    });
  };

  const isAllSelected = filteredDashboards.length > 0 && selectedDashboards.length === filteredDashboards.length;
  const isIndeterminate = selectedDashboards.length > 0 && selectedDashboards.length < filteredDashboards.length;

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ 
      padding: 3,
      '@keyframes slideIn': {
        from: {
          opacity: 0,
          transform: 'translateY(-10px)'
        },
        to: {
          opacity: 1,
          transform: 'translateY(0)'
        }
      }
    }}>
      {/* Error Alert */}
      {error && (
        <Alert severity="error" onClose={clearError} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <DashboardIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
          <Typography variant="h4" component="h1">
            Dashboards
          </Typography>
        </Box>
        {featureFlags.enableAdHocDashboards && (
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setOpenCreateDialog(true)}
            sx={{ minWidth: 140 }}
          >
            New Dashboard
          </Button>
        )}
      </Box>

      <Typography variant="body1" color="text.secondary" paragraph>
        Create and manage your dashboards. Each dashboard can contain multiple panels to monitor different aspects of your system.
      </Typography>

      {/* Tag Filter and Bulk Actions Container */}
      <Box sx={{ position: 'relative', mb: 2, minHeight: 48 }}>
        {/* Tag Filter - Always visible */}
        <Box sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 2,
          opacity: selectedDashboards.length > 0 ? 0.3 : 1,
          transition: 'opacity 0.2s ease-in-out'
        }}>
          <FilterIcon color="action" />
          <Typography variant="body2" color="text.secondary">
            Filter by tag:
          </Typography>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel>Tag Filter</InputLabel>
            <Select
              value={tagFilter}
              label="Tag Filter"
              onChange={(e) => setTagFilter(e.target.value)}
              disabled={selectedDashboards.length > 0}
            >
              <MenuItem value="all">All Dashboards</MenuItem>
              {allTags.map(tag => (
                <MenuItem key={tag} value={tag}>{tag}</MenuItem>
              ))}
            </Select>
          </FormControl>
          {tagFilter !== 'all' && (
            <Chip 
              label={`${filteredDashboards.length} dashboard${filteredDashboards.length !== 1 ? 's' : ''}`}
              size="small"
              color="primary"
              variant="outlined"
            />
          )}
        </Box>

        {/* Bulk Actions - Overlay on top */}
        {featureFlags.enableAdHocDashboards && selectedDashboards.length > 0 && (
          <Box sx={{ 
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            display: 'flex', 
            alignItems: 'center', 
            gap: 2, 
            p: 2, 
            backgroundColor: 'action.selected',
            borderRadius: 1,
            border: '1px solid',
            borderColor: 'primary.main',
            zIndex: 1,
            animation: 'slideIn 0.2s ease-out'
          }}>
            <Typography variant="body2" color="primary.main" fontWeight={500}>
              {selectedDashboards.length} dashboard{selectedDashboards.length !== 1 ? 's' : ''} selected
            </Typography>
            <Button
              size="small"
              variant="outlined"
              color="error"
              startIcon={<DeleteIcon />}
              onClick={async () => {
                // Delete all selected dashboards
                for (const dashboardId of selectedDashboards) {
                  await deleteDashboard(dashboardId);
                }
                setSelectedDashboards([]);
              }}
            >
              Delete Selected
            </Button>
            <Button
              size="small"
              variant="outlined"
              startIcon={<DuplicateIcon />}
              onClick={async () => {
                // Duplicate all selected dashboards
                const dashboardsToDuplicate = dashboards.filter(d => selectedDashboards.includes(d.id));
                for (const dashboard of dashboardsToDuplicate) {
                  await handleDuplicateDashboard(dashboard);
                }
                setSelectedDashboards([]);
              }}
            >
              Duplicate Selected
            </Button>
          </Box>
        )}
      </Box>

      {/* Dashboards Table */}
      <TableContainer component={Paper} sx={{ mt: 2 }}>
        <Table>
          <TableHead>
            <TableRow>
              {featureFlags.enableAdHocDashboards && (
                <TableCell padding="checkbox">
                  <Checkbox
                    indeterminate={isIndeterminate}
                    checked={isAllSelected}
                    onChange={handleSelectAll}
                  />
                </TableCell>
              )}
              <TableCell>Name</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Tags</TableCell>
              <TableCell align="center">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredDashboards.map((dashboard) => (
              <TableRow 
                key={dashboard.id}
                sx={{ 
                  height: 64, // Consistent row height
                  '&:hover': {
                    backgroundColor: 'action.hover'
                  }
                }}
              >
                {featureFlags.enableAdHocDashboards && (
                  <TableCell padding="checkbox">
                    <Checkbox
                      checked={selectedDashboards.includes(dashboard.id)}
                      onChange={(e) => {
                        e.stopPropagation();
                        handleSelectDashboard(dashboard.id);
                      }}
                    />
                  </TableCell>
                )}
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <DashboardIcon sx={{ mr: 1, color: 'primary.main', fontSize: 20 }} />
                    <Typography 
                      variant="body1" 
                      fontWeight={500}
                      sx={{ 
                        cursor: 'pointer',
                        color: 'primary.main',
                        textDecoration: 'none',
                        '&:hover': {
                          textDecoration: 'underline'
                        }
                      }}
                      onClick={() => handleViewDashboard(dashboard)}
                    >
                      {dashboard.title}
                    </Typography>
                    {dashboard.is_default && (
                      <StarIcon sx={{ ml: 1, color: 'warning.main', fontSize: 16 }} />
                    )}
                  </Box>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {dashboard.description}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {dashboard.tags.map((tag) => (
                      <Chip
                        key={tag}
                        label={tag}
                        size="small"
                        variant="outlined"
                        icon={<TagIcon />}
                        sx={{ fontSize: '0.75rem' }}
                      />
                    ))}
                    {dashboard.tags.length === 0 && (
                      <Typography variant="body2" color="text.disabled" sx={{ fontStyle: 'italic' }}>
                        No tags
                      </Typography>
                    )}
                  </Box>
                </TableCell>
                <TableCell align="center">
                  <Box sx={{ display: 'flex', gap: 1, justifyContent: 'center' }}>
                    {/* This action should always be available */}
                    <Tooltip title={(dashboard.is_default || dashboard.id === 'default-dashboard') ? "Default Dashboard" : "Set as Default"}>
                      <IconButton
                        size="small"
                        onClick={() => handleSetDefault(dashboard)}
                        sx={{ 
                          color: (dashboard.is_default || dashboard.id === 'default-dashboard') ? 'warning.main' : 'primary.main' 
                        }}
                      >
                        {(dashboard.is_default || dashboard.id === 'default-dashboard') ? <StarIcon fontSize="small" /> : <StarBorderIcon fontSize="small" />}
                      </IconButton>
                    </Tooltip>

                    {featureFlags.enableAdHocDashboards && (
                      <>
                        <Tooltip title="Edit Tags">
                          <IconButton
                            size="small"
                            onClick={() => handleEditTags(dashboard)}
                            sx={{ color: 'primary.main' }}
                          >
                            <EditIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Duplicate">
                          <IconButton
                            size="small"
                            onClick={() => handleDuplicateDashboard(dashboard)}
                            sx={{ color: 'primary.main' }}
                          >
                            <DuplicateIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            onClick={() => handleDeleteDashboard(dashboard)}
                            sx={{ color: 'error.main' }}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </>
                    )}
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Create Dashboard Dialog */}
      <Dialog open={openCreateDialog} onClose={() => setOpenCreateDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Dashboard</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Dashboard Name"
            fullWidth
            variant="outlined"
            value={newDashboardName}
            onChange={(e) => setNewDashboardName(e.target.value)}
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="Description (optional)"
            fullWidth
            variant="outlined"
            multiline
            rows={3}
            value={newDashboardDescription}
            onChange={(e) => setNewDashboardDescription(e.target.value)}
            sx={{ mb: 2 }}
          />
          <Autocomplete
            multiple
            freeSolo
            options={allTags}
            value={newDashboardTags}
            onChange={(event, newValue) => {
              setNewDashboardTags(newValue);
            }}
            renderTags={(value, getTagProps) =>
              value.map((option, index) => (
                <Chip
                  variant="outlined"
                  label={option}
                  {...getTagProps({ index })}
                  size="small"
                />
              ))
            }
            renderInput={(params) => (
              <TextField
                {...params}
                label="Tags (optional)"
                placeholder="Add tags..."
                helperText="Press Enter to add custom tags"
              />
            )}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenCreateDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleCreateDashboard} 
            variant="contained"
            disabled={!newDashboardName.trim() || loading}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Tags Dialog */}
      <Dialog open={openEditTagsDialog} onClose={() => setOpenEditTagsDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          Edit Tags - {dashboardToEditTags?.title}
        </DialogTitle>
        <DialogContent>
          <Autocomplete
            multiple
            freeSolo
            options={allTags}
            value={editingTags}
            onChange={(event, newValue) => {
              setEditingTags(newValue);
            }}
            renderTags={(value, getTagProps) =>
              value.map((option, index) => (
                <Chip
                  variant="outlined"
                  label={option}
                  {...getTagProps({ index })}
                  size="small"
                />
              ))
            }
            renderInput={(params) => (
              <TextField
                {...params}
                label="Tags"
                placeholder="Add tags..."
                helperText="Press Enter to add custom tags"
                sx={{ mt: 1 }}
              />
            )}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenEditTagsDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleSaveTags} 
            variant="contained"
          >
            Save Tags
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmationDialog
        open={openDeleteDialog}
        title="Delete Dashboard"
        message={`Are you sure you want to delete "${dashboardToDelete?.title}"? This action cannot be undone.`}
        confirmText="Delete"
        cancelText="Cancel"
        confirmColor="error"
        onConfirm={confirmDeleteDashboard}
        onCancel={() => setOpenDeleteDialog(false)}
      />
    </Box>
  );
}
