import React, { useState, useEffect } from 'react';
import {
  Drawer,
  Box,
  Typography,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Alert,
  IconButton,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Close as CloseIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';
import { DashboardPanel } from '../contexts/DashboardContext';

interface PanelEditorDrawerProps {
  open: boolean;
  panel: DashboardPanel | null;
  onClose: () => void;
  onUpdatePanel: (updatedPanel: DashboardPanel) => void;
  onDeletePanel: (panelId: string) => void;
  standalone?: boolean; // When true, renders as a static component instead of a drawer
}

const PanelEditorDrawer: React.FC<PanelEditorDrawerProps> = ({
  open,
  panel,
  onClose,
  onUpdatePanel,
  onDeletePanel,
  standalone = false,
}) => {
  const [localPanel, setLocalPanel] = useState<DashboardPanel | null>(null);

  // Reset local panel state when panel prop changes
  useEffect(() => {
    if (panel) {
      setLocalPanel({ ...panel });
    }
  }, [panel]);

  if (!localPanel) {
    return null;
  }

  const handleFieldChange = (field: string, value: any) => {
    const updatedPanel = { ...localPanel, [field]: value };
    setLocalPanel(updatedPanel);
    onUpdatePanel(updatedPanel);
  };

  const handleEChartsOptionChange = (path: string[], value: any) => {
    const updatedOptions = { ...localPanel.echartsOption };
    let current = updatedOptions;
    
    // Navigate to the nested property
    for (let i = 0; i < path.length - 1; i++) {
      if (!current[path[i]]) {
        current[path[i]] = {};
      }
      current = current[path[i]];
    }
    
    // Set the value
    current[path[path.length - 1]] = value;
    
    const updatedPanel = { ...localPanel, echartsOption: updatedOptions };
    setLocalPanel(updatedPanel);
    onUpdatePanel(updatedPanel);
  };



  const getDefaultEChartsOption = (type: DashboardPanel['type']) => {
    switch (type) {
      case 'stat':
        return {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: '',
              fontSize: 24,
              fontWeight: 'bold',
              fill: '#333'
            }
          }]
        };
      case 'timeseries':
        return {
          title: { text: localPanel.title, left: 'center' },
          tooltip: { trigger: 'axis' },
          xAxis: { type: 'time' },
          yAxis: { type: 'value' },
          series: [{
            name: 'Value',
            type: 'line',
            smooth: true,
            data: []
          }]
        };
      case 'bar':
        return {
          title: { text: localPanel.title, left: 'center' },
          tooltip: { trigger: 'axis' },
          xAxis: { type: 'category', data: [] },
          yAxis: { type: 'value' },
          series: [{
            type: 'bar',
            data: []
          }]
        };
      case 'pie':
        return {
          title: { text: localPanel.title, left: 'center' },
          tooltip: { trigger: 'item' },
          series: [{
            type: 'pie',
            radius: '50%',
            data: []
          }]
        };
      case 'table':
        return {
          title: { text: localPanel.title, left: 'center' },
          tooltip: { show: true }
        };
      default:
        return {};
    }
  };

  const handleTypeChange = (newType: DashboardPanel['type']) => {
    const updatedPanel = {
      ...localPanel,
      type: newType,
      echartsOption: getDefaultEChartsOption(newType)
    };
    setLocalPanel(updatedPanel);
    onUpdatePanel(updatedPanel);
  };

  const handleDelete = () => {
    if (window.confirm(`Are you sure you want to delete panel "${localPanel.title}"?`)) {
      onDeletePanel(localPanel.id);
      onClose();
    }
  };

  const content = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">Panel Settings</Typography>
        <Box>
          <IconButton onClick={handleDelete} color="error" sx={{ mr: 1 }}>
            <DeleteIcon />
          </IconButton>
          {!standalone && (
            <IconButton onClick={onClose}>
              <CloseIcon />
            </IconButton>
          )}
        </Box>
      </Box>

      <Divider sx={{ mb: 2 }} />

      {/* Basic Settings */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="subtitle1">Basic Settings</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Panel Title"
                value={localPanel.title}
                onChange={(e) => handleFieldChange('title', e.target.value)}
              />
            </Grid>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Panel Type</InputLabel>
                <Select
                  value={localPanel.type}
                  label="Panel Type"
                  onChange={(e) => handleTypeChange(e.target.value as DashboardPanel['type'])}
                >
                  <MenuItem value="stat">Stat</MenuItem>
                  <MenuItem value="timeseries">Time Series</MenuItem>
                  <MenuItem value="bar">Bar Chart</MenuItem>
                  <MenuItem value="pie">Pie Chart</MenuItem>
                  <MenuItem value="table">Table</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Query"
                multiline
                rows={4}
                value={localPanel.query}
                onChange={(e) => handleFieldChange('query', e.target.value)}
                placeholder="Enter your SQL query here"
              />
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Visual Settings */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="subtitle1">Visual Settings</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {localPanel.type === 'stat' && (
              <>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Font Size"
                    type="number"
                    value={localPanel.echartsOption?.graphic?.[0]?.style?.fontSize || 24}
                    onChange={(e) => handleEChartsOptionChange(
                      ['graphic', 0, 'style', 'fontSize'],
                      parseInt(e.target.value)
                    )}
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Text Color"
                    value={localPanel.echartsOption?.graphic?.[0]?.style?.fill || '#333'}
                    onChange={(e) => handleEChartsOptionChange(
                      ['graphic', 0, 'style', 'fill'],
                      e.target.value
                    )}
                  />
                </Grid>
              </>
            )}
            
            {(localPanel.type === 'timeseries' || localPanel.type === 'bar') && (
              <>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Y-Axis Label"
                    value={localPanel.echartsOption?.yAxis?.name || ''}
                    onChange={(e) => handleEChartsOptionChange(['yAxis', 'name'], e.target.value)}
                  />
                </Grid>
              </>
            )}

            {localPanel.type === 'timeseries' && (
              <>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Line Width"
                    type="number"
                    value={localPanel.echartsOption?.series?.[0]?.lineStyle?.width || 2}
                    onChange={(e) => handleEChartsOptionChange(
                      ['series', 0, 'lineStyle', 'width'],
                      parseInt(e.target.value)
                    )}
                  />
                </Grid>
              </>
            )}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Position Settings */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="subtitle1">Position & Size</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="X Position"
                type="number"
                value={localPanel.gridPos.x}
                onChange={(e) => handleFieldChange('gridPos', {
                  ...localPanel.gridPos,
                  x: parseInt(e.target.value)
                })}
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="Y Position"
                type="number"
                value={localPanel.gridPos.y}
                onChange={(e) => handleFieldChange('gridPos', {
                  ...localPanel.gridPos,
                  y: parseInt(e.target.value)
                })}
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="Width"
                type="number"
                value={localPanel.gridPos.w}
                onChange={(e) => handleFieldChange('gridPos', {
                  ...localPanel.gridPos,
                  w: parseInt(e.target.value)
                })}
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="Height"
                type="number"
                value={localPanel.gridPos.h}
                onChange={(e) => handleFieldChange('gridPos', {
                  ...localPanel.gridPos,
                  h: parseInt(e.target.value)
                })}
              />
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>
    </Box>
  );

  if (standalone) {
    return (
      <Box sx={{ padding: 2, height: '100%', overflow: 'auto' }}>
        {content}
      </Box>
    );
  }

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      sx={{
        '& .MuiDrawer-paper': {
          width: 400,
          padding: 2,
        },
      }}
    >
      {content}
    </Drawer>
  );
};

export default PanelEditorDrawer;
