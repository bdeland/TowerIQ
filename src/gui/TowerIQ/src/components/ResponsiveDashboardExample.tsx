import React, { useState } from 'react';
import { Box, Button, Typography, Paper, Switch, FormControlLabel } from '@mui/material';
import { DashboardGrid } from './DashboardGrid';
import { DashboardPanel } from '../contexts/DashboardContext';
import { useResponsiveGrid } from '../hooks/useResponsiveGrid';

// Example component demonstrating responsive dashboard usage
export const ResponsiveDashboardExample: React.FC = () => {
  const { breakpoint, columns } = useResponsiveGrid();
  const [enableResponsive, setEnableResponsive] = useState(true);
  
  // Sample panels for demonstration
  const [panels, setPanels] = useState<DashboardPanel[]>([
    {
      id: 'panel-1',
      title: 'Revenue Chart',
      type: 'chart',
      gridPos: { x: 0, y: 0, w: 6, h: 3 },
      query: 'SELECT * FROM revenue',
      echartsOption: {}
    },
    {
      id: 'panel-2',
      title: 'User Stats',
      type: 'stat',
      gridPos: { x: 6, y: 0, w: 3, h: 2 },
      query: 'SELECT COUNT(*) FROM users',
      echartsOption: {}
    },
    {
      id: 'panel-3',
      title: 'Activity Log',
      type: 'table',
      gridPos: { x: 9, y: 0, w: 3, h: 4 },
      query: 'SELECT * FROM activity_log LIMIT 10',
      echartsOption: {}
    },
    {
      id: 'panel-4',
      title: 'Performance Metrics',
      type: 'chart',
      gridPos: { x: 0, y: 3, w: 9, h: 3 },
      query: 'SELECT * FROM performance',
      echartsOption: {}
    }
  ]);

  const [isEditMode, setIsEditMode] = useState(false);

  const handleLayoutChange = (updatedPanels: DashboardPanel[]) => {
    setPanels(updatedPanels);
    console.log('Layout changed:', updatedPanels);
  };

  const handlePanelClick = (panelId: string) => {
    console.log('Panel clicked:', panelId);
  };

  const handlePanelDelete = (panelId: string) => {
    setPanels(prev => prev.filter(p => p.id !== panelId));
    console.log('Panel deleted:', panelId);
  };

  return (
    <Box sx={{ p: 3 }}>
      <Paper sx={{ p: 2, mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          Responsive Dashboard Grid Demo
        </Typography>
        
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 2, flexWrap: 'wrap' }}>
          <Typography variant="body1">
            Current: <strong>{breakpoint.toUpperCase()}</strong> ({columns} columns)
          </Typography>
          
          <FormControlLabel
            control={
              <Switch
                checked={enableResponsive}
                onChange={(e) => setEnableResponsive(e.target.checked)}
              />
            }
            label="Enable Responsive"
          />
          
          <Button
            variant="outlined"
            onClick={() => setIsEditMode(!isEditMode)}
            color={isEditMode ? "secondary" : "primary"}
          >
            {isEditMode ? 'Exit Edit' : 'Edit Mode'}
          </Button>
        </Box>

        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Resize your browser window to see the responsive breakpoints in action:
        </Typography>
        
        <Box component="ul" sx={{ mb: 2, pl: 3 }}>
          <Typography component="li" variant="body2">
            <strong>XS (0px+):</strong> 4 columns, 80px row height - Mobile portrait
          </Typography>
          <Typography component="li" variant="body2">
            <strong>SM (600px+):</strong> 6 columns, 90px row height - Mobile landscape
          </Typography>
          <Typography component="li" variant="body2">
            <strong>MD (900px+):</strong> 8 columns, 100px row height - Tablet
          </Typography>
          <Typography component="li" variant="body2">
            <strong>LG (1200px+):</strong> 12 columns, 100px row height - Desktop
          </Typography>
          <Typography component="li" variant="body2">
            <strong>XL (1536px+):</strong> 16 columns, 100px row height - Large desktop
          </Typography>
        </Box>
      </Paper>

      <Paper sx={{ p: 2 }}>
        <DashboardGrid
          panels={panels}
          isEditMode={isEditMode}
          isEditable={true}
          showMenu={true}
          showFullscreen={true}
          enableResponsive={enableResponsive}
          onLayoutChange={handleLayoutChange}
          onPanelClick={handlePanelClick}
          onPanelDelete={handlePanelDelete}
          onPanelFullscreenToggle={(panelId) => console.log('Fullscreen toggle:', panelId)}
        />
      </Paper>
    </Box>
  );
};
