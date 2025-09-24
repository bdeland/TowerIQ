import React, { useMemo, useState, useCallback } from 'react';
import { Box, Typography } from '@mui/material';
import { Dashboard } from '../domain/dashboard/Dashboard';
import { Panel } from '../domain/dashboard/Panel';
import { NewDashboardPanelView } from './NewDashboardPanelView';
import type { PanelState } from '../hooks/useDashboard';

interface NewDashboardGridProps {
  panels: Panel[];
  panelStates: Map<string, PanelState>;
  dashboard: Dashboard;
  onPanelRefresh: (panelId: string) => Promise<void>;
  onPanelUpdate: (panelId: string, config: any) => void;
  onPanelDelete: (panelId: string) => void;
  isEditMode?: boolean;
  isDevMode?: boolean;
}

export const NewDashboardGrid: React.FC<NewDashboardGridProps> = ({
  panels,
  panelStates,
  dashboard,
  onPanelRefresh,
  onPanelUpdate,
  onPanelDelete,
  isEditMode = false,
  isDevMode = false,
}) => {
  const [fullscreenPanelId, setFullscreenPanelId] = useState<string | null>(null);

  // Sort panels by grid position for consistent rendering
  const sortedPanels = useMemo(() => {
    return [...panels].sort((a, b) => {
      const aPos = a.layout;
      const bPos = b.layout;
      
      // Handle cases where layout might be undefined
      if (!aPos || !bPos) {
        return 0; // Keep original order if layout is missing
      }
      
      // Sort by row first, then by column
      if (aPos.y !== bPos.y) {
        return aPos.y - bPos.y;
      }
      return aPos.x - bPos.x;
    });
  }, [panels]);

  // Calculate grid dimensions based on panel positions
  const gridDimensions = useMemo(() => {
    let maxX = 0;
    let maxY = 0;
    
    panels.forEach(panel => {
      // Handle cases where layout might be undefined
      if (!panel.layout) {
        return; // Skip panels without layout
      }
      
      const right = panel.layout.x + panel.layout.w;
      const bottom = panel.layout.y + panel.layout.h;
      maxX = Math.max(maxX, right);
      maxY = Math.max(maxY, bottom);
    });
    
    return { 
      columns: Math.max(maxX, 24), // Minimum 24 columns
      rows: Math.max(maxY, 12)     // Minimum 12 rows
    };
  }, [panels]);

  // Handle panel fullscreen toggle
  const handleFullscreenToggle = useCallback((panelId: string | null) => {
    setFullscreenPanelId(panelId);
  }, []);

  // Handle panel drag (for edit mode)
  const handlePanelDrag = useCallback((panelId: string, newPosition: { x: number; y: number }) => {
    if (!isEditMode) return;
    
    const panel = panels.find(p => p.id === panelId);
    if (!panel) return;
    
    const updatedConfig = {
      ...panel.serialize(),
      layout: {
        ...panel.layout,
        x: newPosition.x,
        y: newPosition.y,
      }
    };
    
    onPanelUpdate(panelId, updatedConfig);
  }, [isEditMode, panels, onPanelUpdate]);

  // Handle panel resize (for edit mode)
  const handlePanelResize = useCallback((panelId: string, newSize: { w: number; h: number }) => {
    if (!isEditMode) return;
    
    const panel = panels.find(p => p.id === panelId);
    if (!panel) return;
    
    const updatedConfig = {
      ...panel.serialize(),
      layout: {
        ...panel.layout,
        w: newSize.w,
        h: newSize.h,
      }
    };
    
    onPanelUpdate(panelId, updatedConfig);
  }, [isEditMode, panels, onPanelUpdate]);

  // Render fullscreen panel
  if (fullscreenPanelId) {
    const panel = panels.find(p => p.id === fullscreenPanelId);
    const state = panelStates.get(fullscreenPanelId);
    
    if (panel && state) {
      return (
        <Box sx={{ 
          position: 'fixed', 
          top: 0, 
          left: 0, 
          width: '100vw', 
          height: '100vh',
          zIndex: 9999,
          backgroundColor: 'background.default'
        }}>
          <NewDashboardPanelView
            panel={panel}
            state={state}
            onRefresh={() => onPanelRefresh(panel.id)}
            onFullscreenToggle={() => handleFullscreenToggle(null)}
            onEdit={isEditMode ? () => onPanelUpdate(panel.id, panel.serialize()) : undefined}
            onDelete={isEditMode ? () => onPanelDelete(panel.id) : undefined}
            isFullscreen={true}
            dashboard={dashboard}
          />
        </Box>
      );
    }
  }

  return (
    <Box sx={{ 
      width: '100%', 
      height: '100%',
      position: 'relative',
      // Development mode styling
      ...(isDevMode && {
        border: '1px solid',
        borderColor: 'primary.main',
        borderRadius: 1,
      })
    }}>
      {/* CSS Grid container */}
      <Box sx={{
        display: 'grid',
        gridTemplateColumns: `repeat(${gridDimensions.columns}, 1fr)`,
        gridTemplateRows: `repeat(${gridDimensions.rows}, 60px)`, // Each row is 60px
        gap: 1,
        padding: 1,
        minHeight: '600px',
        // Grid debugging in dev mode
        ...(isDevMode && {
          backgroundColor: 'rgba(0, 0, 0, 0.02)',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundImage: `
              linear-gradient(to right, rgba(255, 255, 255, 0.1) 1px, transparent 1px),
              linear-gradient(to bottom, rgba(255, 255, 255, 0.1) 1px, transparent 1px)
            `,
            backgroundSize: `calc(100% / ${gridDimensions.columns}) 60px`,
            pointerEvents: 'none',
            zIndex: 1,
          }
        })
      }}>
        {sortedPanels.map((panel) => {
          const state = panelStates.get(panel.id) || { status: 'idle' };
          
          // Skip panels without proper layout
          if (!panel.layout) {
            return null;
          }
          
          return (
            <Box
              key={panel.id}
              sx={{
                gridColumn: `${panel.layout.x + 1} / span ${panel.layout.w}`,
                gridRow: `${panel.layout.y + 1} / span ${panel.layout.h}`,
                position: 'relative',
                zIndex: 2,
                // Edit mode styling
                ...(isEditMode && {
                  cursor: 'move',
                  '&:hover': {
                    transform: 'scale(1.02)',
                    transition: 'transform 0.2s ease',
                    zIndex: 3,
                  }
                }),
                // Dev mode panel borders
                ...(isDevMode && {
                  border: '1px solid',
                  borderColor: 'warning.main',
                  borderRadius: 1,
                })
              }}
              // Drag and drop handlers for edit mode
              draggable={isEditMode}
              onDragStart={(e) => {
                if (!isEditMode) return;
                e.dataTransfer.setData('text/plain', panel.id);
              }}
              onDragOver={(e) => {
                if (!isEditMode) return;
                e.preventDefault();
              }}
              onDrop={(e) => {
                if (!isEditMode) return;
                e.preventDefault();
                
                const draggedPanelId = e.dataTransfer.getData('text/plain');
                if (draggedPanelId === panel.id) return;
                
                // Calculate new position based on drop location
                const rect = e.currentTarget.getBoundingClientRect();
                const x = Math.floor((e.clientX - rect.left) / (rect.width / panel.layout.w));
                const y = Math.floor((e.clientY - rect.top) / (rect.height / panel.layout.h));
                
                handlePanelDrag(draggedPanelId, { x, y });
              }}
            >
              <NewDashboardPanelView
                panel={panel}
                state={state}
                onRefresh={() => onPanelRefresh(panel.id)}
                onFullscreenToggle={() => handleFullscreenToggle(panel.id)}
                onEdit={isEditMode ? () => onPanelUpdate(panel.id, panel.serialize()) : undefined}
                onDelete={isEditMode ? () => onPanelDelete(panel.id) : undefined}
                isFullscreen={false}
                dashboard={dashboard}
              />
            </Box>
          );
        })}
      </Box>
      
      {/* Empty state for no panels */}
      {panels.length === 0 && (
        <Box sx={{ 
          display: 'flex', 
          flexDirection: 'column',
          alignItems: 'center', 
          justifyContent: 'center',
          height: '400px',
          color: 'text.secondary'
        }}>
          <Typography variant="h6" gutterBottom>
            No panels in this dashboard
          </Typography>
          <Typography variant="body2">
            {isEditMode ? 'Add panels to get started' : 'This dashboard is empty'}
          </Typography>
        </Box>
      )}
    </Box>
  );
};
