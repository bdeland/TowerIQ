import { Box, Typography } from '@mui/material';
import { useMemo, memo, useCallback, useState } from 'react';
import DashboardPanelView from './DashboardPanelView';
import { DashboardPanel } from '../contexts/DashboardContext';

interface DashboardGridProps {
  panels: DashboardPanel[];
  isEditMode: boolean;
  isEditable: boolean; // New prop to control edit capabilities
  showMenu: boolean;
  showFullscreen: boolean;
  dashboardId?: string; // Add dashboard ID for layout caching
  onLayoutChange?: (panels: DashboardPanel[]) => void;
  onPanelClick?: (panelId: string) => void;
  onPanelDelete?: (panelId: string) => void;
  onPanelFullscreenToggle?: (panelId: string) => void;
}

const DashboardGridComponent = ({
  panels,
  isEditMode,
  isEditable,
  showMenu,
  showFullscreen,
  onLayoutChange,
  onPanelClick,
  onPanelDelete,
  onPanelFullscreenToggle
}: DashboardGridProps) => {
  const [draggedPanel, setDraggedPanel] = useState<string | null>(null);
  const [dragPosition, setDragPosition] = useState<{ x: number; y: number } | null>(null);

  // Calculate grid dimensions based on panels
  const gridDimensions = useMemo(() => {
    if (panels.length === 0) return { rows: 6, cols: 12 };
    
    const maxX = Math.max(...panels.map(p => p.gridPos.x + p.gridPos.w));
    const maxY = Math.max(...panels.map(p => p.gridPos.y + p.gridPos.h));
    
    return {
      rows: Math.max(6, maxY), // Minimum 6 rows
      cols: Math.max(12, maxX)  // Minimum 12 columns
    };
  }, [panels]);

  // Create CSS Grid styles
  const gridContainerStyle = useMemo(() => ({
    display: 'grid',
    gridTemplateColumns: `repeat(${gridDimensions.cols}, 1fr)`,
    gridTemplateRows: `repeat(${gridDimensions.rows}, 100px)`,
    gap: '4px',
    padding: '0px',
    border: '1px solid #2196f3',
    borderRadius: '4px',
    minHeight: '200px',
    position: 'relative' as const,
  }), [gridDimensions]);

  // Memoize the visual grid cell components for debugging
  const gridCellComponents = useMemo(() => {
    const cells = [];
    // Loop through each row and column to create a cell
    for (let r = 0; r < gridDimensions.rows; r++) {
      for (let c = 0; c < gridDimensions.cols; c++) {
        cells.push(
          <div
            key={`cell-${r}-${c}`}
            style={{
              gridRow: `${r + 1}`,
              gridColumn: `${c + 1}`,
              border: '1px solid white',
              boxSizing: 'border-box',
              // This is crucial to ensure drag events go to the container
              pointerEvents: 'none', 
            }}
          />
        );
      }
    }
    return cells;
  }, [gridDimensions]);

  // Handle drag start
  const handleDragStart = useCallback((panelId: string, event: React.DragEvent) => {
    if (!isEditMode || !isEditable) return;
    
    setDraggedPanel(panelId);
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', panelId);
  }, [isEditMode, isEditable]);

  // Handle drag over
  const handleDragOver = useCallback((event: React.DragEvent) => {
    if (!draggedPanel) return;
    
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
    
    // Calculate grid position from mouse position
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    const x = event.clientX - rect.left - 8; // Account for padding
    const y = event.clientY - rect.top - 8;
    
    const cellWidth = (rect.width - 16) / gridDimensions.cols; // Account for padding and gaps
    const cellHeight = 108; // 100px + 8px gap
    
    const gridX = Math.floor(x / cellWidth);
    const gridY = Math.floor(y / cellHeight);
    
    setDragPosition({ x: Math.max(0, gridX), y: Math.max(0, gridY) });
  }, [draggedPanel, gridDimensions]);

  // Handle drop
  const handleDrop = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    
    if (!draggedPanel || !dragPosition) return;
    
    const updatedPanels = panels.map(panel => {
      if (panel.id === draggedPanel) {
        return {
          ...panel,
          gridPos: {
            ...panel.gridPos,
            x: dragPosition.x,
            y: dragPosition.y
          }
        };
      }
      return panel;
    });
    
    setDraggedPanel(null);
    setDragPosition(null);
    
    if (onLayoutChange) {
      onLayoutChange(updatedPanels);
    }
  }, [draggedPanel, dragPosition, panels, onLayoutChange]);

  // Memoize the panel components
  const panelComponents = useMemo(() => {
    return panels.map((panel) => {
       const panelStyle = {
         gridColumn: `${panel.gridPos.x + 1} / span ${panel.gridPos.w}`,
         gridRow: `${panel.gridPos.y + 1} / span ${panel.gridPos.h}`,
         backgroundColor: 'white',
         borderRadius: '4px',
         overflow: 'hidden',
         cursor: isEditMode && isEditable ? 'move' : 'default',
         opacity: draggedPanel === panel.id ? 0.5 : 1,
         transition: 'opacity 0.2s ease'
       };

      return (
        <div 
          key={panel.id}
          style={panelStyle}
          draggable={isEditMode && isEditable}
          onDragStart={(e) => handleDragStart(panel.id, e)}
        >
          <DashboardPanelView 
            panel={panel}
            isEditMode={isEditMode}
            showMenu={showMenu}
            showFullscreen={showFullscreen}
            onClick={() => onPanelClick?.(panel.id)}
            onDelete={onPanelDelete}
            onFullscreenToggle={onPanelFullscreenToggle}
          />
        </div>
      );
    });
  }, [panels, isEditMode, isEditable, showMenu, showFullscreen, draggedPanel, onPanelClick, onPanelDelete, onPanelFullscreenToggle, handleDragStart]);

  // Render drag preview
  const dragPreview = useMemo(() => {
    if (!draggedPanel || !dragPosition) return null;
    
    const draggedPanelData = panels.find(p => p.id === draggedPanel);
    if (!draggedPanelData) return null;
    
    const previewStyle = {
      position: 'absolute' as const,
      gridColumn: `${dragPosition.x + 1} / span ${draggedPanelData.gridPos.w}`,
      gridRow: `${dragPosition.y + 1} / span ${draggedPanelData.gridPos.h}`,
      border: '2px dashed #2196f3',
      backgroundColor: 'rgba(33, 150, 243, 0.1)',
      borderRadius: '4px',
      pointerEvents: 'none' as const,
      zIndex: 1000
    };
    
    return <div style={previewStyle} />;
  }, [draggedPanel, dragPosition, panels]);

  if (panels.length === 0) {
    return (
      <Box sx={{ 
        padding: 4, 
        textAlign: 'center', 
        backgroundColor: 'rgba(255, 152, 0, 0.1)',
        border: '0.5px solid #ff9800',
        borderRadius: '4px',
        minHeight: '200px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <Typography variant="h6" color="text.primary">
          No panels available
        </Typography>
      </Box>
    );
  }

  return (
    <div 
      style={gridContainerStyle}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {gridCellComponents} {/* Add the visual cells here */}
      {panelComponents}
      {dragPreview}
    </div>
  );
};

// Memoize the component to prevent unnecessary re-renders
export const DashboardGrid = memo(DashboardGridComponent, (prevProps, nextProps) => {
  // Custom comparison function to determine if re-render is needed
  return (
    prevProps.panels.length === nextProps.panels.length &&
    prevProps.isEditMode === nextProps.isEditMode &&
    prevProps.isEditable === nextProps.isEditable &&
    prevProps.showMenu === nextProps.showMenu &&
    prevProps.showFullscreen === nextProps.showFullscreen &&
    // Deep compare panels array
    prevProps.panels.every((panel, index) => {
      const nextPanel = nextProps.panels[index];
      return (
        panel.id === nextPanel.id &&
        panel.title === nextPanel.title &&
        panel.type === nextPanel.type &&
        panel.gridPos.x === nextPanel.gridPos.x &&
        panel.gridPos.y === nextPanel.gridPos.y &&
        panel.gridPos.w === nextPanel.gridPos.w &&
        panel.gridPos.h === nextPanel.gridPos.h &&
        panel.query === nextPanel.query
      );
    })
  );
});