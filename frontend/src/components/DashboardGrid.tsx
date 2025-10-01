import { Box, Typography } from '@mui/material';
import { useMemo, memo, useCallback, useState, useEffect } from 'react';
import DashboardPanelView from './DashboardPanelView';
import { DashboardPanel } from '../contexts/DashboardContext';
import { useResponsiveGrid, adjustPanelForBreakpoint } from '../hooks/useResponsiveGrid';
import { useDeveloper } from '../contexts/DeveloperContext';

interface DashboardGridProps {
  panels: DashboardPanel[];
  panelData?: Record<string, any[]>; // Optional panel data for pre-fetched data
  panelErrors?: Map<string, string>; // Panel errors map
  isLoading?: boolean; // Loading state from dashboard level
  isEditMode: boolean;
  isEditable: boolean; // New prop to control edit capabilities
  showMenu: boolean;
  showFullscreen?: boolean;
  dashboardId?: string; // Add dashboard ID for layout caching
  onLayoutChange?: (panels: DashboardPanel[]) => void;
  onPanelClick?: (panelId: string) => void;
  onPanelDelete?: (panelId: string) => void;
  enableResponsive?: boolean; // New prop to enable/disable responsive behavior
}

const DashboardGridComponent = ({
  panels,
  panelData,
  panelErrors,
  isLoading = false,
  isEditMode,
  isEditable,
  showMenu,
  onLayoutChange,
  onPanelClick,
  onPanelDelete,
  enableResponsive = true
}: DashboardGridProps) => {
  const [draggedPanel, setDraggedPanel] = useState<string | null>(null);
  const [dragPosition, setDragPosition] = useState<{ x: number; y: number } | null>(null);
  const [previousColumns, setPreviousColumns] = useState<number>(12);
  
  // Get developer mode state
  const { isDevMode, debugBorders, debugBorderSettings } = useDeveloper();
  const showDebugBorders = isDevMode && debugBorders;
  
  // Individual border settings
  const showGridContainerBorder = isDevMode && debugBorderSettings.gridContainer.enabled;
  const showPanelBorders = isDevMode && debugBorderSettings.panels.enabled;
  const showGridCellBorders = isDevMode && debugBorderSettings.gridCells.enabled;
  
  // Get responsive grid configuration
  const { columns: responsiveColumns, cellHeight, breakpoint } = useResponsiveGrid();
  const gridColumns = enableResponsive ? responsiveColumns : 12;

  // Calculate grid dimensions based on panels and responsive settings
  const gridDimensions = useMemo(() => {
    if (panels.length === 0) return { rows: 6, cols: gridColumns };
    
    const maxX = Math.max(...panels.map(p => p.gridPos.x + p.gridPos.w));
    const maxY = Math.max(...panels.map(p => p.gridPos.y + p.gridPos.h));
    
    return {
      rows: Math.max(6, maxY), // Minimum 6 rows
      cols: Math.max(gridColumns, maxX)  // Use responsive columns or panel requirement
    };
  }, [panels, gridColumns]);

  // Create CSS Grid styles with responsive cell height
  const gridContainerStyle = useMemo(() => ({
    display: 'grid',
    gridTemplateColumns: `repeat(${gridDimensions.cols}, 1fr)`,
    gridTemplateRows: `repeat(${gridDimensions.rows}, ${cellHeight}px)`,
    gap: '6px',
    padding: '0px',
    border: showGridContainerBorder ? `1px solid ${debugBorderSettings.gridContainer.color}` : 'none',
    borderRadius: '4px',
    minHeight: '200px',
    position: 'relative' as const,
    // Add transition for smooth responsive changes
    transition: 'grid-template-columns 0.3s ease, grid-template-rows 0.3s ease',
  }), [gridDimensions, cellHeight, showGridContainerBorder, debugBorderSettings.gridContainer.color]);

  // Memoize the visual grid cell components for debugging
  const gridCellComponents = useMemo(() => {
    if (!showGridCellBorders) return null; // Only show grid cells when enabled
    
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
              border: `1px solid ${debugBorderSettings.gridCells.color}`,
              boxSizing: 'border-box',
              opacity: 0.5, // Make grid cells semi-transparent
              // This is crucial to ensure drag events go to the container
              pointerEvents: 'none', 
            }}
          />
        );
      }
    }
    return cells;
  }, [gridDimensions, showGridCellBorders, debugBorderSettings.gridCells.color]);

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
    const cellHeightWithGap = cellHeight + 8; // cellHeight + gap
    
    const gridX = Math.floor(x / cellWidth);
    const gridY = Math.floor(y / cellHeightWithGap);
    
    setDragPosition({ x: Math.max(0, gridX), y: Math.max(0, gridY) });
  }, [draggedPanel, gridDimensions, cellHeight]);

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
         borderRadius: '4px',
         overflow: 'hidden',
         cursor: isEditMode && isEditable ? 'move' : 'default',
         opacity: draggedPanel === panel.id ? 0.5 : 1,
         transition: 'opacity 0.2s ease',
         border: showPanelBorders 
           ? `1px solid ${debugBorderSettings.panels.color}` 
           : '1px solid var(--tiq-border-primary)',
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
            data={panelData?.[panel.id]}
            error={panelErrors?.get(panel.id)}
            loading={isLoading}
            isEditMode={isEditMode}
            showMenu={showMenu}
            onClick={() => onPanelClick?.(panel.id)}
            onDelete={onPanelDelete}
          />
        </div>
      );
    });
  }, [panels, panelData, panelErrors, isLoading, isEditMode, isEditable, showMenu, draggedPanel, showPanelBorders, debugBorderSettings.panels.color, onPanelClick, onPanelDelete, handleDragStart]);

  // Handle responsive breakpoint changes and adjust panels
  useEffect(() => {
    if (!enableResponsive || !onLayoutChange) return;
    
    // Check if columns changed
    if (previousColumns !== gridColumns && previousColumns !== 12) {
      const adjustedPanels = panels.map(panel => 
        adjustPanelForBreakpoint(panel, previousColumns, gridColumns)
      ) as DashboardPanel[];
      
      // Only trigger layout change if panels actually changed
      const hasChanges = adjustedPanels.some((panel, index) => {
        const original = panels[index];
        return panel.gridPos.x !== original.gridPos.x || 
               panel.gridPos.w !== original.gridPos.w;
      });
      
      if (hasChanges) {
        onLayoutChange(adjustedPanels);
      }
    }
    
    setPreviousColumns(gridColumns);
  }, [gridColumns, previousColumns, panels, onLayoutChange, enableResponsive]);

  // Render drag preview
  const dragPreview = useMemo(() => {
    if (!draggedPanel || !dragPosition) return null;
    
    const draggedPanelData = panels.find(p => p.id === draggedPanel);
    if (!draggedPanelData) return null;
    
    const previewStyle = {
      position: 'absolute' as const,
      gridColumn: `${dragPosition.x + 1} / span ${draggedPanelData.gridPos.w}`,
      gridRow: `${dragPosition.y + 1} / span ${draggedPanelData.gridPos.h}`,
      border: '2px dashed var(--tiq-info-main)',
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
        border: '0.5px solid var(--tiq-warning-main)',
        borderRadius: '4px',
        minHeight: '200px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <Box>
          <Typography variant="h6" color="text.primary">
            No panels available
          </Typography>
          {enableResponsive && (
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              Current breakpoint: {breakpoint} ({gridColumns} columns)
            </Typography>
          )}
        </Box>
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
    prevProps.isLoading === nextProps.isLoading &&
    prevProps.isEditMode === nextProps.isEditMode &&
    prevProps.isEditable === nextProps.isEditable &&
    prevProps.showMenu === nextProps.showMenu &&
    prevProps.enableResponsive === nextProps.enableResponsive &&
    // Compare panelData
    JSON.stringify(prevProps.panelData) === JSON.stringify(nextProps.panelData) &&
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



