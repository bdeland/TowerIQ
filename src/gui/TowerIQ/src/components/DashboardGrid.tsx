import { Responsive, WidthProvider, Layout } from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import { Box, Typography } from '@mui/material';
import { useMemo, memo, useCallback, useEffect, useState } from 'react';
import DashboardPanelView from './DashboardPanelView';
import { DashboardPanel } from '../contexts/DashboardContext';
import { layoutCache, panelsToLayout, layoutsEqual } from '../utils/layoutCache';

const ResponsiveGridLayout = WidthProvider(Responsive);

interface DashboardGridProps {
  panels: DashboardPanel[];
  isEditMode: boolean;
  isEditable: boolean; // New prop to control edit capabilities
  showMenu: boolean;
  showFullscreen: boolean;
  dashboardId?: string; // Add dashboard ID for layout caching
  onLayoutChange?: (layout: Layout[]) => void;
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
  dashboardId,
  onLayoutChange,
  onPanelClick,
  onPanelDelete,
  onPanelFullscreenToggle
}: DashboardGridProps) => {
  const [cachedLayout, setCachedLayout] = useState<Layout[]>([]);

  // Load cached layout on mount or when dashboardId changes
  useEffect(() => {
    if (dashboardId) {
      const cached = layoutCache.getLayout(dashboardId, 'lg');
      if (cached) {
        setCachedLayout(cached);
      } else {
        // If no cached layout, use panels data
        const panelLayout = panelsToLayout(panels);
        setCachedLayout(panelLayout);
        // Cache the initial layout
        layoutCache.setLayout(dashboardId, 'lg', panelLayout);
      }
    } else {
      // Fallback to panels data if no dashboardId
      setCachedLayout(panelsToLayout(panels));
    }
  }, [dashboardId, panels]);

  // Memoize the layout to prevent unnecessary recalculations
  const layout = useMemo(() => {
    return { lg: cachedLayout };
  }, [cachedLayout]);

  // Handle layout changes and update cache
  const handleLayoutChange = useCallback((newLayout: Layout[]) => {
    if (dashboardId) {
      // Update cache
      layoutCache.setLayout(dashboardId, 'lg', newLayout);
      setCachedLayout(newLayout);
    }
    
    // Call parent callback
    if (onLayoutChange) {
      onLayoutChange(newLayout);
    }
  }, [dashboardId, onLayoutChange]);

  // Memoize the panel components to prevent unnecessary re-renders
  const panelComponents = useMemo(() => {
    return panels.map((panel) => (
      <div 
        key={panel.id} 
        style={{ 
          height: '100%',
          border: '2px solid #ff9800',
          borderRadius: '4px',
          backgroundColor: 'rgba(255, 152, 0, 0.1)',
          padding: '2px'
        }}
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
    ));
  }, [panels, isEditMode, showMenu, showFullscreen, onPanelClick, onPanelDelete, onPanelFullscreenToggle]);

  if (panels.length === 0) {
    return (
      <Box sx={{ 
        padding: 4, 
        textAlign: 'center', 
        backgroundColor: 'rgba(255, 152, 0, 0.1)',
        border: '2px solid #ff9800',
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
    <ResponsiveGridLayout
      className="layout"
      layouts={layout}
      breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
      cols={{ lg: 12, md: 10, sm: 6, xs: 4, xxs: 2 }}
      rowHeight={100}
      margin={[8, 8]}
      containerPadding={[0, 0]}
      onLayoutChange={handleLayoutChange}
      isDraggable={isEditMode && isEditable}
      isResizable={isEditMode && isEditable}
      // Add stable key to prevent unnecessary re-mounting
      key={`grid-${panels.length}-${isEditMode}`}
      // Prevent layout recalculation on resize
      measureBeforeMount={false}
      // Use transform instead of position for better performance
      useCSSTransforms={true}
      style={{
        backgroundImage: `
          linear-gradient(to right, #e0e0e0 1px, transparent 1px),
          linear-gradient(to bottom, #e0e0e0 1px, transparent 1px)
        `,
        backgroundSize: 'calc(100% / 12) 100px', // 12 columns, 100px row height
        border: '2px solid #2196f3',
        borderRadius: '4px',
        minHeight: '200px'
      }}
    >
      {panelComponents}
    </ResponsiveGridLayout>
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
