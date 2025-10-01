import { useState, useEffect } from 'react';

export interface ResponsiveGridConfig {
  columns: number;
  minPanelWidth: number;
  cellHeight: number;
}

// Define breakpoints and their corresponding grid configurations
const BREAKPOINTS = {
  xs: { width: 0, columns: 4, minPanelWidth: 200, cellHeight: 80 },      // Mobile portrait
  sm: { width: 600, columns: 6, minPanelWidth: 220, cellHeight: 90 },    // Mobile landscape / Small tablet
  md: { width: 900, columns: 8, minPanelWidth: 240, cellHeight: 100 },   // Tablet
  lg: { width: 1200, columns: 12, minPanelWidth: 260, cellHeight: 100 }, // Desktop
  xl: { width: 1536, columns: 16, minPanelWidth: 280, cellHeight: 100 }, // Large desktop
} as const;

type Breakpoint = keyof typeof BREAKPOINTS;

export const useResponsiveGrid = (): ResponsiveGridConfig & { breakpoint: Breakpoint } => {
  const [windowWidth, setWindowWidth] = useState<number>(() => 
    typeof window !== 'undefined' ? window.innerWidth : 1200
  );

  useEffect(() => {
    const handleResize = () => {
      setWindowWidth(window.innerWidth);
    };

    // Throttle resize events for better performance
    let timeoutId: NodeJS.Timeout;
    const throttledResize = () => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(handleResize, 150);
    };

    window.addEventListener('resize', throttledResize);
    return () => {
      window.removeEventListener('resize', throttledResize);
      clearTimeout(timeoutId);
    };
  }, []);

  // Determine current breakpoint
  const currentBreakpoint: Breakpoint = Object.entries(BREAKPOINTS)
    .reverse() // Start from largest breakpoint
    .find(([, config]) => windowWidth >= config.width)?.[0] as Breakpoint || 'xs';

  const config = BREAKPOINTS[currentBreakpoint];

  return {
    columns: config.columns,
    minPanelWidth: config.minPanelWidth,
    cellHeight: config.cellHeight,
    breakpoint: currentBreakpoint,
  };
};

// Utility function to adjust panel positions for different grid sizes
export const adjustPanelForBreakpoint = <T extends { gridPos: { x: number; y: number; w: number; h: number } }>(
  panel: T,
  fromColumns: number,
  toColumns: number
): T => {
  // If moving to a smaller grid, ensure panel fits
  if (toColumns < fromColumns) {
    const maxX = Math.max(0, toColumns - panel.gridPos.w);
    const newX = Math.min(panel.gridPos.x, maxX);
    
    return {
      ...panel,
      gridPos: {
        ...panel.gridPos,
        x: newX,
        w: Math.min(panel.gridPos.w, toColumns), // Ensure width fits
      }
    };
  }
  
  // If moving to a larger grid, proportionally scale position
  if (toColumns > fromColumns) {
    const ratio = toColumns / fromColumns;
    const newX = Math.round(panel.gridPos.x * ratio);
    const newW = Math.min(Math.round(panel.gridPos.w * ratio), toColumns);
    
    return {
      ...panel,
      gridPos: {
        ...panel.gridPos,
        x: Math.min(newX, toColumns - newW),
        w: newW,
      }
    };
  }
  
  return panel;
};
