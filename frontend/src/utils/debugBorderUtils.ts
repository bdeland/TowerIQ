/**
 * Utility functions for managing debug border colors dynamically
 */

export interface DebugBorderColors {
  gridContainer: string;
  panels: string;
  gridCells: string;
}

/**
 * Updates CSS custom properties for debug border colors
 * This allows for dynamic color changes without component re-renders
 */
export function updateDebugBorderColors(colors: Partial<DebugBorderColors>) {
  const root = document.documentElement;
  
  if (colors.gridContainer) {
    root.style.setProperty('--tiq-debug-grid-container', colors.gridContainer);
  }
  
  if (colors.panels) {
    root.style.setProperty('--tiq-debug-panels', colors.panels);
  }
  
  if (colors.gridCells) {
    root.style.setProperty('--tiq-debug-grid-cells', colors.gridCells);
  }
}

/**
 * Resets debug border colors to their default values
 */
export function resetDebugBorderColors() {
  const root = document.documentElement;
  root.style.setProperty('--tiq-debug-grid-container', '#003f5c');
  root.style.setProperty('--tiq-debug-panels', '#f95d6a');
  root.style.setProperty('--tiq-debug-grid-cells', '#ffa600');
}

/**
 * Gets current debug border color from CSS custom properties
 */
export function getDebugBorderColor(borderType: keyof DebugBorderColors): string {
  const root = document.documentElement;
  const propertyMap = {
    gridContainer: '--tiq-debug-grid-container',
    panels: '--tiq-debug-panels',
    gridCells: '--tiq-debug-grid-cells',
  };
  
  return getComputedStyle(root).getPropertyValue(propertyMap[borderType]).trim() || '#000000';
}
