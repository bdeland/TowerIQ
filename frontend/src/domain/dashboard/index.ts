/**
 * TowerIQ Dashboard Domain Model
 * 
 * Hierarchical class-based architecture for dashboard management.
 * This module provides the main entry point for all dashboard domain classes.
 */

// Core domain classes
export { Dashboard } from './Dashboard';
export { Panel } from './Panel';
export { DashboardVariables } from './DashboardVariables';
export { DashboardManager } from './DashboardManager';

// Type definitions
export * from './types';

// Re-export commonly used types for convenience
export type {
  DashboardConfig,
  PanelConfig,
  VariableDefinition,
  DashboardState,
  PanelState,
  VariableSet,
  LoadResult,
  DashboardMetadata,
  GridPosition,
  VisualizationConfig,
  QueryDefinition
} from './types';
