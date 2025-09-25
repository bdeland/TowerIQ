/**
 * TowerIQ Dashboard Domain Types
 * 
 * Comprehensive type system for the hierarchical dashboard architecture.
 * This file defines all interfaces and types used by the domain model classes.
 */

import { z } from 'zod';
import { EChartsOption } from 'echarts';

// ============================================================================
// Data Source Types
// ============================================================================

export type DataSourceType = 'sqlite' | 'postgresql' | 'prometheus' | 'rest_api';

export interface DataSourceConfig {
  id: string;
  name: string;
  type: DataSourceType;
  config: Record<string, any>;
  credentials?: Record<string, any>;
  isActive: boolean;
}

export interface SQLiteDataSource extends DataSourceConfig {
  type: 'sqlite';
  config: {
    database_path: string;
    connection_timeout?: number;
  };
}

export interface PostgreSQLDataSource extends DataSourceConfig {
  type: 'postgresql';
  config: {
    host: string;
    port: number;
    database: string;
    ssl?: boolean;
  };
  credentials: {
    username: string;
    password: string;
  };
}

export interface PrometheusDataSource extends DataSourceConfig {
  type: 'prometheus';
  config: {
    url: string;
    timeout?: number;
  };
}

export interface RestAPIDataSource extends DataSourceConfig {
  type: 'rest_api';
  config: {
    base_url: string;
    headers?: Record<string, string>;
    timeout?: number;
  };
  credentials?: {
    api_key?: string;
    bearer_token?: string;
  };
}

export type DataSource = SQLiteDataSource | PostgreSQLDataSource | PrometheusDataSource | RestAPIDataSource;

export interface DataSourceRef {
  id: string;
  name: string;
  type: DataSourceType;
}

// ============================================================================
// Panel Types
// ============================================================================

export type PanelType = 'chart' | 'table' | 'stat' | 'gauge';
export type ChartType = 'bar' | 'line' | 'pie' | 'timeseries' | 'calendar' | 'treemap' | 'heatmap' | 'ridgeline';

export interface GridPosition {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface QueryDefinition {
  query: string;
  dataSourceId: string;
  refreshInterval?: number;
  timeout?: number;
}

export interface VisualizationConfig {
  type: PanelType;
  chartType?: ChartType;
  echartsOptions?: Partial<EChartsOption>;
  tableConfig?: TableConfig;
  statConfig?: StatConfig;
  gaugeConfig?: GaugeConfig;
}

export interface TableConfig {
  columns?: string[];
  sortable?: boolean;
  filterable?: boolean;
  pagination?: boolean;
  pageSize?: number;
}

export interface StatConfig {
  valueField: string;
  unit?: string;
  decimals?: number;
  colorMode?: 'value' | 'background';
  thresholds?: Threshold[];
}

export interface GaugeConfig {
  min: number;
  max: number;
  unit?: string;
  thresholds?: Threshold[];
}

export interface Threshold {
  value: number;
  color: string;
  condition: 'gt' | 'gte' | 'lt' | 'lte' | 'eq';
}

export interface PanelConfig {
  id: string;
  type: PanelType;
  title: string;
  description?: string;
  gridPos: GridPosition;
  query: QueryDefinition;
  visualization: VisualizationConfig;
  variables?: string[]; // Variable names this panel depends on
  drilldown?: DrilldownConfig;
}

export interface DrilldownConfig {
  enabled: boolean;
  targetPanelId?: string;
  targetDashboardId?: string;
  parameterMapping?: Record<string, string>;
}

// ============================================================================
// Variable Types
// ============================================================================

export type VariableType = 'static' | 'query' | 'range' | 'custom';

export interface VariableOption {
  value: any;
  label: string;
  description?: string;
}

export interface VariableDefinition {
  name: string;
  type: VariableType;
  label: string;
  description?: string;
  required: boolean;
  defaultValue: any;
  options?: VariableOption[];
  queryOptions?: QueryVariableOptions;
  rangeOptions?: RangeVariableOptions;
  validation?: z.ZodSchema;
}

export interface QueryVariableOptions {
  query: string;
  dataSourceId: string;
  valueField: string;
  labelField?: string;
  refreshOnDashboardLoad: boolean;
  refreshInterval?: number;
}

export interface RangeVariableOptions {
  min: number;
  max: number;
  step: number;
  unit?: string;
}

export interface VariableConfig {
  definitions: VariableDefinition[];
  defaultValues: Record<string, any>;
}

export type VariableSet = Record<string, any>;
export type VariableValues = VariableSet;

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

// ============================================================================
// Dashboard Types
// ============================================================================

export interface DashboardMetadata {
  id: string;
  uid: string;
  title: string;
  description?: string;
  tags: string[];
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  isSystem: boolean;
  version: number;
}

export interface DashboardConfig {
  id: string;
  metadata: DashboardMetadata;
  panels: PanelConfig[];
  variables: VariableConfig;
  dataSources: DataSourceRef[];
  settings: DashboardSettings;
}

export interface DashboardSettings {
  refresh?: string;
  timeRange?: TimeRange;
  timezone?: string;
  theme?: string;
  editable: boolean;
}

export interface TimeRange {
  from: string;
  to: string;
}

// ============================================================================
// State Types
// ============================================================================

export type PanelStatus = 'idle' | 'loading' | 'loaded' | 'error';
export type DashboardStatus = 'idle' | 'loading' | 'loaded' | 'error';

export interface PanelData {
  data: any[];
  columns: string[];
  rowCount: number;
  executionTime: number;
  cacheHit: boolean;
  timestamp: number;
}

export interface PanelState {
  status: PanelStatus;
  data: PanelData | null;
  error: Error | null;
  loading: boolean;
  lastUpdated: number;
}

export interface DashboardState {
  status: DashboardStatus;
  loading: boolean;
  error: Error | null;
  variableValues: Map<string, any>;
  panelStates: Map<string, PanelState>;
  lastUpdated: number;
}

// ============================================================================
// Event Types
// ============================================================================

export interface DashboardEvent {
  type: string;
  timestamp: number;
  dashboardId: string;
  data: any;
}

export interface VariableUpdatedEvent extends DashboardEvent {
  type: 'variableUpdated';
  data: {
    name: string;
    value: any;
    oldValue: any;
  };
}

export interface PanelStateChangedEvent extends DashboardEvent {
  type: 'panelStateChanged';
  data: {
    panelId: string;
    state: PanelState;
  };
}

export interface DashboardLoadedEvent extends DashboardEvent {
  type: 'dashboardLoaded';
  data: {
    panelCount: number;
    loadTime: number;
  };
}

export interface DashboardErrorEvent extends DashboardEvent {
  type: 'dashboardError';
  data: {
    error: Error;
    context: string;
  };
}

export type DashboardEventType = 
  | VariableUpdatedEvent
  | PanelStateChangedEvent 
  | DashboardLoadedEvent
  | DashboardErrorEvent;

// ============================================================================
// Service Types
// ============================================================================

export interface QueryRequest {
  query: string;
  dataSourceId: string;
  variables?: VariableSet;
  timeout?: number;
}

export interface QueryResponse {
  data: any[];
  columns: string[];
  rowCount: number;
  executionTime: number;
  error?: string;
}

export interface LoadResult {
  panelId: string;
  success: boolean;
  data?: PanelData;
  error?: Error;
  executionTime: number;
}

export interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
  key: string;
}

export interface CacheConfig {
  defaultTTL: number;
  maxSize: number;
  cleanupInterval: number;
}

// ============================================================================
// Configuration Types
// ============================================================================

export interface DashboardManagerConfig {
  cacheConfig: CacheConfig;
  defaultDataSourceId: string;
  maxConcurrentRequests: number;
  requestTimeout: number;
  retryAttempts: number;
  retryDelay: number;
}

export interface DashboardDataServiceConfig {
  batchSize: number;
  delayBetweenRequests: number;
  delayBetweenBatches: number;
  cacheTTL: number;
  maxRetries: number;
  retryDelay: number;
}

// ============================================================================
// Error Types
// ============================================================================

export class DashboardError extends Error {
  constructor(
    message: string,
    public code: string,
    public dashboardId?: string,
    public panelId?: string,
    public context?: any
  ) {
    super(message);
    this.name = 'DashboardError';
  }
}

export class PanelError extends Error {
  constructor(
    message: string,
    public code: string,
    public panelId: string,
    public query?: string,
    public context?: any
  ) {
    super(message);
    this.name = 'PanelError';
  }
}

export class VariableError extends Error {
  constructor(
    message: string,
    public code: string,
    public variableName: string,
    public value?: any,
    public context?: any
  ) {
    super(message);
    this.name = 'VariableError';
  }
}

export class DataSourceError extends Error {
  constructor(
    message: string,
    public code: string,
    public dataSourceId: string,
    public query?: string,
    public context?: any
  ) {
    super(message);
    this.name = 'DataSourceError';
  }
}

// ============================================================================
// Utility Types
// ============================================================================

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>;

export type OptionalFields<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

// ============================================================================
// Type Guards
// ============================================================================

export function isDashboardConfig(obj: any): obj is DashboardConfig {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.id === 'string' &&
    typeof obj.metadata === 'object' &&
    Array.isArray(obj.panels) &&
    typeof obj.variables === 'object'
  );
}

export function isPanelConfig(obj: any): obj is PanelConfig {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.id === 'string' &&
    typeof obj.title === 'string' &&
    typeof obj.type === 'string' &&
    typeof obj.gridPos === 'object' &&
    typeof obj.query === 'object'
  );
}

export function isVariableDefinition(obj: any): obj is VariableDefinition {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.name === 'string' &&
    typeof obj.type === 'string' &&
    typeof obj.label === 'string' &&
    typeof obj.required === 'boolean'
  );
}

export function isDataSource(obj: any): obj is DataSource {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.id === 'string' &&
    typeof obj.name === 'string' &&
    typeof obj.type === 'string' &&
    ['sqlite', 'postgresql', 'prometheus', 'rest_api'].includes(obj.type)
  );
}

// ============================================================================
// Default Values
// ============================================================================

export const DEFAULT_GRID_POSITION: GridPosition = {
  x: 0,
  y: 0,
  w: 6,
  h: 3
};

export const DEFAULT_DASHBOARD_SETTINGS: DashboardSettings = {
  refresh: 'off',
  editable: true,
  theme: 'dark'
};

export const DEFAULT_CACHE_CONFIG: CacheConfig = {
  defaultTTL: 300000, // 5 minutes
  maxSize: 1000,
  cleanupInterval: 60000 // 1 minute
};

export const DEFAULT_DATA_SERVICE_CONFIG: DashboardDataServiceConfig = {
  batchSize: 1,
  delayBetweenRequests: 100,
  delayBetweenBatches: 300,
  cacheTTL: 300000,
  maxRetries: 1,
  retryDelay: 1000
};

export const DEFAULT_MANAGER_CONFIG: DashboardManagerConfig = {
  cacheConfig: DEFAULT_CACHE_CONFIG,
  defaultDataSourceId: 'default-sqlite',
  maxConcurrentRequests: 10,
  requestTimeout: 30000,
  retryAttempts: 3,
  retryDelay: 1000
};
