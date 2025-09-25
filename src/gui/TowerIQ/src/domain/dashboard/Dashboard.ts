/**
 * Dashboard Class
 * 
 * Encapsulates all dashboard state and operations including panels, variables,
 * data loading, and event emission. Central class in the hierarchical architecture.
 */

import { EventEmitter } from 'events';
import { 
  DashboardConfig,
  DashboardMetadata,
  DashboardState,
  DashboardStatus,
  PanelConfig,
  PanelState,
  LoadResult,
  VariableSet,
  DashboardSettings,
  DashboardEventType,
  VariableUpdatedEvent,
  PanelStateChangedEvent,
  DashboardLoadedEvent,
  DashboardErrorEvent,
  DashboardError
} from './types';
import { Panel } from './Panel';
import { DashboardVariables } from './DashboardVariables';

export class Dashboard extends EventEmitter {
  private _metadata: DashboardMetadata;
  private _panels: Map<string, Panel>;
  private _variables: DashboardVariables;
  private settings: DashboardSettings;
  private state: DashboardState;
  private cache: Map<string, any>;
  
  constructor(config: DashboardConfig) {
    super();
    
    this._metadata = { ...config.metadata };
    this._panels = new Map();
    this._variables = new DashboardVariables(config.variables.definitions);
    this.settings = { ...config.settings };
    this.cache = new Map();
    
    this.state = {
      status: 'idle',
      loading: false,
      error: null,
      variableValues: new Map(),
      panelStates: new Map(),
      lastUpdated: 0
    };
    
    // Initialize panels
    config.panels.forEach(panelConfig => {
      this.addPanel(new Panel(panelConfig));
    });
    
    // Initialize variable values
    this._variables.getVariableNames().forEach(name => {
      const value = this._variables.getValue(name);
      this.state.variableValues.set(name, value);
    });
  }
  
  // ========================================================================
  // Basic Properties
  // ========================================================================
  
  get id(): string {
    return this._metadata.id;
  }
  
  get metadata(): DashboardMetadata {
    return { ...this._metadata };
  }
  
  get panels(): Map<string, Panel> {
    return new Map(this._panels);
  }
  
  get variables(): DashboardVariables {
    return this._variables;
  }
  
  get uid(): string {
    return this._metadata.uid;
  }
  
  get title(): string {
    return this._metadata.title;
  }
  
  get description(): string | undefined {
    return this._metadata.description;
  }
  
  get tags(): string[] {
    return [...this._metadata.tags];
  }
  
  get isSystem(): boolean {
    return this._metadata.isSystem;
  }
  
  get version(): number {
    return this._metadata.version;
  }
  
  get createdAt(): Date {
    return this._metadata.createdAt;
  }
  
  get updatedAt(): Date {
    return this._metadata.updatedAt;
  }
  
  get panelCount(): number {
    return this._panels.size;
  }
  
  get variableCount(): number {
    return this._variables.getVariableCount();
  }
  
  // ========================================================================
  // State Management
  // ========================================================================
  
  getState(): DashboardState {
    return {
      status: this.state.status,
      loading: this.state.loading,
      error: this.state.error,
      variableValues: new Map(this.state.variableValues),
      panelStates: new Map(this.state.panelStates),
      lastUpdated: this.state.lastUpdated
    };
  }
  
  getStatus(): DashboardStatus {
    return this.state.status;
  }
  
  isLoading(): boolean {
    return this.state.loading;
  }
  
  hasError(): boolean {
    return this.state.error !== null;
  }
  
  getError(): Error | null {
    return this.state.error;
  }
  
  private setState(updates: Partial<DashboardState>): void {
    this.state = {
      ...this.state,
      ...updates,
      lastUpdated: Date.now()
    };
  }
  
  // ========================================================================
  // Panel Management
  // ========================================================================
  
  addPanel(panel: Panel): void {
    this._panels.set(panel.id, panel);
    this.state.panelStates.set(panel.id, panel.getState());
    
    // Subscribe to panel state changes
    this.subscribeToPanel(panel);
  }
  
  removePanel(panelId: string): boolean {
    const panel = this._panels.get(panelId);
    if (!panel) return false;
    
    this._panels.delete(panelId);
    this.state.panelStates.delete(panelId);
    
    return true;
  }
  
  getPanel(panelId: string): Panel | undefined {
    return this._panels.get(panelId);
  }
  
  getAllPanels(): Panel[] {
    return Array.from(this._panels.values());
  }
  
  getPanelIds(): string[] {
    return Array.from(this._panels.keys());
  }
  
  hasPanel(panelId: string): boolean {
    return this._panels.has(panelId);
  }
  
  getPanelState(panelId: string): PanelState | undefined {
    return this.state.panelStates.get(panelId);
  }
  
  private subscribeToPanel(panel: Panel): void {
    // In a real implementation, we would listen to panel events
    // For now, we'll manually sync panel state when needed
  }
  
  private syncPanelState(panelId: string): void {
    const panel = this._panels.get(panelId);
    if (panel) {
      const panelState = panel.getState();
      this.state.panelStates.set(panelId, panelState);
      
      // Emit panel state changed event
      this.emitPanelStateChanged(panelId, panelState);
    }
  }
  
  // ========================================================================
  // Variable Management
  // ========================================================================
  
  getVariables(): DashboardVariables {
    return this._variables;
  }
  
  async updateVariable(name: string, value: any): Promise<void> {
    const oldValue = this.state.variableValues.get(name);
    
    try {
      // Validate and update variable
      const result = this._variables.updateValue(name, value);
      
      if (result.isValid) {
        this.state.variableValues.set(name, value);
        
        // Emit variable updated event
        this.emitVariableUpdated(name, value, oldValue);
        
        // Refresh affected panels
        const affectedPanels = this.getAffectedPanels(name);
        if (affectedPanels.length > 0) {
          await this.refreshPanels(affectedPanels.map(p => p.id));
        }
      } else {
        // Emit variable error event
        this.emitDashboardError(
          new DashboardError(
            `Variable validation failed: ${result.errors.join(', ')}`,
            'VARIABLE_VALIDATION_FAILED',
            this.id,
            undefined,
            { variableName: name, value, errors: result.errors }
          ),
          `Variable validation for ${name}`
        );
      }
    } catch (error: unknown) {
      const err = error instanceof Error ? error : new Error(String(error));
      this.emitDashboardError(
        new DashboardError(
          `Failed to update variable ${name}: ${err.message}`,
          'VARIABLE_UPDATE_FAILED',
          this.id,
          undefined,
          { variableName: name, value, originalError: err }
        ),
        `Variable update for ${name}`
      );
    }
  }
  
  getVariableValue(name: string): any {
    return this.state.variableValues.get(name);
  }
  
  getVariableValues(): VariableSet {
    const values: VariableSet = {};
    for (const [name, value] of this.state.variableValues) {
      values[name] = value;
    }
    return values;
  }
  
  resetVariablesToDefaults(): void {
    this._variables.resetToDefaults();
    
    // Sync state
    this._variables.getVariableNames().forEach(name => {
      const value = this._variables.getValue(name);
      this.state.variableValues.set(name, value);
    });
  }
  
  
  // ========================================================================
  // Data Loading
  // ========================================================================
  
  async loadData(): Promise<LoadResult[]> {
    this.setState({
      status: 'loading',
      loading: true,
      error: null
    });
    
    const startTime = Date.now();
    const results: LoadResult[] = [];
    
    try {
      // Load variable options first
      await this.loadVariableOptions();
      
      // Load all panels in parallel
      const panelPromises = Array.from(this._panels.values()).map(async (panel) => {
        const panelStartTime = Date.now();
        
        try {
          const data = await panel.fetchData(this.getVariableValues());
          this.syncPanelState(panel.id);
          
          return {
            panelId: panel.id,
            success: true,
            data,
            executionTime: Date.now() - panelStartTime
          };
        } catch (error: unknown) {
          this.syncPanelState(panel.id);
          
          const err = error instanceof Error ? error : new Error(String(error));

          return {
            panelId: panel.id,
            success: false,
            error: err,
            executionTime: Date.now() - panelStartTime
          };
        }
      });
      
      const panelResults = await Promise.allSettled(panelPromises);
      
      // Process results
      panelResults.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
          const panel = Array.from(this._panels.values())[index];
          const reason = result.reason;
          const err = reason instanceof Error ? reason : new Error(String(reason));
          results.push({
            panelId: panel.id,
            success: false,
            error: err,
            executionTime: 0
          });
        }
      });
      
      // Update state
      const hasErrors = results.some(r => !r.success);
      this.setState({
        status: hasErrors ? 'error' : 'loaded',
        loading: false,
        error: hasErrors ? new Error('Some panels failed to load') : null
      });
      
      // Emit dashboard loaded event
      this.emitDashboardLoaded(results.length, Date.now() - startTime);
      
      return results;
      
    } catch (error: unknown) {
      const err = error instanceof Error ? error : new Error(String(error));
      const dashboardError = new DashboardError(
        `Failed to load dashboard data: ${err.message}`,
        'DASHBOARD_LOAD_FAILED',
        this.id,
        undefined,
        { originalError: err }
      );
      
      this.setState({
        status: 'error',
        loading: false,
        error: dashboardError
      });
      
      this.emitDashboardError(dashboardError, 'Dashboard data loading');
      
      throw dashboardError;
    }
  }
  
  async refreshData(): Promise<LoadResult[]> {
    // Clear cache before refreshing
    this.clearCache();
    return this.loadData();
  }
  
  async refreshPanel(panelId: string): Promise<void> {
    const panel = this._panels.get(panelId);
    if (!panel) {
      throw new DashboardError(
        `Panel not found: ${panelId}`,
        'PANEL_NOT_FOUND',
        this.id,
        panelId
      );
    }
    
    try {
      await panel.fetchData(this.getVariableValues());
      this.syncPanelState(panelId);
    } catch (error: unknown) {
      this.syncPanelState(panelId);
      throw error;
    }
  }
  
  async refreshPanels(panelIds: string[]): Promise<void> {
    const refreshPromises = panelIds.map(id => this.refreshPanel(id));
    await Promise.allSettled(refreshPromises);
  }
  
  private async loadVariableOptions(): Promise<void> {
    const queryVariables = this._variables.getAllDefinitions()
      .filter(def => def.type === 'query');
    
    for (const variable of queryVariables) {
      try {
        await this._variables.loadDynamicOptions(variable.name);
      } catch (error: unknown) {
        console.warn(`Failed to load options for variable ${variable.name}:`, error);
      }
    }
  }
  
  // ========================================================================
  // React Integration - Subscription Methods
  // ========================================================================
  
  /**
   * Subscribe to dashboard state changes (React-friendly)
   * Returns an unsubscribe function
   */
  subscribe(callback: (state: DashboardState) => void): () => void {
    const handler = () => {
      callback(this.getState());
    };
    
    // Listen to all state-changing events
    this.on('variableUpdated', handler);
    this.on('panelStateChanged', handler);
    this.on('dashboardLoaded', handler);
    this.on('dashboardError', handler);
    
    // Return unsubscribe function
    return () => {
      this.off('variableUpdated', handler);
      this.off('panelStateChanged', handler);
      this.off('dashboardLoaded', handler);
      this.off('dashboardError', handler);
    };
  }
  
  /**
   * Subscribe to specific variable changes
   */
  subscribeToVariable(variableName: string, callback: (value: any, oldValue: any) => void): () => void {
    const handler = (event: VariableUpdatedEvent) => {
      if (event.data.name === variableName) {
        callback(event.data.value, event.data.oldValue);
      }
    };
    
    this.on('variableUpdated', handler);
    
    return () => {
      this.off('variableUpdated', handler);
    };
  }
  
  /**
   * Subscribe to specific panel state changes
   */
  subscribeToPanelState(panelId: string, callback: (state: PanelState) => void): () => void {
    const handler = (event: PanelStateChangedEvent) => {
      if (event.data.panelId === panelId) {
        callback(event.data.state);
      }
    };
    
    this.on('panelStateChanged', handler);
    
    return () => {
      this.off('panelStateChanged', handler);
    };
  }
  
  /**
   * Get affected panels for a variable (public method for React integration)
   */
  getAffectedPanels(variableName: string): Panel[] {
    return Array.from(this._panels.values()).filter(panel => 
      panel.variables.includes(variableName)
    );
  }
  
  // ========================================================================
  // Event Emission
  // ========================================================================
  
  private emitVariableUpdated(name: string, value: any, oldValue: any): void {
    const event: VariableUpdatedEvent = {
      type: 'variableUpdated',
      timestamp: Date.now(),
      dashboardId: this.id,
      data: { name, value, oldValue }
    };
    
    this.emit('variableUpdated', event);
    this.emit('dashboardEvent', event);
  }
  
  private emitPanelStateChanged(panelId: string, state: PanelState): void {
    const event: PanelStateChangedEvent = {
      type: 'panelStateChanged',
      timestamp: Date.now(),
      dashboardId: this.id,
      data: { panelId, state }
    };
    
    this.emit('panelStateChanged', event);
    this.emit('dashboardEvent', event);
  }
  
  private emitDashboardLoaded(panelCount: number, loadTime: number): void {
    const event: DashboardLoadedEvent = {
      type: 'dashboardLoaded',
      timestamp: Date.now(),
      dashboardId: this.id,
      data: { panelCount, loadTime }
    };
    
    this.emit('dashboardLoaded', event);
    this.emit('dashboardEvent', event);
  }
  
  private emitDashboardError(error: Error, context: string): void {
    const event: DashboardErrorEvent = {
      type: 'dashboardError',
      timestamp: Date.now(),
      dashboardId: this.id,
      data: { error, context }
    };
    
    this.emit('dashboardError', event);
    this.emit('dashboardEvent', event);
  }
  
  // ========================================================================
  // Configuration Updates
  // ========================================================================
  
  updateMetadata(updates: Partial<DashboardMetadata>): void {
    this._metadata = {
      ...this._metadata,
      ...updates,
      updatedAt: new Date()
    };
  }
  
  updateSettings(updates: Partial<DashboardSettings>): void {
    this.settings = {
      ...this.settings,
      ...updates
    };
  }
  
  getSettings(): DashboardSettings {
    return { ...this.settings };
  }
  
  // ========================================================================
  // Cache Management
  // ========================================================================
  
  clearCache(): void {
    this.cache.clear();
    
    // Clear panel caches
    for (const panel of this._panels.values()) {
      panel.clearCache();
    }
    
    // Clear variable options cache
    this._variables.clearOptionsCache();
  }
  
  getCacheSize(): number {
    let totalSize = this.cache.size;
    
    for (const panel of this._panels.values()) {
      totalSize += panel.getCacheSize();
    }
    
    return totalSize;
  }
  
  // ========================================================================
  // Serialization
  // ========================================================================
  
  serialize(): DashboardConfig {
    const panelConfigs: PanelConfig[] = Array.from(this._panels.values())
      .map(panel => panel.getConfig());
    
    return {
      id: this.id,
      metadata: { ...this._metadata },
      panels: panelConfigs,
      variables: {
        definitions: this._variables.getAllDefinitions(),
        defaultValues: this.getVariableValues()
      },
      dataSources: [], // Would be populated from actual data sources
      settings: { ...this.settings }
    };
  }
  
  static deserialize(config: DashboardConfig): Dashboard {
    return new Dashboard(config);
  }
  
  // ========================================================================
  // Utility Methods
  // ========================================================================
  
  clone(): Dashboard {
    const config = this.serialize();
    return Dashboard.deserialize(config);
  }
  
  isEmpty(): boolean {
    return this._panels.size === 0;
  }
  
  isDataStale(maxAge: number = 300000): boolean {
    return (Date.now() - this.state.lastUpdated) > maxAge;
  }
  
  hasVariables(): boolean {
    return this._variables.getVariableCount() > 0;
  }
  
  getLoadingPanels(): string[] {
    const loadingPanels: string[] = [];
    
    for (const [panelId, panelState] of this.state.panelStates) {
      if (panelState.loading) {
        loadingPanels.push(panelId);
      }
    }
    
    return loadingPanels;
  }
  
  getErrorPanels(): string[] {
    const errorPanels: string[] = [];
    
    for (const [panelId, panelState] of this.state.panelStates) {
      if (panelState.error) {
        errorPanels.push(panelId);
      }
    }
    
    return errorPanels;
  }
  
  getLoadedPanels(): string[] {
    const loadedPanels: string[] = [];
    
    for (const [panelId, panelState] of this.state.panelStates) {
      if (panelState.status === 'loaded' && panelState.data) {
        loadedPanels.push(panelId);
      }
    }
    
    return loadedPanels;
  }
  
  // ========================================================================
  // Static Factory Methods
  // ========================================================================
  
  /**
   * Create a new empty dashboard
   */
  static createEmpty(id: string, title: string): Dashboard {
    const config: DashboardConfig = {
      id,
      metadata: {
        id,
        uid: `${id}-uid`,
        title,
        tags: [],
        createdAt: new Date(),
        updatedAt: new Date(),
        isSystem: false,
        version: 1
      },
      panels: [],
      variables: {
        definitions: [],
        defaultValues: {}
      },
      dataSources: [],
      settings: {
        refresh: 'off',
        editable: true
      }
    };
    
    return new Dashboard(config);
  }
  
  /**
   * Create dashboard from legacy configuration
   */
  static fromLegacyConfig(legacyConfig: any): Dashboard {
    // This would transform old dashboard format to new DashboardConfig
    // Implementation would depend on specific legacy format
    throw new Error('Legacy configuration conversion not implemented');
  }
}
