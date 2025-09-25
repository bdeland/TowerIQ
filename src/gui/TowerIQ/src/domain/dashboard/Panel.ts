/**
 * Panel Class
 * 
 * Encapsulates panel logic including data fetching, visualization configuration,
 * and error handling. Separates data/business logic from React components.
 */

import { EChartsOption } from 'echarts';
import { 
  PanelConfig,
  PanelData,
  PanelState,
  PanelStatus,
  VariableSet,
  QueryRequest,
  QueryResponse,
  GridPosition,
  VisualizationConfig,
  QueryDefinition,
  DrilldownConfig,
  PanelError
} from './types';
import { DashboardVariables } from './DashboardVariables';
import { API_CONFIG } from '../../config/environment';

export class Panel {
  private config: PanelConfig;
  private state: PanelState;
  private dataCache: Map<string, { data: PanelData; timestamp: number }>;
  
  private readonly CACHE_TTL = 300000; // 5 minutes
  
  constructor(config: PanelConfig) {
    this.config = { ...config };
    this.state = {
      status: 'idle',
      data: null,
      error: null,
      loading: false,
      lastUpdated: 0
    };
    this.dataCache = new Map();
  }
  
  // ========================================================================
  // Basic Properties
  // ========================================================================
  
  get id(): string {
    return this.config.id;
  }
  
  get title(): string {
    return this.config.title;
  }
  
  get layout(): GridPosition {
    return this.config.gridPos;
  }
  
  get type(): string {
    return this.config.type;
  }
  
  get description(): string | undefined {
    return this.config.description;
  }
  
  get gridPos(): GridPosition {
    return this.config.gridPos;
  }
  
  get query(): QueryDefinition {
    return this.config.query;
  }
  
  get visualization(): VisualizationConfig {
    return this.config.visualization;
  }
  
  get drilldown(): DrilldownConfig | undefined {
    return this.config.drilldown;
  }
  
  get variables(): string[] {
    return this.config.variables || [];
  }
  
  // ========================================================================
  // State Management
  // ========================================================================
  
  getState(): PanelState {
    return { ...this.state };
  }
  
  getStatus(): PanelStatus {
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
  
  getData(): PanelData | null {
    return this.state.data;
  }
  
  private setState(updates: Partial<PanelState>): void {
    this.state = {
      ...this.state,
      ...updates,
      lastUpdated: Date.now()
    };
  }
  
  // ========================================================================
  // Data Fetching
  // ========================================================================
  
  async fetchData(variables: VariableSet): Promise<PanelData> {
    // Check cache first
    const cacheKey = this.generateCacheKey(variables);
    const cached = this.dataCache.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
      this.setState({
        status: 'loaded',
        data: cached.data,
        error: null,
        loading: false
      });
      return cached.data;
    }
    
    this.setState({
      status: 'loading',
      loading: true,
      error: null
    });
    
    try {
      const startTime = Date.now();
      
      // Compose query with variables
      const composedQuery = this.composeQuery(this.config.query.query, variables);
      
      // Execute query
      const queryRequest: QueryRequest = {
        query: composedQuery,
        dataSourceId: this.config.query.dataSourceId,
        variables,
        timeout: this.config.query.timeout
      };
      
      const response = await this.executeQuery(queryRequest);
      
      // Transform response to PanelData
      const panelData: PanelData = {
        data: response.data,
        columns: response.columns,
        rowCount: response.rowCount,
        executionTime: response.executionTime,
        cacheHit: false,
        timestamp: Date.now()
      };
      
      // Cache the result
      this.dataCache.set(cacheKey, {
        data: panelData,
        timestamp: Date.now()
      });
      
      // Update state
      this.setState({
        status: 'loaded',
        data: panelData,
        error: null,
        loading: false
      });
      
      return panelData;
      
    } catch (error: unknown) {
      const originalError = error instanceof Error ? error : new Error(String(error));
      const panelError = new PanelError(
        `Failed to fetch data for panel ${this.config.title}: ${originalError.message}`,
        'DATA_FETCH_FAILED',
        this.config.id,
        this.config.query.query,
        { originalError, variables }
      );
      
      this.setState({
        status: 'error',
        error: panelError,
        loading: false
      });
      
      throw panelError;
    }
  }
  
  private async executeQuery(request: QueryRequest): Promise<QueryResponse> {
    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}/v2/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(request)
      });
      
      if (!response.ok) {
        throw new Error(`Query failed: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      
      return {
        data: data,
        columns: data.length > 0 ? Object.keys(data[0]) : [],
        rowCount: data.length,
        executionTime: 0, // Would be provided by backend
        error: undefined
      };
      
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Query execution failed: ${message}`);
    }
  }
  
  private composeQuery(rawQuery: string, variables: VariableSet): string {
    // Use DashboardVariables for composition if available
    // For now, implement basic substitution
    let composedQuery = rawQuery;
    
    // Handle tier_filter pattern
    if (composedQuery.includes('${tier_filter}')) {
      const tierValue = variables.tier;
      let tierClause = '';
      
      if (Array.isArray(tierValue) && tierValue.length > 0 && !tierValue.includes('all')) {
        const safeTiers = tierValue
          .map(t => typeof t === 'number' ? t : `'${String(t)}'`)
          .join(',');
        tierClause = composedQuery.toLowerCase().includes('where') 
          ? `AND tier IN (${safeTiers})`
          : `WHERE tier IN (${safeTiers})`;
      }
      
      composedQuery = composedQuery.replace('${tier_filter}', tierClause);
    }
    
    // Handle limit_clause pattern
    if (composedQuery.includes('${limit_clause}')) {
      const limitValue = variables.num_runs;
      let limitClause = '';
      
      if (limitValue && limitValue !== 'all') {
        const limit = parseInt(String(limitValue), 10);
        if (!isNaN(limit) && limit > 0) {
          limitClause = `LIMIT ${limit}`;
        }
      }
      
      composedQuery = composedQuery.replace('${limit_clause}', limitClause);
    }
    
    return composedQuery.replace(/\s+/g, ' ').trim();
  }
  
  private generateCacheKey(variables: VariableSet): string {
    const variablesString = JSON.stringify(variables, Object.keys(variables).sort());
    return `${this.config.id}:${this.config.query.query}:${variablesString}`;
  }
  
  // ========================================================================
  // Visualization
  // ========================================================================
  
  getEChartsOptions(): EChartsOption | null {
    if (!this.state.data || this.state.data.data.length === 0) {
      return null;
    }
    
    const baseOptions = this.config.visualization.echartsOptions || {};
    const data = this.state.data.data;
    
    // Apply data transformation based on panel type
    switch (this.config.visualization.type) {
      case 'chart':
        return this.getChartOptions(baseOptions, data);
      default:
        return baseOptions as EChartsOption;
    }
  }
  
  private getChartOptions(baseOptions: any, data: any[]): EChartsOption {
    // Determine chart type from visualization config
    const chartType = this.config.visualization.chartType || 'bar';
    
    switch (chartType) {
      case 'bar':
        return this.getBarChartOptions(baseOptions, data);
      case 'line':
        return this.getLineChartOptions(baseOptions, data);
      case 'pie':
        return this.getPieChartOptions(baseOptions, data);
      case 'timeseries':
        return this.getTimeseriesOptions(baseOptions, data);
      case 'calendar':
        return this.getCalendarOptions(baseOptions, data);
      case 'treemap':
        return this.getTreemapOptions(baseOptions, data);
      default:
        return baseOptions as EChartsOption;
    }
  }
  
  private getBarChartOptions(baseOptions: any, data: any[]): EChartsOption {
    // Auto-detect x and y axes
    const columns = this.state.data?.columns || [];
    const xColumn = this.detectXColumn(columns, data);
    const yColumn = this.detectYColumn(columns, data);
    
    if (!xColumn || !yColumn) {
      return baseOptions as EChartsOption;
    }
    
    return {
      ...baseOptions,
      xAxis: {
        type: 'category',
        data: data.map(row => row[xColumn]),
        ...baseOptions.xAxis
      },
      yAxis: {
        type: 'value',
        ...baseOptions.yAxis
      },
      series: [{
        type: 'bar',
        data: data.map(row => row[yColumn]),
        ...baseOptions.series?.[0]
      }]
    };
  }
  
  private getLineChartOptions(baseOptions: any, data: any[]): EChartsOption {
    const columns = this.state.data?.columns || [];
    const xColumn = this.detectXColumn(columns, data);
    const yColumn = this.detectYColumn(columns, data);
    
    if (!xColumn || !yColumn) {
      return baseOptions as EChartsOption;
    }
    
    return {
      ...baseOptions,
      xAxis: {
        type: 'category',
        data: data.map(row => row[xColumn]),
        ...baseOptions.xAxis
      },
      yAxis: {
        type: 'value',
        ...baseOptions.yAxis
      },
      series: [{
        type: 'line',
        data: data.map(row => row[yColumn]),
        ...baseOptions.series?.[0]
      }]
    };
  }
  
  private getPieChartOptions(baseOptions: any, data: any[]): EChartsOption {
    const columns = this.state.data?.columns || [];
    const nameColumn = columns.find(col => 
      col.toLowerCase().includes('name') || 
      col.toLowerCase().includes('label') ||
      col.toLowerCase().includes('category')
    ) || columns[0];
    
    const valueColumn = columns.find(col => 
      col.toLowerCase().includes('value') || 
      col.toLowerCase().includes('count') ||
      col.toLowerCase().includes('amount')
    ) || columns[1];
    
    if (!nameColumn || !valueColumn) {
      return baseOptions as EChartsOption;
    }
    
    return {
      ...baseOptions,
      series: [{
        type: 'pie',
        data: data.map(row => ({
          name: row[nameColumn],
          value: row[valueColumn]
        })),
        ...baseOptions.series?.[0]
      }]
    };
  }
  
  private getTimeseriesOptions(baseOptions: any, data: any[]): EChartsOption {
    const columns = this.state.data?.columns || [];
    const timeColumn = this.detectTimeColumn(columns);
    const valueColumn = this.detectYColumn(columns, data);
    
    if (!timeColumn || !valueColumn) {
      return baseOptions as EChartsOption;
    }
    
    return {
      ...baseOptions,
      xAxis: {
        type: 'time',
        data: data.map(row => new Date(row[timeColumn])),
        ...baseOptions.xAxis
      },
      yAxis: {
        type: 'value',
        ...baseOptions.yAxis
      },
      series: [{
        type: 'line',
        data: data.map(row => [new Date(row[timeColumn]), row[valueColumn]]),
        ...baseOptions.series?.[0]
      }]
    };
  }
  
  private getCalendarOptions(baseOptions: any, data: any[]): EChartsOption {
    const columns = this.state.data?.columns || [];
    const dateColumn = this.detectTimeColumn(columns) || 'date';
    const valueColumn = this.detectYColumn(columns, data) || 'value';
    
    return {
      ...baseOptions,
      calendar: {
        range: this.getDateRange(data, dateColumn),
        ...baseOptions.calendar
      },
      series: [{
        type: 'heatmap',
        coordinateSystem: 'calendar',
        data: data.map(row => [row[dateColumn], row[valueColumn]]),
        ...baseOptions.series?.[0]
      }]
    };
  }
  
  private getTreemapOptions(baseOptions: any, data: any[]): EChartsOption {
    const columns = this.state.data?.columns || [];
    const nameColumn = columns.find(col => 
      col.toLowerCase().includes('name') || 
      col.toLowerCase().includes('label')
    ) || columns[0];
    
    const valueColumn = columns.find(col => 
      col.toLowerCase().includes('value') || 
      col.toLowerCase().includes('size') ||
      col.toLowerCase().includes('bytes')
    ) || columns[1];
    
    return {
      ...baseOptions,
      series: [{
        type: 'treemap',
        data: data.map(row => ({
          name: row[nameColumn],
          value: row[valueColumn]
        })),
        ...baseOptions.series?.[0]
      }]
    };
  }
  
  // ========================================================================
  // Column Detection Helpers
  // ========================================================================
  
  private detectXColumn(columns: string[], data: any[]): string | null {
    // Look for common x-axis column patterns
    const xPatterns = [
      /^(x|x_value)$/i,
      /^(run_number|run|index|id)$/i,
      /^(time|timestamp|date)$/i,
      /^(category|name|label)$/i
    ];
    
    for (const pattern of xPatterns) {
      const match = columns.find(col => pattern.test(col));
      if (match) return match;
    }
    
    // Default to first column
    return columns[0] || null;
  }
  
  private detectYColumn(columns: string[], data: any[]): string | null {
    // Look for common y-axis column patterns
    const yPatterns = [
      /^(y|y_value)$/i,
      /^(value|amount|count|total)$/i,
      /^(cph|coins|gems|cells)$/i,
      /^(size|bytes|duration)$/i
    ];
    
    for (const pattern of yPatterns) {
      const match = columns.find(col => pattern.test(col));
      if (match) return match;
    }
    
    // Look for numeric columns
    if (data.length > 0) {
      for (const col of columns) {
        if (typeof data[0][col] === 'number') {
          return col;
        }
      }
    }
    
    // Default to second column or first if only one column
    return columns[1] || columns[0] || null;
  }
  
  private detectTimeColumn(columns: string[]): string | null {
    const timePatterns = [
      /^(time|timestamp|date|datetime)$/i,
      /^(start_time|end_time|created_at|updated_at)$/i
    ];
    
    for (const pattern of timePatterns) {
      const match = columns.find(col => pattern.test(col));
      if (match) return match;
    }
    
    return null;
  }
  
  private getDateRange(data: any[], dateColumn: string): string[] {
    if (data.length === 0) {
      return ['2024-01-01', '2024-12-31'];
    }
    
    const dates = data.map(row => new Date(row[dateColumn]));
    const minDate = new Date(Math.min(...dates.map(d => d.getTime())));
    const maxDate = new Date(Math.max(...dates.map(d => d.getTime())));
    
    return [
      minDate.toISOString().split('T')[0],
      maxDate.toISOString().split('T')[0]
    ];
  }
  
  // ========================================================================
  // Configuration Updates
  // ========================================================================
  
  updateQuery(query: string): void {
    this.config.query.query = query;
    this.clearCache();
  }
  
  updateVisualization(config: Partial<VisualizationConfig>): void {
    this.config.visualization = {
      ...this.config.visualization,
      ...config
    };
  }
  
  updateGridPosition(gridPos: Partial<GridPosition>): void {
    this.config.gridPos = {
      ...this.config.gridPos,
      ...gridPos
    };
  }
  
  updateTitle(title: string): void {
    this.config.title = title;
  }
  
  updateDescription(description: string): void {
    this.config.description = description;
  }
  
  // ========================================================================
  // Error Handling
  // ========================================================================
  
  handleError(error: Error): void {
    const panelError = new PanelError(
      error.message,
      'PANEL_ERROR',
      this.config.id,
      this.config.query.query,
      { originalError: error }
    );
    
    this.setState({
      status: 'error',
      error: panelError,
      loading: false
    });
  }
  
  clearError(): void {
    this.setState({
      error: null,
      status: this.state.data ? 'loaded' : 'idle'
    });
  }
  
  // ========================================================================
  // Cache Management
  // ========================================================================
  
  clearCache(): void {
    this.dataCache.clear();
  }
  
  getCacheSize(): number {
    return this.dataCache.size;
  }
  
  getCacheKeys(): string[] {
    return Array.from(this.dataCache.keys());
  }
  
  // ========================================================================
  // Serialization
  // ========================================================================
  
  getConfig(): PanelConfig {
    return { ...this.config };
  }
  
  serialize(): any {
    return {
      config: this.config,
      state: {
        ...this.state,
        error: this.state.error ? {
          name: this.state.error.name,
          message: this.state.error.message
        } : null
      }
    };
  }
  
  static deserialize(data: any): Panel {
    const panel = new Panel(data.config);
    
    if (data.state) {
      panel.state = {
        ...data.state,
        error: data.state.error ? new Error(data.state.error.message) : null
      };
    }
    
    return panel;
  }
  
  // ========================================================================
  // Utility Methods
  // ========================================================================
  
  clone(): Panel {
    const serialized = this.serialize();
    return Panel.deserialize(serialized);
  }
  
  isDataStale(maxAge: number = this.CACHE_TTL): boolean {
    return !this.state.data || (Date.now() - this.state.lastUpdated) > maxAge;
  }
  
  requiresVariables(): boolean {
    return this.variables.length > 0;
  }
  
  hasData(): boolean {
    return this.state.data !== null && this.state.data.data.length > 0;
  }
}
