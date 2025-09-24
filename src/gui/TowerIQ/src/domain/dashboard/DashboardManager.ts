/**
 * DashboardManager Singleton
 * 
 * Central registry for managing all dashboard instances and lifecycle.
 * Provides unified API for dashboard CRUD operations, loading, and caching.
 */

import { EventEmitter } from 'events';
import { 
  DashboardConfig,
  DashboardManagerConfig,
  DEFAULT_MANAGER_CONFIG,
  LoadResult,
  CacheEntry,
  DashboardError
} from './types';
import { Dashboard } from './Dashboard';
import { dashboardDataService } from '../../services/DashboardDataService';
import { API_CONFIG } from '../../config/environment';

export class DashboardManager extends EventEmitter {
  private static instance: DashboardManager | null = null;
  
  private dashboards: Map<string, Dashboard>;
  private cache: Map<string, CacheEntry<Dashboard>>;
  private config: DashboardManagerConfig;
  private dataService = dashboardDataService;
  private initialized: boolean = false;
  
  private constructor(config: Partial<DashboardManagerConfig> = {}) {
    super();
    
    this.dashboards = new Map();
    this.cache = new Map();
    this.config = { ...DEFAULT_MANAGER_CONFIG, ...config };
    // dataService is already initialized as a class property
    
    // Setup cache cleanup interval
    this.setupCacheCleanup();
  }
  
  // ========================================================================
  // Singleton Pattern
  // ========================================================================
  
  static getInstance(config?: Partial<DashboardManagerConfig>): DashboardManager {
    if (!DashboardManager.instance) {
      DashboardManager.instance = new DashboardManager(config);
    }
    return DashboardManager.instance;
  }
  
  static resetInstance(): void {
    if (DashboardManager.instance) {
      DashboardManager.instance.destroy();
      DashboardManager.instance = null;
    }
  }
  
  // ========================================================================
  // Initialization
  // ========================================================================
  
  async initialize(): Promise<void> {
    if (this.initialized) return;
    
    try {
      // Load system dashboards from database
      await this.loadSystemDashboards();
      
      // Load user dashboards
      await this.loadUserDashboards();
      
      this.initialized = true;
      this.emit('initialized');
      
    } catch (error) {
      throw new DashboardError(
        `Failed to initialize DashboardManager: ${error.message}`,
        'MANAGER_INIT_FAILED',
        undefined,
        undefined,
        { originalError: error }
      );
    }
  }
  
  private async loadSystemDashboards(): Promise<void> {
    // Load hardcoded system dashboards
    // These would be migrated to database in Phase 1B
    const systemDashboardIds = [
      'default-dashboard',
      'database-health-dashboard', 
      'live-run-tracking-dashboard'
    ];
    
    for (const dashboardId of systemDashboardIds) {
      try {
        const config = await this.loadDashboardConfig(dashboardId);
        if (config) {
          const dashboard = new Dashboard(config);
          this.registerDashboard(dashboard);
        }
      } catch (error) {
        console.warn(`Failed to load system dashboard ${dashboardId}:`, error);
      }
    }
  }
  
  private async loadUserDashboards(): Promise<void> {
    try {
      const response = await fetch('/api/dashboards');
      if (response.ok) {
        const dashboardConfigs = await response.json();
        
        for (const config of dashboardConfigs) {
          try {
            const dashboard = new Dashboard(config);
            this.registerDashboard(dashboard);
          } catch (error) {
            console.warn(`Failed to load dashboard ${config.id}:`, error);
          }
        }
      }
    } catch (error) {
      console.warn('Failed to load user dashboards:', error);
    }
  }
  
  private async loadDashboardConfig(dashboardId: string): Promise<DashboardConfig | null> {
    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}/v2/dashboards/${dashboardId}`);
      if (response.ok) {
        return await response.json();
      }
      return null;
    } catch (error) {
      console.warn(`Failed to load dashboard config ${dashboardId}:`, error);
      return null;
    }
  }
  
  // ========================================================================
  // Dashboard Registry
  // ========================================================================
  
  private registerDashboard(dashboard: Dashboard): void {
    this.dashboards.set(dashboard.id, dashboard);
    
    // Subscribe to dashboard events
    dashboard.on('dashboardEvent', (event) => {
      this.emit('dashboardEvent', event);
    });
    
    dashboard.on('variableUpdated', (event) => {
      this.emit('variableUpdated', event);
    });
    
    dashboard.on('panelStateChanged', (event) => {
      this.emit('panelStateChanged', event);
    });
    
    dashboard.on('dashboardError', (event) => {
      this.emit('dashboardError', event);
    });
    
    // Cache the dashboard
    this.cacheSet(dashboard.id, dashboard);
    
    this.emit('dashboardRegistered', { dashboardId: dashboard.id });
  }
  
  private unregisterDashboard(dashboardId: string): void {
    const dashboard = this.dashboards.get(dashboardId);
    if (dashboard) {
      // Remove all listeners
      dashboard.removeAllListeners();
      
      // Remove from registry
      this.dashboards.delete(dashboardId);
      
      // Remove from cache
      this.cache.delete(dashboardId);
      
      this.emit('dashboardUnregistered', { dashboardId });
    }
  }
  
  // ========================================================================
  // Dashboard CRUD Operations
  // ========================================================================
  
  getDashboard(id: string): Dashboard | null {
    // Check registry first
    const dashboard = this.dashboards.get(id);
    if (dashboard) return dashboard;
    
    // Check cache
    const cached = this.cacheGet(id);
    if (cached) {
      this.dashboards.set(id, cached);
      return cached;
    }
    
    return null;
  }
  
  async loadDashboard(id: string): Promise<Dashboard> {
    // Check if already loaded
    let dashboard = this.getDashboard(id);
    if (dashboard) return dashboard;
    
    try {
      // Load from API
      const config = await this.loadDashboardConfig(id);
      if (!config) {
        throw new DashboardError(
          `Dashboard not found: ${id}`,
          'DASHBOARD_NOT_FOUND',
          id
        );
      }
      
      // Create dashboard instance
      dashboard = new Dashboard(config);
      this.registerDashboard(dashboard);
      
      return dashboard;
      
    } catch (error) {
      throw new DashboardError(
        `Failed to load dashboard ${id}: ${error.message}`,
        'DASHBOARD_LOAD_FAILED',
        id,
        undefined,
        { originalError: error }
      );
    }
  }
  
  async createDashboard(config: DashboardConfig): Promise<Dashboard> {
    try {
      // Validate config
      if (!config.id || !config.metadata.title) {
        throw new DashboardError(
          'Dashboard config must have id and title',
          'INVALID_CONFIG',
          config.id
        );
      }
      
      // Check if dashboard already exists
      if (this.dashboards.has(config.id)) {
        throw new DashboardError(
          `Dashboard already exists: ${config.id}`,
          'DASHBOARD_EXISTS',
          config.id
        );
      }
      
      // Create dashboard instance
      const dashboard = new Dashboard(config);
      
      // Save to database
      await this.saveDashboard(dashboard);
      
      // Register in manager
      this.registerDashboard(dashboard);
      
      this.emit('dashboardCreated', { dashboardId: config.id });
      
      return dashboard;
      
    } catch (error) {
      throw new DashboardError(
        `Failed to create dashboard: ${error.message}`,
        'DASHBOARD_CREATE_FAILED',
        config.id,
        undefined,
        { originalError: error }
      );
    }
  }
  
  async updateDashboard(id: string, updates: Partial<DashboardConfig>): Promise<Dashboard> {
    const dashboard = await this.loadDashboard(id);
    
    try {
      // Apply updates
      if (updates.metadata) {
        dashboard.updateMetadata(updates.metadata);
      }
      
      if (updates.settings) {
        dashboard.updateSettings(updates.settings);
      }
      
      // TODO: Handle panel and variable updates
      
      // Save to database
      await this.saveDashboard(dashboard);
      
      // Update cache
      this.cacheSet(id, dashboard);
      
      this.emit('dashboardUpdated', { dashboardId: id });
      
      return dashboard;
      
    } catch (error) {
      throw new DashboardError(
        `Failed to update dashboard ${id}: ${error.message}`,
        'DASHBOARD_UPDATE_FAILED',
        id,
        undefined,
        { originalError: error }
      );
    }
  }
  
  async deleteDashboard(id: string): Promise<boolean> {
    try {
      // Check if dashboard exists
      const dashboard = this.getDashboard(id);
      if (!dashboard) {
        return false; // Already deleted
      }
      
      // Don't delete system dashboards
      if (dashboard.isSystem) {
        throw new DashboardError(
          `Cannot delete system dashboard: ${id}`,
          'SYSTEM_DASHBOARD_DELETE',
          id
        );
      }
      
      // Delete from database
      const response = await fetch(`/api/dashboards/${id}`, {
        method: 'DELETE'
      });
      
      if (!response.ok) {
        throw new Error(`Delete failed: ${response.status} ${response.statusText}`);
      }
      
      // Unregister from manager
      this.unregisterDashboard(id);
      
      this.emit('dashboardDeleted', { dashboardId: id });
      
      return true;
      
    } catch (error) {
      throw new DashboardError(
        `Failed to delete dashboard ${id}: ${error.message}`,
        'DASHBOARD_DELETE_FAILED',
        id,
        undefined,
        { originalError: error }
      );
    }
  }
  
  private async saveDashboard(dashboard: Dashboard): Promise<void> {
    const config = dashboard.serialize();
    
    const response = await fetch(`/api/dashboards/${dashboard.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(config)
    });
    
    if (!response.ok) {
      throw new Error(`Save failed: ${response.status} ${response.statusText}`);
    }
  }
  
  // ========================================================================
  // Dashboard Discovery
  // ========================================================================
  
  getAllDashboards(): Dashboard[] {
    return Array.from(this.dashboards.values());
  }
  
  getDashboardIds(): string[] {
    return Array.from(this.dashboards.keys());
  }
  
  getDashboardCount(): number {
    return this.dashboards.size;
  }
  
  findDashboardsByTag(tag: string): Dashboard[] {
    return this.getAllDashboards().filter(dashboard => 
      dashboard.tags.includes(tag)
    );
  }
  
  findDashboardsByTitle(titlePattern: string): Dashboard[] {
    const regex = new RegExp(titlePattern, 'i');
    return this.getAllDashboards().filter(dashboard => 
      regex.test(dashboard.title)
    );
  }
  
  getSystemDashboards(): Dashboard[] {
    return this.getAllDashboards().filter(dashboard => dashboard.isSystem);
  }
  
  getUserDashboards(): Dashboard[] {
    return this.getAllDashboards().filter(dashboard => !dashboard.isSystem);
  }
  
  // ========================================================================
  // Bulk Operations
  // ========================================================================
  
  async loadAllDashboards(): Promise<LoadResult[]> {
    const results: LoadResult[] = [];
    const dashboards = this.getAllDashboards();
    
    const loadPromises = dashboards.map(async (dashboard) => {
      const startTime = Date.now();
      
      try {
        const loadResults = await dashboard.loadData();
        
        return {
          dashboardId: dashboard.id,
          success: true,
          panelResults: loadResults,
          executionTime: Date.now() - startTime
        };
      } catch (error) {
        return {
          dashboardId: dashboard.id,
          success: false,
          error: error as Error,
          executionTime: Date.now() - startTime
        };
      }
    });
    
    const dashboardResults = await Promise.allSettled(loadPromises);
    
    dashboardResults.forEach((result) => {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      } else {
        results.push({
          dashboardId: 'unknown',
          success: false,
          error: new Error(result.reason),
          executionTime: 0
        });
      }
    });
    
    return results;
  }
  
  async refreshAllDashboards(): Promise<void> {
    const refreshPromises = this.getAllDashboards().map(dashboard => 
      dashboard.refreshData()
    );
    
    await Promise.allSettled(refreshPromises);
  }
  
  clearAllCaches(): void {
    this.cache.clear();
    
    for (const dashboard of this.dashboards.values()) {
      dashboard.clearCache();
    }
    
    this.emit('cachesCleared');
  }
  
  // ========================================================================
  // Cache Management
  // ========================================================================
  
  private cacheSet(key: string, dashboard: Dashboard): void {
    const entry: CacheEntry<Dashboard> = {
      data: dashboard,
      timestamp: Date.now(),
      ttl: this.config.cacheConfig.defaultTTL,
      key
    };
    
    this.cache.set(key, entry);
    
    // Cleanup if cache is too large
    if (this.cache.size > this.config.cacheConfig.maxSize) {
      this.cleanupCache();
    }
  }
  
  private cacheGet(key: string): Dashboard | null {
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    // Check TTL
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }
    
    return entry.data;
  }
  
  private cleanupCache(): void {
    const now = Date.now();
    const entries = Array.from(this.cache.entries());
    
    // Sort by timestamp (oldest first)
    entries.sort(([, a], [, b]) => a.timestamp - b.timestamp);
    
    // Remove expired entries
    for (const [key, entry] of entries) {
      if (now - entry.timestamp > entry.ttl) {
        this.cache.delete(key);
      }
    }
    
    // Remove oldest entries if still too large
    const remainingEntries = Array.from(this.cache.entries());
    remainingEntries.sort(([, a], [, b]) => a.timestamp - b.timestamp);
    
    while (this.cache.size > this.config.cacheConfig.maxSize && remainingEntries.length > 0) {
      const [key] = remainingEntries.shift()!;
      this.cache.delete(key);
    }
  }
  
  private setupCacheCleanup(): void {
    setInterval(() => {
      this.cleanupCache();
    }, this.config.cacheConfig.cleanupInterval);
  }
  
  getCacheStats(): { size: number; hitRate: number; totalSize: number } {
    let totalSize = this.cache.size;
    
    for (const dashboard of this.dashboards.values()) {
      totalSize += dashboard.getCacheSize();
    }
    
    return {
      size: this.cache.size,
      hitRate: 0, // Would track hits/misses in real implementation
      totalSize
    };
  }
  
  // ========================================================================
  // Configuration
  // ========================================================================
  
  getConfig(): DashboardManagerConfig {
    return { ...this.config };
  }
  
  updateConfig(updates: Partial<DashboardManagerConfig>): void {
    this.config = { ...this.config, ...updates };
    this.emit('configUpdated', { config: this.config });
  }
  
  // ========================================================================
  // Lifecycle
  // ========================================================================
  
  isInitialized(): boolean {
    return this.initialized;
  }
  
  destroy(): void {
    // Clear all intervals
    // (In real implementation, we'd track interval IDs)
    
    // Unregister all dashboards
    for (const dashboardId of this.getDashboardIds()) {
      this.unregisterDashboard(dashboardId);
    }
    
    // Clear cache
    this.cache.clear();
    
    // Remove all listeners
    this.removeAllListeners();
    
    this.initialized = false;
  }
  
  // ========================================================================
  // Static Utility Methods
  // ========================================================================
  
  /**
   * Create a dashboard manager with default configuration
   */
  static createDefault(): DashboardManager {
    return DashboardManager.getInstance();
  }
  
  /**
   * Create a dashboard manager with custom configuration
   */
  static createWithConfig(config: Partial<DashboardManagerConfig>): DashboardManager {
    return DashboardManager.getInstance(config);
  }
}
