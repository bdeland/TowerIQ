/**
 * Dashboard Data Service - Centralized data fetching with caching and deduplication
 * 
 * This service replaces the duplicate fetchAllPanelData implementations across
 * dashboard pages, providing:
 * - Request deduplication
 * - In-memory caching with TTL
 * - Configurable batching
 * - Error handling and retry mechanisms
 * - Loading states
 */

import { DashboardPanel } from '../contexts/DashboardContext';
import { composeQuery } from '../utils/queryComposer';
import { API_CONFIG } from '../config/environment';

export interface PanelDataResult {
  data: any[];
  loading: boolean;
  error: string | null;
  timestamp: number;
  cacheHit: boolean;
}

export interface DashboardDataServiceConfig {
  batchSize: number;
  delayBetweenRequests: number;
  delayBetweenBatches: number;
  cacheTTL: number; // milliseconds
  maxRetries: number;
  retryDelay: number; // milliseconds
}

export interface QueryRequest {
  query: string;
  variables?: Record<string, any>;
}

export interface QueryResponse {
  data: any[];
  rowCount: number;
  executionTimeMs?: number;
  cacheHit?: boolean;
}

export class DashboardDataService {
  private cache = new Map<string, PanelDataResult>();
  private pendingRequests = new Map<string, Promise<PanelDataResult>>();
  private config: DashboardDataServiceConfig;
  
  constructor(config?: Partial<DashboardDataServiceConfig>) {
    this.config = {
      batchSize: 1, // Load panels one by one to prevent one bad panel from blocking others
      delayBetweenRequests: 100,
      delayBetweenBatches: 300, // Slightly longer delay between individual panels
      cacheTTL: 5 * 60 * 1000, // 5 minutes
      maxRetries: 1, // Only try once, no retries to prevent infinite loading loops
      retryDelay: 1000,
      ...config
    };
  }
  
  /**
   * Fetch data for a single panel with caching and deduplication
   */
  async fetchPanelData(
    panelId: string, 
    query: string, 
    variables: Record<string, any> = {}
  ): Promise<PanelDataResult> {
    // CRITICAL: Always compose query with variables to handle placeholders
    const finalQuery = composeQuery(query, variables);
    const cacheKey = this.generateCacheKey(panelId, finalQuery, variables);
    
    // Check cache first
    const cached = this.cache.get(cacheKey);
    if (cached && this.isCacheValid(cached)) {
      // Only log cache hits in development mode
      if (import.meta.env.DEV) {
        console.log(`DashboardDataService: Cache hit for panel ${panelId}`);
      }
      return { ...cached, cacheHit: true };
    }
    
    // Check for pending request (deduplication)
    if (this.pendingRequests.has(cacheKey)) {
      if (import.meta.env.DEV) {
        console.log(`DashboardDataService: Deduplicating request for panel ${panelId}`);
      }
      return this.pendingRequests.get(cacheKey)!;
    }
    
    // Make new request
    const promise = this.executeQueryWithRetry(panelId, finalQuery, variables);
    this.pendingRequests.set(cacheKey, promise);
    
    try {
      const result = await promise;
      this.cache.set(cacheKey, result);
      return result;
    } finally {
      this.pendingRequests.delete(cacheKey);
    }
  }
  
  /**
   * Fetch data for a single panel individually (for better error isolation)
   */
  async fetchSinglePanel(
    panel: DashboardPanel,
    variables: Record<string, any> = {}
  ): Promise<PanelDataResult> {
    if (!panel.query) {
      return {
        data: [],
        loading: false,
        error: 'No query defined for panel',
        timestamp: Date.now(),
        cacheHit: false
      };
    }
    
    try {
      return await this.fetchPanelData(panel.id, panel.query, variables);
    } catch (error) {
      console.error(`DashboardDataService: Error fetching single panel ${panel.id}:`, error);
      return {
        data: [],
        loading: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: Date.now(),
        cacheHit: false
      };
    }
  }

  /**
   * Fetch data for all panels in a dashboard with sequential loading
   * This prevents one bad panel from blocking others and allows better error isolation
   */
  async fetchAllPanels(
    panels: DashboardPanel[], 
    variables: Record<string, any> = {}
  ): Promise<Map<string, PanelDataResult>> {
    const results = new Map<string, PanelDataResult>();
    const panelsWithQueries = panels.filter(panel => panel.query);
    
    if (import.meta.env.DEV) {
      console.log(`DashboardDataService: Fetching data sequentially for ${panelsWithQueries.length} panels`);
    }
    
    // Process panels one by one for better error isolation
    for (let i = 0; i < panelsWithQueries.length; i++) {
      const panel = panelsWithQueries[i];
      
      try {
        if (import.meta.env.DEV) {
          console.log(`DashboardDataService: Fetching panel ${i + 1}/${panelsWithQueries.length}: ${panel.id}`);
        }
        
        const result = await this.fetchPanelData(panel.id, panel.query!, variables);
        results.set(panel.id, result);
        
        // Small delay between panels to prevent overwhelming the server
        if (i < panelsWithQueries.length - 1) {
          await this.delay(this.config.delayBetweenBatches);
        }
        
      } catch (error) {
        console.error(`DashboardDataService: Error fetching panel ${panel.id}:`, error);
        
        // Store error result for this panel, but continue with others
        results.set(panel.id, {
          data: [],
          loading: false,
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: Date.now(),
          cacheHit: false
        });
      }
    }
    
    if (import.meta.env.DEV) {
      const errorCount = Array.from(results.values()).filter(r => r.error).length;
      const successCount = results.size - errorCount;
      console.log(`DashboardDataService: Completed loading ${results.size} panels (${successCount} success, ${errorCount} errors)`);
    }
    
    return results;
  }
  
  /**
   * Execute a query with improved error handling and no retries to prevent infinite loops
   */
  private async executeQueryWithRetry(
    panelId: string, 
    query: string, 
    variables: Record<string, any>
  ): Promise<PanelDataResult> {
    try {
      if (import.meta.env.DEV) {
        console.log(`DashboardDataService: Executing query for panel ${panelId}`);
      }
      
      // Check for unresolved placeholders before making the request
      if (query.includes('${')) {
        const unresolved = query.match(/\$\{[^}]+\}/g);
        const errorMessage = `Query contains unresolved placeholders: ${unresolved?.join(', ')}`;
        console.warn(`DashboardDataService: ${errorMessage} for panel ${panelId}`);
        return {
          data: [],
          loading: false,
          error: errorMessage,
          timestamp: Date.now(),
          cacheHit: false
        };
      }
      
      const response = await fetch(`${API_CONFIG.BASE_URL}/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, variables }),
      });
      
      if (!response.ok) {
        let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        
        // Try to get more detailed error from response body
        try {
          const errorData = await response.json();
          if (errorData.detail) {
            errorMessage = errorData.detail;
          } else if (errorData.message) {
            errorMessage = errorData.message;
          }
        } catch (e) {
          // Ignore JSON parsing errors, use the status text
        }
        
        // Log specific error types for debugging
        if (response.status >= 500) {
          console.error(`DashboardDataService: Server error for panel ${panelId}:`, errorMessage);
        } else if (response.status >= 400) {
          console.error(`DashboardDataService: Client error for panel ${panelId}:`, errorMessage);
        }
        
        throw new Error(errorMessage);
      }
      
      const result: QueryResponse = await response.json();
      
      if (import.meta.env.DEV) {
        console.log(`DashboardDataService: Query successful for panel ${panelId}, ${result.rowCount || result.data?.length || 0} rows`);
      }
      
      return {
        data: result.data || [],
        loading: false,
        error: null,
        timestamp: Date.now(),
        cacheHit: false
      };
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      
      // Enhanced error logging for debugging
      if (import.meta.env.DEV) {
        console.error(`DashboardDataService: Query execution failed for panel ${panelId}:`, {
          error: errorMessage,
          query: query.substring(0, 200) + (query.length > 200 ? '...' : ''),
          variables
        });
      } else {
        console.error(`DashboardDataService: Query failed for panel ${panelId}:`, errorMessage);
      }
      
      // Return error state immediately - no retries to prevent infinite loading loops
      return {
        data: [],
        loading: false,
        error: errorMessage,
        timestamp: Date.now(),
        cacheHit: false
      };
    }
  }
  
  /**
   * Generate a cache key for a panel query
   */
  private generateCacheKey(panelId: string, query: string, variables: Record<string, any>): string {
    const variablesString = JSON.stringify(variables, Object.keys(variables).sort());
    return `${panelId}:${query}:${variablesString}`;
  }
  
  /**
   * Check if cached data is still valid
   */
  private isCacheValid(cached: PanelDataResult): boolean {
    return Date.now() - cached.timestamp < this.config.cacheTTL;
  }
  
  /**
   * Helper method to check if query has unresolved placeholders
   */
  hasUnresolvedPlaceholders(query: string, variables: Record<string, any>): boolean {
    const composedQuery = composeQuery(query, variables);
    return composedQuery.includes('${');
  }
  
  /**
   * Clear cache for a specific panel or all panels
   */
  clearCache(panelId?: string): void {
    if (panelId) {
      // Clear cache entries for specific panel
      for (const [key] of this.cache) {
        if (key.startsWith(`${panelId}:`)) {
          this.cache.delete(key);
        }
      }
      console.log(`DashboardDataService: Cleared cache for panel ${panelId}`);
    } else {
      // Clear all cache
      this.cache.clear();
      console.log('DashboardDataService: Cleared all cache');
    }
  }
  
  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; entries: string[] } {
    return {
      size: this.cache.size,
      entries: Array.from(this.cache.keys())
    };
  }
  
  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<DashboardDataServiceConfig>): void {
    this.config = { ...this.config, ...newConfig };
    console.log('DashboardDataService: Configuration updated', this.config);
  }
  
  /**
   * Utility method for delays
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Singleton instance for the application
export const dashboardDataService = new DashboardDataService();

// Export types for use in components
export type { PanelDataResult, DashboardDataServiceConfig };
