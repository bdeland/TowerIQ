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
      batchSize: 6,
      delayBetweenRequests: 100,
      delayBetweenBatches: 200,
      cacheTTL: 5 * 60 * 1000, // 5 minutes
      maxRetries: 3,
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
      console.log(`DashboardDataService: Cache hit for panel ${panelId}`);
      return { ...cached, cacheHit: true };
    }
    
    // Check for pending request (deduplication)
    if (this.pendingRequests.has(cacheKey)) {
      console.log(`DashboardDataService: Deduplicating request for panel ${panelId}`);
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
   * Fetch data for all panels in a dashboard with batching
   */
  async fetchAllPanels(
    panels: DashboardPanel[], 
    variables: Record<string, any> = {}
  ): Promise<Map<string, PanelDataResult>> {
    const results = new Map<string, PanelDataResult>();
    const panelsWithQueries = panels.filter(panel => panel.query);
    
    console.log(`DashboardDataService: Fetching data for ${panelsWithQueries.length} panels`);
    
    // Process panels in batches
    for (let i = 0; i < panelsWithQueries.length; i += this.config.batchSize) {
      const batch = panelsWithQueries.slice(i, i + this.config.batchSize);
      
      // Fetch all panels in the batch concurrently
      const batchPromises = batch.map(panel => 
        this.fetchPanelData(panel.id, panel.query!, variables)
          .then(result => ({ panelId: panel.id, result }))
          .catch(error => ({ 
            panelId: panel.id, 
            result: { 
              data: [], 
              loading: false, 
              error: error.message, 
              timestamp: Date.now(), 
              cacheHit: false 
            } 
          }))
      );
      
      const batchResults = await Promise.all(batchPromises);
      
      // Store results
      batchResults.forEach(({ panelId, result }) => {
        results.set(panelId, result);
      });
      
      // Delay between batches (except for the last batch)
      if (i + this.config.batchSize < panelsWithQueries.length) {
        await this.delay(this.config.delayBetweenBatches);
      }
    }
    
    return results;
  }
  
  /**
   * Execute a query with retry logic
   */
  private async executeQueryWithRetry(
    panelId: string, 
    query: string, 
    variables: Record<string, any>
  ): Promise<PanelDataResult> {
    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        console.log(`DashboardDataService: Executing query for panel ${panelId} (attempt ${attempt})`);
        
        const response = await fetch(`${API_CONFIG.BASE_URL}/query`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query, variables }),
        });
        
        if (!response.ok) {
          throw new Error(`Query failed: ${response.statusText}`);
        }
        
        const result: QueryResponse = await response.json();
        
        console.log(`DashboardDataService: Query successful for panel ${panelId}, ${result.rowCount} rows`);
        
        return {
          data: result.data || [],
          loading: false,
          error: null,
          timestamp: Date.now(),
          cacheHit: false
        };
        
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        console.error(`DashboardDataService: Query failed for panel ${panelId} (attempt ${attempt}):`, lastError.message);
        
        // Don't retry on client errors (4xx)
        if (error instanceof Error && 'status' in error && 
            typeof error.status === 'number' && error.status >= 400 && error.status < 500) {
          break;
        }
        
        // Wait before retry (except on last attempt)
        if (attempt < this.config.maxRetries) {
          await this.delay(this.config.retryDelay * attempt); // Exponential backoff
        }
      }
    }
    
    // All retries failed
    return {
      data: [],
      loading: false,
      error: lastError?.message || 'Query execution failed',
      timestamp: Date.now(),
      cacheHit: false
    };
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
