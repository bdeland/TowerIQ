/**
 * RequestCache - Frontend request caching and deduplication utility
 * 
 * This implements Phase 3 of the ADB duplication fix:
 * - Client-side request caching with configurable TTL
 * - Request deduplication to prevent concurrent identical requests
 * - Cache invalidation and force refresh capabilities
 * 
 * Features:
 * - Map-based cache storage with timestamp-based expiry
 * - Promise sharing for identical concurrent requests
 * - Configurable cache durations per request type
 * - Debug logging for cache behavior
 * - Automatic cleanup of expired entries
 */

export interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number; // Time to live in milliseconds
  promise?: Promise<T>; // For deduplication
}

export interface CacheConfig {
  defaultTtl?: number; // Default TTL in milliseconds
  maxSize?: number; // Maximum cache size
  enableLogging?: boolean; // Enable debug logging
}

export class RequestCache {
  private cache = new Map<string, CacheEntry<any>>();
  private pendingRequests = new Map<string, Promise<any>>();
  private config: Required<CacheConfig>;

  constructor(config: CacheConfig = {}) {
    this.config = {
      defaultTtl: 5000, // 5 seconds default
      maxSize: 100,
      enableLogging: false,
      ...config
    };

    // Periodic cleanup of expired entries
    setInterval(() => this.cleanup(), 30000); // Cleanup every 30 seconds
  }

  /**
   * Get cached data if valid, otherwise execute the request function
   */
  async get<T>(
    key: string,
    requestFn: () => Promise<T>,
    options: { ttl?: number; forceRefresh?: boolean } = {}
  ): Promise<T> {
    const { ttl = this.config.defaultTtl, forceRefresh = false } = options;
    
    // Check for valid cached data first (unless force refresh)
    if (!forceRefresh) {
      const cachedEntry = this.cache.get(key);
      if (cachedEntry && this.isValid(cachedEntry)) {
        if (this.config.enableLogging) {
          console.log(`RequestCache: Cache hit for ${key}`, {
            age: Date.now() - cachedEntry.timestamp,
            ttl: cachedEntry.ttl
          });
        }
        return cachedEntry.data;
      }
    }

    // Check if there's already a pending request for this key
    const pendingRequest = this.pendingRequests.get(key);
    if (pendingRequest && !forceRefresh) {
      if (this.config.enableLogging) {
        console.log(`RequestCache: Sharing pending request for ${key}`);
      }
      return pendingRequest;
    }

    // Create new request
    if (this.config.enableLogging) {
      const reason = forceRefresh ? 'force refresh' : 'cache miss/expired';
      console.log(`RequestCache: Making new request for ${key}`, { reason });
    }

    const requestPromise = this.executeRequest(key, requestFn, ttl);
    
    // Store pending request for deduplication
    this.pendingRequests.set(key, requestPromise);

    try {
      const result = await requestPromise;
      return result;
    } finally {
      // Clean up pending request
      this.pendingRequests.delete(key);
    }
  }

  /**
   * Execute the request and cache the result
   */
  private async executeRequest<T>(
    key: string,
    requestFn: () => Promise<T>,
    ttl: number
  ): Promise<T> {
    try {
      const result = await requestFn();
      
      // Cache the result
      this.set(key, result, ttl);
      
      if (this.config.enableLogging) {
        console.log(`RequestCache: Cached result for ${key}`, {
          ttl,
          dataType: typeof result,
          dataSize: Array.isArray(result) ? result.length : 'not_array'
        });
      }
      
      return result;
    } catch (error) {
      if (this.config.enableLogging) {
        console.error(`RequestCache: Request failed for ${key}`, error);
      }
      throw error;
    }
  }

  /**
   * Manually set cache entry
   */
  set<T>(key: string, data: T, ttl: number = this.config.defaultTtl): void {
    // Enforce max cache size
    if (this.cache.size >= this.config.maxSize) {
      this.evictOldest();
    }

    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl
    });
  }

  /**
   * Check if cache entry is valid (not expired)
   */
  private isValid(entry: CacheEntry<any>): boolean {
    return Date.now() - entry.timestamp < entry.ttl;
  }

  /**
   * Invalidate specific cache key
   */
  invalidate(key: string): void {
    const deleted = this.cache.delete(key);
    if (this.config.enableLogging && deleted) {
      console.log(`RequestCache: Invalidated cache for ${key}`);
    }
  }

  /**
   * Invalidate all cache entries matching a pattern
   */
  invalidatePattern(pattern: string | RegExp): void {
    const regex = typeof pattern === 'string' ? new RegExp(pattern) : pattern;
    const keysToDelete: string[] = [];
    
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        keysToDelete.push(key);
      }
    }
    
    keysToDelete.forEach(key => {
      this.cache.delete(key);
      if (this.config.enableLogging) {
        console.log(`RequestCache: Invalidated cache for ${key} (pattern match)`);
      }
    });
  }

  /**
   * Clear all cache entries
   */
  clear(): void {
    const size = this.cache.size;
    this.cache.clear();
    this.pendingRequests.clear();
    
    if (this.config.enableLogging) {
      console.log(`RequestCache: Cleared all cache entries (${size} items)`);
    }
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const now = Date.now();
    let validCount = 0;
    let expiredCount = 0;
    
    for (const entry of this.cache.values()) {
      if (this.isValid(entry)) {
        validCount++;
      } else {
        expiredCount++;
      }
    }
    
    return {
      totalEntries: this.cache.size,
      validEntries: validCount,
      expiredEntries: expiredCount,
      pendingRequests: this.pendingRequests.size,
      maxSize: this.config.maxSize
    };
  }

  /**
   * Clean up expired cache entries
   */
  private cleanup(): void {
    const before = this.cache.size;
    const expiredKeys: string[] = [];
    
    for (const [key, entry] of this.cache.entries()) {
      if (!this.isValid(entry)) {
        expiredKeys.push(key);
      }
    }
    
    expiredKeys.forEach(key => this.cache.delete(key));
    
    if (this.config.enableLogging && expiredKeys.length > 0) {
      console.log(`RequestCache: Cleaned up ${expiredKeys.length} expired entries (${before} -> ${this.cache.size})`);
    }
  }

  /**
   * Evict oldest cache entry to make room
   */
  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestTimestamp = Infinity;
    
    for (const [key, entry] of this.cache.entries()) {
      if (entry.timestamp < oldestTimestamp) {
        oldestTimestamp = entry.timestamp;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      this.cache.delete(oldestKey);
      if (this.config.enableLogging) {
        console.log(`RequestCache: Evicted oldest entry ${oldestKey}`);
      }
    }
  }
}

// Default cache instance with debug logging enabled in development
export const defaultRequestCache = new RequestCache({
  defaultTtl: 5000, // 5 seconds as specified in PRD
  maxSize: 100,
  enableLogging: import.meta.env.DEV // Enable logging in development
});

// Cache key generators for consistent naming
export const CacheKeys = {
  devices: () => 'devices',
  deviceRefresh: () => 'devices_refresh',
  processes: (deviceId: string) => `processes_${deviceId}`,
  fridaStatus: (deviceId: string) => `frida_status_${deviceId}`,
  hookScripts: () => 'hook_scripts',
  adbStatus: () => 'adb_status',
  scriptStatus: () => 'script_status',
  backendStatus: () => 'backend_status'
} as const;
