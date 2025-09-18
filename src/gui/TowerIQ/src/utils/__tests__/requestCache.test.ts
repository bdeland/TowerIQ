/**
 * Unit tests for RequestCache implementation
 * 
 * Tests Phase 3 frontend caching and request deduplication functionality
 */

import { RequestCache } from '../requestCache';

describe('RequestCache', () => {
  let cache: RequestCache;
  
  beforeEach(() => {
    cache = new RequestCache({
      defaultTtl: 1000, // 1 second for testing
      enableLogging: false // Disable logging in tests
    });
  });

  afterEach(() => {
    cache.clear();
  });

  describe('Basic Caching', () => {
    test('should cache and return data within TTL', async () => {
      let callCount = 0;
      const mockRequest = async () => {
        callCount++;
        return 'test-data';
      };

      // First call should execute the request
      const result1 = await cache.get('test-key', mockRequest);
      expect(result1).toBe('test-data');
      expect(callCount).toBe(1);

      // Second call should use cache
      const result2 = await cache.get('test-key', mockRequest);
      expect(result2).toBe('test-data');
      expect(callCount).toBe(1); // Should not have called again
    });

    test('should re-execute request after TTL expires', async () => {
      let callCount = 0;
      const mockRequest = async () => {
        callCount++;
        return `data-${callCount}`;
      };

      // First call
      const result1 = await cache.get('test-key', mockRequest, { ttl: 50 });
      expect(result1).toBe('data-1');
      expect(callCount).toBe(1);

      // Wait for TTL to expire
      await new Promise(resolve => setTimeout(resolve, 60));

      // Second call should re-execute
      const result2 = await cache.get('test-key', mockRequest, { ttl: 50 });
      expect(result2).toBe('data-2');
      expect(callCount).toBe(2);
    });

    test('should force refresh when requested', async () => {
      let callCount = 0;
      const mockRequest = async () => {
        callCount++;
        return `data-${callCount}`;
      };

      // First call
      const result1 = await cache.get('test-key', mockRequest);
      expect(result1).toBe('data-1');
      expect(callCount).toBe(1);

      // Force refresh should re-execute
      const result2 = await cache.get('test-key', mockRequest, { forceRefresh: true });
      expect(result2).toBe('data-2');
      expect(callCount).toBe(2);
    });
  });

  describe('Request Deduplication', () => {
    test('should deduplicate concurrent requests', async () => {
      let callCount = 0;
      const mockRequest = async () => {
        callCount++;
        // Simulate async delay
        await new Promise(resolve => setTimeout(resolve, 10));
        return `data-${callCount}`;
      };

      // Start multiple concurrent requests
      const promises = [
        cache.get('test-key', mockRequest),
        cache.get('test-key', mockRequest),
        cache.get('test-key', mockRequest)
      ];

      const results = await Promise.all(promises);

      // All should return the same result
      expect(results[0]).toBe('data-1');
      expect(results[1]).toBe('data-1');
      expect(results[2]).toBe('data-1');
      
      // Request should only have been called once
      expect(callCount).toBe(1);
    });

    test('should handle errors in concurrent requests', async () => {
      let callCount = 0;
      const mockRequest = async () => {
        callCount++;
        await new Promise(resolve => setTimeout(resolve, 10));
        throw new Error('Request failed');
      };

      // Start multiple concurrent requests
      const promises = [
        cache.get('test-key', mockRequest).catch(e => e.message),
        cache.get('test-key', mockRequest).catch(e => e.message),
        cache.get('test-key', mockRequest).catch(e => e.message)
      ];

      const results = await Promise.all(promises);

      // All should get the same error
      expect(results[0]).toBe('Request failed');
      expect(results[1]).toBe('Request failed');
      expect(results[2]).toBe('Request failed');
      
      // Request should only have been called once
      expect(callCount).toBe(1);
    });
  });

  describe('Cache Management', () => {
    test('should invalidate specific keys', async () => {
      let callCount = 0;
      const mockRequest = async () => {
        callCount++;
        return `data-${callCount}`;
      };

      // Cache data
      const result1 = await cache.get('test-key', mockRequest);
      expect(result1).toBe('data-1');
      expect(callCount).toBe(1);

      // Invalidate cache
      cache.invalidate('test-key');

      // Should re-execute after invalidation
      const result2 = await cache.get('test-key', mockRequest);
      expect(result2).toBe('data-2');
      expect(callCount).toBe(2);
    });

    test('should clear all cache entries', async () => {
      const mockRequest = async () => 'test-data';

      // Cache multiple keys
      await cache.get('key1', mockRequest);
      await cache.get('key2', mockRequest);

      const statsBefore = cache.getStats();
      expect(statsBefore.totalEntries).toBe(2);

      // Clear cache
      cache.clear();

      const statsAfter = cache.getStats();
      expect(statsAfter.totalEntries).toBe(0);
    });

    test('should provide accurate cache statistics', async () => {
      const mockRequest = async () => 'test-data';

      const initialStats = cache.getStats();
      expect(initialStats.totalEntries).toBe(0);
      expect(initialStats.validEntries).toBe(0);

      // Add cache entries
      await cache.get('key1', mockRequest);
      await cache.get('key2', mockRequest);

      const statsAfter = cache.getStats();
      expect(statsAfter.totalEntries).toBe(2);
      expect(statsAfter.validEntries).toBe(2);
    });
  });

  describe('Cache Key Patterns', () => {
    test('should invalidate cache entries matching pattern', async () => {
      const mockRequest = async () => 'test-data';

      // Cache multiple keys with different patterns
      await cache.get('device_123', mockRequest);
      await cache.get('device_456', mockRequest);
      await cache.get('process_123', mockRequest);

      const statsBefore = cache.getStats();
      expect(statsBefore.totalEntries).toBe(3);

      // Invalidate all device-related cache entries
      cache.invalidatePattern(/^device_/);

      const statsAfter = cache.getStats();
      expect(statsAfter.totalEntries).toBe(1); // Only process_123 should remain
    });
  });
});
