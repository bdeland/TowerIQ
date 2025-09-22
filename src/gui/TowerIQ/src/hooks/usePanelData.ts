/**
 * React Hook for Panel Data Management
 * 
 * This hook provides a clean interface for fetching and managing panel data
 * using the DashboardDataService with caching, deduplication, and error handling.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { dashboardDataService, PanelDataResult } from '../services/DashboardDataService';

export interface UsePanelDataOptions {
  enabled?: boolean;
  refetchInterval?: number;
  onSuccess?: (data: any[]) => void;
  onError?: (error: string) => void;
}

export interface UsePanelDataResult {
  data: any[];
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  clearCache: () => void;
}

/**
 * Hook for fetching data for a single panel
 */
export const usePanelData = (
  panelId: string,
  query: string,
  variables: Record<string, any> = {},
  options: UsePanelDataOptions = {}
): UsePanelDataResult => {
  const { enabled = true, refetchInterval, onSuccess, onError } = options;
  
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Use refs to track the latest values and prevent stale closures
  const variablesRef = useRef(variables);
  const queryRef = useRef(query);
  const panelIdRef = useRef(panelId);
  
  // Update refs when values change
  variablesRef.current = variables;
  queryRef.current = query;
  panelIdRef.current = panelId;
  
  const fetchData = useCallback(async () => {
    // Don't fetch if no query or if variables are still loading
    if (!queryRef.current || !enabled) {
      return;
    }
    
    // Don't fetch if query contains unresolved placeholders
    if (dashboardDataService.hasUnresolvedPlaceholders(queryRef.current, variablesRef.current)) {
      console.log(`usePanelData: Skipping fetch for panel ${panelIdRef.current} - unresolved placeholders`);
      return;
    }
    
    setLoading(true);
    setError(null);
    
    try {
      const result: PanelDataResult = await dashboardDataService.fetchPanelData(
        panelIdRef.current,
        queryRef.current,
        variablesRef.current
      );
      
      setData(result.data);
      setError(result.error);
      
      if (result.error && onError) {
        onError(result.error);
      } else if (result.data && onSuccess) {
        onSuccess(result.data);
      }
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch panel data';
      setError(errorMessage);
      setData([]);
      
      if (onError) {
        onError(errorMessage);
      }
    } finally {
      setLoading(false);
    }
  }, [enabled, onSuccess, onError]);
  
  const clearCache = useCallback(() => {
    dashboardDataService.clearCache(panelId);
    setData([]);
    setError(null);
  }, [panelId]);
  
  // Fetch data when dependencies change
  useEffect(() => {
    fetchData();
  }, [panelId, query, JSON.stringify(variables), enabled]);
  
  // Set up refetch interval if specified
  useEffect(() => {
    if (refetchInterval && enabled) {
      const interval = setInterval(fetchData, refetchInterval);
      return () => clearInterval(interval);
    }
  }, [fetchData, refetchInterval, enabled]);
  
  return {
    data,
    loading,
    error,
    refetch: fetchData,
    clearCache
  };
};
