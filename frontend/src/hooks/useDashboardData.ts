/**
 * React Hook for Dashboard Data Management
 * 
 * This hook provides a clean interface for fetching data for all panels
 * in a dashboard using the DashboardDataService with batching and caching.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { DashboardPanel } from '../contexts/DashboardContext';
import { dashboardDataService, PanelDataResult } from '../services/DashboardDataService';

export interface UseDashboardDataOptions {
  enabled?: boolean;
  refetchInterval?: number;
  onSuccess?: (data: Map<string, PanelDataResult>) => void;
  onError?: (errors: Map<string, string>) => void;
}

export interface UseDashboardDataResult {
  panelData: Map<string, PanelDataResult>;
  loading: boolean;
  errors: Map<string, string>;
  refetch: () => Promise<void>;
  clearCache: () => void;
  getPanelData: (panelId: string) => PanelDataResult | undefined;
}

/**
 * Hook for fetching data for all panels in a dashboard
 */
export const useDashboardData = (
  panels: DashboardPanel[],
  variables: Record<string, any> = {},
  options: UseDashboardDataOptions = {}
): UseDashboardDataResult => {
  const { enabled = true, refetchInterval, onSuccess, onError } = options;
  
  const [panelData, setPanelData] = useState<Map<string, PanelDataResult>>(new Map());
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Map<string, string>>(new Map());
  
  // Use refs to track the latest values and prevent stale closures
  const panelsRef = useRef(panels);
  const variablesRef = useRef(variables);
  const isInitialMount = useRef(true);
  const lastFetchKey = useRef<string>('');
  
  // Update refs when values change
  panelsRef.current = panels;
  variablesRef.current = variables;
  
  const fetchAllData = useCallback(async () => {
    // Don't fetch if no panels or if disabled
    if (panelsRef.current.length === 0 || !enabled) {
      return;
    }
    
    // Generate a key to prevent duplicate fetches
    const fetchKey = `${panelsRef.current.map(p => p.id).sort().join(',')}:${JSON.stringify(variablesRef.current)}`;
    if (fetchKey === lastFetchKey.current && !isInitialMount.current) {
      if (import.meta.env.DEV) {
        console.log('useDashboardData: Skipping duplicate fetch');
      }
      return;
    }
    
    lastFetchKey.current = fetchKey;
    isInitialMount.current = false;
    
    setLoading(true);
    setErrors(new Map());
    
    try {
      if (import.meta.env.DEV) {
        console.log(`useDashboardData: Fetching data for ${panelsRef.current.length} panels`);
      }
      
      const results = await dashboardDataService.fetchAllPanels(
        panelsRef.current,
        variablesRef.current
      );
      
      setPanelData(results);
      
      // Collect errors
      const errorMap = new Map<string, string>();
      results.forEach((result, panelId) => {
        if (result.error) {
          errorMap.set(panelId, result.error);
        }
      });
      
      setErrors(errorMap);
      
      if (errorMap.size > 0 && onError) {
        onError(errorMap);
      } else if (results.size > 0 && onSuccess) {
        onSuccess(results);
      }
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch dashboard data';
      console.error('useDashboardData: Failed to fetch dashboard data:', errorMessage);
      
      // Set error for all panels
      const errorMap = new Map<string, string>();
      panelsRef.current.forEach(panel => {
        errorMap.set(panel.id, errorMessage);
      });
      setErrors(errorMap);
      
      if (onError) {
        onError(errorMap);
      }
    } finally {
      setLoading(false);
    }
  }, [enabled, onSuccess, onError]);
  
  const clearCache = useCallback(() => {
    dashboardDataService.clearCache();
    setPanelData(new Map());
    setErrors(new Map());
  }, []);
  
  const getPanelData = useCallback((panelId: string): PanelDataResult | undefined => {
    return panelData.get(panelId);
  }, [panelData]);
  
  // Fetch data when dependencies change - using JSON.stringify for deep comparison
  useEffect(() => {
    fetchAllData();
  }, [JSON.stringify(panels.map(p => ({ id: p.id, query: p.query }))), JSON.stringify(variables), enabled, fetchAllData]);
  
  // Set up refetch interval if specified
  useEffect(() => {
    if (refetchInterval && enabled) {
      const interval = setInterval(fetchAllData, refetchInterval);
      return () => clearInterval(interval);
    }
  }, [fetchAllData, refetchInterval, enabled]);
  
  return {
    panelData,
    loading,
    errors,
    refetch: fetchAllData,
    clearCache,
    getPanelData
  };
};

/**
 * Hook for getting data for a single panel from dashboard data
 */
export const usePanelDataFromDashboard = (
  panelId: string,
  dashboardData: Map<string, PanelDataResult>
): PanelDataResult | undefined => {
  return dashboardData.get(panelId);
};
