import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { TransformationConfig } from '../services/transformationService';
import { API_CONFIG } from '../config/environment';

// Dashboard Variable interfaces
export interface DashboardVariableOption {
  label: string;
  value: any;
}

export interface DashboardVariable {
  name: string;
  label: string;
  type: 'multiselect' | 'singleselect';
  options: DashboardVariableOption[];
  defaultValue: any;
}

// Dashboard interfaces based on the backend schema
export interface DashboardPanel {
  id: string;
  type: 'timeseries' | 'bar' | 'pie' | 'stat' | 'table' | 'calendar';
  title: string;
  gridPos: {
    x: number;
    y: number;
    w: number;
    h: number;
  };
  query: string; // The SQL query to fetch data for this panel
  echartsOption: Record<string, any>; // Will hold the ECharts option object
  datasourceUid?: string;
  options?: Record<string, any>; // Made optional since we're using echartsOption now
  columnMapping?: {
    xAxis?: string; // Column name for x-axis
    yAxis?: string; // Column name for y-axis
    label?: string; // Column name for labels (pie charts)
  };
  transformations?: TransformationConfig[]; // Add this line
}

export interface Dashboard {
  id: string;
  uid: string;
  title: string;
  description?: string;
  config: {
    panels: DashboardPanel[];
    refresh?: string;
    time?: {
      from: string;
      to: string;
    };
  };
  variables?: DashboardVariable[];
  tags: string[];
  created_at: string;
  updated_at: string;
  created_by: string;
  is_default: boolean;
  schema_version: number;
}

export interface DashboardCreateRequest {
  title: string;
  description?: string;
  config: {
    panels: DashboardPanel[];
    refresh?: string;
    time?: {
      from: string;
      to: string;
    };
  };
  tags?: string[];
}

export interface DashboardCreateRequest {
  title: string;
  description?: string;
  config: {
    panels: DashboardPanel[];
    refresh?: string;
    time?: {
      from: string;
      to: string;
    };
  };
  tags?: string[];
}

export interface DashboardUpdateRequest {
  title?: string;
  description?: string;
  config?: {
    panels: DashboardPanel[];
    refresh?: string;
    time?: {
      from: string;
      to: string;
    };
  };
  tags?: string[];
}

interface DashboardContextType {
  // State
  dashboards: Dashboard[];
  currentDashboard: Dashboard | null;
  loading: boolean;
  error: string | null;
  
  // Actions
  fetchDashboards: () => Promise<void>;
  fetchDashboard: (id: string) => Promise<Dashboard | null>;
  createDashboard: (data: DashboardCreateRequest) => Promise<Dashboard | null>;
  updateDashboard: (id: string, data: DashboardUpdateRequest) => Promise<Dashboard | null>;
  deleteDashboard: (id: string) => Promise<boolean>;
  setDefaultDashboard: (id: string) => Promise<boolean>;
  getDefaultDashboard: () => Promise<Dashboard | null>;
  setCurrentDashboard: (dashboard: Dashboard | null) => void;
  clearError: () => void;
}

const DashboardContext = createContext<DashboardContextType | undefined>(undefined);

export const useDashboard = () => {
  const context = useContext(DashboardContext);
  if (context === undefined) {
    throw new Error('useDashboard must be used within a DashboardProvider');
  }
  return context;
};

interface DashboardProviderProps {
  children: ReactNode;
}

export const DashboardProvider: React.FC<DashboardProviderProps> = ({ children }) => {
  const [dashboards, setDashboards] = useState<Dashboard[]>([]);
  const [currentDashboard, setCurrentDashboard] = useState<Dashboard | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const API_BASE = API_CONFIG.BASE_URL;

  const clearError = useCallback(() => setError(null), []);

  const fetchDashboards = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/dashboards`);
      if (!response.ok) {
        throw new Error(`Failed to fetch dashboards: ${response.statusText}`);
      }
      const data = await response.json();
      setDashboards(data);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch dashboards';
      setError(errorMessage);
      console.error('Error fetching dashboards:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchDashboard = useCallback(async (id: string): Promise<Dashboard | null> => {
    setLoading(true);
    setError(null);
    try {
      console.log('DashboardContext - Fetching dashboard with ID:', id);
      const response = await fetch(`${API_BASE}/dashboards/${id}`);
      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`Failed to fetch dashboard: ${response.statusText}`);
      }
      const data = await response.json();
      console.log('DashboardContext - Fetched dashboard data:', data);
      console.log('DashboardContext - Dashboard title:', data.title);
      console.log('DashboardContext - Dashboard ID:', data.id);
      return data;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch dashboard';
      setError(errorMessage);
      console.error('Error fetching dashboard:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const createDashboard = useCallback(async (data: DashboardCreateRequest): Promise<Dashboard | null> => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/dashboards`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
      if (!response.ok) {
        throw new Error(`Failed to create dashboard: ${response.statusText}`);
      }
      const newDashboard = await response.json();
      
      // Update local state
      setDashboards(prev => [newDashboard, ...prev]);
      return newDashboard;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to create dashboard';
      setError(errorMessage);
      console.error('Error creating dashboard:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const updateDashboard = useCallback(async (id: string, data: DashboardUpdateRequest): Promise<Dashboard | null> => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/dashboards/${id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
      if (!response.ok) {
        throw new Error(`Failed to update dashboard: ${response.statusText}`);
      }
      const updatedDashboard = await response.json();
      
      // Update local state
      setDashboards(prev => prev.map(d => d.id === id ? updatedDashboard : d));
      if (currentDashboard?.id === id) {
        setCurrentDashboard(updatedDashboard);
        console.log('DashboardContext - Updated current dashboard:', updatedDashboard);
      }
      return updatedDashboard;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to update dashboard';
      setError(errorMessage);
      console.error('Error updating dashboard:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, [currentDashboard]);

  const deleteDashboard = useCallback(async (id: string): Promise<boolean> => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/dashboards/${id}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        throw new Error(`Failed to delete dashboard: ${response.statusText}`);
      }
      
      // Update local state
      setDashboards(prev => prev.filter(d => d.id !== id));
      if (currentDashboard?.id === id) {
        setCurrentDashboard(null);
      }
      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to delete dashboard';
      setError(errorMessage);
      console.error('Error deleting dashboard:', err);
      return false;
    } finally {
      setLoading(false);
    }
  }, [currentDashboard]);

  const setDefaultDashboard = useCallback(async (id: string): Promise<boolean> => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/dashboards/${id}/set-default`, {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error(`Failed to set default dashboard: ${response.statusText}`);
      }
      
      // Update local state
      setDashboards(prev => prev.map(d => ({
        ...d,
        is_default: d.id === id
      })));
      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to set default dashboard';
      setError(errorMessage);
      console.error('Error setting default dashboard:', err);
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  const getDefaultDashboard = useCallback(async (): Promise<Dashboard | null> => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/dashboards/default`);
      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`Failed to get default dashboard: ${response.statusText}`);
      }
      const data = await response.json();
      return data;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to get default dashboard';
      setError(errorMessage);
      console.error('Error getting default dashboard:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const setCurrentDashboardCallback = useCallback((dashboard: Dashboard | null) => {
    console.log('DashboardContext - Setting current dashboard:', dashboard);
    console.log('DashboardContext - New dashboard title:', dashboard?.title);
    console.log('DashboardContext - New dashboard ID:', dashboard?.id);
    setCurrentDashboard(dashboard);
  }, []);

  // Load dashboards on mount
  useEffect(() => {
    fetchDashboards();
  }, [fetchDashboards]);

  const value: DashboardContextType = {
    dashboards,
    currentDashboard,
    loading,
    error,
    fetchDashboards,
    fetchDashboard,
    createDashboard,
    updateDashboard,
    deleteDashboard,
    setDefaultDashboard,
    getDefaultDashboard,
    setCurrentDashboard: setCurrentDashboardCallback,
    clearError,
  };

  return (
    <DashboardContext.Provider value={value}>
      {children}
    </DashboardContext.Provider>
  );
};
