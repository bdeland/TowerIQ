import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { DashboardManager } from '../domain/dashboard/DashboardManager';
import { Dashboard } from '../domain/dashboard/Dashboard';
import { Panel } from '../domain/dashboard/Panel';
import { DashboardError } from '../domain/dashboard/types';
import { API_CONFIG } from '../config/environment';

interface NewDashboardContextValue {
  // Core domain model access
  dashboardManager: DashboardManager;
  currentDashboard: Dashboard | null;
  
  // State
  loading: boolean;
  error: Error | null;
  panelStates: Map<string, PanelState>;
  
  // Actions
  loadDashboard: (id: string) => Promise<void>;
  updateVariable: (name: string, value: any) => void;
  refreshPanel: (panelId: string) => Promise<void>;
  refreshAll: () => Promise<void>;
  createDashboard: (config: DashboardConfig) => Promise<Dashboard>;
  updateDashboard: (id: string, updates: Partial<DashboardConfig>) => Promise<void>;
  deleteDashboard: (id: string) => Promise<void>;
  
  // Event handlers
  onDashboardUpdated: (callback: (dashboard: Dashboard) => void) => () => void;
  onPanelStateChanged: (callback: (panelId: string, state: PanelState) => void) => () => void;
}

interface PanelState {
  status: 'idle' | 'loading' | 'loaded' | 'error';
  data?: any;
  error?: Error;
  lastUpdated?: Date;
}

// Import domain model types
import type { 
  DashboardConfig,
  DashboardMetadata,
  PanelConfig,
  VariableConfig 
} from '../domain/dashboard/types';

const NewDashboardContext = createContext<NewDashboardContextValue | undefined>(undefined);

export const useNewDashboard = () => {
  const context = useContext(NewDashboardContext);
  if (context === undefined) {
    throw new Error('useNewDashboard must be used within a NewDashboardProvider');
  }
  return context;
};

interface NewDashboardProviderProps {
  children: ReactNode;
}

export const NewDashboardProvider: React.FC<NewDashboardProviderProps> = ({ children }) => {
  const [dashboardManager] = useState(() => DashboardManager.getInstance());
  const [currentDashboard, setCurrentDashboard] = useState<Dashboard | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [panelStates, setPanelStates] = useState<Map<string, PanelState>>(new Map());

  // Dashboard loading
  const loadDashboard = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    
    try {
      let dashboard = dashboardManager.getDashboard(id);
      
      if (!dashboard) {
        // Load from database if not in memory
        const config = await fetchDashboardConfig(id);
        if (!config) {
          throw new DashboardError(`Dashboard with id ${id} not found`);
        }
        dashboard = dashboardManager.createDashboard(config);
      }
      
      setCurrentDashboard(dashboard);
      
      // Initialize panel states
      const initialStates = new Map<string, PanelState>();
      dashboard.panels.forEach((panel, panelId) => {
        initialStates.set(panelId, { status: 'idle' });
      });
      setPanelStates(initialStates);
      
      // Start loading panel data
      await refreshAll();
      
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to load dashboard');
      setError(error);
      console.error('Error loading dashboard:', error);
    } finally {
      setLoading(false);
    }
  }, [dashboardManager]);

  // Variable updates
  const updateVariable = useCallback((name: string, value: any) => {
    if (!currentDashboard) return;
    
    try {
      currentDashboard.updateVariable(name, value);
      
      // Refresh affected panels
      const affectedPanels = currentDashboard.getAffectedPanels(name);
      affectedPanels.forEach(panel => {
        refreshPanel(panel.id);
      });
      
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to update variable');
      setError(error);
      console.error('Error updating variable:', error);
    }
  }, [currentDashboard]);

  // Panel refresh
  const refreshPanel = useCallback(async (panelId: string) => {
    if (!currentDashboard) return;
    
    const panel = currentDashboard.panels.get(panelId);
    if (!panel) return;
    
    // Update panel state to loading
    setPanelStates(prev => new Map(prev.set(panelId, { 
      ...prev.get(panelId), 
      status: 'loading' 
    })));
    
    try {
      const variables = currentDashboard.variables.getValues();
      const data = await panel.fetchData(variables);
      
      setPanelStates(prev => new Map(prev.set(panelId, {
        status: 'loaded',
        data,
        lastUpdated: new Date()
      })));
      
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to fetch panel data');
      setPanelStates(prev => new Map(prev.set(panelId, {
        status: 'error',
        error,
        lastUpdated: new Date()
      })));
    }
  }, [currentDashboard]);

  // Refresh all panels
  const refreshAll = useCallback(async () => {
    if (!currentDashboard) return;
    
    const panelIds = Array.from(currentDashboard.panels.keys());
    
    // Use Promise.allSettled for parallel loading (Phase 1 goal: 3-5x faster)
    await Promise.allSettled(
      panelIds.map(panelId => refreshPanel(panelId))
    );
  }, [currentDashboard, refreshPanel]);

  // Dashboard CRUD operations
  const createDashboard = useCallback(async (config: DashboardConfig): Promise<Dashboard> => {
    setLoading(true);
    setError(null);
    
    try {
      const dashboard = dashboardManager.createDashboard(config);
      await saveDashboardConfig(config); // Save to backend
      return dashboard;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to create dashboard');
      setError(error);
      throw error;
    } finally {
      setLoading(false);
    }
  }, [dashboardManager]);

  const updateDashboard = useCallback(async (id: string, updates: Partial<DashboardConfig>) => {
    if (!currentDashboard || currentDashboard.id !== id) return;
    
    setLoading(true);
    setError(null);
    
    try {
      currentDashboard.updateConfig(updates);
      await saveDashboardConfig(currentDashboard.serialize()); // Save to backend
      
      // Trigger re-render
      setCurrentDashboard({ ...currentDashboard });
      
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to update dashboard');
      setError(error);
      console.error('Error updating dashboard:', error);
    } finally {
      setLoading(false);
    }
  }, [currentDashboard]);

  const deleteDashboard = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    
    try {
      dashboardManager.deleteDashboard(id);
      await deleteDashboardConfig(id); // Delete from backend
      
      if (currentDashboard?.id === id) {
        setCurrentDashboard(null);
        setPanelStates(new Map());
      }
      
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to delete dashboard');
      setError(error);
      console.error('Error deleting dashboard:', error);
    } finally {
      setLoading(false);
    }
  }, [dashboardManager, currentDashboard]);

  // Event handling for dashboard updates
  const onDashboardUpdated = useCallback((callback: (dashboard: Dashboard) => void) => {
    const handler = (dashboard: Dashboard) => {
      if (dashboard === currentDashboard) {
        callback(dashboard);
        // Trigger React re-render
        setCurrentDashboard({ ...dashboard });
      }
    };
    
    dashboardManager.on('dashboardUpdated', handler);
    return () => dashboardManager.off('dashboardUpdated', handler);
  }, [dashboardManager, currentDashboard]);

  // Event handling for panel state changes
  const onPanelStateChanged = useCallback((callback: (panelId: string, state: PanelState) => void) => {
    const handler = (event: { panelId: string; state: any }) => {
      const panelState: PanelState = {
        status: event.state.status,
        data: event.state.data,
        error: event.state.error,
        lastUpdated: new Date()
      };
      
      setPanelStates(prev => new Map(prev.set(event.panelId, panelState)));
      callback(event.panelId, panelState);
    };
    
    currentDashboard?.on('panelStateChanged', handler);
    return () => currentDashboard?.off('panelStateChanged', handler);
  }, [currentDashboard]);

  // Set up dashboard event listeners
  useEffect(() => {
    if (!currentDashboard) return;
    
    const handleDashboardUpdate = (dashboard: Dashboard) => {
      setCurrentDashboard({ ...dashboard }); // Trigger re-render
    };
    
    const handlePanelStateChange = (event: { panelId: string; state: any }) => {
      const panelState: PanelState = {
        status: event.state.status,
        data: event.state.data,
        error: event.state.error,
        lastUpdated: new Date()
      };
      
      setPanelStates(prev => new Map(prev.set(event.panelId, panelState)));
    };
    
    const handleVariableUpdate = (event: { name: string; value: any }) => {
      // Variable updates trigger panel refreshes automatically
      console.log(`Variable ${event.name} updated to:`, event.value);
    };
    
    currentDashboard.on('dashboardUpdated', handleDashboardUpdate);
    currentDashboard.on('panelStateChanged', handlePanelStateChange);
    currentDashboard.on('variableUpdated', handleVariableUpdate);
    
    return () => {
      currentDashboard.off('dashboardUpdated', handleDashboardUpdate);
      currentDashboard.off('panelStateChanged', handlePanelStateChange);
      currentDashboard.off('variableUpdated', handleVariableUpdate);
    };
  }, [currentDashboard]);

  // Initialize dashboard manager on mount
  useEffect(() => {
    dashboardManager.initialize().catch(err => {
      console.error('Failed to initialize dashboard manager:', err);
      setError(err instanceof Error ? err : new Error('Failed to initialize dashboard manager'));
    });
  }, [dashboardManager]);

  const value: NewDashboardContextValue = {
    dashboardManager,
    currentDashboard,
    loading,
    error,
    panelStates,
    loadDashboard,
    updateVariable,
    refreshPanel,
    refreshAll,
    createDashboard,
    updateDashboard,
    deleteDashboard,
    onDashboardUpdated,
    onPanelStateChanged,
  };

  return (
    <NewDashboardContext.Provider value={value}>
      {children}
    </NewDashboardContext.Provider>
  );
};

// Helper functions for backend integration (will use v2 API endpoints from Phase 1B)
async function fetchDashboardConfig(id: string): Promise<DashboardConfig | null> {
  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/v2/dashboards/${id}`);
    if (!response.ok) {
      if (response.status === 404) return null;
      throw new Error(`Failed to fetch dashboard: ${response.statusText}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching dashboard config:', error);
    return null;
  }
}

async function saveDashboardConfig(config: DashboardConfig): Promise<void> {
  try {
    const method = config.id ? 'PUT' : 'POST';
    const url = config.id ? `${API_CONFIG.BASE_URL}/v2/dashboards/${config.id}` : `${API_CONFIG.BASE_URL}/v2/dashboards`;
    
    const response = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    
    if (!response.ok) {
      throw new Error(`Failed to save dashboard: ${response.statusText}`);
    }
  } catch (error) {
    console.error('Error saving dashboard config:', error);
    throw error;
  }
}

async function deleteDashboardConfig(id: string): Promise<void> {
  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/v2/dashboards/${id}`, {
      method: 'DELETE',
    });
    
    if (!response.ok) {
      throw new Error(`Failed to delete dashboard: ${response.statusText}`);
    }
  } catch (error) {
    console.error('Error deleting dashboard config:', error);
    throw error;
  }
}
