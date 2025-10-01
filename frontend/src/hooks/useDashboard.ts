import { useState, useEffect, useCallback, useMemo } from 'react';
import { useNewDashboard } from '../contexts/NewDashboardContext';
import { Dashboard } from '../domain/dashboard/Dashboard';
import { Panel } from '../domain/dashboard/Panel';
import type { DashboardState, PanelState, VariableValues } from '../domain/dashboard/types';

// Re-export types for other components
export type { PanelState, VariableValues } from '../domain/dashboard/types';

interface UseDashboardOptions {
  dashboardId?: string;
  autoLoad?: boolean;
  refreshInterval?: number;
}

interface UseDashboardReturn {
  // Dashboard state
  dashboard: Dashboard | null;
  dashboardState: DashboardState | null;
  panelStates: Map<string, PanelState>;
  
  // Loading and error states
  loading: boolean;
  error: Error | null;
  
  // Dashboard metadata
  metadata: {
    title: string;
    description?: string;
    panelCount: number;
    variableCount: number;
    lastUpdated?: Date;
  } | null;
  
  // Panel access
  panels: Panel[];
  getPanelById: (panelId: string) => Panel | null;
  getPanelState: (panelId: string) => PanelState | null;
  
  // Variable access
  variables: VariableValues;
  getVariableValue: (name: string) => any;
  getVariableOptions: (name: string) => Array<{label: string; value: any}>;
  
  // Actions
  actions: {
    loadDashboard: (id: string) => Promise<void>;
    refreshDashboard: () => Promise<void>;
    refreshPanel: (panelId: string) => Promise<void>;
    updateVariable: (name: string, value: any) => void;
    resetVariables: () => void;
    
    // Panel actions
    addPanel: (config: any) => void;
    removePanel: (panelId: string) => void;
    updatePanel: (panelId: string, config: any) => void;
    
    // Dashboard actions
    updateDashboardMetadata: (metadata: { title?: string; description?: string }) => Promise<void>;
    saveDashboard: () => Promise<void>;
  };
  
  // Reactive subscriptions
  subscribe: {
    onDashboardUpdate: (callback: (dashboard: Dashboard) => void) => () => void;
    onPanelStateChange: (panelId: string, callback: (state: PanelState) => void) => () => void;
    onVariableChange: (variableName: string, callback: (value: any) => void) => () => void;
    onError: (callback: (error: Error) => void) => () => void;
  };
}

export const useDashboard = (options: UseDashboardOptions = {}): UseDashboardReturn => {
  const { dashboardId, autoLoad = true, refreshInterval } = options;
  const newDashboardContext = useNewDashboard();
  
  const [dashboardState, setDashboardState] = useState<DashboardState | null>(null);
  const [subscriptions, setSubscriptions] = useState<Map<string, () => void>>(new Map());

  // Get current dashboard from context
  const dashboard = newDashboardContext.currentDashboard;
  const panelStates = newDashboardContext.panelStates;
  const loading = newDashboardContext.loading;
  const error = newDashboardContext.error;

  // Load dashboard if dashboardId provided and autoLoad enabled
  useEffect(() => {
    if (dashboardId && autoLoad && (!dashboard || dashboard.id !== dashboardId)) {
      newDashboardContext.loadDashboard(dashboardId);
    }
  }, [dashboardId, autoLoad, dashboard, newDashboardContext]);

  // Subscribe to dashboard state changes
  useEffect(() => {
    if (!dashboard) {
      setDashboardState(null);
      return;
    }

    // Get initial state
    setDashboardState(dashboard.getState());

    // Subscribe to state changes
    const unsubscribe = dashboard.subscribe((state) => {
      setDashboardState(state);
    });

    return unsubscribe;
  }, [dashboard]);

  // Set up refresh interval if specified
  useEffect(() => {
    if (!refreshInterval || !dashboard) return;

    const interval = setInterval(() => {
      newDashboardContext.refreshAll();
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [refreshInterval, dashboard, newDashboardContext]);

  // Cleanup subscriptions on unmount
  useEffect(() => {
    return () => {
      subscriptions.forEach(unsubscribe => unsubscribe());
    };
  }, [subscriptions]);

  // Memoized dashboard metadata
  const metadata = useMemo(() => {
    if (!dashboard || !dashboardState) return null;

    return {
      title: dashboard.metadata.title,
      description: dashboard.metadata.description,
      panelCount: dashboard.panels.size,
      variableCount: dashboard.variables.definitions.size,
      lastUpdated: dashboardState.lastUpdated ? new Date(dashboardState.lastUpdated) : undefined,
    };
  }, [dashboard, dashboardState]);

  // Memoized panels array
  const panels = useMemo(() => {
    if (!dashboard) return [];
    return Array.from(dashboard.panels.values());
  }, [dashboard]);

  // Panel access functions
  const getPanelById = useCallback((panelId: string): Panel | null => {
    return dashboard?.panels.get(panelId) || null;
  }, [dashboard]);

  const getPanelState = useCallback((panelId: string): PanelState | null => {
    return panelStates.get(panelId) || null;
  }, [panelStates]);

  // Variable access
  const variables = useMemo((): VariableValues => {
    return dashboard?.variables.getValues() || {};
  }, [dashboard, dashboardState?.variableValues]);

  const getVariableValue = useCallback((name: string): any => {
    return dashboard?.variables.getValue(name);
  }, [dashboard, dashboardState?.variableValues]);

  const getVariableOptions = useCallback((name: string): Array<{label: string; value: any}> => {
    return dashboard?.variables.getOptions(name) || [];
  }, [dashboard]);

  // Actions object
  const actions = useMemo(() => ({
    loadDashboard: newDashboardContext.loadDashboard,
    refreshDashboard: newDashboardContext.refreshAll,
    refreshPanel: newDashboardContext.refreshPanel,
    updateVariable: newDashboardContext.updateVariable,
    
    resetVariables: () => {
      if (!dashboard) return;
      dashboard.variables.resetToDefaults();
    },
    
    addPanel: (config: any) => {
      if (!dashboard) return;
      dashboard.addPanel(new Panel(config));
    },
    
    removePanel: (panelId: string) => {
      if (!dashboard) return;
      dashboard.removePanel(panelId);
    },
    
    updatePanel: (panelId: string, config: any) => {
      if (!dashboard) return;

      const panelConfig = config?.config ?? config;
      if (!panelConfig) {
        return;
      }

      dashboard.removePanel(panelId);
      dashboard.addPanel(new Panel(panelConfig));
    },
    
    updateDashboardMetadata: async (metadata: { title?: string; description?: string }) => {
      if (!dashboard) return;
      
      const currentConfig = dashboard.serialize();
      const updatedConfig = {
        ...currentConfig,
        metadata: {
          ...currentConfig.metadata,
          ...metadata,
        },
      };
      
      await newDashboardContext.updateDashboard(dashboard.id, updatedConfig);
    },
    
    saveDashboard: async () => {
      if (!dashboard) return;
      const config = dashboard.serialize();
      await newDashboardContext.updateDashboard(dashboard.id, config);
    },
  }), [dashboard, newDashboardContext]);

  // Subscription functions
  const subscribe = useMemo(() => ({
    onDashboardUpdate: (callback: (dashboard: Dashboard) => void) => {
      if (!dashboard) return () => {};
      
      const handler = (updatedDashboard: Dashboard) => {
        if (updatedDashboard === dashboard) {
          callback(updatedDashboard);
        }
      };
      
      const unsubscribe = newDashboardContext.onDashboardUpdated(handler);
      
      // Track subscription for cleanup
      const subscriptionId = `dashboard-${Date.now()}-${Math.random()}`;
      setSubscriptions(prev => new Map(prev.set(subscriptionId, unsubscribe)));
      
      return () => {
        unsubscribe();
        setSubscriptions(prev => {
          const newSubs = new Map(prev);
          newSubs.delete(subscriptionId);
          return newSubs;
        });
      };
    },
    
    onPanelStateChange: (panelId: string, callback: (state: PanelState) => void) => {
      const handler = (id: string, state: PanelState) => {
        if (id === panelId) {
          callback(state);
        }
      };
      
      const unsubscribe = newDashboardContext.onPanelStateChanged(handler);
      
      const subscriptionId = `panel-${panelId}-${Date.now()}`;
      setSubscriptions(prev => new Map(prev.set(subscriptionId, unsubscribe)));
      
      return () => {
        unsubscribe();
        setSubscriptions(prev => {
          const newSubs = new Map(prev);
          newSubs.delete(subscriptionId);
          return newSubs;
        });
      };
    },
    
    onVariableChange: (variableName: string, callback: (value: any) => void) => {
      if (!dashboard) return () => {};
      
      const handler = (event: { name: string; value: any }) => {
        if (event.name === variableName) {
          callback(event.value);
        }
      };
      
      dashboard.on('variableUpdated', handler);
      
      const subscriptionId = `variable-${variableName}-${Date.now()}`;
      const unsubscribe = () => dashboard.off('variableUpdated', handler);
      
      setSubscriptions(prev => new Map(prev.set(subscriptionId, unsubscribe)));
      
      return () => {
        unsubscribe();
        setSubscriptions(prev => {
          const newSubs = new Map(prev);
          newSubs.delete(subscriptionId);
          return newSubs;
        });
      };
    },
    
    onError: (callback: (error: Error) => void) => {
      // Subscribe to context error changes
      const subscriptionId = `error-${Date.now()}`;
      
      // This would be handled by the context's error state changes
      // For now, we'll just return a no-op cleanup function
      const unsubscribe = () => {};
      
      setSubscriptions(prev => new Map(prev.set(subscriptionId, unsubscribe)));
      
      return () => {
        unsubscribe();
        setSubscriptions(prev => {
          const newSubs = new Map(prev);
          newSubs.delete(subscriptionId);
          return newSubs;
        });
      };
    },
  }), [dashboard, newDashboardContext]);

  return {
    dashboard,
    dashboardState,
    panelStates,
    loading,
    error,
    metadata,
    panels,
    getPanelById,
    getPanelState,
    variables,
    getVariableValue,
    getVariableOptions,
    actions,
    subscribe,
  };
};

// Specialized hooks for common use cases
export const useDashboardPanel = (panelId: string) => {
  const { getPanelById, getPanelState, actions } = useDashboard();
  
  const panel = getPanelById(panelId);
  const state = getPanelState(panelId);
  
  return {
    panel,
    state,
    refresh: () => actions.refreshPanel(panelId),
    update: (config: any) => actions.updatePanel(panelId, config),
    remove: () => actions.removePanel(panelId),
  };
};

export const useDashboardVariable = (variableName: string) => {
  const { getVariableValue, getVariableOptions, actions, subscribe } = useDashboard();
  const [value, setValue] = useState(() => getVariableValue(variableName));
  const [options] = useState(() => getVariableOptions(variableName));
  
  // Subscribe to variable changes
  useEffect(() => {
    const unsubscribe = subscribe.onVariableChange(variableName, setValue);
    return unsubscribe;
  }, [variableName, subscribe]);
  
  return {
    value,
    options,
    setValue: (newValue: any) => actions.updateVariable(variableName, newValue),
  };
};
