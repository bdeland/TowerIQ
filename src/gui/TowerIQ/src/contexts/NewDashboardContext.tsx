import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';



import { DashboardManager } from '../domain/dashboard/DashboardManager';



import { Dashboard } from '../domain/dashboard/Dashboard';



import type {



  DashboardConfig,



  DashboardMetadata,



  PanelConfig,



  VariableConfig,



  PanelState as DomainPanelState,



} from '../domain/dashboard/types';



interface NewDashboardContextValue {



  dashboardManager: DashboardManager;



  currentDashboard: Dashboard | null;



  loading: boolean;



  error: Error | null;



  panelStates: Map<string, PanelState>;



  loadDashboard: (id: string) => Promise<void>;



  updateVariable: (name: string, value: any) => void;



  refreshPanel: (panelId: string) => Promise<void>;



  refreshAll: () => Promise<void>;



  createDashboard: (config: DashboardConfig) => Promise<Dashboard>;



  updateDashboard: (id: string, updates: Partial<DashboardConfig>) => Promise<void>;



  deleteDashboard: (id: string) => Promise<void>;



  onDashboardUpdated: (callback: (dashboard: Dashboard) => void) => () => void;



  onPanelStateChanged: (callback: (panelId: string, state: PanelState) => void) => () => void;



}



type PanelState = DomainPanelState;

const mapDomainPanelState = (state?: DomainPanelState | null): PanelState => ({
  status: state?.status ?? 'idle',
  data: state?.data ?? null,
  error: state?.error ?? null,
  loading: state?.loading ?? false,
  lastUpdated: state?.lastUpdated ?? 0,
});

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



  const buildPanelStateMap = useCallback((dashboardInstance: Dashboard) => {



    const states = new Map<string, PanelState>();



    dashboardInstance.panels.forEach((panel, panelId) => {



      const domainState = dashboardInstance.getPanelState(panelId) ?? panel.getState();



      states.set(panelId, mapDomainPanelState(domainState));



    });



    return states;



  }, []);



  const refreshPanel = useCallback(



    async (panelId: string) => {



      if (!currentDashboard) {



        return;



      }



      setPanelStates((prev) => {



        const next = new Map(prev);



        const previous = next.get(panelId) ?? mapDomainPanelState(null);

        next.set(panelId, { ...previous, status: 'loading', error: null });



        return next;



      });



      try {



        await currentDashboard.refreshPanel(panelId);



      } catch (err) {



        const panelError = err instanceof Error ? err : new Error('Failed to fetch panel data');



        setError(panelError);



      } finally {



        const domainState = currentDashboard.getPanelState(panelId);



        setPanelStates((prev) => {



          const next = new Map(prev);



          next.set(panelId, mapDomainPanelState(domainState));



          return next;



        });



      }



    },



    [currentDashboard],



  );



  const refreshAll = useCallback(async () => {



    if (!currentDashboard) {



      return;



    }



    setLoading(true);



    setError(null);



    try {



      await currentDashboard.refreshData();



      setPanelStates(buildPanelStateMap(currentDashboard));



    } catch (err) {



      const refreshError = err instanceof Error ? err : new Error('Failed to refresh dashboard');



      setError(refreshError);



      console.error('Error refreshing dashboard:', refreshError);



    } finally {



      setLoading(false);



    }



  }, [currentDashboard, buildPanelStateMap]);



  const loadDashboard = useCallback(



    async (id: string) => {



      setLoading(true);



      setError(null);



      try {



        const dashboard = await dashboardManager.loadDashboard(id);



        await dashboard.loadData();



        setCurrentDashboard(dashboard);



        setPanelStates(buildPanelStateMap(dashboard));



      } catch (err) {



        const loadError = err instanceof Error ? err : new Error('Failed to load dashboard');



        setError(loadError);



        console.error('Error loading dashboard:', loadError);



      } finally {



        setLoading(false);



      }



    },



    [dashboardManager, buildPanelStateMap],



  );



  const updateVariable = useCallback(



    (name: string, value: any) => {



      if (!currentDashboard) {



        return;



      }



      try {



        currentDashboard.updateVariable(name, value);



        currentDashboard.getAffectedPanels(name).forEach((panel) => {



          void refreshPanel(panel.id);



        });



      } catch (err) {



        const variableError = err instanceof Error ? err : new Error('Failed to update variable');



        setError(variableError);



        console.error('Error updating variable:', variableError);



      }



    },



    [currentDashboard, refreshPanel],



  );



  const createDashboard = useCallback(



    async (config: DashboardConfig): Promise<Dashboard> => {



      setLoading(true);



      setError(null);



      try {



        const dashboard = await dashboardManager.createDashboard(config);



        return dashboard;



      } catch (err) {



        const createError = err instanceof Error ? err : new Error('Failed to create dashboard');



        setError(createError);



        throw createError;



      } finally {



        setLoading(false);



      }



    },



    [dashboardManager],



  );



  const updateDashboard = useCallback(



    async (id: string, updates: Partial<DashboardConfig>) => {



      if (!currentDashboard || currentDashboard.id !== id) {



        return;



      }



      setLoading(true);



      setError(null);



      try {



        const updatedDashboard = await dashboardManager.updateDashboard(id, updates);



        setCurrentDashboard(updatedDashboard);



        setPanelStates(buildPanelStateMap(updatedDashboard));



      } catch (err) {



        const updateError = err instanceof Error ? err : new Error('Failed to update dashboard');



        setError(updateError);



        console.error('Error updating dashboard:', updateError);



      } finally {



        setLoading(false);



      }



    },



    [currentDashboard, dashboardManager, buildPanelStateMap],



  );



  const deleteDashboard = useCallback(



    async (id: string) => {



      setLoading(true);



      setError(null);



      try {



        const deleted = await dashboardManager.deleteDashboard(id);



        if (deleted && currentDashboard?.id === id) {



          setCurrentDashboard(null);



          setPanelStates(new Map());



        }



      } catch (err) {



        const deleteError = err instanceof Error ? err : new Error('Failed to delete dashboard');



        setError(deleteError);



        console.error('Error deleting dashboard:', deleteError);



      } finally {



        setLoading(false);



      }



    },



    [currentDashboard, dashboardManager],



  );



  const onDashboardUpdated = useCallback(



    (callback: (dashboard: Dashboard) => void) => {



      if (!currentDashboard) {



        return () => {};



      }



      const handler = (dashboard: Dashboard) => {



        callback(dashboard);



      };



      currentDashboard.on('dashboardUpdated', handler);



      return () => currentDashboard.off('dashboardUpdated', handler);



    },



    [currentDashboard],



  );



  const onPanelStateChanged = useCallback(



    (callback: (panelId: string, state: PanelState) => void) => {



      if (!currentDashboard) {



        return () => {};



      }



      const handler = (event: { panelId: string; state: DomainPanelState }) => {



        const panelState = mapDomainPanelState(event.state);



        setPanelStates((prev) => {



          const next = new Map(prev);



          next.set(event.panelId, panelState);



          return next;



        });



        callback(event.panelId, panelState);



      };



      currentDashboard.on('panelStateChanged', handler);



      return () => currentDashboard.off('panelStateChanged', handler);



    },



    [currentDashboard],



  );



  useEffect(() => {



    if (!currentDashboard) {



      return;



    }



    const handleDashboardUpdate = (dashboard: Dashboard) => {



      setCurrentDashboard(dashboard);



      setPanelStates(buildPanelStateMap(dashboard));



    };



    const handlePanelStateChange = (event: { panelId: string; state: DomainPanelState }) => {



      const panelState = mapDomainPanelState(event.state);



      setPanelStates((prev) => {



        const next = new Map(prev);



        next.set(event.panelId, panelState);



        return next;



      });



    };



    const handleVariableUpdate = (event: { name: string; value: any }) => {



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



  }, [currentDashboard, buildPanelStateMap]);



  useEffect(() => {



    dashboardManager.initialize().catch((err) => {



      const initError = err instanceof Error ? err : new Error('Failed to initialize dashboard manager');



      console.error('Failed to initialize dashboard manager:', initError);



      setError(initError);



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

