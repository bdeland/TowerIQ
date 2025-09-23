/**
 * useDeviceData.ts - Custom hook for device data management
 * 
 * Manages device loading, processes, hook scripts, and related data
 */

import { useState, useEffect, useCallback } from 'react';
import { Device, Process, HookScript, ScriptStatus, FridaStatus, AdbStatus, useBackend } from './useBackend';

export function useDeviceData() {
  // Backend Data State
  const [devices, setDevices] = useState<Device[]>([]);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [hookScripts, setHookScripts] = useState<HookScript[]>([]);
  const [selectedHookScript, setSelectedHookScript] = useState<HookScript | null>(null);

  // Loading States - derived from backend session state
  const [devicesLoading, setDevicesLoading] = useState(false);
  const [processesLoading, setProcessesLoading] = useState(false);

  // Script Status State
  const [scriptStatus, setScriptStatus] = useState<ScriptStatus | null>(null);
  const [scriptStatusLoading, setScriptStatusLoading] = useState(false);

  // Frida Server Status State
  const [fridaStatus, setFridaStatus] = useState<FridaStatus | null>(null);
  const [fridaStatusLoading, setFridaStatusLoading] = useState(false);
  const [fridaError, setFridaError] = useState<string | null>(null);

  // ADB Server Status State
  const [adbStatus, setAdbStatus] = useState<AdbStatus | null>(null);
  const [isAdbRestarting, setIsAdbRestarting] = useState(false);

  // Process Search State
  const [processSearchTerm, setProcessSearchTerm] = useState<string>('');

  const {
    status,
    scanDevices,
    refreshDevices,
    getProcesses,
    getHookScripts,
    getFridaStatus,
    getScriptStatus,
    getAdbStatus,
    startAdbServer,
    killAdbServer,
    restartAdbServer
  } = useBackend();

  // Load devices from backend with proper loading state management
  const loadDevices = useCallback(async () => {
    try {
      setDevicesLoading(true);
      const deviceList = await scanDevices();
      setDevices(deviceList);
    } catch (err) {
      console.error('Failed to load devices:', err);
    } finally {
      setDevicesLoading(false);
    }
  }, [scanDevices]);

  // Load hook scripts from backend
  const loadHookScripts = useCallback(async () => {
    try {
      const scriptList = await getHookScripts();
      setHookScripts(scriptList);
    } catch (err) {
      console.error('Failed to load hook scripts:', err);
    }
  }, [getHookScripts]);

  // Load script status from backend
  const loadScriptStatus = useCallback(async () => {
    try {
      setScriptStatusLoading(true);
      const status = await getScriptStatus();
      setScriptStatus(status);
    } catch (err) {
      console.error('Failed to load script status:', err);
    } finally {
      setScriptStatusLoading(false);
    }
  }, [getScriptStatus]);

  // Load Frida status from backend
  const loadFridaStatus = useCallback(async (deviceId: string) => {
    try {
      setFridaStatusLoading(true);
      setFridaError(null);
      console.log('Loading Frida status for device:', deviceId);
      const status = await getFridaStatus(deviceId);
      console.log('Frida status received:', status);
      setFridaStatus(status);
    } catch (err) {
      console.error('Failed to load Frida status:', err);
      setFridaStatus(null);
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      setFridaError(`Failed to load Frida status: ${errorMsg}`);
    } finally {
      setFridaStatusLoading(false);
    }
  }, [getFridaStatus]);

  // Centralized ADB state updater
  const updateAdbState = useCallback(async (shouldRefreshDevices?: boolean) => {
    await new Promise((resolve) => setTimeout(resolve, 500));
    const status = await getAdbStatus();
    setAdbStatus(status);
    if (shouldRefreshDevices) {
      try {
        const deviceList = await refreshDevices();
        setDevices(deviceList);
      } catch (e) {}
    }
  }, [getAdbStatus, refreshDevices]);

  // Handle refresh devices with proper loading state management
  const handleRefreshDevices = useCallback(async () => {
    try {
      setDevicesLoading(true);
      setDevices([]);
      const deviceList = await refreshDevices();
      setDevices(deviceList);
    } catch (err) {
      console.error('Failed to refresh devices:', err);
    } finally {
      setDevicesLoading(false);
    }
  }, [refreshDevices]);

  // ADB Server Management Handlers
  const handleRestartAdbServer = useCallback(async () => {
    try {
      setIsAdbRestarting(true);
      setDevices([]);
      await restartAdbServer();
      await updateAdbState(true);
    } catch (err) {
      console.error('Failed to restart ADB server:', err);
    } finally {
      setIsAdbRestarting(false);
    }
  }, [restartAdbServer, updateAdbState]);

  const handleStartAdbServer = useCallback(async () => {
    try {
      setIsAdbRestarting(true);
      await startAdbServer();
      await updateAdbState(true);
    } catch (err) {
      console.error('Failed to start ADB server:', err);
    } finally {
      setIsAdbRestarting(false);
    }
  }, [startAdbServer, updateAdbState]);

  const handleKillAdbServer = useCallback(async () => {
    try {
      setIsAdbRestarting(true);
      await killAdbServer();
      setDevices([]);
      await updateAdbState();
    } catch (err) {
      console.error('Failed to kill ADB server:', err);
    } finally {
      setIsAdbRestarting(false);
    }
  }, [killAdbServer, updateAdbState]);

  // Initial data loading effect - only run once on mount
  useEffect(() => {
    console.log('DeviceData: Component mounted');
    
    // Load initial data
    const initializeData = async () => {
      try {
        await Promise.all([
          loadDevices(),
          loadHookScripts(),
          loadScriptStatus(),
          (async () => {
            try {
              const status = await getAdbStatus();
              setAdbStatus(status);
            } catch (e) {
              // ignore, UI will show unknown
            }
          })()
        ]);
      } catch (err) {
        console.error('Failed to initialize device data:', err);
      }
    };
    
    initializeData();
  }, []); // Empty dependency array - run only once on mount

  // Auto-select first hook script when scripts change
  useEffect(() => {
    if (hookScripts.length > 0 && !selectedHookScript) {
      setSelectedHookScript(hookScripts[0]);
    }
  }, [hookScripts, selectedHookScript]);

  // Script status loading effect
  useEffect(() => {
    if (!status?.session.is_connected) {
      setScriptStatus(null);
      return;
    }

    const loadScriptStatusEffect = async () => {
      try {
        const status = await getScriptStatus();
        setScriptStatus(status);
      } catch (err) {
        console.error('Failed to load script status:', err);
      }
    };

    loadScriptStatusEffect();
  }, [status?.session.is_connected]); // Remove getScriptStatus dependency

  // Use proper loading state management instead of deriving from backend session

  return {
    // Data
    devices,
    processes,
    hookScripts,
    selectedHookScript,
    scriptStatus,
    fridaStatus,
    adbStatus,
    processSearchTerm,
    // Loading states - derived from backend session
    devicesLoading,
    processesLoading,
    scriptStatusLoading,
    fridaStatusLoading,
    isAdbRestarting,
    // Errors
    fridaError,
    // Setters
    setDevices,
    setProcesses,
    setSelectedHookScript,
    setScriptStatus,
    setFridaStatus,
    setFridaError,
    setProcessSearchTerm,
    setDevicesLoading,
    setProcessesLoading,
    // Functions
    loadDevices,
    loadHookScripts,
    loadScriptStatus,
    loadFridaStatus,
    handleRefreshDevices,
    handleRestartAdbServer,
    handleStartAdbServer,
    handleKillAdbServer
  };
}
