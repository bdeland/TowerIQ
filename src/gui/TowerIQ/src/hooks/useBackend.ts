import { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';

export interface SessionState {
  is_connected: boolean;
  current_device?: string;
  current_process?: any;
  test_mode: boolean;
  connection_stage?: string;
  connection_message?: string;
}

export interface Device {
  id: string;
  name: string;
  type: string;
  status: 'device' | 'offline' | 'unauthorized' | 'no permissions' | string;  // Raw ADB status
  serial: string;
  model: string;
  device_name?: string;  // Human-readable device name like "Samsung Galaxy S21 Ultra"
  brand?: string;        // Device brand like "Samsung", "OnePlus", etc.
  android_version: string;
  api_level: number;
  architecture: string;
  is_network_device: boolean;
  ip_address?: string;
  port?: string;
}

export interface Process {
  id: string;
  name: string;
  pid: number;
  package?: string;
  version?: string;
}

export interface HookScript {
  id: string;
  fileName?: string;
  name: string;
  description: string;
  content: string;
  targetPackage?: string;
  targetApp?: string;
  supportedVersions?: string[];
}

export interface FridaStatus {
  is_installed: boolean;
  is_running: boolean;
  needs_update: boolean;
  architecture?: string;
  version?: string;
  required_version?: string;
  error?: string | null;
}

export interface ScriptStatus {
  is_active: boolean;
  last_heartbeat?: string;
  heartbeat_interval_seconds: number;
  is_game_reachable: boolean;
  script_name?: string;
  injection_time?: string;
  error_count: number;
  last_error?: string;
}

export interface BackendStatus {
  status: string;
  session: SessionState;
}

export interface BackendError {
  message: string;
}

export interface AdbStatus {
  running: boolean;
  version?: string | null;
  error?: string;
}

// Shared polling state to prevent multiple components from polling simultaneously
let globalPollingInterval: NodeJS.Timeout | null = null;
let globalStatus: BackendStatus | null = null;
let globalStatusListeners: Set<(status: BackendStatus | null) => void> = new Set();

// Development option to disable polling (set to true to disable)
const DISABLE_POLLING = false;

const startGlobalPolling = () => {
  if (globalPollingInterval || DISABLE_POLLING) {
    return; // Already polling or polling disabled
  }

  const pollStatus = async () => {
    try {
      const result = await invoke<BackendStatus>('get_backend_status');
      globalStatus = result;
      // Notify all listeners
      globalStatusListeners.forEach(listener => listener(result));
    } catch (err) {
      console.error('Failed to poll backend status:', err);
      // Notify listeners of error state
      globalStatusListeners.forEach(listener => listener(null));
    }
  };

  // Initial status check
  pollStatus();

  // Poll every 30 seconds instead of 5 seconds (much less frequent)
  globalPollingInterval = setInterval(pollStatus, 30000);
};

const stopGlobalPolling = () => {
  if (globalPollingInterval) {
    clearInterval(globalPollingInterval);
    globalPollingInterval = null;
  }
};

export const useBackend = () => {
  const [status, setStatus] = useState<BackendStatus | null>(globalStatus);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isInitialized = useRef(false);

  const getStatus = async (): Promise<BackendStatus> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke<BackendStatus>('get_backend_status');
      setStatus(result);
      globalStatus = result; // Update global status
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const connectDevice = async (deviceSerial: string): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('connect_device', { deviceSerial });
      // Refresh status after connection
      await getStatus();
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const disconnectDevice = async (): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('disconnect_device');
      // Refresh status after disconnection
      await getStatus();
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const setTestMode = async (
    testMode: boolean,
    testModeReplay: boolean = false,
    testModeGenerate: boolean = false
  ): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('set_test_mode', {
        testMode,
        testModeReplay,
        testModeGenerate,
      });
      // Refresh status after setting test mode
      await getStatus();
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  // Shared polling mechanism
  useEffect(() => {
    if (!isInitialized.current) {
      isInitialized.current = true;
      
      // Add this component as a listener
      const statusListener = (newStatus: BackendStatus | null) => {
        setStatus(newStatus);
      };
      globalStatusListeners.add(statusListener);
      
      // Start global polling if not already started
      startGlobalPolling();
      
      // Cleanup function
      return () => {
        globalStatusListeners.delete(statusListener);
        
        // If no more listeners, stop polling
        if (globalStatusListeners.size === 0) {
          stopGlobalPolling();
        }
      };
    }
  }, []);

  const scanDevices = async (): Promise<Device[]> => {
    try {
      setLoading(true);
      setError(null);
      
      // Add timeout to prevent hanging
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Device scanning timed out')), 45000); // 45 second timeout
      });
      
      const scanPromise = invoke<{devices: Device[]}>('scan_devices');
      
      const result = await Promise.race([scanPromise, timeoutPromise]);
      return result.devices;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      console.error('Device scanning failed:', errorMessage);
      // Return empty array instead of throwing to prevent UI from breaking
      return [];
    } finally {
      setLoading(false);
    }
  };

  const refreshDevices = async (): Promise<Device[]> => {
    try {
      setLoading(true);
      setError(null);
      
      // Add timeout to prevent hanging
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Device refresh timed out')), 45000); // 45 second timeout
      });
      
      const refreshPromise = invoke<{devices: Device[]}>('refresh_devices');
      
      const result = await Promise.race([refreshPromise, timeoutPromise]);
      return result.devices;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      console.error('Device refresh failed:', errorMessage);
      // Return empty array instead of throwing to prevent UI from breaking
      return [];
    } finally {
      setLoading(false);
    }
  };

  const getProcesses = async (deviceId: string): Promise<Process[]> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke<{processes: Process[], message?: string}>('get_processes', { deviceId });
      
      // Log message if provided
      if (result.message) {
        console.log('Process listing message:', result.message);
      }
      
      return result.processes;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const getHookScripts = async (): Promise<HookScript[]> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke<{scripts: HookScript[]}>('get_hook_scripts');
      return result.scripts;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const startConnectionFlow = async (
    deviceId: string,
    processId: string,
    hookScriptContent?: string
  ): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      
      // For now, use the existing connect_device method
      const result = await invoke('connect_device', { deviceSerial: deviceId });
      
      // Refresh status after connection
      await getStatus();
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const getFridaStatus = async (deviceId: string): Promise<FridaStatus> => {
    try {
      setLoading(true);
      setError(null);
      console.log('useBackend: Getting Frida status for device:', deviceId);
      const result = await invoke<{frida_status: FridaStatus}>('get_frida_status', { deviceId });
      console.log('useBackend: Frida status result:', result);
      return result.frida_status;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const provisionFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('provision_frida_server', { deviceId });
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const startFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('start_frida_server', { deviceId });
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const stopFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('stop_frida_server', { deviceId });
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const installFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('install_frida_server', { deviceId });
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const removeFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('remove_frida_server', { deviceId });
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const activateHook = async (deviceId: string, processInfo: any, scriptId: string): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('activate_hook', { deviceId, processInfo, scriptId });
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const deactivateHook = async (deviceId: string, processInfo: any): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('deactivate_hook', { deviceId, processInfo });
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const getScriptStatus = async (): Promise<ScriptStatus> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke<ScriptStatus>('get_script_status');
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  // ADB Server Management Methods
  const startAdbServer = async (): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('start_adb_server');
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const killAdbServer = async (): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('kill_adb_server');
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const restartAdbServer = async (): Promise<any> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke('restart_adb_server');
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const getAdbStatus = async (): Promise<AdbStatus> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke<AdbStatus>('get_adb_status');
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      // Return a safe default to allow UI to render
      return { running: false, version: null, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  return {
    status,
    loading,
    error,
    getStatus,
    connectDevice,
    disconnectDevice,
    setTestMode,
    scanDevices,
    refreshDevices,
    getProcesses,
    getHookScripts,
    startConnectionFlow,
    getFridaStatus,
    provisionFridaServer,
    startFridaServer,
    stopFridaServer,
    installFridaServer,
    removeFridaServer,
    activateHook,
    deactivateHook,
    getScriptStatus,
    startAdbServer,
    killAdbServer,
    restartAdbServer,
    getAdbStatus,
  };
};
