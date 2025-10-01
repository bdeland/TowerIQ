import { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { defaultRequestCache, CacheKeys } from '../utils/requestCache';

export interface SessionState {
  is_connected: boolean;
  current_device?: string;
  current_process?: any;
  test_mode: boolean;
  connection_state?: string;
  connection_sub_state?: string;
  device_monitoring_active?: boolean;
  last_error?: any;
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

const SESSION_STORAGE_KEY = 'toweriq.backendStatus';

function loadPersistedStatus(): BackendStatus | null {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    const stored = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    return stored ? JSON.parse(stored) as BackendStatus : null;
  } catch (err) {
    console.warn('Failed to load persisted backend status', err);
    return null;
  }
}

function persistStatus(status: BackendStatus | null): void {
  if (typeof window === 'undefined') {
    return;
  }
  try {
    if (status) {
      window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(status));
    } else {
      window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }
  } catch (err) {
    console.warn('Failed to persist backend status', err);
  }
}

// Shared polling state to prevent multiple components from polling simultaneously
let globalPollingInterval: NodeJS.Timeout | null = null;
let globalStatus: BackendStatus | null = loadPersistedStatus();
let globalStatusListeners: Set<(status: BackendStatus | null) => void> = new Set();

// Development option to disable polling (set to true to disable)
const DISABLE_POLLING = true;

const startGlobalPolling = () => {
  if (globalPollingInterval || DISABLE_POLLING) {
    return; // Already polling or polling disabled
  }

  const pollStatus = async () => {
    try {
      const result = await invoke<BackendStatus>('get_backend_status');
      globalStatus = result;
      persistStatus(result);
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

  // Poll every 5 seconds for faster detection of device disconnections
  globalPollingInterval = setInterval(pollStatus, 5000);
};

const stopGlobalPolling = () => {
  if (globalPollingInterval) {
    clearInterval(globalPollingInterval);
    globalPollingInterval = null;
  }
};

export const useBackend = () => {
  const [status, setStatus] = useState<BackendStatus | null>(globalStatus);
  const [error, setError] = useState<string | null>(null);
  const isInitialized = useRef(false);

  const updateStatusState = useCallback((nextStatus: BackendStatus | null) => {
    setStatus(nextStatus);
    globalStatus = nextStatus;
    persistStatus(nextStatus);
  }, []);

  const getStatus = useCallback(async (): Promise<BackendStatus> => {
    try {
      setError(null);
      const result = await invoke<BackendStatus>('get_backend_status');
      updateStatusState(result);
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, [updateStatusState]);

  const connectDevice = async (deviceSerial: string): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('connect_device', { deviceSerial });
      // Refresh status after connection
      await getStatus();
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const disconnectDevice = async (): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('disconnect_device');
      // Refresh status after disconnection
      await getStatus();
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const setTestMode = async (
    testMode: boolean,
    testModeReplay: boolean = false,
    testModeGenerate: boolean = false
  ): Promise<any> => {
    try {
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
    }
  };

  // Shared polling mechanism
  useEffect(() => {
    if (!isInitialized.current) {
      isInitialized.current = true;
      
      // Add this component as a listener
      const statusListener = (newStatus: BackendStatus | null) => {
        updateStatusState(newStatus);
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
      setError(null);
      
      // Use cache with longer TTL to reduce automatic refreshing
      const result = await defaultRequestCache.get(
        CacheKeys.devices(),
        async () => {
          // Add timeout to prevent hanging
          const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('Device scanning timed out')), 45000); // 45 second timeout
          });
          
          const scanPromise = invoke<{devices: Device[]}>('scan_devices');
          
          const result = await Promise.race([scanPromise, timeoutPromise]);
          return result.devices;
        },
        { ttl: 300000 } // 5 minutes instead of 5 seconds to prevent auto-refresh
      );
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      console.error('Device scanning failed:', errorMessage);
      // Return empty array instead of throwing to prevent UI from breaking
      return [];
    }
  };

  const refreshDevices = async (): Promise<Device[]> => {
    try {
      setError(null);
      
      // Force refresh by invalidating cache and making new request
      const result = await defaultRequestCache.get(
        CacheKeys.devices(),
        async () => {
          // Add timeout to prevent hanging
          const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('Device refresh timed out')), 45000); // 45 second timeout
          });
          
          const refreshPromise = invoke<{devices: Device[]}>('refresh_devices');
          
          const result = await Promise.race([refreshPromise, timeoutPromise]);
          return result.devices;
        },
        { forceRefresh: true, ttl: 5000 } // Force refresh and cache for 5 seconds
      );
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      console.error('Device refresh failed:', errorMessage);
      // Return empty array instead of throwing to prevent UI from breaking
      return [];
    }
  };

  const getProcesses = async (deviceId: string): Promise<Process[]> => {
    try {
      setError(null);
      
      // Cache processes for 10 seconds per device
      const result = await defaultRequestCache.get(
        CacheKeys.processes(deviceId),
        async () => {
          const result = await invoke<{processes: Process[], message?: string}>('get_processes', { deviceId });
          
          // Log message if provided
          if (result.message) {
            console.log('Process listing message:', result.message);
          }
          
          return result.processes;
        },
        { ttl: 10000 } // 10 seconds for process lists
      );
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const getHookScripts = async (): Promise<HookScript[]> => {
    try {
      setError(null);
      
      // Cache hook scripts for 30 seconds (they don't change often)
      const result = await defaultRequestCache.get(
        CacheKeys.hookScripts(),
        async () => {
          const result = await invoke<{scripts: HookScript[]}>('get_hook_scripts');
          return result.scripts;
        },
        { ttl: 30000 } // 30 seconds for hook scripts
      );
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const startConnectionFlow = async (
    deviceId: string,
    processId: string,
    hookScriptContent?: string
  ): Promise<any> => {
    try {
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
    }
  };

  const getFridaStatus = async (deviceId: string): Promise<FridaStatus> => {
    try {
      setError(null);
      
      // Cache Frida status for 15 seconds per device
      const result = await defaultRequestCache.get(
        CacheKeys.fridaStatus(deviceId),
        async () => {
          console.log('useBackend: Getting Frida status for device:', deviceId);
          const result = await invoke<{frida_status: FridaStatus}>('get_frida_status', { deviceId });
          console.log('useBackend: Frida status result:', result);
          return result.frida_status;
        },
        { ttl: 15000 } // 15 seconds for Frida status
      );
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const provisionFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('provision_frida_server', { deviceId });
      
      // Invalidate Frida status cache after provisioning
      defaultRequestCache.invalidate(CacheKeys.fridaStatus(deviceId));
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const startFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('start_frida_server', { deviceId });
      
      // Invalidate Frida status cache after starting
      defaultRequestCache.invalidate(CacheKeys.fridaStatus(deviceId));
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const stopFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('stop_frida_server', { deviceId });
      
      // Invalidate Frida status cache after stopping
      defaultRequestCache.invalidate(CacheKeys.fridaStatus(deviceId));
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const installFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('install_frida_server', { deviceId });
      
      // Invalidate Frida status cache after installing
      defaultRequestCache.invalidate(CacheKeys.fridaStatus(deviceId));
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const removeFridaServer = async (deviceId: string): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('remove_frida_server', { deviceId });
      
      // Invalidate Frida status cache after removing
      defaultRequestCache.invalidate(CacheKeys.fridaStatus(deviceId));
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const activateHook = async (deviceId: string, processInfo: any, scriptId: string): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('activate_hook', { deviceId, processInfo, scriptId });
      
      // Invalidate script status cache after activation
      defaultRequestCache.invalidate(CacheKeys.scriptStatus());
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const deactivateHook = async (deviceId: string, processInfo: any): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('deactivate_hook', { deviceId, processInfo });
      
      // Invalidate script status cache after deactivation
      defaultRequestCache.invalidate(CacheKeys.scriptStatus());
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const getScriptStatus = async (): Promise<ScriptStatus> => {
    try {
      setError(null);
      
      // Cache script status for 3 seconds (frequently changing data)
      const result = await defaultRequestCache.get(
        CacheKeys.scriptStatus(),
        async () => {
          return await invoke<ScriptStatus>('get_script_status');
        },
        { ttl: 3000 } // 3 seconds for script status
      );
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  // ADB Server Management Methods
  const startAdbServer = async (): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('start_adb_server');
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const killAdbServer = async (): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('kill_adb_server');
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const restartAdbServer = async (): Promise<any> => {
    try {
      setError(null);
      const result = await invoke('restart_adb_server');
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const getAdbStatus = async (): Promise<AdbStatus> => {
    try {
      setError(null);
      
      // Cache ADB status for 10 seconds
      const result = await defaultRequestCache.get(
        CacheKeys.adbStatus(),
        async () => {
          return await invoke<AdbStatus>('get_adb_status');
        },
        { ttl: 10000 } // 10 seconds for ADB status
      );
      
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      // Return a safe default to allow UI to render
      return { running: false, version: null, error: errorMessage };
    }
  };

  return {
    status,
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
