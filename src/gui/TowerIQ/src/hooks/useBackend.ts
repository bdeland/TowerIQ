import { useState, useEffect } from 'react';
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
  status: 'connected' | 'disconnected' | 'error';
}

export interface Process {
  id: string;
  name: string;
  pid: number;
  package?: string;
}

export interface HookScript {
  id: string;
  name: string;
  description: string;
  content: string;
}

export interface BackendStatus {
  status: string;
  session: SessionState;
}

export interface BackendError {
  message: string;
}

export const useBackend = () => {
  const [status, setStatus] = useState<BackendStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const getStatus = async (): Promise<BackendStatus> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke<BackendStatus>('get_backend_status');
      setStatus(result);
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

  // Poll for status updates
  useEffect(() => {
    const pollStatus = async () => {
      try {
        await getStatus();
      } catch (err) {
        console.error('Failed to poll backend status:', err);
      }
    };

    // Initial status check
    pollStatus();

    // Poll every 5 seconds
    const interval = setInterval(pollStatus, 5000);

    return () => clearInterval(interval);
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

  const getProcesses = async (deviceId: string): Promise<Process[]> => {
    try {
      setLoading(true);
      setError(null);
      const result = await invoke<{processes: Process[]}>('get_processes', { deviceId });
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

  return {
    status,
    loading,
    error,
    getStatus,
    connectDevice,
    setTestMode,
    scanDevices,
    getProcesses,
    getHookScripts,
    startConnectionFlow,
  };
};
