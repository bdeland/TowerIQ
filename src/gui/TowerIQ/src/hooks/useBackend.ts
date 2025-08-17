import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

export interface SessionState {
  is_connected: boolean;
  current_device?: string;
  current_process?: any;
  test_mode: boolean;
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

  return {
    status,
    loading,
    error,
    getStatus,
    connectDevice,
    setTestMode,
  };
};
