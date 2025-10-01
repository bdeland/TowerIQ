/**
 * useConnectionState.ts - Custom hook for connection state management
 * 
 * Manages device selection, backend status synchronization, and connection states
 */

import { useState, useEffect, useCallback } from 'react';
import { Device, BackendStatus, useBackend } from './useBackend';
import { ConnectionFlowState } from '../utils/connectionPageUtils';

interface UseConnectionStateProps {
  devices: Device[];
  setFlowState: (state: ConnectionFlowState) => void;
  setStatusMessage: (message: string) => void;
  setErrorMessage: (message: string | null) => void;
}

export function useConnectionState({ 
  devices, 
  setFlowState, 
  setStatusMessage, 
  setErrorMessage 
}: UseConnectionStateProps) {
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'connecting' | 'connected' | 'error'>('idle');

  const { status, getStatus } = useBackend();

  // Backend status synchronization function
  const applyBackendStatus = useCallback((nextStatus: BackendStatus | null) => {
    console.log('ConnectionPage: Applying backend status', {
      hasSession: Boolean(nextStatus?.session),
      backendState: nextStatus?.session?.connection_state,
      isConnected: nextStatus?.session?.is_connected,
      deviceMonitoringActive: nextStatus?.session?.device_monitoring_active,
      lastError: nextStatus?.session?.last_error
    });

    if (!nextStatus?.session) {
      console.log('ConnectionPage: No session data available in backend status');
      return;
    }

    const backendState = nextStatus.session.connection_state;
    const isConnected = nextStatus.session.is_connected;
    const lastError = nextStatus.session.last_error;
    const monitoringActive = Boolean(nextStatus.session.device_monitoring_active);

    if (lastError && lastError.code === 'device_disconnected') {
      console.log('ConnectionPage: Device disconnection detected in backend status');
      setFlowState('ERROR');
      setErrorMessage(`Device disconnected: ${lastError.message}`);
      setStatusMessage('');
      setConnectionStatus('idle');
      return;
    }

    if ((backendState === 'active' && isConnected) || monitoringActive) {
      console.log('ConnectionPage: Backend indicates monitoring is active');
      setConnectionStatus('connected');
      setFlowState('MONITORING_ACTIVE');
      setStatusMessage('Monitoring is active!');
      setErrorMessage(null);
      return;
    }

    if (backendState === 'connected' && isConnected) {
      console.log('ConnectionPage: Backend indicates device is connected');
      setConnectionStatus('connected');
      setFlowState('IDLE');
      setStatusMessage('Device connected');
      setErrorMessage(null);
      return;
    }

    if (backendState === 'connecting') {
      console.log('ConnectionPage: Backend indicates connection in progress');
      setConnectionStatus('connecting');
      setFlowState('CONNECTING_DEVICE');
      setStatusMessage('Connecting to device...');
      setErrorMessage(null);
      return;
    }

    if (backendState === 'error') {
      console.log('ConnectionPage: Backend reports an error state');
      setConnectionStatus('error');
      setFlowState('ERROR');
      setStatusMessage('');
      setErrorMessage(lastError?.message ?? 'An unknown error occurred while connecting.');
      return;
    }

    if (backendState === 'disconnected' || !isConnected) {
      console.log('ConnectionPage: Backend indicates device is disconnected');
      setConnectionStatus('idle');
      setFlowState('IDLE');
      setStatusMessage('');
      setErrorMessage(null);
    }
  }, [setFlowState, setStatusMessage, setErrorMessage]);

  // Backend status synchronization effect
  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    let isSyncing = false;

    const syncStatus = async () => {
      if (isSyncing) {
        return;
      }
      isSyncing = true;
      try {
        const latest = await getStatus();
        applyBackendStatus(latest);
      } catch (err) {
        console.error('ConnectionPage: Failed to refresh backend status', err);
      } finally {
        isSyncing = false;
      }
    };

    void syncStatus();

    const handleWindowFocus = () => {
      void syncStatus();
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void syncStatus();
      }
    };

    window.addEventListener('focus', handleWindowFocus);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      window.removeEventListener('focus', handleWindowFocus);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [applyBackendStatus, getStatus]);

  // Backend status change effect
  useEffect(() => {
    applyBackendStatus(status ?? null);
  }, [applyBackendStatus, status]);

  // Device selection synchronization effect
  useEffect(() => {
    console.log('ConnectionPage: Device sync useEffect triggered', {
      backendConnected: status?.session.is_connected,
      backendDevice: status?.session.current_device,
      devicesCount: devices.length,
      selectedDeviceId: selectedDevice?.id
    });
    
    // Handle connection state sync - only sync when backend is connected
    if (status?.session.is_connected && status?.session.current_device) {
      // Only sync if no device is selected, or if selected device doesn't match backend
      if (!selectedDevice || (selectedDevice.id !== status.session.current_device)) {
        if (devices.length > 0) {
          // Find the connected device in our devices list and select it
          const connectedDevice = devices.find(d => d.id === status.session.current_device);
          if (connectedDevice) {
            console.log('ConnectionPage: Syncing selected device with connected device:', connectedDevice.id);
            setSelectedDevice(connectedDevice);
          } else {
            console.log('ConnectionPage: Backend device not found in devices list', {
              backendDevice: status.session.current_device,
              availableDevices: devices.map(d => d.id)
            });
          }
        } else {
          // Devices not loaded yet, create placeholder device
          console.log('ConnectionPage: Devices not loaded yet, creating placeholder for connected device:', status.session.current_device);
          setSelectedDevice({
            id: status.session.current_device,
            name: status.session.current_device,
            serial: status.session.current_device,
            type: 'unknown',
            status: 'device',
            model: 'Loading...',
            android_version: 'Unknown',
            api_level: 0,
            architecture: 'unknown',
            is_network_device: status.session.current_device.includes(':')
          });
        }
      }
    }
    // Only clear selected device if there's an actual disconnection error
    // Don't clear on manual selection when backend isn't connected yet
    else if (!status?.session.is_connected && !status?.session.current_device && selectedDevice && 
             status?.session.connection_state === 'error') {
      console.log('ConnectionPage: Clearing selected device due to connection error');
      setSelectedDevice(null);
    }
  }, [status?.session.is_connected, status?.session.current_device, devices, selectedDevice]);

  // Device details update effect
  useEffect(() => {
    if (selectedDevice && devices.length > 0 && selectedDevice.model === 'Loading...') {
      const fullDevice = devices.find(d => d.id === selectedDevice.id);
      if (fullDevice) {
        console.log('ConnectionPage: Updating placeholder device with full details:', fullDevice.id);
        setSelectedDevice(fullDevice);
      }
    }
  }, [devices, selectedDevice]);

  return {
    selectedDevice,
    setSelectedDevice,
    connectionStatus
  };
}
