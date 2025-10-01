/**
 * useConnectionFlow.ts - Custom hook for connection flow management
 * 
 * Manages the connection flow state machine and orchestration
 */

import { useState, useCallback } from 'react';
import { Device, Process, HookScript, useBackend } from './useBackend';
import { ConnectionFlowState, TARGET_PROCESS_PACKAGE, TARGET_PROCESS_NAME } from '../utils/connectionPageUtils';

export function useConnectionFlow() {
  const [flowState, setFlowState] = useState<ConnectionFlowState>('IDLE');
  const [statusMessage, setStatusMessage] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const {
    startConnectionFlow,
    getProcesses,
    getFridaStatus,
    provisionFridaServer,
    startFridaServer,
    activateHook,
    deactivateHook,
    disconnectDevice
  } = useBackend();

  // Auto-provision Frida helper function
  const handleAutoProvisionFrida = useCallback(async (device: Device): Promise<boolean> => {
    try {
      // Check Frida status
      const fridaStatus = await getFridaStatus(device.id);
      
      if (fridaStatus.is_running) {
        console.log('Frida server is already running');
        return true;
      }

      // Provision Frida server
      console.log('Provisioning Frida server...');
      await provisionFridaServer(device.id);
      
      // Start Frida server
      console.log('Starting Frida server...');
      await startFridaServer(device.id);
      
      // Wait a moment and check if it's running
      await new Promise(resolve => setTimeout(resolve, 2000));
      const newStatus = await getFridaStatus(device.id);
      
      return newStatus.is_running;
      
    } catch (err) {
      console.error('Frida auto-provision failed:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error during Frida setup';
      console.error('Frida setup error details:', errorMessage);
      return false;
    }
  }, [getFridaStatus, provisionFridaServer, startFridaServer]);

  // Master orchestration function for starting monitoring
  const handleStartMonitoring = useCallback(async (selectedDevice: Device | null, selectedHookScript: HookScript | null) => {
    if (!selectedDevice) {
      setFlowState('ERROR');
      setErrorMessage('No device selected. Please select a device first.');
      return;
    }

    if (!selectedHookScript) {
      setFlowState('ERROR');
      setErrorMessage('No hook script selected. Please select a hook script first.');
      return;
    }

    try {
      // 1. Connect to Device
      setFlowState('CONNECTING_DEVICE');
      setStatusMessage('Connecting to device...');
      await startConnectionFlow(selectedDevice.id, '', '');

      // 2. Find Target Process
      setFlowState('SEARCHING_PROCESS');
      setStatusMessage(`Searching for target process: ${TARGET_PROCESS_NAME}...`);
      
      const processList = await getProcesses(selectedDevice.id);
      if (!processList || !Array.isArray(processList)) {
        throw new Error('Failed to retrieve process list from device. Please check device connection.');
      }
      
      const targetProcess = processList.find(p => p.package === TARGET_PROCESS_PACKAGE);
      
      if (!targetProcess) {
        throw new Error(`Target process "${TARGET_PROCESS_NAME}" not found. Please ensure the game is running.`);
      }

      // 3. Configure Frida
      setFlowState('CONFIGURING_FRIDA');
      setStatusMessage('Configuring Frida environment...');
      
      const isFridaReady = await handleAutoProvisionFrida(selectedDevice);
      if (!isFridaReady) {
        throw new Error('Failed to configure Frida server. Please check device connection and ensure Frida server can be installed and started.');
      }

      // 4. Start Hook
      setFlowState('STARTING_HOOK');
      setStatusMessage('Starting monitoring script...');
      
      // Use the selected hook script by id only
      await activateHook(selectedDevice.id, targetProcess, selectedHookScript.id);

      // 5. Success
      setFlowState('MONITORING_ACTIVE');
      setStatusMessage('Monitoring is now active!');

    } catch (err: any) {
      setFlowState('ERROR');
      setErrorMessage(err.message || 'An unexpected error occurred during connection.');
      console.error('Connection error:', err);
    }
  }, [startConnectionFlow, getProcesses, handleAutoProvisionFrida, activateHook]);

  // Stop monitoring function
  const handleStopMonitoring = useCallback(async (selectedDevice: Device | null) => {
    try {
      setStatusMessage('Stopping monitoring...');
      
      // Deactivate hook
      if (selectedDevice) {
        await deactivateHook(selectedDevice.id, {});
      }
      
      // Disconnect device
      await disconnectDevice();
      
      // Reset states
      setFlowState('IDLE');
      setErrorMessage(null);
      
    } catch (err: any) {
      console.error('Error stopping monitoring:', err);
      setErrorMessage('Error stopping monitoring: ' + err.message);
    }
  }, [deactivateHook, disconnectDevice]);

  return {
    flowState,
    statusMessage,
    errorMessage,
    setFlowState,
    setStatusMessage,
    setErrorMessage,
    handleStartMonitoring,
    handleStopMonitoring
  };
}
