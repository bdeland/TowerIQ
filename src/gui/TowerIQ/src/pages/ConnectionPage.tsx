/**
 * ConnectionPage.tsx - Main device connection and monitoring interface
 * 
 * This component provides the primary UI for:
 * - Device selection and connection
 * - Process discovery and monitoring
 * - Frida server management
 * - ADB server controls
 * - Hook script selection and activation
 * - Connection flow orchestration
 */

import React, { useEffect } from 'react';
import {
  Box,
  Button,
  Typography,
  Alert,
  CircularProgress,
  Divider,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
} from '@mui/icons-material';
import { useBackend } from '../hooks/useBackend';
import { ScriptStatusWidget } from '../components/ScriptStatusWidget';
import { HookScriptCard } from '../components/HookScriptCard';
import { SectionCard } from '../components/SectionCard';
import { DeviceTable } from '../components/DeviceTable';
import { ProcessTable } from '../components/ProcessTable';
import { DeviceInformation } from '../components/DeviceInformation';
import { FridaServerControls } from '../components/FridaServerControls';
import { AdbServerControls } from '../components/AdbServerControls';
import { useConnectionFlow } from '../hooks/useConnectionFlow';
import { useConnectionState } from '../hooks/useConnectionState';
import { useDeviceData } from '../hooks/useDeviceData';
import { TARGET_PROCESS_PACKAGE, TARGET_PROCESS_NAME, getDeviceStatusTooltip } from '../utils/connectionPageUtils';

export function ConnectionPage() {
  // ============================================================================
  // HOOKS - Custom hooks for state management and logic
  // ============================================================================
  
  // Backend API hook
  const { 
    loading, 
    provisionFridaServer,
    startFridaServer,
    stopFridaServer,
    removeFridaServer,
    getProcesses
  } = useBackend();

  // Connection flow management
  const {
    flowState,
    statusMessage,
    errorMessage,
    handleStartMonitoring,
    handleStopMonitoring
  } = useConnectionFlow();

  // Device data management
  const {
    devices,
    processes,
    hookScripts,
    selectedHookScript,
    scriptStatus,
    fridaStatus,
    adbStatus,
    processSearchTerm,
    devicesLoading,
    processesLoading,
    scriptStatusLoading,
    fridaStatusLoading,
    isAdbRestarting,
    fridaError,
    setDevices,
    setProcesses,
    setSelectedHookScript,
    setFridaError,
    setProcessSearchTerm,
    setProcessesLoading,
    loadFridaStatus,
    handleRefreshDevices,
    handleRestartAdbServer,
    handleStartAdbServer,
    handleKillAdbServer
  } = useDeviceData();

  // Connection state management
  const {
    selectedDevice,
    connectionStatus
  } = useConnectionState({ 
    devices, 
    setFlowState: () => {}, // These are managed by useConnectionFlow now
    setStatusMessage: () => {},
    setErrorMessage: () => {}
  });

  // ============================================================================
  // EFFECTS - Simplified effects for specific functionality
  // ============================================================================
  
  // Load processes when device becomes connected
  useEffect(() => {
    if (selectedDevice) {
      const loadProcessesForDevice = async () => {
        try {
          setProcessesLoading(true);
          const processList = await getProcesses(selectedDevice.id);
          setProcesses(processList);
        } catch (err) {
          console.error('Failed to load processes for device:', err);
        } finally {
          setProcessesLoading(false);
        }
      };
      
      loadProcessesForDevice();
    }
  }, [selectedDevice, getProcesses, setProcesses, setProcessesLoading]);

  // Load Frida status when device is selected
  useEffect(() => {
    if (selectedDevice) {
      loadFridaStatus(selectedDevice.id);
    }
  }, [selectedDevice, loadFridaStatus]);

  // ============================================================================
  // EVENT HANDLERS - Simplified handlers using custom hooks
  // ============================================================================
  
  // Handle device selection from the device table
  const handleDeviceSelection = (device: any) => {
    // Device selection is now handled by useConnectionState
    console.log('Device selected:', device.id);
  };

  // Frida server operation handlers
  const handleProvisionFrida = async () => {
    if (selectedDevice) {
      try {
        setFridaError(null);
        await provisionFridaServer(selectedDevice.id);
        await loadFridaStatus(selectedDevice.id);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : 'Unknown error';
        setFridaError(`Failed to provision Frida server: ${errorMsg}`);
      }
    }
  };

  const handleStartFrida = async () => {
    if (selectedDevice) {
      try {
        setFridaError(null);
        await startFridaServer(selectedDevice.id);
        await loadFridaStatus(selectedDevice.id);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : 'Unknown error';
        setFridaError(`Failed to start Frida server: ${errorMsg}`);
      }
    }
  };

  const handleStopFrida = async () => {
    if (selectedDevice) {
      try {
        setFridaError(null);
        await stopFridaServer(selectedDevice.id);
        await loadFridaStatus(selectedDevice.id);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : 'Unknown error';
        setFridaError(`Failed to stop Frida server: ${errorMsg}`);
      }
    }
  };

  const handleRemoveFrida = async () => {
    if (selectedDevice) {
      try {
        setFridaError(null);
        await removeFridaServer(selectedDevice.id);
        await loadFridaStatus(selectedDevice.id);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : 'Unknown error';
        setFridaError(`Failed to remove Frida server: ${errorMsg}`);
      }
    }
  };

  return (
    <Box sx={{ 
      mx: 'auto',
      width: '100%',
      maxWidth: 1200,
      px: { xs: 0.5, sm: 1, md: 2 },
      py: { xs: 0.5, sm: 1, md: 2 },
    }}>
      {/* PAGE HEADER SECTION */}
      <Box sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between', 
        mb: 4,
        px: { xs: 1, sm: 2 },
        py: 0,
      }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            Device Connection
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Connect to a device and automatically start monitoring The Tower game.
          </Typography>
        </Box>
        
        {/* MAIN ACTION BUTTONS */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {(flowState === 'CONNECTING_DEVICE' || flowState === 'SEARCHING_PROCESS' || 
            flowState === 'CONFIGURING_FRIDA' || flowState === 'STARTING_HOOK') && (
            <CircularProgress size={24} />
          )}
          
          {flowState === 'MONITORING_ACTIVE' ? (
            <Button
              variant="contained"
              color="error"
              size="large"
              startIcon={<StopIcon />}
              onClick={() => handleStopMonitoring(selectedDevice)}
              sx={{
                minWidth: 80,
                height: 80,
                borderRadius: 0.5,
                fontSize: '0.875rem',
                fontWeight: 'bold'
              }}
            >
              Stop
            </Button>
          ) : (
            <Button
              variant="contained"
              color="primary"
              size="large"
              startIcon={<PlayIcon />}
              onClick={() => handleStartMonitoring(selectedDevice, selectedHookScript)}
              disabled={!selectedDevice || 
                       !selectedHookScript ||
                       flowState === 'CONNECTING_DEVICE' || 
                       flowState === 'SEARCHING_PROCESS' || 
                       flowState === 'CONFIGURING_FRIDA' || 
                       flowState === 'STARTING_HOOK'}
              sx={{
                minWidth: 80,
                height: 80,
                borderRadius: 0.5,
                fontSize: '0.875rem',
                fontWeight: 'bold'
              }}
            >
              Start
            </Button>
          )}
        </Box>
      </Box>

      {/* DEVICE SELECTION SECTION */}
      <SectionCard
        title="Available Devices"
        onRefresh={handleRefreshDevices}
        refreshDisabled={devicesLoading}
        refreshSpinning={devicesLoading}
      >
        <DeviceTable
          devices={devices}
          selectedDevice={selectedDevice}
          onDeviceSelection={handleDeviceSelection}
          devicesLoading={devicesLoading}
          isAdbRestarting={isAdbRestarting}
          getDeviceStatusTooltip={getDeviceStatusTooltip}
        />
      </SectionCard>

      {/* ERROR ALERT */}
      {flowState === 'ERROR' && errorMessage && (
        <Alert severity="error" sx={{ 
          mb: 4,
          mx: { xs: 1, sm: 2 },
          px: 2,
          py: 2,
        }}>
          {errorMessage}
          <Button 
            size="small" 
            onClick={() => handleStartMonitoring(selectedDevice, selectedHookScript)}
            sx={{ ml: 1 }}
          >
            Retry
          </Button>
        </Alert>
      )}

      {/* STATUS MESSAGE */}
      {statusMessage && (
        <Typography variant="body1" sx={{ 
          mb: 4, 
          fontStyle: 'italic',
          mx: { xs: 1, sm: 2 },
          px: 2,
          py: 1,
          textAlign: 'center',
          color: 'primary.main',
          fontWeight: 'medium',
        }}>
          {statusMessage}
        </Typography>
      )}

      {/* ADVANCED CONTROLS SECTION */}
      <Box sx={{ 
        mt: 2,
      }}>
        <Typography variant="h6" component="h2" sx={{ 
          mb: 3,
          px: 1,
        }}>
          Advanced Controls & Troubleshooting
        </Typography>
        
        {/* PROCESS SELECTION SECTION */}
        <SectionCard
          title="Available Processes"
          onRefresh={async () => {
            if (selectedDevice) {
              try {
                setProcessesLoading(true);
                const processList = await getProcesses(selectedDevice.id);
                setProcesses(processList);
              } catch (err) {
                console.error('Failed to load processes:', err);
              } finally {
                setProcessesLoading(false);
              }
            }
          }}
          refreshDisabled={!selectedDevice || processesLoading}
          refreshSpinning={processesLoading}
          additionalHeaderItems={
            <Typography variant="caption" color="text.secondary">
              {processes.filter(process => 
                processSearchTerm === '' || 
                process.name.toLowerCase().includes(processSearchTerm.toLowerCase()) ||
                (process.package && process.package.toLowerCase().includes(processSearchTerm.toLowerCase()))
              ).length} of {processes.length} processes
            </Typography>
          }
        >
          <ProcessTable
            processes={processes}
            processesLoading={processesLoading}
            processSearchTerm={processSearchTerm}
            onProcessSearchChange={setProcessSearchTerm}
            targetProcessPackage={TARGET_PROCESS_PACKAGE}
            targetProcessName={TARGET_PROCESS_NAME}
          />
        </SectionCard>

        {/* DEVICE INFORMATION SECTION */}
        <SectionCard
          title="Device Information"
          infoTooltip="Detailed information about the selected device including hardware specifications and system details."
          onRefresh={handleRefreshDevices}
          refreshDisabled={devicesLoading}
          refreshSpinning={devicesLoading}
        >
          <DeviceInformation selectedDevice={selectedDevice} />
        </SectionCard>

        {/* FRIDA SERVER CONTROLS SECTION */}
        <SectionCard
          title="Frida Server Controls"
          infoTooltip="Frida is a dynamic instrumentation toolkit that allows you to inject JavaScript code into running applications. The Frida server runs on your Android device and enables communication between your computer and the target application."
          onRefresh={() => selectedDevice && loadFridaStatus(selectedDevice.id)}
          refreshDisabled={!selectedDevice || fridaStatusLoading}
          refreshSpinning={fridaStatusLoading}
        >
          <FridaServerControls
            selectedDevice={selectedDevice}
            fridaStatus={fridaStatus}
            fridaStatusLoading={fridaStatusLoading}
            fridaError={fridaError}
            loading={loading}
            onProvisionFrida={handleProvisionFrida}
            onStartFrida={handleStartFrida}
            onStopFrida={handleStopFrida}
            onRemoveFrida={handleRemoveFrida}
          />
        </SectionCard>

        {/* ADB SERVER CONTROLS SECTION */}
        <SectionCard
          title="ADB Server Controls"
          infoTooltip="ADB (Android Debug Bridge) is the communication protocol that allows your computer to interact with Android devices. The ADB server manages device connections and must be running for device detection and communication."
          onRefresh={handleRefreshDevices}
          refreshDisabled={isAdbRestarting}
          refreshSpinning={isAdbRestarting}
        >
          <AdbServerControls
            adbStatus={adbStatus}
            isAdbRestarting={isAdbRestarting}
            onStartAdbServer={handleStartAdbServer}
            onKillAdbServer={handleKillAdbServer}
            onRestartAdbServer={handleRestartAdbServer}
          />
        </SectionCard>

        {/* HOOK SCRIPT SELECTION SECTION */}
        <SectionCard
          title="Available Hook Scripts"
          infoTooltip="Hook scripts are JavaScript code that gets injected into the target application to monitor and intercept specific functions. These scripts can capture game data, modify behavior, or log events in real-time."
        >
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Select a hook script to inject into the target application. Scripts are loaded from the scripts folder and contain metadata about their target application and supported versions.
          </Typography>
          
          {hookScripts.length === 0 ? (
            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="body2">
                No hook scripts found. Please ensure scripts are available in the scripts folder.
              </Typography>
            </Alert>
          ) : (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {hookScripts.map((script) => (
                <HookScriptCard
                  key={script.id}
                  script={script}
                  selected={selectedHookScript?.id === script.id}
                  onSelect={(selectedScript) => {
                    console.log('HookScriptCard onSelect triggered:', selectedScript.id);
                    setSelectedHookScript(selectedScript);
                  }}
                />
              ))}
            </Box>
          )}
          
          {selectedHookScript && (
            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="body2">
                Selected script: <strong>{selectedHookScript.name}</strong>
                {selectedHookScript.fileName && (
                  <span style={{ fontFamily: 'monospace', fontSize: '0.8em', marginLeft: '8px' }}>
                    ({selectedHookScript.fileName})
                  </span>
                )}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {selectedHookScript.description}
              </Typography>
            </Alert>
          )}
        </SectionCard>
      </Box>
    </Box>
  );
}

