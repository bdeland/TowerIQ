import React, { useState, useEffect, useCallback, useRef } from 'react';
import { keyframes } from '@mui/system';
import { styled } from '@mui/material/styles';
import {
  Box,
  Button,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemButton,
  ListItemIcon,
  TextField,
  FormControlLabel,
  Checkbox,
  Alert,
  CircularProgress,
  IconButton,
  Chip,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  Paper,
  Radio,
  RadioGroup,
} from '@mui/material';
import {
  Check as CheckIcon,
  Error as ErrorIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  DeviceHub as DeviceIcon,
  Memory as ProcessIcon,
  Code as ScriptIcon,
  Link as ConnectIcon,
  Search as SearchIcon,
  DeveloperMode as DeveloperModeIcon,
  Smartphone as SmartphoneIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Remove as RemoveIcon,
  ExpandMore as ExpandMoreIcon,
  InfoOutline as InfoOutlineIcon,
  Settings as SettingsIcon,
} from '@mui/icons-material';
import RefreshIcon from '@mui/icons-material/Refresh';
import { useBackend, Device, Process, HookScript, FridaStatus, ScriptStatus, AdbStatus } from '../hooks/useBackend';
import { ScriptStatusWidget } from '../components/ScriptStatusWidget';
import { HookScriptCard } from '../components/HookScriptCard';

// Application constants for auto-selection
const TARGET_PROCESS_PACKAGE = 'com.TechTreeGames.TheTower';
const TARGET_PROCESS_NAME = 'The Tower';

// Connection flow state type
type ConnectionFlowState = 'IDLE' | 'CONNECTING_DEVICE' | 'SEARCHING_PROCESS' | 'CONFIGURING_FRIDA' | 'STARTING_HOOK' | 'MONITORING_ACTIVE' | 'ERROR';

// Helper function for generating device status tooltip content
const getDeviceStatusTooltip = (status: string) => {
  switch (status) {
    case 'unauthorized':
      return (
        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>Device Unauthorized</Typography>
          <Typography variant="body2">Your computer is not trusted. Please follow these steps:</Typography>
          <List dense sx={{ listStyleType: 'decimal', pl: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>Check your device for an "Allow USB debugging?" popup.</ListItem>
            <ListItem sx={{ display: 'list-item' }}>Accept the prompt (check "Always allow").</ListItem>
            <ListItem sx={{ display: 'list-item' }}>If you don't see it, unplug and reconnect the cable.</ListItem>
          </List>
        </Box>
      );
    case 'offline':
    case 'disconnected':
      return (
        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>Device Offline</Typography>
          <Typography variant="body2">The connection is unresponsive. Try the following:</Typography>
          <List dense sx={{ listStyleType: 'decimal', pl: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>Reboot your Android device.</ListItem>
            <ListItem sx={{ display: 'list-item' }}>Use a different USB cable and port.</ListItem>
            <ListItem sx={{ display: 'list-item' }}>Use the "Restart ADB Server" control below.</ListItem>
          </List>
        </Box>
      );
    case 'no permissions':
      return <Typography>Your system is blocking access to this USB device. (Linux/macOS issue)</Typography>;
    case 'device':
    case 'connected':
      return <Typography>Device is connected and ready.</Typography>;
    case 'error':
      return <Typography>Device connection error. Try restarting the ADB server.</Typography>;
    default:
      return <Typography>Status: {status}</Typography>;
  }
};

export function ConnectionPage() {
  // Animation configuration
  const refreshAnimationConfig = {
    duration: 600,
    easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
    rotations: 1
  };



  const { 
    status, 
    loading, 
    error, 
    scanDevices, 
    refreshDevices,
    getProcesses, 
    getHookScripts, 
    startConnectionFlow,
    disconnectDevice,
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
    getAdbStatus
  } = useBackend();
  
  // Simplified state management
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [isRefreshSpinning, setIsRefreshSpinning] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'connecting' | 'connected' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Master connection flow state machine
  const [flowState, setFlowState] = useState<ConnectionFlowState>('IDLE');
  const [statusMessage, setStatusMessage] = useState<string>('');

  // Troubleshooting section
  const [showTroubleshooting, setShowTroubleshooting] = useState(false);

  // Data from backend
  const [devices, setDevices] = useState<Device[]>([]);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [hookScripts, setHookScripts] = useState<HookScript[]>([]);
  const [selectedHookScript, setSelectedHookScript] = useState<HookScript | null>(null);

  // Loading states
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [processesLoading, setProcessesLoading] = useState(false);

  // Script status state
  const [scriptStatus, setScriptStatus] = useState<ScriptStatus | null>(null);
  const [scriptStatusLoading, setScriptStatusLoading] = useState(false);

  // ADB server management state
  const [isAdbRestarting, setIsAdbRestarting] = useState(false);
  const [adbStatus, setAdbStatus] = useState<AdbStatus | null>(null);

  // Centralized ADB state updater with delay and optional device refresh
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

  // Frida server status state
  const [fridaStatus, setFridaStatus] = useState<FridaStatus | null>(null);
  const [fridaStatusLoading, setFridaStatusLoading] = useState(false);
  const [fridaError, setFridaError] = useState<string | null>(null);

  // Process search state
  const [processSearchTerm, setProcessSearchTerm] = useState<string>('');

  // Load initial data
  useEffect(() => {
    console.log('ConnectionPage: Component mounted');
    loadDevices();
    loadHookScripts();
    loadScriptStatus();
    // Fetch ADB status at mount
    (async () => {
      try {
        const status = await getAdbStatus();
        setAdbStatus(status);
      } catch (e) {
        // ignore, UI will show unknown
      }
    })();
  }, []);

  // Initial sync when component mounts and status is already available
  useEffect(() => {
    if (status?.session) {
      console.log('ConnectionPage: Initial sync on mount', {
        isConnected: status.session.is_connected,
        currentDevice: status.session.current_device,
        connectionState: status.session.connection_state
      });
      
      // Force an immediate sync of connection state on mount
      // This ensures that if we navigate back to a page where the backend is already connected,
      // the UI shows the correct state immediately
      const backendState = status.session.connection_state;
      const isConnected = status.session.is_connected;
      
      if (backendState === 'active' && isConnected) {
        setConnectionStatus('connected');
        setFlowState('MONITORING_ACTIVE');
        setStatusMessage('Monitoring is active!');
        setErrorMessage(null);
      } else if (backendState === 'connected' && isConnected) {
        setConnectionStatus('connected');
        setFlowState('IDLE');
        setStatusMessage('Device connected');
        setErrorMessage(null);
      } else if (backendState === 'connecting') {
        setConnectionStatus('connecting');
        setFlowState('CONNECTING_DEVICE');
        setStatusMessage('Connecting to device...');
        setErrorMessage(null);
      }
    }
  }, []); // Only run once on mount

  // Auto-select first hook script when scripts change
  useEffect(() => {
    if (hookScripts.length > 0 && !selectedHookScript) {
      setSelectedHookScript(hookScripts[0]);
    }
  }, [hookScripts, selectedHookScript]);

  // Load script status when connected
  useEffect(() => {
    console.log('ConnectionPage: useEffect triggered', { 
      isConnected: status?.session.is_connected
    });

    if (!status?.session.is_connected) {
      console.log('ConnectionPage: Not connected, clearing script status');
      setScriptStatus(null);
      return;
    }

    const loadScriptStatus = async () => {
      try {
        console.log('ConnectionPage: Loading script status...');
        const status = await getScriptStatus();
        setScriptStatus(status);
        console.log('ConnectionPage: Script status loaded', status);
      } catch (err) {
        console.error('ConnectionPage: Failed to load script status:', err);
      }
    };

    loadScriptStatus();
  }, [status?.session.is_connected]);

  // Update connection status and flow state based on backend status
  useEffect(() => {
    console.log('ConnectionPage: Status change detected', { 
      isConnected: status?.session.is_connected,
      currentDevice: status?.session.current_device,
      connectionState: status?.session.connection_state,
      connectionSubState: status?.session.connection_sub_state,
      lastError: status?.session.last_error,
      currentFlowState: flowState,
      backendState: status?.session.connection_state
    });
    
    if (!status?.session) {
      console.log('ConnectionPage: No session data, skipping sync');
      return;
    }
    
    const backendState = status.session.connection_state;
    const isConnected = status.session.is_connected;
    const lastError = status.session.last_error;
    
    // Handle device disconnection errors
    if (lastError && lastError.code === 'device_disconnected') {
      console.log('ConnectionPage: Device disconnection detected');
      setFlowState('ERROR');
      setErrorMessage(`Device disconnected: ${lastError.message}`);
      setStatusMessage('');
      setScriptStatus(null);
      setConnectionStatus('idle');
    }
    // Sync with backend connection state - this handles page navigation sync
    else if (backendState === 'active') {
      // Backend says we're active (monitoring)
      console.log('ConnectionPage: Backend is ACTIVE, syncing to MONITORING_ACTIVE');
      setConnectionStatus('connected');
      setFlowState('MONITORING_ACTIVE');
      setStatusMessage('Monitoring is active!');
      setErrorMessage(null);
    }
    else if (backendState === 'connected' && isConnected) {
      // Backend says we're connected but not yet active
      console.log('ConnectionPage: Backend is CONNECTED, syncing to IDLE');
      setConnectionStatus('connected');
      setFlowState('IDLE');
      setStatusMessage('Device connected');
      setErrorMessage(null);
    }
    else if (backendState === 'connecting') {
      console.log('ConnectionPage: Backend is CONNECTING, syncing to CONNECTING_DEVICE');
      setConnectionStatus('connecting');
      setFlowState('CONNECTING_DEVICE');
      setStatusMessage('Connecting to device...');
      setErrorMessage(null);
    }
    else if (backendState === 'disconnected' || !isConnected) {
      // Backend says we're disconnected
      console.log('ConnectionPage: Backend is DISCONNECTED, syncing to IDLE');
      setConnectionStatus('idle');
      setFlowState('IDLE');
      setStatusMessage('');
      setErrorMessage(null);
    }
  }, [status]);

  // Sync selected device with globally connected device
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
      // and the backend is actually connected (to avoid overriding manual selection)
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
          // Devices not loaded yet, but we know which device should be selected
          // Create a minimal device object to maintain state until full device list loads
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
    // Clear selected device if backend shows disconnected (only when transitioning from connected to disconnected)
    else if (!status?.session.is_connected && !status?.session.current_device && selectedDevice) {
      console.log('ConnectionPage: Clearing selected device due to disconnection');
      setSelectedDevice(null);
    }
  }, [status?.session.is_connected, status?.session.current_device, devices]);

  // Update selected device with full details when devices list becomes available
  useEffect(() => {
    if (selectedDevice && devices.length > 0 && selectedDevice.model === 'Loading...') {
      const fullDevice = devices.find(d => d.id === selectedDevice.id);
      if (fullDevice) {
        console.log('ConnectionPage: Updating placeholder device with full details:', fullDevice.id);
        setSelectedDevice(fullDevice);
      }
    }
  }, [devices, selectedDevice]);

  // Load processes when device becomes connected
  useEffect(() => {
    if (status?.session.is_connected && selectedDevice && status?.session.current_device === selectedDevice.id) {
      const loadProcessesForConnectedDevice = async () => {
        try {
          setProcessesLoading(true);
          const processList = await getProcesses(selectedDevice.id);
          setProcesses(processList);
        } catch (err) {
          console.error('Failed to load processes for connected device:', err);
        } finally {
          setProcessesLoading(false);
        }
      };
      
      loadProcessesForConnectedDevice();
    }
  }, [status?.session.is_connected, status?.session.current_device, selectedDevice]);

  // Load Frida status when device is selected
  useEffect(() => {
    if (selectedDevice) {
      loadFridaStatus(selectedDevice.id);
    } else {
      setFridaStatus(null);
    }
  }, [selectedDevice]);

  // Load devices
  const loadDevices = async () => {
    try {
      setDevicesLoading(true);
      const deviceList = await scanDevices();
      setDevices(deviceList);
    } catch (err) {
      console.error('Failed to load devices:', err);
    } finally {
      setDevicesLoading(false);
    }
  };

  // Load hook scripts
  const loadHookScripts = async () => {
    try {
      const scriptList = await getHookScripts();
      setHookScripts(scriptList);
      // Auto-select the first script if no script is currently selected
      if (scriptList.length > 0 && !selectedHookScript) {
        setSelectedHookScript(scriptList[0]);
      }
    } catch (err) {
      console.error('Failed to load hook scripts:', err);
    }
  };

  // Load script status
  const loadScriptStatus = async () => {
    try {
      setScriptStatusLoading(true);
      const status = await getScriptStatus();
      setScriptStatus(status);
    } catch (err) {
      console.error('Failed to load script status:', err);
    } finally {
      setScriptStatusLoading(false);
    }
  };

  // Load Frida status
  const loadFridaStatus = async (deviceId: string) => {
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
  };

  // Master orchestration function for starting monitoring
  const handleStartMonitoring = async () => {
    if (!selectedDevice) {
      setFlowState('ERROR');
      setErrorMessage('No device selected. Please select a device first.');
      return;
    }

    // Check if hook script is selected
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
      const targetProcess = processList.find(p => p.package === TARGET_PROCESS_PACKAGE);
      
      if (!targetProcess) {
        throw new Error(`Target process "${TARGET_PROCESS_NAME}" not found. Please ensure the game is running.`);
      }

      // 3. Configure Frida
      setFlowState('CONFIGURING_FRIDA');
      setStatusMessage('Configuring Frida environment...');
      
      const isFridaReady = await handleAutoProvisionFrida(selectedDevice);
      if (!isFridaReady) {
        throw new Error('Failed to configure Frida server. Please check device connection and try again.');
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
  };

  // Auto-provision Frida helper
  const handleAutoProvisionFrida = async (device: Device): Promise<boolean> => {
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
      return false;
    }
  };

  // Stop monitoring function
  const handleStopMonitoring = async () => {
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
  };

  // Handle device selection
  const handleDeviceSelection = (device: Device) => {
    setSelectedDevice(device);
  };

  // Handle refresh devices
  const handleRefreshDevices = async () => {
    setIsRefreshSpinning(true);
    try {
      // Clear the existing device list first to show fresh data
      setDevices([]);
      setDevicesLoading(true);
      
      const deviceList = await refreshDevices();
      setDevices(deviceList);
    } catch (err) {
      console.error('Failed to refresh devices:', err);
    } finally {
      setIsRefreshSpinning(false);
      setDevicesLoading(false);
    }
  };

  // ADB Server Management Handlers
  const handleRestartAdbServer = async () => {
    try {
      setIsAdbRestarting(true);
      // Clear the device list to show fresh data
      setDevices([]);
      setDevicesLoading(true);
      
      // Restart ADB server
      await restartAdbServer();
      // Centralized status refresh
      await updateAdbState(true);
    } catch (err) {
      console.error('Failed to restart ADB server:', err);
    } finally {
      setIsAdbRestarting(false);
      setDevicesLoading(false);
    }
  };

  const handleStartAdbServer = async () => {
    try {
      setIsAdbRestarting(true);
      await startAdbServer();
      await updateAdbState(true);
    } catch (err) {
      console.error('Failed to start ADB server:', err);
    } finally {
      setIsAdbRestarting(false);
    }
  };

  const handleKillAdbServer = async () => {
    try {
      setIsAdbRestarting(true);
      await killAdbServer();
      // Clear devices after killing server
      setDevices([]);
      await updateAdbState();
    } catch (err) {
      console.error('Failed to kill ADB server:', err);
    } finally {
      setIsAdbRestarting(false);
    }
  };

  return (
    <Box sx={{ 
      mx: 'auto',
      width: '100%',
      maxWidth: 1200,
    }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            Device Connection
          </Typography>
          
          <Typography variant="body1" color="text.secondary">
            Connect to a device and automatically start monitoring The Tower game.
          </Typography>
        </Box>
        
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {flowState === 'CONNECTING_DEVICE' || flowState === 'SEARCHING_PROCESS' || 
           flowState === 'CONFIGURING_FRIDA' || flowState === 'STARTING_HOOK' ? (
            <CircularProgress size={24} />
          ) : null}
          
          {flowState === 'MONITORING_ACTIVE' ? (
            <Button
              variant="contained"
              color="error"
              size="large"
              startIcon={<StopIcon />}
              onClick={handleStopMonitoring}
              sx={{
                minWidth: 80,
                height: 80,
                borderRadius: 3,
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
              onClick={handleStartMonitoring}
              disabled={!selectedDevice || 
                       !selectedHookScript ||
                       flowState === 'CONNECTING_DEVICE' || 
                       flowState === 'SEARCHING_PROCESS' || 
                       flowState === 'CONFIGURING_FRIDA' || 
                       flowState === 'STARTING_HOOK'}
              sx={{
                minWidth: 80,
                height: 80,
                borderRadius: 3,
                fontSize: '0.875rem',
                fontWeight: 'bold'
              }}
            >
              Start
            </Button>
          )}
        </Box>
      </Box>

      {/* Device Selection Section */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6" component="h2">
            Available Devices
          </Typography>
          <IconButton
            onClick={handleRefreshDevices}
            disabled={isRefreshSpinning}
            size="small"
          >
            <RefreshIcon 
              sx={{ 
                transform: isRefreshSpinning ? 'rotate(360deg)' : 'rotate(0deg)',
                transition: 'transform 0.6s cubic-bezier(0.4, 0, 0.2, 1)',
              }} 
            />
          </IconButton>
        </Box>
        
        <TableContainer sx={{ maxHeight: 300 }}>
          <Table stickyHeader size="small">
            <TableHead>
              <TableRow>
                <TableCell>Select</TableCell>
                <TableCell>Device</TableCell>
                <TableCell>Model</TableCell>
                <TableCell>Android</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Status</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(devicesLoading || isAdbRestarting) ? (
                Array.from({ length: 3 }).map((_, index) => (
                  <TableRow key={index}>
                    <TableCell><Skeleton /></TableCell>
                    <TableCell><Skeleton /></TableCell>
                    <TableCell><Skeleton /></TableCell>
                    <TableCell><Skeleton /></TableCell>
                    <TableCell><Skeleton /></TableCell>
                    <TableCell><Skeleton /></TableCell>
                    <TableCell><Skeleton /></TableCell>
                  </TableRow>
                ))
              ) : isAdbRestarting ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
                      <CircularProgress size={16} />
                      <Typography variant="body2" color="text.secondary">
                        ADB server is rebooting... Please wait.
                      </Typography>
                    </Box>
                  </TableCell>
                </TableRow>
              ) : devices.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography variant="body2" color="text.secondary">
                      No devices found. Please ensure your device is connected and USB debugging is enabled.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                devices.map((device) => (
                  <TableRow 
                    key={device.id}
                    sx={{ 
                      backgroundColor: selectedDevice?.id === device.id ? 'action.selected' : 'inherit',
                      '&:hover': { backgroundColor: 'action.hover' }
                    }}
                  >
                    <TableCell>
                      <Radio
                        checked={selectedDevice?.id === device.id}
                        onChange={() => handleDeviceSelection(device)}
                        disabled={device.status !== 'device' && device.status !== 'connected'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <SmartphoneIcon fontSize="small" />
                        <Typography variant="body2" fontFamily="monospace">
                          {device.id}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {device.model || 'Unknown'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {device.android_version} (API {device.api_level})
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={device.type === 'emulator' ? 'Emulator' : 'Physical'} 
                        size="small"
                        color={device.type === 'emulator' ? 'secondary' : 'primary'}
                      />
                    </TableCell>
                    <TableCell>
                      <Tooltip title={getDeviceStatusTooltip(device.status)} arrow>
                        <Chip 
                          label={device.status.charAt(0).toUpperCase() + device.status.slice(1)} 
                          size="small"
                          color={(device.status === 'device' || device.status === 'connected') ? 'success' : 'warning'}
                        />
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>

      {flowState === 'ERROR' && errorMessage && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {errorMessage}
          <Button 
            size="small" 
            onClick={handleStartMonitoring}
            sx={{ ml: 1 }}
          >
            Retry
          </Button>
        </Alert>
      )}

      <Typography variant="body1" sx={{ mb: 3, fontStyle: 'italic' }}>
        {statusMessage}
      </Typography>

      {/* Troubleshooting Section */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">Advanced Controls & Troubleshooting</Typography>
        </AccordionSummary>
        <AccordionDetails>
          {/* Process Selection */}
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="h6">
                Available Processes
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="caption" color="text.secondary">
                  {processes.filter(process => 
                    processSearchTerm === '' || 
                    process.name.toLowerCase().includes(processSearchTerm.toLowerCase()) ||
                    (process.package && process.package.toLowerCase().includes(processSearchTerm.toLowerCase()))
                  ).length} of {processes.length} processes
                </Typography>
                <IconButton
                  onClick={async () => {
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
                  disabled={!selectedDevice || processesLoading}
                  size="small"
                >
                  <RefreshIcon 
                    sx={{ 
                      transform: processesLoading ? 'rotate(360deg)' : 'rotate(0deg)',
                      transition: 'transform 0.6s cubic-bezier(0.4, 0, 0.2, 1)',
                    }} 
                  />
                </IconButton>
              </Box>
            </Box>
            
            {/* Search Box */}
            <Box sx={{ mb: 2 }}>
              <TextField
                fullWidth
                size="small"
                placeholder="Search processes by name or package..."
                value={processSearchTerm}
                onChange={(e) => setProcessSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                }}
                sx={{ mb: 1 }}
              />
            </Box>
            
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              All available processes on the selected device. Use the search box above to filter processes. The Tower game should be highlighted in green if found.
            </Typography>
            
            {processesLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                <CircularProgress />
              </Box>
            ) : (
              <TableContainer sx={{ maxHeight: 400, mb: 3 }}>
                <Table stickyHeader size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>App Name</TableCell>
                      <TableCell>Package</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>PID</TableCell>
                      <TableCell>Type</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(() => {
                      const filteredProcesses = processes.filter(process => 
                        processSearchTerm === '' || 
                        process.name.toLowerCase().includes(processSearchTerm.toLowerCase()) ||
                        (process.package && process.package.toLowerCase().includes(processSearchTerm.toLowerCase()))
                      );
                      const filteredProcessesSorted = [...filteredProcesses].sort((a, b) => {
                        const aIsTarget = a.package === TARGET_PROCESS_PACKAGE;
                        const bIsTarget = b.package === TARGET_PROCESS_PACKAGE;
                        if (aIsTarget && !bIsTarget) return -1;
                        if (!aIsTarget && bIsTarget) return 1;
                        return 0;
                      });
                      
                      if (processes.length === 0) {
                        return (
                          <TableRow>
                            <TableCell colSpan={5} align="center">
                              <Typography variant="body2" color="text.secondary">
                                No processes found. Try refreshing or check device connection.
                              </Typography>
                            </TableCell>
                          </TableRow>
                        );
                      } else if (filteredProcesses.length === 0) {
                        return (
                          <TableRow>
                            <TableCell colSpan={5} align="center">
                              <Typography variant="body2" color="text.secondary">
                                No processes match your search criteria.
                              </Typography>
                            </TableCell>
                          </TableRow>
                        );
                      } else {
                        return filteredProcessesSorted.map((process) => (
                          <TableRow 
                            key={process.pid}
                            sx={{ 
                              backgroundColor: process.package === TARGET_PROCESS_PACKAGE ? 'success.light' : 'inherit',
                              '&:hover': { backgroundColor: 'action.hover' }
                            }}
                          >
                            <TableCell>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                {process.package === TARGET_PROCESS_PACKAGE && (
                                  <CheckCircleIcon color="success" fontSize="small" />
                                )}
                                {process.name}
                              </Box>
                            </TableCell>
                            <TableCell sx={{ fontFamily: 'monospace' }}>{process.package}</TableCell>
                            <TableCell>{process.version}</TableCell>
                            <TableCell>{process.pid}</TableCell>
                            <TableCell>
                              <Chip 
                                label="User" 
                                size="small"
                                color="primary"
                                variant="filled"
                              />
                            </TableCell>
                          </TableRow>
                        ));
                      }
                    })()}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
            
            {/* Debug Information */}
            {processes.length === 0 && selectedDevice && !processesLoading && (
              <Alert severity="info" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  No processes found. This could be due to:
                </Typography>
                <List dense sx={{ mt: 1 }}>
                  <ListItem sx={{ display: 'list-item' }}>
                    <Typography variant="body2">The device may not have any user applications running</Typography>
                  </ListItem>
                  <ListItem sx={{ display: 'list-item' }}>
                    <Typography variant="body2">The game "The Tower" may not be installed or running</Typography>
                  </ListItem>
                  <ListItem sx={{ display: 'list-item' }}>
                    <Typography variant="body2">ADB permissions may be insufficient to list processes</Typography>
                  </ListItem>
                </List>
                <Typography variant="body2" sx={{ mt: 1 }}>
                  Try refreshing the process list or ensure the game is running on the device.
                </Typography>
              </Alert>
            )}
            
            {/* Target Process Status */}
            {selectedDevice && processes.length > 0 && (
              <Box sx={{ mt: 2, p: 2, borderRadius: 1, border: 1, borderColor: 'divider' }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Target Process Status: {TARGET_PROCESS_NAME}
                </Typography>
                {processes.find(p => p.package === TARGET_PROCESS_PACKAGE) ? (
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CheckCircleIcon color="success" />
                    <Typography variant="body2" color="success.main">
                      ✓ Found! The Tower game is running and ready for connection.
                    </Typography>
                  </Box>
                ) : (
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CancelIcon color="error" />
                    <Typography variant="body2" color="error.main">
                      ✗ Not found. Please ensure "The Tower" game is installed and running on the device.
                    </Typography>
                  </Box>
                )}
              </Box>
            )}
          </Box>

          <Divider sx={{ my: 2 }} />

          {/* Device Information */}
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="h6">
                  Device Information
                </Typography>
                <Tooltip title="Detailed information about the selected device including hardware specifications and system details." arrow>
                  <InfoOutlineIcon fontSize="small" color="action" />
                </Tooltip>
              </Box>
              <IconButton
                onClick={handleRefreshDevices}
                disabled={isRefreshSpinning}
                size="small"
              >
                <RefreshIcon 
                  sx={{ 
                    transform: isRefreshSpinning ? 'rotate(360deg)' : 'rotate(0deg)',
                    transition: 'transform 0.6s cubic-bezier(0.4, 0, 0.2, 1)',
                  }} 
                />
              </IconButton>
            </Box>
            {selectedDevice && (
              <Box sx={{ p: 2, borderRadius: 1, border: 1, borderColor: 'divider' }}>
                <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                  {/* Basic Device Info */}
                  <Box>
                    <Typography variant="caption" color="text.secondary">Device ID:</Typography>
                    <Typography variant="body2" fontFamily="monospace">{selectedDevice.id}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Device Name:</Typography>
                    <Typography variant="body2">{selectedDevice.device_name || selectedDevice.name || 'Unknown'}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Brand:</Typography>
                    <Typography variant="body2">{selectedDevice.brand || 'Unknown'}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Model:</Typography>
                    <Typography variant="body2">{selectedDevice.model || 'Unknown'}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Device Type:</Typography>
                    <Typography variant="body2">{selectedDevice.type === 'emulator' ? 'Emulator' : 'Physical Device'}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Connection Type:</Typography>
                    <Typography variant="body2">
                      {selectedDevice.is_network_device ? 'Network' : 'USB'}
                    </Typography>
                  </Box>
                  
                  {/* System Information */}
                  <Box>
                    <Typography variant="caption" color="text.secondary">Android Version:</Typography>
                    <Typography variant="body2">{selectedDevice.android_version} (API {selectedDevice.api_level})</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Architecture:</Typography>
                    <Typography variant="body2">{selectedDevice.architecture || 'Unknown'}</Typography>
                  </Box>
                  
                  {/* Network Information (if applicable) */}
                  {selectedDevice.is_network_device && (
                    <>
                      <Box>
                        <Typography variant="caption" color="text.secondary">IP Address:</Typography>
                        <Typography variant="body2" fontFamily="monospace">{selectedDevice.ip_address || 'Unknown'}</Typography>
                      </Box>
                      <Box>
                        <Typography variant="caption" color="text.secondary">Port:</Typography>
                        <Typography variant="body2" fontFamily="monospace">{selectedDevice.port || 'Unknown'}</Typography>
                      </Box>
                    </>
                  )}
                  
                  {/* Status Information */}
                  <Box>
                    <Typography variant="caption" color="text.secondary">Status:</Typography>
                    <Chip 
                      label={selectedDevice.status.charAt(0).toUpperCase() + selectedDevice.status.slice(1)} 
                      size="small"
                      color={(selectedDevice.status === 'device' || selectedDevice.status === 'connected') ? 'success' : 'warning'}
                    />
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Serial:</Typography>
                    <Typography variant="body2" fontFamily="monospace">{selectedDevice.serial || selectedDevice.id}</Typography>
                  </Box>
                </Box>
              </Box>
            )}
          </Box>

          <Divider sx={{ my: 2 }} />

          {/* Frida Server Controls */}
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="h6">
                  Frida Server Controls
                </Typography>
                <Tooltip title="Frida is a dynamic instrumentation toolkit that allows you to inject JavaScript code into running applications. The Frida server runs on your Android device and enables communication between your computer and the target application." arrow>
                  <InfoOutlineIcon fontSize="small" color="action" />
                </Tooltip>
              </Box>
              <IconButton
                onClick={() => selectedDevice && loadFridaStatus(selectedDevice.id)}
                disabled={!selectedDevice || fridaStatusLoading}
                size="small"
              >
                <RefreshIcon 
                  sx={{ 
                    transform: fridaStatusLoading ? 'rotate(360deg)' : 'rotate(0deg)',
                    transition: 'transform 0.6s cubic-bezier(0.4, 0, 0.2, 1)',
                  }} 
                />
              </IconButton>
            </Box>
            {/* Frida Server Status */}
            {selectedDevice && (
              <Box sx={{ mb: 2, p: 2, borderRadius: 1, border: 1, borderColor: 'divider' }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>Frida Server Status:</Typography>
                {fridaStatusLoading ? (
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CircularProgress size={16} />
                    <Typography variant="body2" color="text.secondary">Loading status...</Typography>
                  </Box>
                ) : fridaStatus ? (
                  <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
                    <Box>
                      <Typography variant="caption" color="text.secondary">Server Status:</Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Chip 
                          label={fridaStatus.is_running ? 'Running' : 'Stopped'} 
                          size="small"
                          color={fridaStatus.is_running ? 'success' : 'default'}
                        />
                      </Box>
                    </Box>
                                         <Box>
                       <Typography variant="caption" color="text.secondary">Installation Status:</Typography>
                       <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                         <Chip 
                           label={fridaStatus.is_installed ? 'Installed' : 'Not installed'} 
                           size="small"
                           color={fridaStatus.is_installed ? 'success' : 'default'}
                         />
                       </Box>
                     </Box>
                                                              <Box>
                       <Typography variant="caption" color="text.secondary">Installed Version:</Typography>
                       <Typography variant="body2" fontFamily="monospace">
                         {fridaStatus.version || 'Unknown'}
                       </Typography>
                     </Box>
                     <Box>
                       <Typography variant="caption" color="text.secondary">Required Version:</Typography>
                       <Typography variant="body2" fontFamily="monospace">
                         {fridaStatus.required_version || 'Unknown'}
                       </Typography>
                     </Box>
                     <Box>
                       <Typography variant="caption" color="text.secondary">Architecture:</Typography>
                       <Typography variant="body2">
                         {fridaStatus.architecture || 'Unknown'}
                       </Typography>
                     </Box>
                     <Box>
                       <Typography variant="caption" color="text.secondary">Update Needed:</Typography>
                       <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                         <Chip 
                           label={fridaStatus.needs_update ? 'Yes' : 'No'} 
                           size="small"
                           color={fridaStatus.needs_update ? 'warning' : 'success'}
                         />
                       </Box>
                     </Box>
                  </Box>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    Unable to load Frida server status. Please check device connection.
                  </Typography>
                )}
              </Box>
            )}

            <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
              <Box sx={{ position: 'relative' }}>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={async () => {
                  if (selectedDevice) {
                    try {
                      setFridaError(null);
                      await provisionFridaServer(selectedDevice.id);
                      // Refresh Frida status after provisioning
                      await loadFridaStatus(selectedDevice.id);
                    } catch (err) {
                      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
                      setFridaError(`Failed to provision Frida server: ${errorMsg}`);
                      console.error('Failed to provision Frida server:', err);
                    }
                  }
                }}
                  disabled={!selectedDevice || loading || (fridaStatus?.is_installed === true)}
                  title={fridaStatus?.is_installed ? 'Frida server is already installed' : undefined}
                  sx={{ minWidth: 160 }}
                >
                  Install Frida Server
                </Button>
                {loading && (
                  <CircularProgress size={16} sx={{ position: 'absolute', top: '50%', left: '50%', mt: '-8px', ml: '-8px' }} />
                )}
              </Box>
              <Box sx={{ position: 'relative' }}>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={async () => {
                  if (selectedDevice) {
                    try {
                      setFridaError(null);
                      await startFridaServer(selectedDevice.id);
                      // Refresh Frida status after starting
                      await loadFridaStatus(selectedDevice.id);
                    } catch (err) {
                      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
                      setFridaError(`Failed to start Frida server: ${errorMsg}`);
                      console.error('Failed to start Frida server:', err);
                    }
                  }
                }}
                  disabled={!selectedDevice || loading || !fridaStatus?.is_installed || fridaStatus?.is_running === true}
                  title={
                    !fridaStatus?.is_installed ? 'Frida server must be installed first' :
                    fridaStatus?.is_running ? 'Frida server is already running' : undefined
                  }
                  sx={{ minWidth: 160 }}
                >
                  Start Frida Server
                </Button>
                {loading && (
                  <CircularProgress size={16} sx={{ position: 'absolute', top: '50%', left: '50%', mt: '-8px', ml: '-8px' }} />
                )}
              </Box>
              <Box sx={{ position: 'relative' }}>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={async () => {
                  if (selectedDevice) {
                    try {
                      setFridaError(null);
                      await stopFridaServer(selectedDevice.id);
                      // Refresh Frida status after stopping
                      await loadFridaStatus(selectedDevice.id);
                    } catch (err) {
                      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
                      setFridaError(`Failed to stop Frida server: ${errorMsg}`);
                      console.error('Failed to stop Frida server:', err);
                    }
                  }
                }}
                  disabled={!selectedDevice || loading || !fridaStatus?.is_running}
                  title={!fridaStatus?.is_running ? 'Frida server is not running' : undefined}
                  sx={{ minWidth: 160 }}
                >
                  Stop Frida Server
                </Button>
                {loading && (
                  <CircularProgress size={16} sx={{ position: 'absolute', top: '50%', left: '50%', mt: '-8px', ml: '-8px' }} />
                )}
              </Box>
              <Box sx={{ position: 'relative' }}>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={async () => {
                  if (selectedDevice) {
                    try {
                      setFridaError(null);
                      await removeFridaServer(selectedDevice.id);
                      // Refresh Frida status after removing
                      await loadFridaStatus(selectedDevice.id);
                    } catch (err) {
                      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
                      setFridaError(`Failed to remove Frida server: ${errorMsg}`);
                      console.error('Failed to remove Frida server:', err);
                    }
                  }
                }}
                  disabled={!selectedDevice || loading || !fridaStatus?.is_installed}
                  title={!fridaStatus?.is_installed ? 'Frida server is not installed' : undefined}
                  sx={{ minWidth: 160 }}
                >
                  Remove Frida Server
                </Button>
                {loading && (
                  <CircularProgress size={16} sx={{ position: 'absolute', top: '50%', left: '50%', mt: '-8px', ml: '-8px' }} />
                )}
              </Box>

            </Box>

            {/* Frida Error Display */}
            {fridaError && (
              <Alert severity="error" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  {fridaError}
                </Typography>
              </Alert>
            )}

            {/* Debug Information removed per spec */}

          </Box>

          <Divider sx={{ my: 2 }} />

          {/* ADB Server Controls */}
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="h6">
                  ADB Server Controls
                </Typography>
                <Tooltip title="ADB (Android Debug Bridge) is the communication protocol that allows your computer to interact with Android devices. The ADB server manages device connections and must be running for device detection and communication." arrow>
                  <InfoOutlineIcon fontSize="small" color="action" />
                </Tooltip>
              </Box>
              <IconButton
                onClick={handleRefreshDevices}
                disabled={isAdbRestarting}
                size="small"
              >
                <RefreshIcon 
                  sx={{ 
                    transform: isAdbRestarting ? 'rotate(360deg)' : 'rotate(0deg)',
                    transition: 'transform 0.6s cubic-bezier(0.4, 0, 0.2, 1)',
                  }} 
                />
              </IconButton>
            </Box>
            {/* ADB Status Row */}
            <Box sx={{ mb: 1 }}>
              <Typography variant="subtitle2" sx={{ mb: 0.5 }}>ADB Server Status</Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                <Chip 
                  label={adbStatus?.running ? 'Running' : 'Stopped'} 
                  size="small"
                  color={adbStatus?.running ? 'success' : 'default'}
                />
                <Typography variant="caption" color="text.secondary">
                  {adbStatus?.version ? adbStatus.version : 'Version: Unknown'}
                </Typography>
                {/* Redundant manual refresh removed per spec */}
              </Box>
            </Box>

            <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
              <Button
                variant="outlined"
                size="small"
                onClick={handleStartAdbServer}
                disabled={isAdbRestarting || adbStatus === null || adbStatus?.running === true}
              >
                Start ADB Server
              </Button>
              <Button
                variant="outlined"
                size="small"
                onClick={handleKillAdbServer}
                disabled={isAdbRestarting || adbStatus === null || adbStatus?.running === false}
              >
                Kill ADB Server
              </Button>
              <Button
                variant="outlined"
                size="small"
                onClick={handleRestartAdbServer}
                disabled={isAdbRestarting || adbStatus === null || adbStatus?.running === false}
              >
                Restart ADB Server
              </Button>
            </Box>

          </Box>

          <Divider sx={{ my: 2 }} />

          {/* Hook Script Selection */}
          <Box>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="h6">
                  Available Hook Scripts
                </Typography>
                <Tooltip title="Hook scripts are JavaScript code that gets injected into the target application to monitor and intercept specific functions. These scripts can capture game data, modify behavior, or log events in real-time." arrow>
                  <InfoOutlineIcon fontSize="small" color="action" />
                </Tooltip>
              </Box>
              <IconButton
                onClick={async () => {
                  await loadHookScripts();
                }}
                size="small"
              >
                <RefreshIcon />
              </IconButton>
            </Box>
            
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
          </Box>
        </AccordionDetails>
      </Accordion>
    </Box>
  );
}

