import React, { useState, useEffect, useCallback, useRef } from 'react';
import { keyframes } from '@mui/system';
import { styled } from '@mui/material/styles';
import {
  Box,
  Button,
  Paper,
  Typography,
  Card,
  CardContent,
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
} from '@mui/material';
import MuiAccordion, { AccordionProps } from '@mui/material/Accordion';
import MuiAccordionSummary, {
  AccordionSummaryProps,
  accordionSummaryClasses,
} from '@mui/material/AccordionSummary';
import MuiAccordionDetails from '@mui/material/AccordionDetails';
import {
  Refresh as RefreshIcon,
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
} from '@mui/icons-material';
import { useBackend, Device, Process, HookScript, FridaStatus, FridaCompatibility, ScriptStatus } from '../hooks/useBackend';
import { ScriptStatusWidget } from '../components/ScriptStatusWidget';

// Styled Accordion Components
const Accordion = styled((props: AccordionProps) => (
  <MuiAccordion disableGutters elevation={0} square {...props} />
))(({ theme }) => ({
  border: `1px solid ${theme.palette.divider}`,
  '&:not(:last-child)': {
    borderBottom: 0,
  },
  '&::before': {
    display: 'none',
  },
}));

const AccordionSummary = styled((props: AccordionSummaryProps) => (
  <MuiAccordionSummary
    expandIcon={<ExpandMoreIcon sx={{ fontSize: '0.9rem' }} />}
    {...props}
  />
))(({ theme }) => ({
  backgroundColor: 'rgba(0, 0, 0, .03)',
  flexDirection: 'row-reverse',
  [`& .${accordionSummaryClasses.expandIconWrapper}.${accordionSummaryClasses.expanded}`]:
    {
      transform: 'rotate(90deg)',
    },
  [`& .${accordionSummaryClasses.content}`]: {
    marginLeft: theme.spacing(1),
  },
  ...theme.applyStyles('dark', {
    backgroundColor: 'rgba(255, 255, 255, .05)',
  }),
}));

const AccordionDetails = styled(MuiAccordionDetails)(({ theme }) => ({
  padding: theme.spacing(2),
  borderTop: '1px solid rgba(0, 0, 0, .125)',
}));

// Remove duplicate interfaces since they're imported from useBackend

const steps = [
  {
    label: 'Select Device',
    description: 'Choose a device to connect to. This can be a physical device or emulator.',
    icon: <DeviceIcon />,
  },
  {
    label: 'Configure Frida Server',
    description: 'Check and configure the Frida server on the selected device.',
    icon: <DeveloperModeIcon />,
  },
  {
    label: 'Select Process',
    description: 'Choose the target process to attach to on the selected device.',
    icon: <ProcessIcon />,
  },
  {
    label: 'Configure Hook Script',
    description: 'Optionally select and configure a hook script to inject into the process.',
    icon: <ScriptIcon />,
    optional: true,
  },
  {
    label: 'Establish Connection',
    description: 'Connect to the device and attach to the selected process.',
    icon: <ConnectIcon />,
  },
];

export function ConnectionPage() {
  // Animation configuration
  const refreshAnimationConfig = {
    duration: 600, // Duration in milliseconds
    easing: 'cubic-bezier(0.4, 0, 0.2, 1)', // Material Design standard easing
    rotations: 1 // Number of full rotations
  };

  // Styled refresh button with animation
  const AnimatedRefreshIcon = styled(RefreshIcon)<{ $isSpinning: boolean }>(({ theme, $isSpinning }) => ({
    transform: $isSpinning ? `rotate(${360 * refreshAnimationConfig.rotations}deg)` : 'rotate(0deg)',
    transition: `transform ${refreshAnimationConfig.duration}ms ${refreshAnimationConfig.easing}`,
  }));

  const { 
    status, 
    loading, 
    error, 
    scanDevices, 
    getProcesses, 
    getHookScripts, 
    startConnectionFlow,
    disconnectDevice,
    getFridaStatus,
    provisionFridaServer,
    checkFridaCompatibility,
    startFridaServer,
    stopFridaServer,
    installFridaServer,
    removeFridaServer,
    activateHook,
    deactivateHook,
    getScriptStatus
  } = useBackend();
  
  const [activeStep, setActiveStep] = useState(0);
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set([0])); // Start with first step expanded
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [selectedProcess, setSelectedProcess] = useState<Process | null>(null);
  const [selectedScript, setSelectedScript] = useState<HookScript | null>(null);
  const [isRefreshSpinning, setIsRefreshSpinning] = useState(false);
  const [useHookScript, setUseHookScript] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'connecting' | 'connected' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Frida-related state
  const [fridaStatus, setFridaStatus] = useState<FridaStatus | null>(null);
  const [fridaCompatibility, setFridaCompatibility] = useState<FridaCompatibility | null>(null);
  const [hookActivationStatus, setHookActivationStatus] = useState<'idle' | 'activating' | 'active' | 'deactivating' | 'error'>('idle');
  const [hookError, setHookError] = useState<string | null>(null);
  const [fridaLoading, setFridaLoading] = useState(false);
  const [fridaError, setFridaError] = useState<string | null>(null);

  // Script status state
  const [scriptStatus, setScriptStatus] = useState<ScriptStatus | null>(null);
  const [scriptStatusLoading, setScriptStatusLoading] = useState(false);

  // Data from backend
  const [devices, setDevices] = useState<Device[]>([]);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [hookScripts, setHookScripts] = useState<HookScript[]>([]);

  // Loading states - show skeleton immediately when commands start
  const [devicesLoading, setDevicesLoading] = useState(true); // Start with loading true
  const [processesLoading, setProcessesLoading] = useState(false);

  // Search and filter states
  const [processSearchTerm, setProcessSearchTerm] = useState('');
  const [showOnlyThirdParty, setShowOnlyThirdParty] = useState(true);
  const [showOnlyRunning, setShowOnlyRunning] = useState(false);

  // Load initial data
  useEffect(() => {
    loadDevices();
    loadHookScripts();
    loadScriptStatus();
  }, []);

  // Use ref to track if polling is active
  // Load script status when connected (no polling - backend handles heartbeats)
  useEffect(() => {
    console.log('ConnectionPage: useEffect triggered', { 
      isConnected: status?.session.is_connected
    });

    if (!status?.session.is_connected) {
      console.log('ConnectionPage: Not connected, clearing script status');
      setScriptStatus(null);
      return;
    }

    // Load initial script status
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
  }, [status?.session.is_connected]); // Removed getScriptStatus from dependencies to prevent infinite re-renders

  // Update connection status based on backend status
  useEffect(() => {
    if (status?.session.is_connected) {
      setConnectionStatus('connected');
    } else if (status?.session.connection_stage) {
      setConnectionStatus('connecting');
    } else {
      setConnectionStatus('idle');
    }
  }, [status]);

  // Load processes when device becomes connected
  useEffect(() => {
    if (status?.session.is_connected && selectedDevice && status?.session.current_device === selectedDevice.id) {
      // Load processes for the connected device
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

  // Helper function to check if a process is third party
  const isThirdPartyProcess = (process: Process) => {
    return !!(process.package && 
              !process.package.startsWith('com.android.') &&
              !process.package.startsWith('android.') &&
              !process.package.startsWith('system') &&
              !process.package.startsWith('com.google.android.') &&
              !process.package.startsWith('com.samsung.') &&
              !process.package.startsWith('com.sec.') &&
              !process.package.startsWith('com.qualcomm.'));
  };

  // Helper function to check if a process is running
  const isRunningProcess = (process: Process) => {
    return process.pid > 0;
  };

  // Calculate counts for different process categories
  const totalProcesses = processes.length;
  const thirdPartyProcesses = processes.filter(isThirdPartyProcess).length;
  const runningProcesses = processes.filter(isRunningProcess).length;
  const searchFilteredProcesses = processes.filter(process => 
    process.name.toLowerCase().includes(processSearchTerm.toLowerCase()) ||
    (process.package && process.package.toLowerCase().includes(processSearchTerm.toLowerCase()))
  ).length;

  // Filter processes based on search term, third party filter, and running filter
  const filteredProcesses = processes.filter(process => {
    const matchesSearch = process.name.toLowerCase().includes(processSearchTerm.toLowerCase()) ||
                         (process.package && process.package.toLowerCase().includes(processSearchTerm.toLowerCase()));
    
    // Apply third party filter
    let passesThirdPartyFilter = true;
    if (showOnlyThirdParty) {
      passesThirdPartyFilter = isThirdPartyProcess(process);
    }
    
    // Apply running filter
    const passesRunningFilter = !showOnlyRunning || isRunningProcess(process);
    
    return matchesSearch && passesThirdPartyFilter && passesRunningFilter;
  });

  const loadDevices = async () => {
    try {
      console.log('Starting device scan...');
      const startTime = Date.now();
      const deviceList = await scanDevices();
      console.log('Device scan completed:', deviceList);
      setDevices(deviceList);
      
      // Add artificial delay to ensure skeleton is visible for at least 1 second
      const elapsedTime = Date.now() - startTime;
      if (elapsedTime < 1000) {
        await new Promise(resolve => setTimeout(resolve, 1000 - elapsedTime));
      }
    } catch (err) {
      console.error('Failed to load devices:', err);
      setErrorMessage(`Failed to scan for devices: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setDevicesLoading(false);
    }
  };

  const loadHookScripts = async () => {
    try {
      const scriptList = await getHookScripts();
      setHookScripts(scriptList);
    } catch (err) {
      console.error('Failed to load hook scripts:', err);
    }
  };

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

  const refreshScriptStatus = async () => {
    console.log('ConnectionPage: Manually refreshing script status');
    await loadScriptStatus();
  };

  const handleNext = () => {
    const nextStep = activeStep + 1;
    setActiveStep(nextStep);
    // Collapse the previous step and expand the next step
    setExpandedSteps(prev => {
      const newSet = new Set(prev);
      newSet.delete(activeStep); // Collapse current step
      newSet.add(nextStep); // Expand next step
      return newSet;
    });
  };

  const handleBack = () => {
    setActiveStep((prevActiveStep) => prevActiveStep - 1);
  };

  const handleReset = () => {
    setActiveStep(0);
    setSelectedDevice(null);
    setSelectedProcess(null);
    setSelectedScript(null);
    setUseHookScript(false);
    setConnectionStatus('idle');
    setErrorMessage(null);
  };

  const handleDeviceSelect = async (device: Device) => {
    setSelectedDevice(device);
    // Reset process selection when device changes
    setSelectedProcess(null);
    setProcesses([]); // Clear processes - they will be loaded after connection
  };

  const handleProcessSelect = (process: Process) => {
    setSelectedProcess(process);
  };

  const handleScriptSelect = (script: HookScript) => {
    setSelectedScript(script);
  };

  const toggleStepExpansion = (stepIndex: number) => {
    setExpandedSteps(prev => {
      const newSet = new Set(prev);
      if (newSet.has(stepIndex)) {
        newSet.delete(stepIndex);
      } else {
        newSet.add(stepIndex);
      }
      return newSet;
    });
  };

  const isStepExpanded = (stepIndex: number) => {
    return expandedSteps.has(stepIndex);
  };

  // Function to check script compatibility
  const checkScriptCompatibility = (script: HookScript) => {
    if (!selectedProcess) return { 
      isCompatible: false, 
      packageMatch: false, 
      versionMatch: false, 
      packageMismatch: '', 
      versionMismatch: '',
      compatibilityMessage: `This script is compatible with ${script.targetApp || script.targetPackage || 'Unknown'} (${script.targetPackage || 'Unknown'}) version ${script.supportedVersions?.join(', ') || 'Unknown'}. Please select a process first.`
    };
    
    const packageMatch = script.targetPackage === selectedProcess.package;
    const versionMatch = script.supportedVersions?.includes(selectedProcess.version || '') || false;
    const isCompatible = packageMatch && versionMatch;
    
    // Build plain English compatibility messages
    let compatibilityMessage = '';
    let packageMismatch = '';
    let versionMismatch = '';
    
    if (packageMatch && versionMatch) {
      compatibilityMessage = `This script is compatible with ${script.targetApp || script.targetPackage} (${script.targetPackage}) version ${script.supportedVersions?.join(', ') || 'Unknown'}. You have selected ${selectedProcess.name} version ${selectedProcess.version || 'Unknown'}.`;
    } else if (packageMatch && !versionMatch) {
      packageMismatch = `This script is compatible with ${script.targetApp || script.targetPackage} (${script.targetPackage}) version ${script.supportedVersions?.join(', ') || 'Unknown'}. You have selected ${selectedProcess.name} version ${selectedProcess.version || 'Unknown'}.`;
    } else {
      packageMismatch = `This script is compatible with ${script.targetApp || script.targetPackage || 'Unknown'} (${script.targetPackage || 'Unknown'}) version ${script.supportedVersions?.join(', ') || 'Unknown'}. You have selected ${selectedProcess.name} (${selectedProcess.package || 'Unknown'}) version ${selectedProcess.version || 'Unknown'}.`;
    }
    
    return {
      isCompatible,
      packageMatch,
      versionMatch,
      packageMismatch,
      versionMismatch,
      compatibilityMessage
    };
  };

  const handleRefreshDevices = async () => {
    try {
      setDevicesLoading(true);
      setIsRefreshSpinning(true);
      
      // Add artificial delay to ensure skeleton is visible for at least 1 second
      const startTime = Date.now();
      await loadDevices();
      const elapsedTime = Date.now() - startTime;
      
      if (elapsedTime < 1000) {
        await new Promise(resolve => setTimeout(resolve, 1000 - elapsedTime));
      }
    } catch (err) {
      console.error('Failed to refresh devices:', err);
    } finally {
      setDevicesLoading(false);
      // Stop spinning after animation completes
      setTimeout(() => setIsRefreshSpinning(false), 600);
    }
  };

  const handleRefreshProcesses = async () => {
    if (!selectedDevice || !status?.session.is_connected) return;
    
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

  const handleCheckFridaStatus = async () => {
    if (!selectedDevice) return;
    
    try {
      setFridaLoading(true);
      setFridaError(null);
      
      const status = await getFridaStatus(selectedDevice.id);
      setFridaStatus(status);
      
      // Also check compatibility
      const compatibility = await checkFridaCompatibility(selectedDevice.id);
      setFridaCompatibility(compatibility);
      
    } catch (err) {
      console.error('Failed to check Frida status:', err);
      setFridaError(err instanceof Error ? err.message : 'Failed to check Frida status');
    } finally {
      setFridaLoading(false);
    }
  };

  const handleProvisionFridaServer = async () => {
    if (!selectedDevice) return;
    
    try {
      setFridaLoading(true);
      setFridaError(null);
      
      await provisionFridaServer(selectedDevice.id);
      
      // Refresh status after provisioning
      await handleCheckFridaStatus();
      
    } catch (err) {
      console.error('Failed to provision Frida server:', err);
      setFridaError(err instanceof Error ? err.message : 'Failed to provision Frida server');
    } finally {
      setFridaLoading(false);
    }
  };

  const handleStartFridaServer = async () => {
    if (!selectedDevice) return;
    
    try {
      setFridaLoading(true);
      setFridaError(null);
      
      await startFridaServer(selectedDevice.id);
      
      // Refresh status after starting
      await handleCheckFridaStatus();
      
    } catch (err) {
      console.error('Failed to start Frida server:', err);
      setFridaError(err instanceof Error ? err.message : 'Failed to start Frida server');
    } finally {
      setFridaLoading(false);
    }
  };

  const handleStopFridaServer = async () => {
    if (!selectedDevice) return;
    
    try {
      setFridaLoading(true);
      setFridaError(null);
      
      await stopFridaServer(selectedDevice.id);
      
      // Refresh status after stopping
      await handleCheckFridaStatus();
      
    } catch (err) {
      console.error('Failed to stop Frida server:', err);
      setFridaError(err instanceof Error ? err.message : 'Failed to stop Frida server');
    } finally {
      setFridaLoading(false);
    }
  };

  const handleInstallFridaServer = async () => {
    if (!selectedDevice) return;
    
    try {
      setFridaLoading(true);
      setFridaError(null);
      
      await installFridaServer(selectedDevice.id);
      
      // Refresh status after installation
      await handleCheckFridaStatus();
      
    } catch (err) {
      console.error('Failed to install Frida server:', err);
      setFridaError(err instanceof Error ? err.message : 'Failed to install Frida server');
    } finally {
      setFridaLoading(false);
    }
  };

  const handleRemoveFridaServer = async () => {
    if (!selectedDevice) return;
    
    try {
      setFridaLoading(true);
      setFridaError(null);
      
      await removeFridaServer(selectedDevice.id);
      
      // Refresh status after removal
      await handleCheckFridaStatus();
      
    } catch (err) {
      console.error('Failed to remove Frida server:', err);
      setFridaError(err instanceof Error ? err.message : 'Failed to remove Frida server');
    } finally {
      setFridaLoading(false);
    }
  };

  const handleStartHook = async () => {
    if (!selectedDevice || !selectedProcess || !selectedScript) return;
    
    try {
      setHookActivationStatus('activating');
      setHookError(null);
      
      await activateHook(selectedDevice.id, selectedProcess, selectedScript.content);
      
      setHookActivationStatus('active');
      
    } catch (err) {
      console.error('Failed to start hook:', err);
      setHookError(err instanceof Error ? err.message : 'Failed to start hook');
      setHookActivationStatus('error');
    }
  };

  const handleStopHook = async () => {
    if (!selectedDevice || !selectedProcess) return;
    
    try {
      setHookActivationStatus('deactivating');
      setHookError(null);
      
      await deactivateHook(selectedDevice.id, selectedProcess);
      
      setHookActivationStatus('idle');
      
    } catch (err) {
      console.error('Failed to stop hook:', err);
      setHookError(err instanceof Error ? err.message : 'Failed to stop hook');
      setHookActivationStatus('error');
    }
  };

  // Load Frida status when device is selected
  useEffect(() => {
    if (selectedDevice) {
      handleCheckFridaStatus();
    }
  }, [selectedDevice]);

  const handleConnect = async () => {
    if (!selectedDevice) {
      setErrorMessage('Please select a device first');
      return;
    }

    setConnectionStatus('connecting');
    setErrorMessage(null);

    try {
      await startConnectionFlow(selectedDevice.id, '', '');
      // The connection status will be updated via the useEffect that watches status
      // Processes will be loaded automatically when device becomes connected
    } catch (error) {
      setConnectionStatus('error');
      setErrorMessage(error instanceof Error ? error.message : 'Connection failed');
    }
  };

  const handleDisconnect = async () => {
    try {
      setConnectionStatus('connecting');
      setErrorMessage(null);
      
      await disconnectDevice();
      
      // The connection status will be updated via the useEffect that watches status
      setConnectionStatus('idle');
    } catch (error) {
      setConnectionStatus('error');
      setErrorMessage(error instanceof Error ? error.message : 'Disconnection failed');
    }
  };

  const canProceedToNext = () => {
    switch (activeStep) {
      case 0:
        // Can proceed to next step if device is selected and connected
        return selectedDevice !== null && status?.session.is_connected;
      case 1:
        // Can proceed to next step if Frida server is configured or not needed
        return fridaStatus !== null && (fridaStatus.is_running || fridaStatus.error === null);
      case 2:
        // Can proceed to next step if process is selected
        return selectedProcess !== null;
      case 3:
        // Can proceed to next step if hook script is not required or is selected
        return !useHookScript || selectedScript !== null;
      case 4:
        // Can proceed to finish if everything is configured
        return true;
      default:
        return false;
    }
  };

  const getStepStatus = (stepIndex: number) => {
    if (stepIndex < activeStep) return 'completed';
    if (stepIndex === activeStep) return 'active';
    return 'pending';
  };

  // Reusable table structure configuration
const deviceTableConfig = {
  containerHeight: 220,
  minWidth: 650,
  columns: [
    { width: '30%', header: 'Serial', key: 'serial' },
    { width: '50%', header: 'Model', key: 'model' },
    { width: '15%', header: 'Status', key: 'status' }
  ]
};

  // Reusable table structure component
  const DeviceTableStructure = ({ children, showRefreshButton = false, onRefresh, loading = false, isSpinning = false }: {
    children: React.ReactNode;
    showRefreshButton?: boolean;
    onRefresh?: () => void;
    loading?: boolean;
    isSpinning?: boolean;
  }) => (
    <TableContainer sx={{ height: deviceTableConfig.containerHeight }}>
      <Table sx={{ minWidth: deviceTableConfig.minWidth }}>
        <TableHead sx={{ '& .MuiTableCell-head': { py: 1 } }}>
          <TableRow>
            {deviceTableConfig.columns.map((column) => (
              <TableCell key={column.key} sx={{ width: column.width, verticalAlign: 'middle' }}>
                {column.key === 'status' && showRefreshButton ? (
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', height: 32 }}>
                    <span>{column.header}</span>
                    <Tooltip title="Refresh Device List" placement="top">
                      <IconButton 
                        size="small" 
                        onClick={onRefresh} 
                        disabled={loading}
                        sx={{ ml: 1, width: 32, height: 32, minWidth: 32 }}
                      >
                        <AnimatedRefreshIcon sx={{ fontSize: 20 }} $isSpinning={isSpinning} />
                      </IconButton>
                    </Tooltip>
                  </Box>
                ) : (
                  column.header
                )}
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {children}
        </TableBody>
      </Table>
    </TableContainer>
  );



  const ProcessSkeleton = () => (
    <TableContainer sx={{ maxHeight: 250 }}>
      <Table sx={{ minWidth: 650 }}>
        <TableHead>
          <TableRow>
            <TableCell sx={{ width: '40%', verticalAlign: 'middle' }}>App Name</TableCell>
            <TableCell sx={{ width: '60%', verticalAlign: 'middle' }}>Package</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {[1, 2, 3, 4, 5].map((i) => (
            <TableRow key={i}>
              <TableCell sx={{ width: '40%' }}><Skeleton variant="text" width="80%" /></TableCell>
              <TableCell sx={{ width: '60%' }}><Skeleton variant="text" width="90%" /></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  return (
    <Box sx={{ 
      width: '100%',
      height: 'calc(100vh - 120px)', // Account for AppBar, Toolbar, and Breadcrumbs
      display: 'flex',
      flexDirection: 'column'
    }}>
      {/* Fixed header section */}
      <Box sx={{ flexShrink: 0 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
          <ConnectIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
          <Typography variant="h4" component="h1">
            Device Connection
          </Typography>
        </Box>

        <Typography variant="body1" color="text.secondary" paragraph>
          Connect to a device and attach to a process to begin monitoring and analysis.
        </Typography>

        {(errorMessage || error) && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {errorMessage || error}
          </Alert>
        )}
      </Box>

      {/* Scrollable content section */}
      <Box sx={{ 
        flex: 1, 
        overflow: 'auto', 
        minHeight: 1,
        pb: 4 // Add bottom margin/padding
      }}>
        {steps.map((step, index) => (
          <Accordion 
            key={step.label}
            expanded={isStepExpanded(index)}
            onChange={() => {
              // Toggle expansion for any step
              if (isStepExpanded(index)) {
                // If already expanded, collapse it
                setExpandedSteps(prev => {
                  const newSet = new Set(prev);
                  newSet.delete(index);
                  return newSet;
                });
              } else {
                // If collapsed, expand it and navigate to it
                setActiveStep(index);
                setExpandedSteps(prev => new Set([...prev, index]));
              }
            }}

          >
            <AccordionSummary
              sx={{ 
                alignItems: 'center',
                cursor: 'pointer',
                '& .MuiAccordionSummary-content': {
                  alignItems: 'center',
                  gap: 2
                }
              }}
            >
              {step.icon}
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="h6">{step.label}</Typography>
                {step.optional && (
                  <Typography variant="caption" color="text.secondary">
                    (Optional)
                  </Typography>
                )}
                <Tooltip title={step.description} placement="top">
                  <InfoOutlineIcon sx={{ fontSize: '1rem', color: 'text.secondary', ml: 1 }} />
                </Tooltip>
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ pb: 2 }}>

                {/* Step 0: Device Selection */}
                {index === 0 && (
                  <Card variant="outlined">
                    <CardContent sx={{ pt: 1, pb: 2, px: 2, minHeight: 200, transition: 'all 0.3s ease-in-out' }}>
                                            <Box sx={{ 
                        position: 'relative',
                        minHeight: deviceTableConfig.containerHeight,
                        transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)'
                      }}>
                        {/* Fixed Header - Always Visible */}
                        <DeviceTableStructure key="device-table-header" showRefreshButton onRefresh={handleRefreshDevices} loading={devicesLoading} isSpinning={isRefreshSpinning}>
                          <TableBody>
                            {/* Empty body - header only */}
                          </TableBody>
                        </DeviceTableStructure>

                        {/* Animated Body Content */}
                        <Box sx={{
                          position: 'absolute',
                          top: 48, // Height of the header
                          left: 0,
                          right: 0,
                          bottom: 0,
                          overflow: 'hidden'
                        }}>
                          {/* Skeleton Body Layer */}
                          <Box sx={{
                            position: 'absolute',
                            top: 0,
                            left: 0,
                            right: 0,
                            opacity: devicesLoading ? 1 : 0,
                            transform: devicesLoading ? 'translateY(0)' : 'translateY(-10px)',
                            transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                            pointerEvents: devicesLoading ? 'auto' : 'none',
                            zIndex: devicesLoading ? 2 : 1
                          }}>
                            <Table>
                              <TableBody>
                                {[1, 2, 3].map((i) => (
                                  <TableRow key={i}>
                                    <TableCell sx={{ width: '30%', verticalAlign: 'middle' }}>
                                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                        <Skeleton variant="rectangular" width={16} height={21} sx={{ borderRadius: 0.7}} animation="wave" />
                                        <Skeleton variant="text" width="80%" animation="wave" />
                                      </Box>
                                    </TableCell>
                                    <TableCell sx={{ width: '50%', verticalAlign: 'middle' }}><Skeleton variant="text" width="70%" animation="wave" /></TableCell>
                                    <TableCell sx={{ width: '15%', verticalAlign: 'middle' }}>
                                      <Skeleton variant="rectangular" width={100} height={24} sx={{ borderRadius: 12 }} animation="wave" />
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </Box>

                          {/* Real Content Body Layer */}
                          <Box sx={{
                            opacity: devicesLoading ? 0 : 1,
                            transform: devicesLoading ? 'translateY(10px)' : 'translateY(0)',
                            transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                            pointerEvents: devicesLoading ? 'none' : 'auto',
                            zIndex: devicesLoading ? 1 : 2
                          }}>
                            {devices.length === 0 ? (
                              <Alert severity="warning" sx={{ mb: 2 }}>
                                No devices found. This could be because:
                                <ul>
                                  <li>No Android devices or emulators are connected</li>
                                  <li>ADB is not properly configured</li>
                                  <li>Devices are not authorized for debugging</li>
                                </ul>
                                Try refreshing the device list or check your ADB configuration.
                              </Alert>
                            ) : (
                              <Table>
                                <TableBody>
                                  {devices.map((device) => {
                                    // Determine if this device is currently connected
                                    const isConnected = status?.session.is_connected && 
                                                      status?.session.current_device === device.id;
                                   
                                    return (
                                      <TableRow 
                                        key={device.id} 
                                        selected={selectedDevice?.id === device.id}
                                        hover
                                        onClick={() => handleDeviceSelect(device)}
                                        sx={{ cursor: 'pointer' }}
                                      >
                                        <TableCell sx={{ width: '30%', verticalAlign: 'middle' }}>
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            {device.type === 'emulator' ? (
                                              <DeveloperModeIcon fontSize="small" color="primary" />
                                            ) : (
                                              <SmartphoneIcon fontSize="small" color="primary" />
                                            )}
                                            {device.id}
                                          </Box>
                                        </TableCell>
                                        <TableCell sx={{ width: '50%', verticalAlign: 'middle' }}>{device.name}</TableCell>
                                        <TableCell sx={{ width: '15%', verticalAlign: 'middle' }}>
                                          <Box sx={{ display: 'flex', justifyContent: 'center' }}>
                                            <Chip
                                              label={isConnected ? 'Connected' : device.status}
                                              color={isConnected ? 'success' : 'default'}
                                              size="small"
                                              sx={{ minWidth: 100, justifyContent: 'center' }}
                                            />
                                          </Box>
                                        </TableCell>
                                      </TableRow>
                                    );
                                  })}
                                </TableBody>
                              </Table>
                            )}
                          </Box>
                        </Box>
                      </Box>
                    </CardContent>
                  </Card>
                )}

                {/* Step 1: Frida Server Configuration */}
                {index === 1 && (
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                        <Typography variant="h6">Frida Server Configuration</Typography>
                        <IconButton onClick={handleCheckFridaStatus} disabled={fridaLoading || !selectedDevice}>
                          {fridaLoading ? <CircularProgress size={20} /> : <RefreshIcon />}
                        </IconButton>
                      </Box>
                      
                      {!selectedDevice ? (
                        <Alert severity="info" sx={{ mb: 2 }}>
                          Please select a device first to configure Frida server.
                        </Alert>
                      ) : fridaLoading ? (
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                          <Skeleton variant="rectangular" height={60} />
                          <Skeleton variant="rectangular" height={40} />
                          <Skeleton variant="rectangular" height={40} />
                        </Box>
                      ) : fridaError ? (
                        <Alert severity="error" sx={{ mb: 2 }}>
                          {fridaError}
                        </Alert>
                      ) : fridaStatus ? (
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                          {/* Frida Server Status */}
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                            <Typography variant="subtitle1">Server Status:</Typography>
                            <Chip
                              label={fridaStatus.is_running ? 'Running' : 'Not Running'}
                              color={fridaStatus.is_running ? 'success' : 'error'}
                              size="small"
                            />
                          </Box>
                          
                          {/* Installation Status */}
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                            <Typography variant="subtitle1">Installation:</Typography>
                            <Chip
                              label={fridaStatus.is_installed ? 'Installed' : 'Not Installed'}
                              color={fridaStatus.is_installed ? 'success' : 'warning'}
                              size="small"
                            />
                          </Box>
                          
                          {/* Architecture */}
                          {fridaStatus.architecture && (
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                              <Typography variant="subtitle1">Architecture:</Typography>
                              <Typography variant="body2" color="text.secondary">
                                {fridaStatus.architecture}
                              </Typography>
                            </Box>
                          )}
                          
                          {/* Version Information */}
                          {fridaStatus.version && (
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                              <Typography variant="subtitle1">Current Version:</Typography>
                              <Typography variant="body2" color="text.secondary">
                                {fridaStatus.version}
                              </Typography>
                            </Box>
                          )}
                          
                          {fridaStatus.required_version && (
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                              <Typography variant="subtitle1">Required Version:</Typography>
                              <Typography variant="body2" color="text.secondary">
                                {fridaStatus.required_version}
                              </Typography>
                            </Box>
                          )}
                          
                          {/* Compatibility Information */}
                          {fridaCompatibility && (
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                              <Typography variant="subtitle1">Compatibility:</Typography>
                              <Chip
                                label={fridaCompatibility.is_compatible ? 'Compatible' : 'Incompatible'}
                                color={fridaCompatibility.is_compatible ? 'success' : 'error'}
                                size="small"
                              />
                            </Box>
                          )}
                          
                          {/* Action Buttons */}
                          <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 1 }}>
                            {/* Primary Actions */}
                            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                              {!fridaStatus.is_running ? (
                                <Button
                                  variant="contained"
                                  color="primary"
                                  onClick={handleStartFridaServer}
                                  disabled={fridaLoading}
                                  startIcon={fridaLoading ? <CircularProgress size={16} /> : <PlayIcon />}
                                >
                                  {fridaLoading ? 'Starting...' : 'Start Server'}
                                </Button>
                              ) : (
                                <Button
                                  variant="contained"
                                  color="error"
                                  onClick={handleStopFridaServer}
                                  disabled={fridaLoading}
                                  startIcon={fridaLoading ? <CircularProgress size={16} /> : <StopIcon />}
                                >
                                  {fridaLoading ? 'Stopping...' : 'Stop Server'}
                                </Button>
                              )}
                              
                              <Button
                                variant="outlined"
                                onClick={handleProvisionFridaServer}
                                disabled={fridaLoading}
                                startIcon={fridaLoading ? <CircularProgress size={16} /> : <PlayIcon />}
                              >
                                {fridaLoading ? 'Provisioning...' : 'Provision Server'}
                              </Button>
                            </Box>
                            
                            {/* Secondary Actions */}
                            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                              <Button
                                variant="outlined"
                                color="secondary"
                                onClick={handleInstallFridaServer}
                                disabled={fridaLoading}
                                startIcon={fridaLoading ? <CircularProgress size={16} /> : <DeveloperModeIcon />}
                              >
                                {fridaLoading ? 'Installing...' : 'Install Only'}
                              </Button>
                              
                              <Button
                                variant="outlined"
                                color="warning"
                                onClick={handleRemoveFridaServer}
                                disabled={fridaLoading}
                                startIcon={fridaLoading ? <CircularProgress size={16} /> : <RemoveIcon />}
                              >
                                {fridaLoading ? 'Removing...' : 'Remove Server'}
                              </Button>
                            </Box>
                          </Box>
                          
                          {/* Status Messages */}
                          {fridaStatus.is_running && (
                            <Alert severity="success" sx={{ mt: 2 }}>
                              Frida server is running and ready for use.
                            </Alert>
                          )}
                          
                          {!fridaStatus.is_installed && (
                            <Alert severity="warning" sx={{ mt: 2 }}>
                              Frida server is not installed. Click "Install Only" or "Provision Server" to install.
                            </Alert>
                          )}
                          
                          {fridaStatus.is_installed && !fridaStatus.is_running && (
                            <Alert severity="info" sx={{ mt: 2 }}>
                              Frida server is installed but not running. Click "Start Server" to start it.
                            </Alert>
                          )}
                          
                          {fridaStatus.needs_update && (
                            <Alert severity="warning" sx={{ mt: 2 }}>
                              Frida server needs to be updated. Click "Provision Server" to update.
                            </Alert>
                          )}
                          
                          {fridaStatus.error && (
                            <Alert severity="error" sx={{ mt: 2 }}>
                              Error: {fridaStatus.error}
                            </Alert>
                          )}
                        </Box>
                      ) : (
                        <Alert severity="info" sx={{ mb: 2 }}>
                          Click the refresh button to check Frida server status.
                        </Alert>
                      )}
                    </CardContent>
                  </Card>
                )}

                {/* Step 2: Process Selection */}
                {index === 2 && (
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                        <Typography variant="h6">Available Processes ({totalProcesses})</Typography>
                        <IconButton 
                          onClick={handleRefreshProcesses} 
                          disabled={!selectedDevice || !status?.session.is_connected || processesLoading}
                        >
                          {processesLoading ? <CircularProgress size={20} /> : <RefreshIcon />}
                        </IconButton>
                      </Box>
                      
                      {!status?.session.is_connected ? (
                        <Alert severity="info" sx={{ mb: 2 }}>
                          Please connect to a device first to view available processes.
                        </Alert>
                      ) : selectedDevice ? (
                        <>
                          {/* Search and filter controls */}
                          <Box sx={{ mb: 2, display: 'flex', flexDirection: 'column', gap: 1 }}>
                            <TextField
                              fullWidth
                              size="small"
                              placeholder={`Search processes... (${searchFilteredProcesses} match${searchFilteredProcesses !== 1 ? 'es' : ''})`}
                              value={processSearchTerm}
                              onChange={(e) => setProcessSearchTerm(e.target.value)}
                              InputProps={{
                                startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                              }}
                            />
                            <Box sx={{ display: 'flex', gap: 2 }}>
                              <FormControlLabel
                                control={
                                  <Checkbox
                                    checked={showOnlyThirdParty}
                                    onChange={(e) => setShowOnlyThirdParty(e.target.checked)}
                                    size="small"
                                  />
                                }
                                label={`Show Only Third Party Processes (${thirdPartyProcesses})`}
                              />
                              <FormControlLabel
                                control={
                                  <Checkbox
                                    checked={showOnlyRunning}
                                    onChange={(e) => setShowOnlyRunning(e.target.checked)}
                                    size="small"
                                  />
                                }
                                label={`Show Only Running Processes (${runningProcesses})`}
                              />
                            </Box>
                          </Box>
                          
                          {processesLoading ? (
                            <ProcessSkeleton />
                          ) : filteredProcesses.length === 0 ? (
                            <Alert severity="warning" sx={{ mb: 2 }}>
                              {processes.length === 0 ? (
                                <>
                                  No user processes found on this device. This could be because:
                                  <ul>
                                    <li>The device is still starting up</li>
                                    <li>No user applications are currently running</li>
                                    <li>The device connection is unstable</li>
                                  </ul>
                                  Try refreshing the process list or wait a moment and try again.
                                </>
                              ) : (
                                <>
                                  No processes match your search criteria.
                                  {showOnlyThirdParty && (
                                    <Typography variant="body2" sx={{ mt: 1 }}>
                                      Try unchecking "Show Only Third Party Processes" to see system processes as well.
                                    </Typography>
                                  )}
                                </>
                              )}
                            </Alert>
                          ) : (
                            <TableContainer sx={{ maxHeight: 250 }}>
                              <Table sx={{ minWidth: 650 }}>
                                <TableHead>
                                  <TableRow>
                                    <TableCell sx={{ width: '40%', verticalAlign: 'middle' }}>App Name</TableCell>
                                    <TableCell sx={{ width: '60%', verticalAlign: 'middle' }}>Package</TableCell>
                                  </TableRow>
                                </TableHead>
                                <TableBody>
                                  {filteredProcesses.map((process) => {
                                    // Format the process name to add spaces before capital letters
                                    const formatProcessName = (name: string) => {
                                      return name.replace(/([A-Z])/g, ' $1').trim();
                                    };
                                    
                                    return (
                                      <TableRow 
                                        key={process.id} 
                                        selected={selectedProcess?.id === process.id}
                                        hover
                                        onClick={() => handleProcessSelect(process)}
                                        sx={{ cursor: 'pointer' }}
                                      >
                                        <TableCell sx={{ width: '40%', verticalAlign: 'middle' }}>
                                          {formatProcessName(process.name)}
                                        </TableCell>
                                        <TableCell sx={{ width: '60%', verticalAlign: 'middle' }}>
                                          {process.package || 'N/A'}
                                        </TableCell>
                                      </TableRow>
                                    );
                                  })}
                                </TableBody>
                              </Table>
                            </TableContainer>
                          )}
                        </>
                      ) : (
                        <Typography color="text.secondary">
                          Please select a device first to view available processes.
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                )}

                {/* Step 3: Hook Script Configuration */}
                {index === 3 && (
                  <Card variant="outlined">
                    <CardContent>
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={useHookScript}
                            onChange={(e) => setUseHookScript(e.target.checked)}
                          />
                        }
                        label="Use Hook Script"
                      />
                      
                      {useHookScript && (
                        <Box sx={{ mt: 2 }}>
                          <Typography variant="h6" gutterBottom>Available Scripts</Typography>
                          <List>
                            {hookScripts.map((script) => {
                              const compatibility = checkScriptCompatibility(script);
                              return (
                                <ListItem key={script.id} disablePadding>
                                  <ListItemButton
                                    selected={selectedScript?.id === script.id}
                                    onClick={() => handleScriptSelect(script)}
                                  >
                                    <ListItemIcon>
                                      <ScriptIcon />
                                    </ListItemIcon>
                                    <ListItemText
                                      primary={script.name}
                                      secondary={
                                        <Box>
                                          <Typography variant="body2" color="text.secondary">
                                            {script.description}
                                          </Typography>
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
                                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                              {compatibility.packageMatch ? (
                                                <CheckCircleIcon fontSize="small" color="success" />
                                              ) : (
                                                <CancelIcon fontSize="small" color="error" />
                                              )}
                                              <Typography variant="caption" color={compatibility.packageMatch ? "success.main" : "error.main"}>
                                                App: {script.targetApp || script.targetPackage || 'Unknown'}
                                              </Typography>
                                            </Box>
                                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                              {compatibility.versionMatch ? (
                                                <CheckCircleIcon fontSize="small" color="success" />
                                              ) : (
                                                <CancelIcon fontSize="small" color="error" />
                                              )}
                                              <Typography variant="caption" color={compatibility.versionMatch ? "success.main" : "error.main"}>
                                                Version: {script.supportedVersions?.join(', ') || 'Unknown'}
                                              </Typography>
                                            </Box>
                                          </Box>
                                          {!compatibility.isCompatible && (
                                            <Box sx={{ mt: 1 }}>
                                              <Typography 
                                                variant="caption" 
                                                color="error.main" 
                                                display="block"
                                              >
                                                {compatibility.compatibilityMessage || compatibility.packageMismatch}
                                              </Typography>
                                            </Box>
                                          )}
                                        </Box>
                                      }
                                    />
                                  </ListItemButton>
                                </ListItem>
                              );
                            })}
                          </List>
                          
                          {/* Hook Activation Controls */}
                          {selectedScript && (
                            <Box sx={{ mt: 3 }}>
                              <Typography variant="h6" gutterBottom>Hook Controls</Typography>
                              
                              {/* Hook Status */}
                              <Box sx={{ mb: 2 }}>
                                <Typography variant="body2" color="text.secondary">
                                  Status: 
                                  <Chip
                                    label={
                                      hookActivationStatus === 'idle' ? 'Not Active' :
                                      hookActivationStatus === 'activating' ? 'Activating...' :
                                      hookActivationStatus === 'active' ? 'Active' :
                                      hookActivationStatus === 'deactivating' ? 'Deactivating...' :
                                      'Error'
                                    }
                                    color={
                                      hookActivationStatus === 'active' ? 'success' :
                                      hookActivationStatus === 'error' ? 'error' :
                                      'default'
                                    }
                                    size="small"
                                    sx={{ ml: 1 }}
                                  />
                                </Typography>
                              </Box>
                              
                              {/* Hook Error */}
                              {hookError && (
                                <Alert severity="error" sx={{ mb: 2 }}>
                                  {hookError}
                                </Alert>
                              )}
                              
                              {/* Hook Action Buttons */}
                              <Box sx={{ display: 'flex', gap: 2 }}>
                                <Button
                                  variant="contained"
                                  color="primary"
                                  onClick={handleStartHook}
                                  disabled={
                                    hookActivationStatus === 'activating' || 
                                    hookActivationStatus === 'deactivating' ||
                                    hookActivationStatus === 'active' ||
                                    !selectedDevice ||
                                    !selectedProcess
                                  }
                                  startIcon={
                                    hookActivationStatus === 'activating' ? 
                                    <CircularProgress size={16} /> : 
                                    <PlayIcon />
                                  }
                                >
                                  {hookActivationStatus === 'activating' ? 'Starting...' : 'Start Hook'}
                                </Button>
                                
                                <Button
                                  variant="contained"
                                  color="error"
                                  onClick={handleStopHook}
                                  disabled={
                                    hookActivationStatus === 'activating' || 
                                    hookActivationStatus === 'deactivating' ||
                                    hookActivationStatus === 'idle' ||
                                    !selectedDevice ||
                                    !selectedProcess
                                  }
                                  startIcon={
                                    hookActivationStatus === 'deactivating' ? 
                                    <CircularProgress size={16} /> : 
                                    <StopIcon />
                                  }
                                >
                                  {hookActivationStatus === 'deactivating' ? 'Stopping...' : 'Stop Hook'}
                                </Button>
                              </Box>
                              
                              {/* Hook Status Messages */}
                              {hookActivationStatus === 'active' && (
                                <Alert severity="success" sx={{ mt: 2 }}>
                                  Hook is active and monitoring the selected process.
                                </Alert>
                              )}
                              
                              {hookActivationStatus === 'idle' && selectedScript && (
                                <Alert severity="info" sx={{ mt: 2 }}>
                                  Ready to activate hook on the selected process.
                                </Alert>
                              )}
                            </Box>
                          )}
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                )}

                {/* Step 4: Connection */}
                {index === 4 && (
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>Connection Summary</Typography>
                      
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="body2" color="text.secondary">
                          Device: {selectedDevice?.name}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Process: {selectedProcess?.name} (PID: {selectedProcess?.pid})
                        </Typography>
                        {useHookScript && selectedScript && (
                          <Typography variant="body2" color="text.secondary">
                            Script: {selectedScript.name}
                          </Typography>
                        )}
                        {hookActivationStatus !== 'idle' && (
                          <Typography variant="body2" color="text.secondary">
                            Hook Status: 
                            <Chip
                              label={
                                hookActivationStatus === 'activating' ? 'Activating...' :
                                hookActivationStatus === 'active' ? 'Active' :
                                hookActivationStatus === 'deactivating' ? 'Deactivating...' :
                                'Error'
                              }
                              color={
                                hookActivationStatus === 'active' ? 'success' :
                                hookActivationStatus === 'error' ? 'error' :
                                'default'
                              }
                              size="small"
                              sx={{ ml: 1 }}
                            />
                          </Typography>
                        )}
                      </Box>

                      {/* Script Status Widget */}
                      {status?.session.is_connected && (
                        <Box sx={{ mb: 2 }}>
                          <ScriptStatusWidget 
                            scriptStatus={scriptStatus} 
                            isLoading={scriptStatusLoading}
                            onRefresh={refreshScriptStatus}
                          />
                        </Box>
                      )}

                      <Alert severity="success">
                        All configuration is complete. You can now start monitoring the selected process.
                      </Alert>
                    </CardContent>
                  </Card>
                )}

                <Box sx={{ mb: 2, mt: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Box>
                    <Tooltip 
                      title={
                        index === 0 && !canProceedToNext() ? "Please connect to a device to continue" :
                        index === 1 && !canProceedToNext() ? "Please configure Frida server to continue" :
                        ""
                      }
                      open={(index === 0 || index === 1) && !canProceedToNext() ? undefined : false}
                    >
                      <span>
                        <Button
                          variant="contained"
                          onClick={handleNext}
                          disabled={!canProceedToNext()}
                          sx={{ mt: 1, mr: 1 }}
                        >
                          {index === steps.length - 1 ? 'Finish' : 'Continue'}
                        </Button>
                      </span>
                    </Tooltip>
                    {index > 0 && (
                      <Button
                        onClick={handleBack}
                        sx={{ mt: 1, mr: 1 }}
                      >
                        Back
                      </Button>
                    )}
                  </Box>
                  
                  {/* Connect/Disconnect button for device selection step */}
                  {index === 0 && selectedDevice && (
                    <Button
                      variant={status?.session.is_connected && status?.session.current_device === selectedDevice.id ? "outlined" : "contained"}
                      color={status?.session.is_connected && status?.session.current_device === selectedDevice.id ? "error" : "primary"}
                      startIcon={status?.session.is_connected && status?.session.current_device === selectedDevice.id ? <StopIcon /> : <PlayIcon />}
                      onClick={status?.session.is_connected && status?.session.current_device === selectedDevice.id ? handleDisconnect : handleConnect}
                      disabled={connectionStatus === 'connecting'}
                      sx={{ mt: 1 }}
                    >
                      {status?.session.is_connected && status?.session.current_device === selectedDevice.id ? 'Disconnect' : 'Connect'}
                    </Button>
                  )}
                </Box>
            </AccordionDetails>
          </Accordion>
        ))}
      </Box>

      {activeStep === steps.length && (
        <Paper square elevation={0} sx={{ p: 3, mt: 3 }}>
          <Typography>All steps completed - you're ready to connect!</Typography>
          <Button onClick={handleReset} sx={{ mt: 1, mr: 1 }}>
            Reset
          </Button>
        </Paper>
      )}
    </Box>
  );
}
