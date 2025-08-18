import React, { useState, useEffect } from 'react';
import {
  Box,
  Stepper,
  Step,
  StepLabel,
  StepContent,
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
} from '@mui/material';
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
} from '@mui/icons-material';
import { useBackend, Device, Process, HookScript } from '../hooks/useBackend';

// Remove duplicate interfaces since they're imported from useBackend

const steps = [
  {
    label: 'Select Device',
    description: 'Choose a device to connect to. This can be a physical device or emulator.',
    icon: <DeviceIcon />,
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
  const { 
    status, 
    loading, 
    error, 
    scanDevices, 
    getProcesses, 
    getHookScripts, 
    startConnectionFlow 
  } = useBackend();
  
  const [activeStep, setActiveStep] = useState(0);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [selectedProcess, setSelectedProcess] = useState<Process | null>(null);
  const [selectedScript, setSelectedScript] = useState<HookScript | null>(null);
  const [useHookScript, setUseHookScript] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'connecting' | 'connected' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Data from backend
  const [devices, setDevices] = useState<Device[]>([]);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [hookScripts, setHookScripts] = useState<HookScript[]>([]);

  // Load initial data
  useEffect(() => {
    loadDevices();
    loadHookScripts();
  }, []);

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

  const loadDevices = async () => {
    try {
      console.log('Starting device scan...');
      const deviceList = await scanDevices();
      console.log('Device scan completed:', deviceList);
      setDevices(deviceList);
    } catch (err) {
      console.error('Failed to load devices:', err);
      setErrorMessage(`Failed to scan for devices: ${err instanceof Error ? err.message : 'Unknown error'}`);
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

  const handleNext = () => {
    setActiveStep((prevActiveStep) => prevActiveStep + 1);
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
    setProcesses([]); // Clear processes until we scan for the new device
    
    // Load processes for the selected device
    try {
      const processList = await getProcesses(device.id);
      setProcesses(processList);
    } catch (err) {
      console.error('Failed to load processes for device:', err);
    }
  };

  const handleProcessSelect = (process: Process) => {
    setSelectedProcess(process);
  };

  const handleScriptSelect = (script: HookScript) => {
    setSelectedScript(script);
  };

  const handleRefreshDevices = async () => {
    try {
      await loadDevices();
    } catch (err) {
      console.error('Failed to refresh devices:', err);
    }
  };

  const handleRefreshProcesses = async () => {
    if (!selectedDevice) return;
    
    try {
      const processList = await getProcesses(selectedDevice.id);
      setProcesses(processList);
    } catch (err) {
      console.error('Failed to refresh processes:', err);
    }
  };

  const handleConnect = async () => {
    if (!selectedDevice || !selectedProcess) {
      setErrorMessage('Please select both a device and process');
      return;
    }

    setConnectionStatus('connecting');
    setErrorMessage(null);

    try {
      const hookScriptContent = useHookScript && selectedScript ? selectedScript.content : undefined;
      
      await startConnectionFlow(
        selectedDevice.id,
        selectedProcess.id,
        hookScriptContent
      );
      
      // The connection status will be updated via the useEffect that watches status
    } catch (error) {
      setConnectionStatus('error');
      setErrorMessage(error instanceof Error ? error.message : 'Connection failed');
    }
  };

  const handleDisconnect = async () => {
    setConnectionStatus('idle');
    setErrorMessage(null);
    // Update device status
    setDevices(prev => prev.map(d => ({ ...d, status: 'disconnected' as const })));
  };

  const canProceedToNext = () => {
    switch (activeStep) {
      case 0:
        return selectedDevice !== null;
      case 1:
        return selectedProcess !== null;
      case 2:
        return !useHookScript || selectedScript !== null;
      case 3:
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

  return (
    <Box sx={{ padding: 3, maxWidth: 800 }}>
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

      <Stepper activeStep={activeStep} orientation="vertical">
        {steps.map((step, index) => (
          <Step key={step.label}>
            <StepLabel
              optional={step.optional ? (
                <Typography variant="caption">Optional</Typography>
              ) : null}
              icon={step.icon}
            >
              {step.label}
            </StepLabel>
            <StepContent>
              <Typography sx={{ mb: 2 }}>
                {step.description}
              </Typography>

              {/* Step 0: Device Selection */}
              {index === 0 && (
                <Card variant="outlined">
                  <CardContent>
                                         <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                       <Typography variant="h6">Available Devices</Typography>
                       <IconButton onClick={handleRefreshDevices} disabled={loading}>
                         {loading ? <CircularProgress size={20} /> : <RefreshIcon />}
                       </IconButton>
                     </Box>
                    <List>
                      {devices.map((device) => (
                        <ListItem key={device.id} disablePadding>
                          <ListItemButton
                            selected={selectedDevice?.id === device.id}
                            onClick={() => handleDeviceSelect(device)}
                          >
                            <ListItemIcon>
                              <DeviceIcon />
                            </ListItemIcon>
                            <ListItemText
                              primary={device.name}
                              secondary={`Type: ${device.type} | Status: ${device.status}`}
                            />
                            <Chip
                              label={device.status}
                              color={device.status === 'connected' ? 'success' : 'default'}
                              size="small"
                            />
                          </ListItemButton>
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              )}

              {/* Step 1: Process Selection */}
              {index === 1 && (
                <Card variant="outlined">
                  <CardContent>
                                         <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                       <Typography variant="h6">Available Processes</Typography>
                       <IconButton onClick={handleRefreshProcesses} disabled={!selectedDevice || loading}>
                         {loading ? <CircularProgress size={20} /> : <RefreshIcon />}
                       </IconButton>
                     </Box>
                    {selectedDevice ? (
                      <List>
                        {processes.map((process) => (
                          <ListItem key={process.id} disablePadding>
                            <ListItemButton
                              selected={selectedProcess?.id === process.id}
                              onClick={() => handleProcessSelect(process)}
                            >
                              <ListItemIcon>
                                <ProcessIcon />
                              </ListItemIcon>
                              <ListItemText
                                primary={process.name}
                                secondary={`PID: ${process.pid}${process.package ? ` | Package: ${process.package}` : ''}`}
                              />
                            </ListItemButton>
                          </ListItem>
                        ))}
                      </List>
                    ) : (
                      <Typography color="text.secondary">
                        Please select a device first to view available processes.
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Step 2: Hook Script Configuration */}
              {index === 2 && (
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
                          {hookScripts.map((script) => (
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
                                  secondary={script.description}
                                />
                              </ListItemButton>
                            </ListItem>
                          ))}
                        </List>
                        
                        {selectedScript && (
                          <TextField
                            fullWidth
                            multiline
                            rows={4}
                            label="Script Preview"
                            value={selectedScript.content}
                            InputProps={{ readOnly: true }}
                            sx={{ mt: 2 }}
                          />
                        )}
                      </Box>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Step 3: Connection */}
              {index === 3 && (
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
                    </Box>

                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      {connectionStatus === 'connecting' && (
                        <CircularProgress size={20} />
                      )}
                      
                      {connectionStatus === 'connected' ? (
                        <Button
                          variant="outlined"
                          color="error"
                          startIcon={<StopIcon />}
                          onClick={handleDisconnect}
                        >
                          Disconnect
                        </Button>
                      ) : (
                        <Button
                          variant="contained"
                          startIcon={<PlayIcon />}
                          onClick={handleConnect}
                          disabled={connectionStatus === 'connecting'}
                        >
                          Connect
                        </Button>
                      )}
                      
                      {connectionStatus === 'connected' && (
                        <Chip
                          icon={<CheckIcon />}
                          label="Connected"
                          color="success"
                        />
                      )}
                    </Box>
                  </CardContent>
                </Card>
              )}

              <Box sx={{ mb: 2, mt: 2 }}>
                <Button
                  variant="contained"
                  onClick={handleNext}
                  disabled={!canProceedToNext()}
                  sx={{ mt: 1, mr: 1 }}
                >
                  {index === steps.length - 1 ? 'Finish' : 'Continue'}
                </Button>
                <Button
                  disabled={index === 0}
                  onClick={handleBack}
                  sx={{ mt: 1, mr: 1 }}
                >
                  Back
                </Button>
              </Box>
            </StepContent>
          </Step>
        ))}
      </Stepper>

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
