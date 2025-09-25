import { Box, Typography, Card, CardContent, Button, Switch, FormControlLabel, Alert, CircularProgress } from '@mui/material';
import { Home as HomeIcon, PlayArrow as PlayIcon, Stop as StopIcon } from '@mui/icons-material';
import { useBackend } from '../hooks/useBackend';

export function HomePage() {
  const { status, error, connectDevice, setTestMode } = useBackend();
  const isLoading = !status && !error;

  const handleTestModeToggle = async (enabled: boolean) => {
    try {
      await setTestMode(enabled);
    } catch (err) {
      console.error('Failed to set test mode:', err);
    }
  };

  const handleConnectDevice = async () => {
    try {
      // For demo purposes, using a test device serial
      await connectDevice('test_device_001');
    } catch (err) {
      console.error('Failed to connect device:', err);
    }
  };

  return (
    <Box sx={{ padding: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <HomeIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
        <Typography variant="h4" component="h1">
          Welcome to TowerIQ
        </Typography>
      </Box>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        Your central hub for managing and monitoring your TowerIQ system.
      </Typography>

      {/* Backend Status */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          Backend Error: {error}
        </Alert>
      )}

      {isLoading && (
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
          <CircularProgress size={20} sx={{ mr: 2 }} />
          <Typography>Connecting to backend...</Typography>
        </Box>
      )}
      
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mt: 2 }}>
        {/* Backend Status Card */}
        <Box sx={{ width: { xs: '100%', md: '50%' }, mb: 2 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Backend Status
              </Typography>
              {status ? (
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Status: {status.status}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Connected: {status.session.is_connected ? 'Yes' : 'No'}
                  </Typography>
                  {status.session.current_device && (
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Device: {status.session.current_device}
                    </Typography>
                  )}
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Test Mode: {status.session.test_mode ? 'Enabled' : 'Disabled'}
                  </Typography>
                </Box>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No backend connection
                </Typography>
              )}
            </CardContent>
          </Card>
        </Box>

        {/* Test Mode Controls */}
        <Box sx={{ width: { xs: '100%', md: '50%' }, mb: 2 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Test Mode
              </Typography>
              <FormControlLabel
                control={
                  <Switch
                    checked={status?.session.test_mode || false}
                    onChange={(e) => handleTestModeToggle(e.target.checked)}
                    disabled={isLoading}
                  />
                }
                label="Enable Test Mode"
              />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Test mode allows you to work with simulated data for development and testing.
              </Typography>
            </CardContent>
          </Card>
        </Box>

        {/* Device Connection */}
        <Box sx={{ width: { xs: '100%', md: '50%' }, mb: 2 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Device Connection
              </Typography>
              <Button
                variant="contained"
                startIcon={status?.session.is_connected ? <StopIcon /> : <PlayIcon />}
                onClick={handleConnectDevice}
                disabled={isLoading}
                sx={{ mb: 2 }}
              >
                {status?.session.is_connected ? 'Disconnect' : 'Connect Test Device'}
              </Button>
              <Typography variant="body2" color="text.secondary">
                Connect to a device to start monitoring and analysis.
              </Typography>
            </CardContent>
          </Card>
        </Box>
        
        <Box sx={{ width: { xs: '100%', md: '50%' }, mb: 2 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Quick Start
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Get started with TowerIQ by exploring the dashboard and configuring your settings.
              </Typography>
            </CardContent>
          </Card>
        </Box>
      </Box>
    </Box>
  );
}
