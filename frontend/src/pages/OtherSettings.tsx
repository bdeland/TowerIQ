import { useState, useEffect } from 'react';
import type { KeyboardEvent } from 'react';
import { Box, Typography, Card, CardContent, Switch, FormControlLabel, TextField, Button, MenuItem, Collapse } from '@mui/material';
import Grid from '@mui/material/Grid';
import { MoreHoriz as OtherIcon, Save, Notifications, Security, DeveloperMode, ExpandMore, ExpandLess } from '@mui/icons-material';
import { useDeveloper } from '../contexts/DeveloperContext';
import { DebugBorderSetting } from '../components/DebugBorderSetting';
import { DashboardDebugPreview } from '../components/DashboardDebugPreview';

export function OtherSettings() {
  const { 
    isDevMode, 
    toggleDevMode, 
    debugBorders, 
    setDebugBorders, 
    debugBorderSettings,
    setDebugBorderSettings,
    breadcrumbCopy, 
    setBreadcrumbCopy, 
    minPanelLoadingMs, 
    setMinPanelLoadingMs 
  } = useDeveloper();
  
  // Local state for other settings
  const [notifications, setNotifications] = useState(true);
  const [emailAlerts, setEmailAlerts] = useState(false);
  const [systemUpdates, setSystemUpdates] = useState(true);
  const [autoLogoutTimeout, setAutoLogoutTimeout] = useState('30');
  const [twoFactorAuth, setTwoFactorAuth] = useState(true);
  const [sessionEncryption, setSessionEncryption] = useState(false);
  const [saving, setSaving] = useState(false);

  const [minLoadingInput, setMinLoadingInput] = useState<string>(() => String(minPanelLoadingMs));
  const [debugBordersExpanded, setDebugBordersExpanded] = useState(false);

  // Auto-expand/collapse debug borders section when the main toggle changes
  useEffect(() => {
    setDebugBordersExpanded(debugBorders);
  }, [debugBorders]);

  useEffect(() => {
    setMinLoadingInput(String(minPanelLoadingMs));
  }, [minPanelLoadingMs]);

  const handleMinLoadingCommit = () => {
    const parsed = Number(minLoadingInput);
    if (!Number.isNaN(parsed) && parsed >= 0) {
      setMinPanelLoadingMs(parsed);
    } else {
      setMinLoadingInput(String(minPanelLoadingMs));
    }
  };

  const handleMinLoadingKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      handleMinLoadingCommit();
    }
  };



  const handleSave = async () => {
    setSaving(true);
    // TODO: Implement actual save functionality when backend endpoints are available
    setTimeout(() => {
      setSaving(false);
    }, 1000);
  };

  return (
    <Box sx={{ padding: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <OtherIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
        <Typography variant="h4" component="h1">
          Other Settings
        </Typography>
      </Box>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        Configure notifications, security, developer tools, and advanced options.
      </Typography>
      
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Notifications sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">
                  Notifications
                </Typography>
              </Box>
              <FormControlLabel
                control={
                  <Switch 
                    checked={notifications} 
                    onChange={(e) => setNotifications(e.target.checked)} 
                  />
                }
                label="Enable notifications"
                sx={{ mb: 1, display: 'block' }}
              />
              <FormControlLabel
                control={
                  <Switch 
                    checked={emailAlerts} 
                    onChange={(e) => setEmailAlerts(e.target.checked)} 
                  />
                }
                label="Email alerts"
                sx={{ mb: 1, display: 'block' }}
              />
              <FormControlLabel
                control={
                  <Switch 
                    checked={systemUpdates} 
                    onChange={(e) => setSystemUpdates(e.target.checked)} 
                  />
                }
                label="System updates"
                sx={{ display: 'block' }}
              />
            </CardContent>
          </Card>
        </Grid>
        
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Security sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">
                  Security
                </Typography>
              </Box>
              <TextField
                fullWidth
                select
                label="Auto-logout timeout"
                value={autoLogoutTimeout}
                onChange={(e) => setAutoLogoutTimeout(e.target.value)}
                sx={{ mb: 2 }}
              >
                <MenuItem value="15">15 minutes</MenuItem>
                <MenuItem value="30">30 minutes</MenuItem>
                <MenuItem value="60">1 hour</MenuItem>
                <MenuItem value="120">2 hours</MenuItem>
                <MenuItem value="0">Never</MenuItem>
              </TextField>
              <FormControlLabel
                control={
                  <Switch 
                    checked={twoFactorAuth} 
                    onChange={(e) => setTwoFactorAuth(e.target.checked)} 
                  />
                }
                label="Two-factor authentication"
                sx={{ mb: 1, display: 'block' }}
              />
              <FormControlLabel
                control={
                  <Switch 
                    checked={sessionEncryption} 
                    onChange={(e) => setSessionEncryption(e.target.checked)} 
                  />
                }
                label="Session encryption"
                sx={{ display: 'block' }}
              />
            </CardContent>
          </Card>
        </Grid>
        
        <Grid size={12}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <DeveloperMode sx={{ mr: 1, color: 'primary.main' }} />
                  <Typography variant="h6">
                    Developer Tools
                  </Typography>
                </Box>
                <FormControlLabel
                  control={
                    <Switch
                      checked={isDevMode}
                      onChange={toggleDevMode}
                    />
                  }
                  label="Enable Development Mode"
                />
              </Box>
              
              <Collapse in={isDevMode} sx={{ mb: isDevMode ? 0 : -1 }}>
                <Box sx={{ mt: isDevMode ? 2 : 0, pl: 1, display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={debugBorders}
                          onChange={(e) => setDebugBorders(e.target.checked)}
                          disabled={!isDevMode}
                        />
                      }
                      label="Show dashboard debug borders"
                    />
                    <Button
                      size="small"
                      onClick={() => {
                        const newExpanded = !debugBordersExpanded;
                        setDebugBordersExpanded(newExpanded);
                        if (newExpanded && !debugBorders) {
                          setDebugBorders(true);
                        } else if (!newExpanded && debugBorders) {
                          setDebugBorders(false);
                        }
                      }}
                      disabled={!isDevMode}
                      sx={{ minWidth: 'auto', p: 0.5 }}
                    >
                      {debugBordersExpanded ? <ExpandLess /> : <ExpandMore />}
                    </Button>
                  </Box>
                  
                  <Collapse in={debugBordersExpanded && isDevMode && debugBorders}>
                    <Box sx={{ ml: 4, mt: 2, display: 'flex', gap: 3, alignItems: 'flex-start' }}>
                      {/* Left side: Color options */}
                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, flex: '0 0 auto' }}>
                        <DebugBorderSetting
                          label="Grid Container"
                          value={debugBorderSettings.gridContainer.color}
                          onChange={(color) => setDebugBorderSettings({
                            ...debugBorderSettings,
                            gridContainer: { ...debugBorderSettings.gridContainer, color, enabled: color !== 'off' }
                          })}
                          minWidth="100px"
                        />

                        <DebugBorderSetting
                          label="Panel Borders"
                          value={debugBorderSettings.panels.color}
                          onChange={(color) => setDebugBorderSettings({
                            ...debugBorderSettings,
                            panels: { ...debugBorderSettings.panels, color, enabled: color !== 'off' }
                          })}
                          minWidth="100px"
                        />

                        <DebugBorderSetting
                          label="Grid Cells"
                          value={debugBorderSettings.gridCells.color}
                          onChange={(color) => setDebugBorderSettings({
                            ...debugBorderSettings,
                            gridCells: { ...debugBorderSettings.gridCells, color, enabled: color !== 'off' }
                          })}
                          minWidth="100px"
                        />
                      </Box>

                      {/* Right side: Preview */}
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="caption" color="text.secondary" sx={{ ml: 0.5, mb: 1, display: 'block' }}>
                          Preview
                        </Typography>
                        <DashboardDebugPreview />
                      </Box>
                    </Box>
                  </Collapse>
                </Box>
                <FormControlLabel
                  control={
                    <Switch
                      checked={breadcrumbCopy}
                      onChange={(e) => setBreadcrumbCopy(e.target.checked)}
                      disabled={!isDevMode}
                    />
                  }
                  label="Enable breadcrumb copy menu"
                  sx={{ display: 'block' }}
                />
                <TextField
                  fullWidth
                  label="Minimum skeleton load time (ms)"
                  type="number"
                  value={minLoadingInput}
                  onChange={(e) => setMinLoadingInput(e.target.value)}
                  onBlur={handleMinLoadingCommit}
                  onKeyDown={handleMinLoadingKeyDown}
                  disabled={!isDevMode}
                  helperText="Set 0 to keep charts loading indefinitely for skeleton testing."
                  inputProps={{ min: 0, step: 100 }}
                />
                </Box>
              </Collapse>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Advanced Options</Typography>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="Log Level"
                    defaultValue="info"
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="debug">Debug</MenuItem>
                    <MenuItem value="info">Info</MenuItem>
                    <MenuItem value="warning">Warning</MenuItem>
                    <MenuItem value="error">Error</MenuItem>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="Performance Mode"
                    defaultValue="balanced"
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="performance">High Performance</MenuItem>
                    <MenuItem value="balanced">Balanced</MenuItem>
                    <MenuItem value="battery">Battery Saver</MenuItem>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControlLabel
                    control={<Switch defaultChecked />}
                    label="Enable telemetry"
                    sx={{ display: 'block' }}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControlLabel
                    control={<Switch />}
                    label="Beta features"
                    sx={{ display: 'block' }}
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={12}>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <Button 
              variant="contained" 
              startIcon={<Save />} 
              onClick={handleSave}
              disabled={saving}
            >
              {saving ? 'Saving...' : 'Save Settings'}
            </Button>
            <Button 
              variant="outlined" 
              onClick={() => {
                setNotifications(true);
                setEmailAlerts(false);
                setSystemUpdates(true);
                setAutoLogoutTimeout('30');
                setTwoFactorAuth(true);
                setSessionEncryption(false);
              }}
            >
              Reset to Defaults
            </Button>
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
}




