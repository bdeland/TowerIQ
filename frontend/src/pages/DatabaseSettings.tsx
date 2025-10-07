import { CheckCircle, ContentCopy, Storage as DatabaseIcon, ExpandLess, ExpandMore, FolderOpen, Cable as GrafanaIcon, PlayArrow, Refresh as RefreshIcon, Save } from '@mui/icons-material';
import { Alert, Box, Button, Card, CardContent, CardHeader, CircularProgress, Collapse, FormControlLabel, IconButton, InputAdornment, List, ListItem, ListItemText, Radio, RadioGroup, Snackbar, Switch, TextField, Typography } from '@mui/material';
import Grid from '@mui/material/Grid';
import { open } from '@tauri-apps/plugin-dialog';
import { useEffect, useState } from 'react';
import { API_CONFIG } from '../config/environment';

export function DatabaseSettings() {
  
  // Local state for database path and backup settings
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [runningBackup, setRunningBackup] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [sqlitePath, setSqlitePath] = useState('');
  const [backupEnabled, setBackupEnabled] = useState(true);
  const [backupDir, setBackupDir] = useState('');
  const [retentionCount, setRetentionCount] = useState(7);
  const [intervalSeconds, setIntervalSeconds] = useState(86400);
  const [onShutdown, setOnShutdown] = useState(true);
  const [compressZip, setCompressZip] = useState(true);
  const [filenamePrefix, setFilenamePrefix] = useState('toweriq_backup_');
  
  // Database statistics state
  const [dbStats, setDbStats] = useState<any>(null);
  const [statsLoading, setStatsLoading] = useState(false);
  const [statsError, setStatsError] = useState<string | null>(null);
  
  // Grafana integration state
  const [grafanaEnabled, setGrafanaEnabled] = useState(false);
  const [grafanaBindAddress, setGrafanaBindAddress] = useState('localhost');
  const [grafanaCustomIp, setGrafanaCustomIp] = useState('127.0.0.1');
  const [grafanaPort, setGrafanaPort] = useState(8000);
  const [grafanaQueryTimeout, setGrafanaQueryTimeout] = useState(30);
  const [grafanaMaxRows, setGrafanaMaxRows] = useState(10000);
  const [grafanaLoading, setGrafanaLoading] = useState(false);
  const [grafanaSaving, setGrafanaSaving] = useState(false);
  const [grafanaValidating, setGrafanaValidating] = useState(false);
  const [grafanaValidationResult, setGrafanaValidationResult] = useState<any>(null);
  const [showAdvancedGrafana, setShowAdvancedGrafana] = useState(false);
  const [copySnackbarOpen, setCopySnackbarOpen] = useState(false);

  const loadSettings = async () => {
    try {
      setLoading(true);
      setError(null);
      const [pathRes, backupRes] = await Promise.all([
        fetch(`${API_CONFIG.BASE_URL}/settings/database/path`),
        fetch(`${API_CONFIG.BASE_URL}/settings/database/backup`),
      ]);
      const pathData = await pathRes.json();
      const backupData = await backupRes.json();
      if (pathData?.sqlite_path) setSqlitePath(pathData.sqlite_path);
      if (backupData) {
        setBackupEnabled(!!backupData.enabled);
        setBackupDir(String(backupData.backup_dir || ''));
        setRetentionCount(parseInt(backupData.retention_count ?? 7));
        setIntervalSeconds(parseInt(backupData.interval_seconds ?? 86400));
        setOnShutdown(!!backupData.on_shutdown);
        setCompressZip(!!backupData.compress_zip);
        setFilenamePrefix(String(backupData.filename_prefix || 'toweriq_backup_'));
      }
    } catch (e: any) {
      setError(e?.message || 'Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const loadDatabaseStats = async () => {
    try {
      setStatsLoading(true);
      setStatsError(null);
      const response = await fetch(`${API_CONFIG.BASE_URL}/v1/database/statistics`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const stats = await response.json();
      setDbStats(stats);
    } catch (e: any) {
      setStatsError(e?.message || 'Failed to load database statistics');
    } finally {
      setStatsLoading(false);
    }
  };

  const refreshDatabaseStats = async () => {
    try {
      setStatsLoading(true);
      setStatsError(null);
      
      // First, trigger metrics collection
      const metricsResponse = await fetch(`${API_CONFIG.BASE_URL}/v1/database/collect-metrics`, {
        method: 'POST',
      });
      
      if (!metricsResponse.ok) {
        throw new Error(`Failed to collect metrics: HTTP ${metricsResponse.status}`);
      }
      
      // Then, load the updated statistics
      const statsResponse = await fetch(`${API_CONFIG.BASE_URL}/v1/database/statistics`);
      if (!statsResponse.ok) {
        throw new Error(`HTTP ${statsResponse.status}: ${statsResponse.statusText}`);
      }
      const stats = await statsResponse.json();
      setDbStats(stats);
      
      // Show success message (Snackbar will auto-dismiss)
      setSuccess('Database metrics collected and statistics refreshed');
      
    } catch (e: any) {
      setStatsError(e?.message || 'Failed to refresh database statistics');
    } finally {
      setStatsLoading(false);
    }
  };

  // Utility function to format file sizes
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  // Utility function to format dates
  const formatDate = (dateString: string): string => {
    if (!dateString) return 'Unknown';
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  const loadGrafanaSettings = async () => {
    try {
      setGrafanaLoading(true);
      const response = await fetch(`${API_CONFIG.BASE_URL}/settings/grafana`);
      const data = await response.json();
      if (data) {
        setGrafanaEnabled(data.enabled);
        // Determine bind address type
        if (data.bind_address === '127.0.0.1') {
          setGrafanaBindAddress('localhost');
        } else if (data.bind_address === '0.0.0.0') {
          setGrafanaBindAddress('network');
        } else {
          setGrafanaBindAddress('custom');
          setGrafanaCustomIp(data.bind_address);
        }
        setGrafanaPort(data.port);
        setGrafanaQueryTimeout(data.query_timeout);
        setGrafanaMaxRows(data.max_rows);
      }
    } catch (e: any) {
      setError(e?.message || 'Failed to load Grafana settings');
    } finally {
      setGrafanaLoading(false);
    }
  };

  const saveGrafanaSettings = async () => {
    try {
      setGrafanaSaving(true);
      setError(null);
      setSuccess(null);
      setGrafanaValidationResult(null);
      
      // Determine actual bind address
      let actualBindAddress = '127.0.0.1';
      if (grafanaBindAddress === 'network') {
        actualBindAddress = '0.0.0.0';
      } else if (grafanaBindAddress === 'custom') {
        actualBindAddress = grafanaCustomIp;
      }
      
      const response = await fetch(`${API_CONFIG.BASE_URL}/settings/grafana`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enabled: grafanaEnabled,
          bind_address: actualBindAddress,
          port: grafanaPort,
          allow_read_only: true,
          query_timeout: grafanaQueryTimeout,
          max_rows: grafanaMaxRows
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to save settings');
      }
      
      setSuccess('Grafana settings saved successfully. Restart TowerIQ to apply network changes.');
    } catch (e: any) {
      setError(e?.message || 'Failed to save Grafana settings');
    } finally {
      setGrafanaSaving(false);
    }
  };

  const validateGrafanaConnection = async () => {
    try {
      setGrafanaValidating(true);
      setGrafanaValidationResult(null);
      
      const response = await fetch(`${API_CONFIG.BASE_URL}/settings/grafana/validate`, {
        method: 'POST'
      });
      
      const data = await response.json();
      setGrafanaValidationResult(data);
      
      if (data.success) {
        setSuccess(data.message);
      } else {
        setError(data.message);
      }
    } catch (e: any) {
      setError(e?.message || 'Failed to validate Grafana connection');
    } finally {
      setGrafanaValidating(false);
    }
  };

  const getConnectionUrl = () => {
    let actualBindAddress = '127.0.0.1';
    if (grafanaBindAddress === 'network') {
      actualBindAddress = '<laptop-ip>';
    } else if (grafanaBindAddress === 'custom') {
      actualBindAddress = grafanaCustomIp;
    }
    return `http://${actualBindAddress}:${grafanaPort}/api/grafana/query`;
  };

  const copyConnectionUrl = async () => {
    try {
      await navigator.clipboard.writeText(getConnectionUrl());
      setCopySnackbarOpen(true);
    } catch (e) {
      setError('Failed to copy URL to clipboard');
    }
  };

  useEffect(() => {
    loadSettings();
    loadDatabaseStats();
    loadGrafanaSettings();
  }, []);

  const browseForPath = async (setter: (v: string) => void, dir = false) => {
    try {
      const selected = await open({ directory: dir, multiple: false });
      if (typeof selected === 'string') setter(selected);
      if (Array.isArray(selected) && selected.length > 0) setter(String(selected[0]));
    } catch (e: any) {
      setError(e?.message || 'Failed to open dialog');
    }
  };

  const saveAll = async () => {
    try {
      setSaving(true);
      setError(null);
      setSuccess(null);
      // Save DB path
      await fetch(`${API_CONFIG.BASE_URL}/settings/database/path`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sqlite_path: sqlitePath }),
      });
      // Save backup settings
      await fetch(`${API_CONFIG.BASE_URL}/settings/database/backup`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enabled: backupEnabled,
          backup_dir: backupDir,
          retention_count: retentionCount,
          interval_seconds: intervalSeconds,
          on_shutdown: onShutdown,
          compress_zip: compressZip,
          filename_prefix: filenamePrefix,
        }),
      });
      setSuccess('Settings saved');
    } catch (e: any) {
      setError(e?.message || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const runBackup = async () => {
    try {
      setRunningBackup(true);
      setError(null);
      setSuccess(null);
      const res = await fetch(`${API_CONFIG.BASE_URL}/database/backup`, { method: 'POST' });
      const data = await res.json();
      if (!data?.success) throw new Error(data?.message || 'Backup failed');
      setSuccess('Backup completed');
    } catch (e: any) {
      setError(e?.message || 'Failed to run backup');
    } finally {
      setRunningBackup(false);
    }
  };

  return (
    <Box sx={{ padding: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <DatabaseIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
        <Typography variant="h4" component="h1">
          Database Settings
        </Typography>
      </Box>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        Configure database path, backup settings, and view database statistics.
      </Typography>

      {loading && (
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <CircularProgress size={20} sx={{ mr: 1 }} />
          <Typography variant="body2">Loading settings…</Typography>
        </Box>
      )}
      
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid size={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Database Path</Typography>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 8 }}>
                  <TextField
                    fullWidth
                    label="SQLite database path"
                    value={sqlitePath}
                    onChange={(e) => setSqlitePath(e.target.value)}
                    InputProps={{
                      endAdornment: (
                        <InputAdornment position="end">
                          <Button size="small" startIcon={<FolderOpen />} onClick={() => browseForPath(setSqlitePath, false)}>Browse…</Button>
                        </InputAdornment>
                      )
                    }}
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={12}>
          <Card>
            <CardHeader 
              title="Database Statistics"
              action={
                <IconButton 
                  onClick={refreshDatabaseStats} 
                  disabled={statsLoading}
                  title="Collect metrics and refresh statistics"
                >
                  {statsLoading ? <CircularProgress size={20} /> : <RefreshIcon />}
                </IconButton>
              }
            />
            <CardContent>
              {statsLoading && !dbStats && (
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <CircularProgress size={20} sx={{ mr: 1 }} />
                  <Typography variant="body2">Loading database statistics…</Typography>
                </Box>
              )}
              
              {statsError && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  {statsError}
                </Alert>
              )}
              
              {dbStats && (
                <List dense>
                  <ListItem>
                    <ListItemText 
                      primary="Database File Size" 
                      secondary={formatFileSize(dbStats.file_size || 0)}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="Total Runs" 
                      secondary={dbStats.table_rows?.runs?.toLocaleString() || '0'}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="Total Metrics" 
                      secondary={dbStats.table_rows?.metrics?.toLocaleString() || '0'}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="Total Events" 
                      secondary={dbStats.table_rows?.events?.toLocaleString() || '0'}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="Last Modified" 
                      secondary={formatDate(dbStats.modified_date)}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="SQLite Version" 
                      secondary={dbStats.sqlite_version || 'Unknown'}
                    />
                  </ListItem>
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid size={12}>
          <Card>
            <CardHeader 
              avatar={<GrafanaIcon sx={{ color: 'primary.main' }} />}
              title="Grafana Integration"
              subheader="Expose database for Grafana dashboards on your local network"
            />
            <CardContent>
              {grafanaLoading && (
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <CircularProgress size={20} sx={{ mr: 1 }} />
                  <Typography variant="body2">Loading Grafana settings…</Typography>
                </Box>
              )}
              
              <Grid container spacing={2}>
                <Grid size={12}>
                  <FormControlLabel
                    control={
                      <Switch 
                        checked={grafanaEnabled} 
                        onChange={(e) => setGrafanaEnabled(e.target.checked)} 
                      />
                    }
                    label="Enable Grafana Integration"
                  />
                </Grid>

                {grafanaEnabled && (
                  <>
                    <Grid size={12}>
                      <Alert severity="warning" sx={{ mb: 2 }}>
                        ⚠️ This exposes your database for read-only SQL queries over the network. Only enable on trusted networks.
                      </Alert>
                    </Grid>

                    <Grid size={12}>
                      <Typography variant="subtitle2" sx={{ mb: 1 }}>Network Access</Typography>
                      <RadioGroup 
                        value={grafanaBindAddress} 
                        onChange={(e) => setGrafanaBindAddress(e.target.value)}
                      >
                        <FormControlLabel 
                          value="localhost" 
                          control={<Radio />} 
                          label="Localhost only (127.0.0.1) - Most secure, Grafana must run on this machine" 
                        />
                        <FormControlLabel 
                          value="network" 
                          control={<Radio />} 
                          label="Local Network (0.0.0.0) - Accessible from other devices on your network" 
                        />
                        <FormControlLabel 
                          value="custom" 
                          control={<Radio />} 
                          label="Custom IP Address" 
                        />
                      </RadioGroup>
                    </Grid>

                    {grafanaBindAddress === 'custom' && (
                      <Grid size={{ xs: 12, md: 6 }}>
                        <TextField
                          fullWidth
                          label="Custom IP Address"
                          value={grafanaCustomIp}
                          onChange={(e) => setGrafanaCustomIp(e.target.value)}
                          placeholder="192.168.1.100"
                          helperText="Enter the specific IP address to bind to"
                        />
                      </Grid>
                    )}

                    <Grid size={{ xs: 12, md: 6 }}>
                      <TextField
                        fullWidth
                        type="number"
                        label="Port"
                        value={grafanaPort}
                        onChange={(e) => setGrafanaPort(parseInt(e.target.value) || 8000)}
                        helperText="Port 1024-65535 (requires restart to change)"
                        inputProps={{ min: 1024, max: 65535 }}
                      />
                    </Grid>

                    <Grid size={12}>
                      <TextField
                        fullWidth
                        label="Connection URL"
                        value={getConnectionUrl()}
                        InputProps={{
                          readOnly: true,
                          endAdornment: (
                            <InputAdornment position="end">
                              <Button 
                                size="small" 
                                startIcon={<ContentCopy />} 
                                onClick={copyConnectionUrl}
                              >
                                Copy
                              </Button>
                            </InputAdornment>
                          )
                        }}
                        helperText="Use this URL in Grafana Infinity data source"
                      />
                    </Grid>

                    <Grid size={12}>
                      <Button
                        variant="outlined"
                        onClick={() => setShowAdvancedGrafana(!showAdvancedGrafana)}
                        endIcon={showAdvancedGrafana ? <ExpandLess /> : <ExpandMore />}
                      >
                        Advanced Settings
                      </Button>
                    </Grid>

                    <Grid size={12}>
                      <Collapse in={showAdvancedGrafana}>
                        <Grid container spacing={2} sx={{ mt: 1 }}>
                          <Grid size={{ xs: 12, md: 6 }}>
                            <TextField
                              fullWidth
                              type="number"
                              label="Query Timeout (seconds)"
                              value={grafanaQueryTimeout}
                              onChange={(e) => setGrafanaQueryTimeout(parseInt(e.target.value) || 30)}
                              helperText="Maximum query execution time"
                              inputProps={{ min: 1, max: 300 }}
                            />
                          </Grid>
                          <Grid size={{ xs: 12, md: 6 }}>
                            <TextField
                              fullWidth
                              type="number"
                              label="Max Rows per Query"
                              value={grafanaMaxRows}
                              onChange={(e) => setGrafanaMaxRows(parseInt(e.target.value) || 10000)}
                              helperText="Maximum rows returned per query"
                              inputProps={{ min: 1, max: 100000 }}
                            />
                          </Grid>
                        </Grid>
                      </Collapse>
                    </Grid>

                    <Grid size={12}>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        <Button 
                          variant="contained" 
                          startIcon={grafanaSaving ? <CircularProgress size={16} /> : <Save />}
                          onClick={saveGrafanaSettings}
                          disabled={grafanaSaving}
                        >
                          Save Grafana Settings
                        </Button>
                        <Button 
                          variant="outlined" 
                          startIcon={grafanaValidating ? <CircularProgress size={16} /> : <CheckCircle />}
                          onClick={validateGrafanaConnection}
                          disabled={grafanaValidating}
                        >
                          Test Connection
                        </Button>
                      </Box>
                    </Grid>

                    {grafanaValidationResult && (
                      <Grid size={12}>
                        <Alert 
                          severity={grafanaValidationResult.success ? 'success' : 'error'}
                          sx={{ mt: 1 }}
                        >
                          <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                            {grafanaValidationResult.message}
                          </Typography>
                          {grafanaValidationResult.errors && grafanaValidationResult.errors.length > 0 && (
                            <List dense>
                              {grafanaValidationResult.errors.map((err: string, idx: number) => (
                                <ListItem key={idx} sx={{ py: 0 }}>
                                  <ListItemText 
                                    primary={err}
                                    primaryTypographyProps={{ variant: 'body2' }}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          )}
                        </Alert>
                      </Grid>
                    )}

                    <Grid size={12}>
                      <Alert severity="info" sx={{ mt: 1 }}>
                        <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
                          Setup Instructions for Grafana:
                        </Typography>
                        <List dense>
                          <ListItem sx={{ py: 0 }}>
                            <ListItemText primary="1. Install 'Infinity' plugin in Grafana" />
                          </ListItem>
                          <ListItem sx={{ py: 0 }}>
                            <ListItemText primary="2. Add new Infinity data source with Type: JSON, Method: POST" />
                          </ListItem>
                          <ListItem sx={{ py: 0 }}>
                            <ListItemText primary='3. In panels, use Body: {"sql": "SELECT * FROM runs LIMIT 10"}' />
                          </ListItem>
                          <ListItem sx={{ py: 0 }}>
                            <ListItemText primary="4. View available tables at: /api/grafana/schema" />
                          </ListItem>
                        </List>
                      </Alert>
                    </Grid>
                  </>
                )}
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Database Backups</Typography>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControlLabel
                    control={<Switch checked={backupEnabled} onChange={(e) => setBackupEnabled(e.target.checked)} />}
                    label="Enable scheduled backups"
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControlLabel
                    control={<Switch checked={onShutdown} onChange={(e) => setOnShutdown(e.target.checked)} />}
                    label="Run backup on shutdown"
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 8 }}>
                  <TextField
                    fullWidth
                    label="Backup directory"
                    value={backupDir}
                    onChange={(e) => setBackupDir(e.target.value)}
                    InputProps={{
                      endAdornment: (
                        <InputAdornment position="end">
                          <Button size="small" startIcon={<FolderOpen />} onClick={() => browseForPath(setBackupDir, true)}>Browse…</Button>
                        </InputAdornment>
                      )
                    }}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField
                    fullWidth
                    type="number"
                    label="Retention (count)"
                    value={retentionCount}
                    onChange={(e) => setRetentionCount(parseInt(e.target.value || '0'))}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField
                    fullWidth
                    type="number"
                    label="Interval (seconds)"
                    value={intervalSeconds}
                    onChange={(e) => setIntervalSeconds(parseInt(e.target.value || '0'))}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <FormControlLabel
                    control={<Switch checked={compressZip} onChange={(e) => setCompressZip(e.target.checked)} />}
                    label="Compress backups (zip)"
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField
                    fullWidth
                    label="Filename prefix"
                    value={filenamePrefix}
                    onChange={(e) => setFilenamePrefix(e.target.value)}
                  />
                </Grid>
              </Grid>
              <Box sx={{ display: 'flex', gap: 1, mt: 2, flexWrap: 'wrap' }}>
                <Button variant="contained" startIcon={saving ? <CircularProgress size={16} /> : <Save />} onClick={saveAll} disabled={saving}>
                  Save Settings
                </Button>
                <Button variant="outlined" startIcon={runningBackup ? <CircularProgress size={16} /> : <PlayArrow />} onClick={runBackup} disabled={runningBackup}>
                  Run Backup Now
                </Button>
                <Button variant="outlined" color="secondary" onClick={async () => {
                  try {
                    setError(null);
                    const picked = await open({ directory: false, multiple: false, filters: [ { name: 'SQLite or Zip', extensions: ['sqlite', 'zip'] } ] });
                    const pickedPath = typeof picked === 'string' ? picked : Array.isArray(picked) ? String(picked[0]) : '';
                    if (!pickedPath) return;
                    const res = await fetch(`${API_CONFIG.BASE_URL}/database/restore`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ backup_path: pickedPath }),
                    });
                    if (!res.ok) {
                      const data = await res.json().catch(() => ({}));
                      throw new Error(data?.detail || 'Restore failed');
                    }
                    setSuccess('Restore completed');
                  } catch (e: any) {
                    setError(e?.message || 'Failed to restore database');
                  }
                }}>
                  Restore from Backup
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Snackbars for feedback with auto-dismiss (Pattern #10: Debounce/throttle instead of sleep) */}
      <Snackbar
        open={copySnackbarOpen}
        autoHideDuration={2000}
        onClose={() => setCopySnackbarOpen(false)}
        message="URL copied to clipboard"
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      />
      
      {/* Success message snackbar with auto-dismiss */}
      <Snackbar
        open={!!success}
        autoHideDuration={3000}
        onClose={() => setSuccess(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="success" onClose={() => setSuccess(null)} sx={{ width: '100%' }}>
          {success}
        </Alert>
      </Snackbar>
      
      {/* Error message snackbar with auto-dismiss */}
      <Snackbar
        open={!!error}
        autoHideDuration={4000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="error" onClose={() => setError(null)} sx={{ width: '100%' }}>
          {error}
        </Alert>
      </Snackbar>
    </Box>
  );
}
