import { useEffect, useState } from 'react';
import { Box, Typography, Card, CardContent, Switch, FormControlLabel, TextField, Button, InputAdornment, CircularProgress, Alert } from '@mui/material';
import Grid from '@mui/material/Grid';
import { Settings as SettingsIcon, Notifications, Security, DisplaySettings, FolderOpen, Save, PlayArrow } from '@mui/icons-material';
import { open } from '@tauri-apps/plugin-dialog';
import { API_CONFIG } from '../config/environment';

export function SettingsPage() {
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

  useEffect(() => {
    loadSettings();
  }, []);

  const browseForPath = async (setter: (v: string) => void, dir = false) => {
    try {
      const selected = await open({ directory: dir, multiple: false });
      if (typeof selected === 'string') setter(selected);
      if (Array.isArray(selected) && selected.length > 0) setter(String(selected[0]));
    } catch (e: any) {
      setError(e?.message || 'Failed to open dialog');
      setTimeout(() => setError(null), 2500);
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
      setTimeout(() => setSuccess(null), 2000);
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
      setTimeout(() => setSuccess(null), 2000);
    }
  };

  return (
    <Box sx={{ padding: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <SettingsIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
        <Typography variant="h4" component="h1">
          Settings
        </Typography>
      </Box>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        Configure your TowerIQ application preferences and system settings.
      </Typography>

      {loading && (
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <CircularProgress size={20} sx={{ mr: 1 }} />
          <Typography variant="body2">Loading settings…</Typography>
        </Box>
      )}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>{success}</Alert>
      )}
      
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid size={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Database</Typography>
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
                  Save
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
                    setTimeout(() => setSuccess(null), 2000);
                  } catch (e: any) {
                    setError(e?.message || 'Failed to restore database');
                    setTimeout(() => setError(null), 3000);
                  }
                }}>
                  Restore from Backup
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
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
                control={<Switch defaultChecked />}
                label="Enable notifications"
                sx={{ mb: 1 }}
              />
              <FormControlLabel
                control={<Switch />}
                label="Email alerts"
                sx={{ mb: 1 }}
              />
              <FormControlLabel
                control={<Switch defaultChecked />}
                label="System updates"
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
                label="Auto-logout timeout (minutes)"
                type="number"
                defaultValue={30}
                sx={{ mb: 2 }}
              />
              <FormControlLabel
                control={<Switch defaultChecked />}
                label="Two-factor authentication"
                sx={{ mb: 1 }}
              />
              <FormControlLabel
                control={<Switch />}
                label="Session encryption"
              />
            </CardContent>
          </Card>
        </Grid>
        
        <Grid size={12}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <DisplaySettings sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">
                  Display Settings
                </Typography>
              </Box>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Theme"
                    select
                    defaultValue="light"
                    sx={{ mb: 2 }}
                  >
                    <option value="light">Light</option>
                    <option value="dark">Dark</option>
                    <option value="auto">Auto</option>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Language"
                    select
                    defaultValue="en"
                    sx={{ mb: 2 }}
                  >
                    <option value="en">English</option>
                    <option value="es">Spanish</option>
                    <option value="fr">French</option>
                  </TextField>
                </Grid>
              </Grid>
              <Button variant="contained" sx={{ mt: 2 }} onClick={saveAll} disabled={saving}>
                {saving ? 'Saving…' : 'Save Settings'}
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
