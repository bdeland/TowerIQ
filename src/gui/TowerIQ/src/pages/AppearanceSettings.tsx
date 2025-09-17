import { useState } from 'react';
import { Box, Typography, Card, CardContent, TextField, Button, MenuItem } from '@mui/material';
import Grid from '@mui/material/Grid';
import { Palette as AppearanceIcon, Save } from '@mui/icons-material';

export function AppearanceSettings() {
  
  // Local state for appearance settings
  const [theme, setTheme] = useState('dark');
  const [language, setLanguage] = useState('en');
  const [fontSize, setFontSize] = useState('14');
  const [saving, setSaving] = useState(false);

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
        <AppearanceIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
        <Typography variant="h4" component="h1">
          Appearance Settings
        </Typography>
      </Box>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        Customize the look and feel of your TowerIQ application.
      </Typography>
      
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid size={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Theme & Display</Typography>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="Theme"
                    value={theme}
                    onChange={(e) => setTheme(e.target.value)}
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="light">Light</MenuItem>
                    <MenuItem value="dark">Dark</MenuItem>
                    <MenuItem value="auto">Auto (System)</MenuItem>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="Language"
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="en">English</MenuItem>
                    <MenuItem value="es">Spanish</MenuItem>
                    <MenuItem value="fr">French</MenuItem>
                    <MenuItem value="de">German</MenuItem>
                    <MenuItem value="ja">Japanese</MenuItem>
                    <MenuItem value="zh">Chinese</MenuItem>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="Font Size"
                    value={fontSize}
                    onChange={(e) => setFontSize(e.target.value)}
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="12">Small (12px)</MenuItem>
                    <MenuItem value="14">Medium (14px)</MenuItem>
                    <MenuItem value="16">Large (16px)</MenuItem>
                    <MenuItem value="18">Extra Large (18px)</MenuItem>
                  </TextField>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Dashboard Preferences</Typography>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="Default Chart Theme"
                    defaultValue="dark"
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="dark">Dark</MenuItem>
                    <MenuItem value="light">Light</MenuItem>
                    <MenuItem value="auto">Match Application Theme</MenuItem>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="Grid Density"
                    defaultValue="comfortable"
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="compact">Compact</MenuItem>
                    <MenuItem value="comfortable">Comfortable</MenuItem>
                    <MenuItem value="spacious">Spacious</MenuItem>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="Animation Speed"
                    defaultValue="normal"
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="none">None</MenuItem>
                    <MenuItem value="fast">Fast</MenuItem>
                    <MenuItem value="normal">Normal</MenuItem>
                    <MenuItem value="slow">Slow</MenuItem>
                  </TextField>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Accessibility</Typography>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="High Contrast Mode"
                    defaultValue="off"
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="off">Off</MenuItem>
                    <MenuItem value="on">On</MenuItem>
                    <MenuItem value="auto">Auto (System)</MenuItem>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    select
                    label="Reduce Motion"
                    defaultValue="respect"
                    sx={{ mb: 2 }}
                  >
                    <MenuItem value="respect">Respect System Setting</MenuItem>
                    <MenuItem value="reduce">Always Reduce</MenuItem>
                    <MenuItem value="normal">Normal Motion</MenuItem>
                  </TextField>
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
                setTheme('dark');
                setLanguage('en');
                setFontSize('14');
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
