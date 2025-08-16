import { Box, Typography, Card, CardContent, Grid, Switch, FormControlLabel, TextField, Button } from '@mui/material';
import { Settings as SettingsIcon, Notifications, Security, DisplaySettings } from '@mui/icons-material';

export function SettingsPage() {
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
      
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid item xs={12} md={6}>
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
        
        <Grid item xs={12} md={6}>
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
        
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <DisplaySettings sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">
                  Display Settings
                </Typography>
              </Box>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
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
                <Grid item xs={12} md={6}>
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
              <Button variant="contained" sx={{ mt: 2 }}>
                Save Settings
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
