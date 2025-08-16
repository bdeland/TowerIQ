import { Box, Typography, Card, CardContent, Grid } from '@mui/material';
import { Home as HomeIcon } from '@mui/icons-material';

export function HomePage() {
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
      
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid item xs={12} md={6}>
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
        </Grid>
        
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Overview
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Monitor your system status and view recent activity at a glance.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
