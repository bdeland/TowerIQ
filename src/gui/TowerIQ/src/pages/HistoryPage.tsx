import { Box, Typography, Card, CardContent, Grid, List, ListItem, ListItemText, ListItemIcon } from '@mui/material';
import { History as HistoryIcon, Schedule, Event } from '@mui/icons-material';

export function HistoryPage() {
  const historyItems = [
    { id: 1, title: 'System Update', description: 'Updated to version 2.1.0', time: '2 hours ago' },
    { id: 2, title: 'Data Backup', description: 'Completed daily backup', time: '1 day ago' },
    { id: 3, title: 'User Login', description: 'User session started', time: '2 days ago' },
    { id: 4, title: 'Configuration Change', description: 'Updated system settings', time: '3 days ago' },
  ];

  return (
    <Box sx={{ padding: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <HistoryIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
        <Typography variant="h4" component="h1">
          History
        </Typography>
      </Box>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        View your system activity and historical data.
      </Typography>
      
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Activity
              </Typography>
              <List>
                {historyItems.map((item) => (
                  <ListItem key={item.id} divider>
                    <ListItemIcon>
                      <Event color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary={item.title}
                      secondary={`${item.description} • ${item.time}`}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Schedule sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">
                  Activity Summary
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Total activities: 24
              </Typography>
              <Typography variant="body2" color="text.secondary">
                This week: 8
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Last month: 156
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
