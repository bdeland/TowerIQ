import { Box, Typography, Card, CardContent, Grid, Button } from '@mui/material';
import { Explore as ExploreIcon, Search, TrendingUp } from '@mui/icons-material';

export function ExplorePage() {
  return (
    <Box sx={{ padding: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <ExploreIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
        <Typography variant="h4" component="h1">
          Explore
        </Typography>
      </Box>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        Discover new features and explore your data.
      </Typography>
      
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Search sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">
                  Data Analysis
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" paragraph>
                Analyze your data with advanced search and filtering capabilities.
              </Typography>
              <Button variant="outlined" size="small">
                Start Analysis
              </Button>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <TrendingUp sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">
                  Trends & Insights
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" paragraph>
                Discover patterns and insights in your data over time.
              </Typography>
              <Button variant="outlined" size="small">
                View Trends
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
