import { Box, Typography, Card, CardContent, Button } from '@mui/material';
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
      
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mt: 2 }}>
        <Box sx={{ width: { xs: '100%', md: '50%' }, mb: 2 }}>
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
        </Box>
        
        <Box sx={{ width: { xs: '100%', md: '50%' }, mb: 2 }}>
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
        </Box>
      </Box>
    </Box>
  );
}
