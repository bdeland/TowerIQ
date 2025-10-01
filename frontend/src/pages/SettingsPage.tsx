import { Box, Typography, Card, CardContent, CardActionArea } from '@mui/material';
import Grid from '@mui/material/Grid';
import { 
  Settings as SettingsIcon, 
  Storage as DatabaseIcon, 
  Palette as AppearanceIcon, 
  MoreHoriz as OtherIcon 
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

interface SettingsCategory {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  path: string;
}

const settingsCategories: SettingsCategory[] = [
  {
    id: 'database',
    title: 'Database',
    description: 'Database path, backups, statistics, and restore options',
    icon: <DatabaseIcon sx={{ fontSize: 48, color: 'primary.main' }} />,
    path: '/settings/database'
  },
  {
    id: 'appearance',
    title: 'Appearance',
    description: 'Theme, language, display settings, and visual preferences',
    icon: <AppearanceIcon sx={{ fontSize: 48, color: 'primary.main' }} />,
    path: '/settings/appearance'
  },
  {
    id: 'other',
    title: 'Other',
    description: 'Notifications, security, developer tools, and advanced options',
    icon: <OtherIcon sx={{ fontSize: 48, color: 'primary.main' }} />,
    path: '/settings/other'
  }
];

export function SettingsPage() {
  const navigate = useNavigate();

  const handleCategoryClick = (path: string) => {
    navigate(path);
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

      <Grid container spacing={3} sx={{ mt: 2 }}>
        {settingsCategories.map((category) => (
          <Grid size={{ xs: 12, md: 4 }} key={category.id}>
            <Card sx={{ height: '100%' }}>
              <CardActionArea 
                onClick={() => handleCategoryClick(category.path)}
                sx={{ 
                  height: '100%',
                  p: 3,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  textAlign: 'center',
                  minHeight: 200
                }}
              >
                <Box sx={{ mb: 2 }}>
                  {category.icon}
                </Box>
                <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
                  <Typography variant="h6" component="h2" sx={{ mb: 1 }}>
                    {category.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {category.description}
                  </Typography>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
}
