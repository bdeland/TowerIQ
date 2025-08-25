import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import {
  AppBar,
  Box,
  CssBaseline,
  Drawer,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  ThemeProvider,
  createTheme,
  Tooltip,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Home as HomeIcon,
  Dashboard as DashboardIcon,
  Settings as SettingsIcon,
  Explore as ExploreIcon,
  History as HistoryIcon,
  Smartphone as SmartphoneIcon,
  ViewSidebar as ViewSidebarIcon,
  ViewSidebarOutlined as ViewSidebarOutlinedIcon,
} from '@mui/icons-material';
import { HomePage } from './pages/HomePage';
import { DashboardsPage } from './pages/DashboardsPage';
import { DashboardViewPage } from './pages/DashboardViewPage';
import { ExplorePage } from './pages/ExplorePage';
import { HistoryPage } from './pages/HistoryPage';
import { SettingsPage } from './pages/SettingsPage';
import { ConnectionPage } from './pages/ConnectionPage';
import { Breadcrumbs } from './components/Breadcrumbs';
import { SearchBar } from './components/SearchBar';
import SplashScreen from './components/SplashScreen';
import { DashboardProvider } from './contexts/DashboardContext';

import './App.css';

// Create a Grafana-inspired dark theme
const theme = createTheme({
  palette: {
    // Don't use mode: 'dark' to avoid Material-UI's default dark theme
    primary: {
      main: '#f79520', // Grafana's orange
    },
    secondary: {
      main: '#ff6464',
    },
    background: {
      default: '#111217', // Grafana's main background
      paper: '#202226',   // Grafana's sidebar/card background
    },
    text: {
      primary: '#e0e0e0',
      secondary: '#8e8e8e',
    },
    divider: '#343434', // Grafana's border color
    // Explicitly set dark theme colors to avoid Material-UI defaults
    action: {
      active: '#e0e0e0',
      hover: 'rgba(255, 255, 255, 0.04)',
      selected: 'rgba(255, 255, 255, 0.08)',
      disabled: 'rgba(255, 255, 255, 0.3)',
      disabledBackground: 'rgba(255, 255, 255, 0.12)',
    },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    fontSize: 14,
    h1: {
      fontSize: '2rem',
      fontWeight: 600,
    },
    h2: {
      fontSize: '1.75rem',
      fontWeight: 600,
    },
    h3: {
      fontSize: '1.5rem',
      fontWeight: 600,
    },
    h4: {
      fontSize: '1.25rem',
      fontWeight: 600,
    },
    h5: {
      fontSize: '1.125rem',
      fontWeight: 600,
    },
    h6: {
      fontSize: '1rem',
      fontWeight: 600,
    },
    body1: {
      fontSize: '0.875rem',
    },
    body2: {
      fontSize: '0.8rem',
    },
  },
  // Force override Material-UI's default dark theme colors
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: (theme) => ({
        body: {
          '&::-webkit-scrollbar': {
            width: '8px',
          },
          '&::-webkit-scrollbar-track': {
            backgroundColor: theme.palette.background.paper,
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: theme.palette.divider,
            borderRadius: '4px',
          },
          '&::-webkit-scrollbar-thumb:hover': {
            backgroundColor: '#404040', // A slightly lighter divider color on hover
          },
        },
        // Global override for all drawer papers
        '.MuiDrawer-paper': {
          backgroundColor: '#202226 !important',
        },
        // Specific override for temporary variant
        '.MuiDrawer-temporary .MuiDrawer-paper': {
          backgroundColor: '#202226 !important',
        },
        // Specific override for permanent variant
        '.MuiDrawer-permanent .MuiDrawer-paper': {
          backgroundColor: '#202226 !important',
        },
        // More aggressive overrides for Material-UI dark theme
        '[data-mui-color-scheme="dark"] .MuiDrawer-paper': {
          backgroundColor: '#202226 !important',
        },
        '[data-mui-color-scheme="dark"] .MuiDrawer-temporary .MuiDrawer-paper': {
          backgroundColor: '#202226 !important',
        },
        // Target the specific Material-UI dark theme classes
        '.MuiDrawer-paper.MuiPaper-root': {
          backgroundColor: '#202226 !important',
        },
        // Force override any Material-UI dark theme background
        '.MuiDrawer-paper[style*="background"]': {
          backgroundColor: '#202226 !important',
        },
      }),
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: '#202226 !important', // Force our theme color
          boxShadow: 'none', // Remove shadow to make it flat
          borderTop: '1px solid #343434', // Add top border
          borderBottom: '1px solid #343434', // Add bottom border
          height: `${appBarHeight}px !important`, // Force exact height
          minHeight: `${appBarHeight}px !important`, // Force exact min height
          maxHeight: `${appBarHeight}px !important`, // Force exact max height
          boxSizing: 'border-box !important', // Include borders in height calculation
        },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          '&.Mui-selected': {
            backgroundColor: 'rgba(247, 149, 32, 0.1)',
            borderLeft: '4px solid #f79520',
            color: 'primary.main',
            '&:hover': {
              backgroundColor: 'rgba(247, 149, 32, 0.15)',
            },
          },
          '&:hover': {
            backgroundColor: 'rgba(255, 255, 255, 0.04)',
          },
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: '#202226 !important', // Force our theme color
        },
        root: {
          '& .MuiDrawer-paper': {
            backgroundColor: '#202226 !important',
          },
        },
      },
    },
    MuiToolbar: {
      styleOverrides: {
        root: {
          backgroundColor: '#202226 !important', // Ensure toolbar matches
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundColor: '#202226 !important', // Ensure all paper components use our color
        },
      },
    },
  },
});

const drawerWidth = 240;
const appBarHeight = 40; // Single source of truth for AppBar height

// Navigation items with routes - Grafana-style organization
const navigationItems = [
  { text: 'Home', icon: <HomeIcon />, path: '/', position: 'top' },
  { text: 'Dashboards', icon: <DashboardIcon />, path: '/dashboards' },
  { text: 'Explore', icon: <ExploreIcon />, path: '/explore' },
  { text: 'History', icon: <HistoryIcon />, path: '/history' },
  { text: 'Connection', icon: <SmartphoneIcon />, path: '/connection', position: 'bottom' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings', position: 'bottom' },
];

// Main layout component with navigation
function DashboardLayout() {
  // Updated state management according to requirements
  const [sidebarHidden, setSidebarHidden] = useState(true); // Manages the hidden state - default to hidden
  const [sidebarDocked, setSidebarDocked] = useState(false); // Manages the docked state
  const navigate = useNavigate();
  const location = useLocation();
  
  // Ref for dynamic positioning (optional - for future flexibility)
  const firstAppBarRef = useState<HTMLElement | null>(null)[0];

  // Shared styles for sidebar list items to ensure consistency
  const listItemButtonStyles = {
    height: '40px',
    justifyContent: 'initial',
    px: 1,
    mx: 1,
    borderRadius: 0.5,
  };

  const listItemIconStyles = {
    minWidth: 0,
    mr: 2,
    justifyContent: 'left',
    '& .MuiSvgIcon-root': {
      fontSize: "1.2rem", // Target the actual SVG icon
    },
  };

  const listItemTextStyles = {
    '& .MuiListItemText-primary': {
      fontSize: '0.8rem', // Make text smaller (default is usually 1rem)
    },
  };

  const sidebarHeaderStyles = {
    minHeight: '40px',
    height: '40px', // Slightly larger to account for 200% scaling
    maxHeight: '40px', // Force maximum height
    px: 1, // Match listItemButtonStyles px
    borderTop: '1px solid #343434', // Add top border
    borderBottom: '1px solid #343434', // Use the divider color directly
    display: 'flex',
    alignItems: 'center',
    boxSizing: 'border-box', // Include borders in the height calculation
    overflow: 'hidden', // Prevent content from expanding height
  };

  // Master sidebar toggle function according to requirements
  const handleSidebarToggle = () => {
    // Simple toggle: hidden <-> expanded (works for both docked and undocked)
    setSidebarHidden(!sidebarHidden);
  };

  // Dock toggle function according to requirements
  const handleDockToggle = () => {
    const newDockedState = !sidebarDocked;
    setSidebarDocked(newDockedState);
    
    // When undocking, close the sidebar after a brief delay to allow transition
    if (!newDockedState) {
      setTimeout(() => {
        setSidebarHidden(true);
      }, 0); // Small delay to allow state change to propagate
    }
  };

  const handleNavigation = (path: string) => {
    navigate(path);
    // Close sidebar when not docked (overlay mode)
    if (!sidebarDocked) {
      setSidebarHidden(true);
    }
  };

  return (
    <ThemeProvider theme={theme}>
      <Box sx={{ display: 'flex' }}>
        <CssBaseline />
        <AppBar
          position="fixed"
          sx={{
              width: { 
              sm: sidebarDocked 
                ? (sidebarHidden 
                    ? '100%' 
                    : `calc(100% - ${drawerWidth}px)`) // Span from sidebar to right edge when docked
                : '100%' // Full width when not docked (overlay mode)
            },
            zIndex: (theme) => sidebarDocked ? theme.zIndex.drawer + 1 : 1,
            ml: { 
              sm: sidebarDocked 
                ? (sidebarHidden 
                    ? 0 
                    : `${drawerWidth}px`) // Position AppBar after sidebar when docked
                : 0 // No margin when not docked (overlay mode)
            },
            // Override theme to remove bottom border from first AppBar
            borderBottom: 'none !important',
            '& .MuiToolbar-root': {
              minHeight: '40px !important', // 40px AppBar - 1px border = 39px
              height: '40px !important',
              paddingLeft: '1 !important',
              paddingRight: "12px !important",
              paddingTop: "0 !important",
              paddingBottom: "0 !important"
            }
          }}
        >
          <Toolbar sx={{ 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'space-between',
            borderBottom: '1px solid #343434', // Add bottom border
          }}>
            {/* Main Menu Toggle Icon - Show when not docked or when docked and hidden */}
            <IconButton
              aria-label="toggle sidebar"
              onClick={handleSidebarToggle}
              sx={{ 
                ...listItemIconStyles,
                display: sidebarDocked ? (sidebarHidden ? 'block' : 'none') : 'block',
                color: 'text.primary', // Explicitly set color to match theme
                marginLeft: '-8px', // Compensate for Toolbar's left padding
                '&:hover': {
                  backgroundColor: 'rgba(255, 255, 255, 0.04)',
                }
              }}
            >
              <MenuIcon />
            </IconButton>

            {/* Breadcrumbs */}
            <Box sx={{ flexGrow: 1, display: 'flex', alignItems: 'center' }}>
              <Breadcrumbs />
            </Box>

            {/* Search Bar - Pushed to the right */}
            <Box sx={{ 
              marginLeft: 'auto',
              margin: 0,
              padding: 0,
              marginRight: 0,
              paddingRight: 0,
            }}>
              <SearchBar />
            </Box>
          </Toolbar>
        </AppBar>

        {/* Secondary Toolbar/AppBar */}
        <AppBar
          position="fixed"
          sx={{
            top: `${appBarHeight + 1}px`, // Position below the first AppBar (40px + 1px border)
            width: { 
              sm: sidebarDocked 
                ? (sidebarHidden 
                    ? '100%' 
                    : `calc(100% - ${drawerWidth}px)`) // Span from sidebar to right edge when docked
                : '100%' // Full width when not docked (overlay mode)
            },
            zIndex: (theme) => sidebarDocked ? theme.zIndex.drawer + 1 : 1,
            ml: { 
              sm: sidebarDocked 
                ? (sidebarHidden 
                    ? 0 
                    : `${drawerWidth}px`) // Position AppBar after sidebar when docked
                : 0 // No margin when not docked (overlay mode)
            },
            // Override theme to remove top border from second AppBar
            borderTop: 'none !important',
            '& .MuiToolbar-root': {
              minHeight: '39px !important', // 40px AppBar - 1px border = 39px
              height: '39px !important',
              paddingLeft: '1 !important',
              paddingRight: "12px !important",
              paddingTop: "0 !important",
              paddingBottom: "0 !important"
            }
          }}
        >
          <Toolbar sx={{ 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'space-between',
          }}>
            {/* Secondary toolbar content - currently empty */}
            <Box sx={{ flexGrow: 1, display: 'flex', alignItems: 'center' }}>
              {/* Empty for now - add your controls here */}
            </Box>
          </Toolbar>
        </AppBar>

        {/* Sidebar */}
        <Box
          component="nav"
          sx={{ 
            width: sidebarDocked ? (sidebarHidden ? 0 : drawerWidth) : 0, 
            flexShrink: 0,
            height: '100vh',
            position: sidebarDocked ? 'fixed' : 'relative',
            top: sidebarDocked ? 0 : 'auto',
            left: sidebarDocked ? 0 : 'auto',
            zIndex: sidebarDocked ? (theme) => theme.zIndex.drawer : 'auto',
          }}
        >
          {/* Desktop drawer - Grafana Style */}
          <Drawer
            variant={sidebarDocked ? "permanent" : "temporary"}
            open={!sidebarHidden}
            onClose={() => {
              if (!sidebarDocked) {
                setSidebarHidden(true);
              }
            }}
            ModalProps={{
              keepMounted: true,
              // Add backdrop for overlay mode
              BackdropProps: {
                invisible: sidebarDocked,
              },
            }}
            sx={{
              '& .MuiDrawer-paper': { 
                  boxSizing: 'border-box', 
                  width: sidebarHidden ? 0 : drawerWidth,
                  overflowX: 'hidden',
                  backgroundColor: '#202226 !important', // Force our theme color
                  // When not docked, ensure it overlays content and spans full height
                  position: sidebarDocked ? 'relative' : 'fixed',
                  top: sidebarDocked ? 'auto' : 0,
                  height: sidebarDocked ? '100vh' : '100vh',
                  zIndex: sidebarDocked ? 'auto' : 9999,
                },
              // Additional specificity for temporary variant
              '&.MuiDrawer-temporary .MuiDrawer-paper': {
                backgroundColor: '#202226 !important',
              },
              '&.MuiDrawer-temporary': {
                '& .MuiDrawer-paper': {
                  backgroundColor: '#202226 !important',
                },
              },
              // Force override any Material-UI dark theme styles
              '& .MuiPaper-root.MuiDrawer-paper': {
                backgroundColor: '#202226 !important',
              },
              // Target the specific temporary drawer paper
              '&[data-variant="temporary"] .MuiDrawer-paper': {
                backgroundColor: '#202226 !important',
              },
            }}
          >
            {/* Sidebar Header */}
            <Box sx={sidebarHeaderStyles}>
              {/* Hamburger Menu Toggle - Always show in sidebar when visible */}
              <IconButton
                color="inherit"
                aria-label="toggle sidebar"
                onClick={handleSidebarToggle}
                sx={{ 
                  ...listItemIconStyles,
                  color: 'text.primary',
                  '&:hover': {
                    backgroundColor: 'rgba(255, 255, 255, 0.04)',
                  },
                }}
              >
                <MenuIcon />
              </IconButton>
              
              {/* TowerIQ Text */}
              <Box sx={{ fontWeight: 600, color: 'text.primary', flexGrow: 1 }}>TowerIQ</Box>
              
              {/* Dock/Undock Button - Aligned to the right */}
              <Tooltip title={sidebarDocked ? "Undock menu" : "Dock menu"} placement="bottom">
                <IconButton
                  color={sidebarDocked ? "primary" : "inherit"}
                  aria-label={sidebarDocked ? "undock sidebar" : "dock sidebar"}
                  onClick={handleDockToggle}
                  sx={{ 
                    ...listItemIconStyles,
                    color: sidebarDocked ? 'primary.main' : 'text.primary',
                    marginLeft: 'auto', // Push to the right
                    marginRight: 0, // Ensure no right margin
                    '&:hover': {
                      backgroundColor: 'rgba(255, 255, 255, 0.04)',
                    },
                  }}
                >
                  {sidebarDocked ? <ViewSidebarIcon /> : <ViewSidebarOutlinedIcon />}
                </IconButton>
              </Tooltip>
            </Box>

            <List sx={{ pt: 1 }}>
              {navigationItems.map((item) => (
                <ListItem key={item.text} disablePadding>
                  <ListItemButton
                    selected={location.pathname === item.path}
                    onClick={() => handleNavigation(item.path)}
                    sx={listItemButtonStyles}
                  >
                    <ListItemIcon sx={listItemIconStyles}>
                      {item.icon}
                    </ListItemIcon>
                    <ListItemText primary={item.text} sx={listItemTextStyles} />
                  </ListItemButton>
                </ListItem>
              ))}
            </List>
          </Drawer>
        </Box>

        {/* Main content - Grafana Style */}
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            pt: `${(appBarHeight * 2) + 4}px`, // Add top padding to account for both AppBar heights plus spacing
            pb: 2,
            px: 3,
            width: sidebarDocked 
              ? (sidebarHidden 
                  ? '100%' // Full width when hidden
                  : `calc(100% - ${drawerWidth}px)`) // Adjust for expanded sidebar
              : '100%', // Full width when not docked (overlay mode)
            // The margin-left is only needed for the docked state
            ml: sidebarDocked 
              ? (sidebarHidden 
                  ? 0 
                  : `${drawerWidth}px`) // For docked sidebar that pushes content
              : 0, // No margin when not docked (overlay mode)
            height: '100vh',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            transition: 'margin-left 0.15s ease-in-out',
          }}
        >

          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/dashboards" element={<DashboardsPage />} />
            <Route path="/dashboard/:id" element={<DashboardViewPage />} />
            <Route path="/connection" element={<ConnectionPage />} />
            <Route path="/explore" element={<ExplorePage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </Box>
      </Box>
    </ThemeProvider>
  );
}

function App() {
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const checkLoadingStatus = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/status');
        const data = await response.json();
        
        if (data.loading_complete) {
          // Wait a bit more to ensure minimum splash screen time
          setTimeout(() => {
            setIsLoading(false);
          }, 1000);
          return true; // Signal that we should stop polling
        }
        return false; // Continue polling
      } catch (error) {
        // If we can't reach the API, it might not be started yet
        // Continue polling but don't log errors to avoid spam
        return false; // Continue polling
      }
    };

    // Check loading status every 500ms until complete
    const interval = setInterval(async () => {
      const shouldStop = await checkLoadingStatus();
      if (shouldStop) {
        clearInterval(interval);
      }
    }, 500);

    return () => clearInterval(interval);
  }, []);

  return (
    <>
      <Router>
        <DashboardProvider>
          <DashboardLayout />
        </DashboardProvider>
      </Router>
      {isLoading && <SplashScreen onComplete={() => setIsLoading(false)} />}
    </>
  );
}

export default App;
