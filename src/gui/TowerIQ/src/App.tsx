import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import {
  Box,
  CssBaseline,
  ThemeProvider,
  createTheme,
} from '@mui/material';
import { Alert, Snackbar, Button } from '@mui/material';
import {
  Home as HomeIcon,
  Dashboard as DashboardIcon,
  Settings as SettingsIcon,
  Explore as ExploreIcon,
  History as HistoryIcon,
  Smartphone as SmartphoneIcon,
} from '@mui/icons-material';
import { HomePage } from './pages/HomePage';
import { DashboardsPage } from './pages/DashboardsPage';
import { DashboardViewPage } from './pages/DashboardViewPage';
import { DatabaseHealthDashboardPage } from './pages/DatabaseHealthDashboardPage';
import { PanelViewPage } from './pages/PanelViewPage';
import { PanelEditPage } from './pages/PanelEditPage';
import { ExplorePage } from './pages/ExplorePage';
import { HistoryPage } from './pages/HistoryPage';
import { SettingsPage } from './pages/SettingsPage';
import { DatabaseSettings } from './pages/DatabaseSettings';
import { AppearanceSettings } from './pages/AppearanceSettings';
import { OtherSettings } from './pages/OtherSettings';
import { ConnectionPage } from './pages/ConnectionPage';

import SplashScreen from './components/SplashScreen';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { DashboardProvider } from './contexts/DashboardContext';
import { DashboardEditProvider } from './contexts/DashboardEditContext';
import { DashboardVariableProvider } from './contexts/DashboardVariableContext';
import { DeveloperProvider } from './contexts/DeveloperContext';

import './App.css';

// Centralized layout configuration
const layout = {
  appBarHeight: 40,
  drawerWidth: 180,
  border: '1px solid #2e3136',
  borderColor: '#2e3136',
  backgroundColor: {
    main: '#111217',      // Grafana's main background
    paper: '#181b1f',     // Grafana's sidebar/card background
  },
  colors: {
    primary: '#00a7e1',   // Grafana's orange
    secondary: '#ff6464',
    textPrimary: '#e0e0e0',
    textSecondary: '#8e8e8e',
  }
};

// Create a Grafana-inspired dark theme
const theme = createTheme({
  palette: {
    // Don't use mode: 'dark' to avoid Material-UI's default dark theme
    primary: {
      main: layout.colors.primary,
    },
    secondary: {
      main: layout.colors.secondary,
    },
    background: {
      default: layout.backgroundColor.main,
      paper: layout.backgroundColor.paper,
    },
    text: {
      primary: layout.colors.textPrimary,
      secondary: layout.colors.textSecondary,
    },
    divider: layout.borderColor,
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
            ':root': {
              // Expose theme colors as CSS custom properties for react-grid-layout
              '--theme-text-secondary': theme.palette.text.secondary,
              '--theme-primary-main': theme.palette.primary.main,
            },
            body: {
              '&::-webkit-scrollbar': {
                width: '0px',
                background: 'transparent',
              },
              '&::-webkit-scrollbar-track': {
                background: 'transparent',
              },
              '&::-webkit-scrollbar-thumb': {
                background: 'transparent',
              },
              '&::-webkit-scrollbar-thumb:hover': {
                background: 'transparent',
              },
            },
            // Hide scrollbars for all elements
            '*': {
              '&::-webkit-scrollbar': {
                width: '0px',
                background: 'transparent',
              },
              '&::-webkit-scrollbar-track': {
                background: 'transparent',
              },
              '&::-webkit-scrollbar-thumb': {
                background: 'transparent',
              },
              '&::-webkit-scrollbar-thumb:hover': {
                background: 'transparent',
              },
            },
            // Global override for all drawer papers
            '.MuiDrawer-paper': {
              backgroundColor: theme.palette.background.paper,
            },
            // React Grid Layout resize handle styles - only SE (bottom-right) handle  
            '.react-resizable-handle-se': {
              opacity: 1.0,
              transition: 'all 0.2s ease',
              // Change the color of the existing handle to match theme
              filter: 'brightness(0) saturate(100%) invert(56%) sepia(0%) saturate(0%) hue-rotate(0deg) brightness(89%) contrast(87%)',
            },
            // Breadcrumbs collapse button styling
            '.MuiBreadcrumbs-collapsedButton': {
              color: 'inherit !important',
              backgroundColor: 'transparent !important',
              border: 'none !important',
              boxShadow: 'none !important',
              '&:hover': {
                backgroundColor: 'rgba(255, 255, 255, 0.04) !important',
              },
              '&:focus': {
                backgroundColor: 'transparent !important',
              }
            },
            '.MuiBreadcrumbs-collapsedIcon': {
              color: 'inherit !important',
              backgroundColor: 'transparent !important',
            }
          }),
        },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: layout.backgroundColor.paper,
          boxShadow: 'none', // Remove shadow to make it flat
          // Don't set borders or height here - let individual components handle it
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
          backgroundColor: layout.backgroundColor.paper,
        },
      },
    },
    MuiToolbar: {
      styleOverrides: {
        root: {
          backgroundColor: layout.backgroundColor.paper,
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundColor: layout.backgroundColor.paper,
        },
      },
    },
    MuiAccordion: {
      styleOverrides: {
        root: {
          backgroundColor: '#22252b',
          '&:before': {
            display: 'none', // Remove the default border
          },
        },
      },
    },
    MuiAccordionSummary: {
      styleOverrides: {
        root: {
          backgroundColor: '#22252b',
          '&:hover': {
            backgroundColor: '#2a2d33', // Slightly lighter on hover
          },
        },
      },
    },
    MuiAccordionDetails: {
      styleOverrides: {
        root: {
          backgroundColor: '#22252b',
        },
      },
    },
  },
});

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
  const location = useLocation();
  
  // Check if we're viewing the default dashboard
  const isDefaultDashboard = location.pathname === '/dashboard/default-dashboard';
  
  // Check if we're on the PanelEditPage to remove bottom padding
  const isPanelEditPage = location.pathname.includes('/dashboard/') && location.pathname.includes('/panels/') && location.pathname.includes('/edit');



  // Shared transition configuration for synchronized animations
  const sharedTransition = (theme: any) => theme.transitions.create(['margin', 'width'], {
    easing: theme.transitions.easing.sharp,
    duration: theme.transitions.duration.enteringScreen,
  });

  // Dynamic layout calculations - single source of truth
  const getLayoutStyles = () => {
    const baseStyles = {
      width: sidebarDocked && !sidebarHidden ? `calc(100% - ${layout.drawerWidth}px)` : '100%',
      marginLeft: sidebarDocked && !sidebarHidden ? `${layout.drawerWidth}px` : 0,
    };
    
    return {
      appBar: {
        ...baseStyles,
        zIndex: (theme: any) => sidebarDocked ? theme.zIndex.drawer + 1 : 1,
        transition: sharedTransition,
      },
      mainContent: {
        ...baseStyles,
        transition: sharedTransition,
      }
    };
  };

  const layoutStyles = getLayoutStyles();

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
    minHeight: `${layout.appBarHeight + 1}px`,
    height: `${layout.appBarHeight + 1}px`,
    maxHeight: `${layout.appBarHeight + 1}px`,
    px: 1, // Match listItemButtonStyles px
    borderTop: layout.border,
    borderBottom: layout.border,
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



  const layoutContent = (
    <ThemeProvider theme={theme}>
      <Box sx={{ display: 'flex' }}>
        <CssBaseline />
        
        <Header 
          sidebarDocked={sidebarDocked}
          sidebarHidden={sidebarHidden}
          onSidebarToggle={handleSidebarToggle}
          layoutStyles={layoutStyles}
          layout={layout}
        />

        <Sidebar
          sidebarDocked={sidebarDocked}
          sidebarHidden={sidebarHidden}
          onSidebarToggle={handleSidebarToggle}
          onDockToggle={handleDockToggle}
          navigationItems={navigationItems}
          layout={layout}
          listItemButtonStyles={listItemButtonStyles}
          listItemIconStyles={listItemIconStyles}
          listItemTextStyles={listItemTextStyles}
          sidebarHeaderStyles={sidebarHeaderStyles}
        />

        {/* Main content - Grafana Style */}
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            pt: `${layout.appBarHeight * 2 + 1}px`, // Add top padding to account for combined AppBar height (80px) plus borders (2px)
            pb: isPanelEditPage ? 0 : 2, // Remove bottom padding for PanelEditPage
            px: 0,
            height: '100vh',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            ...layoutStyles.mainContent,
          }}
        >

          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/dashboards" element={<DashboardsPage />} />
            <Route path="/dashboard/:id" element={<DashboardViewPage />} />
            <Route path="/dashboards/:id" element={<DashboardViewPage />} />
            <Route path="/dashboard/:dashboardId/panels/:panelId/view" element={<PanelViewPage />} />
            <Route path="/dashboard/:dashboardId/panels/:panelId/edit" element={<PanelEditPage />} />
            <Route path="/database-health" element={<DatabaseHealthDashboardPage />} />
            <Route path="/connection" element={<ConnectionPage />} />
            <Route path="/explore" element={<ExplorePage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/settings/database" element={<DatabaseSettings />} />
            <Route path="/settings/appearance" element={<AppearanceSettings />} />
            <Route path="/settings/other" element={<OtherSettings />} />
          </Routes>
        </Box>
      </Box>
    </ThemeProvider>
  );

  // Wrap with DashboardVariableProvider if viewing the default dashboard
  if (isDefaultDashboard) {
    return (
      <DashboardVariableProvider>
        {layoutContent}
      </DashboardVariableProvider>
    );
  }

  return layoutContent;
}

function App() {
  const [isLoading, setIsLoading] = useState(true);
  const [restorePrompt, setRestorePrompt] = useState<{open: boolean, latest?: string, reason?: string}>({ open: false });
  const [restoring, setRestoring] = useState(false);

  useEffect(() => {
    const checkLoadingStatus = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/status');
        const data = await response.json();
        
        if (data.loading_complete) {
          // Also check restore suggestion once after backend is ready
          try {
            const r = await fetch('http://localhost:8000/api/database/restore-suggestion');
            const s = await r.json();
            if (s?.suggest) {
              setRestorePrompt({ open: true, latest: s.latest_backup, reason: s.reason });
            }
          } catch {}
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
        <DeveloperProvider>
          <DashboardProvider>
            <DashboardEditProvider>
              <DashboardLayout />
            </DashboardEditProvider>
          </DashboardProvider>
        </DeveloperProvider>
      </Router>
      <Snackbar open={restorePrompt.open} anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
        <Alert
          severity="warning"
          sx={{ width: '100%' }}
          action={
            <>
              <Button color="inherit" size="small" disabled={restoring} onClick={async () => {
                try {
                  setRestoring(true);
                  const latest = restorePrompt.latest;
                  if (!latest) return;
                  const res = await fetch('http://localhost:8000/api/database/restore', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ backup_path: latest })
                  });
                  if (!res.ok) {
                    const data = await res.json().catch(() => ({}));
                    throw new Error(data?.detail || 'Restore failed');
                  }
                  setRestorePrompt({ open: false });
                } catch (e) {
                  setRestorePrompt({ open: false });
                } finally {
                  setRestoring(false);
                }
              }}>Restore</Button>
              <Button color="inherit" size="small" onClick={() => setRestorePrompt({ open: false })}>Dismiss</Button>
            </>
          }
        >
          The main database is {restorePrompt.reason}. Restore from latest backup?
        </Alert>
      </Snackbar>
      {isLoading && <SplashScreen onComplete={() => setIsLoading(false)} />}
    </>
  );
}

export default App;
