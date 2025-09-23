import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import {
  Box,
  CssBaseline,
  ThemeProvider,
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
import { DashboardProvider, useDashboard } from './contexts/DashboardContext';
import { DashboardEditProvider } from './contexts/DashboardEditContext';
import { DashboardVariableProvider } from './contexts/DashboardVariableContext';
import { DeveloperProvider } from './contexts/DeveloperContext';
import { HeaderToolbarProvider } from './contexts/HeaderToolbarContext';
import { toweriqTheme, colors, spacing } from './theme';

import './App.css';

// Centralized layout configuration - now using theme values
const layout = {
  appBarHeight: spacing.layout.headerHeight,
  drawerWidth: spacing.layout.sidebarWidth,
  border: `1px solid ${colors.borders.primary}`,
  borderColor: colors.borders.primary,
  backgroundColor: {
    main: colors.backgrounds.main,
    paper: colors.backgrounds.paper,
  },
  colors: {
    primary: colors.brand.primary,
    secondary: colors.accent.secondary,
    textPrimary: colors.text.primary,
    textSecondary: colors.text.secondary,
  }
};

// Use the centralized TowerIQ theme
const theme = toweriqTheme;

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
// Component that determines if we need DashboardVariableProvider
function DashboardVariableWrapper({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const { currentDashboard } = useDashboard();
  
  // Check if we're on a dashboard or panel view page that has variables
  // Also check URL path directly for default dashboard to avoid race conditions
  const isDefaultDashboard = location.pathname.includes('/dashboard/default-dashboard') || 
                            (currentDashboard?.id === 'default-dashboard');
  
  const needsVariableProvider = 
    (location.pathname.startsWith('/dashboard/') && isDefaultDashboard) ||
    (location.pathname.includes('/panels/') && location.pathname.includes('/view') && isDefaultDashboard);
  
  if (needsVariableProvider) {
    return (
      <DashboardVariableProvider>
        {children}
      </DashboardVariableProvider>
    );
  }
  
  return <>{children}</>;
}

function DashboardLayout() {
  // Updated state management according to requirements
  //TODO fix the stupid sidebar transition when undocking
  const [sidebarHidden, setSidebarHidden] = useState(true); // Manages the hidden state - default to hidden
  const [sidebarDocked, setSidebarDocked] = useState(false); // Manages the docked state
  const location = useLocation();
  
  // Check if we're on the PanelEditPage to remove bottom padding
  const isPanelEditPage = location.pathname.includes('/dashboard/') && location.pathname.includes('/panels/') && location.pathname.includes('/edit');



  // Shared transition configuration for synchronized animations
  const transitionDuration = 300; // Synchronized transition duration for all sidebar animations
  const sharedTransition = (theme: any) => theme.transitions.create(['margin', 'width', 'margin-left', 'transform'], {
    easing: theme.transitions.easing.sharp,
    duration: transitionDuration,
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
        zIndex: (theme: any) => sidebarDocked ? theme.zIndex.drawer - 1 : 1,
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
    
    // When undocking, start the layout transition, then hide sidebar after it slides out
    if (!newDockedState) {
      // First change docked state to start header/content expansion
      setSidebarDocked(newDockedState);
      // Then hide sidebar to trigger its slide-out transition
      // Small delay to ensure state changes are processed in order
      setTimeout(() => {
        setSidebarHidden(true);
      }, 0); // Just enough delay to ensure proper state sequencing
    } else {
      // When docking, set layout state immediately to prevent content overlap, then show sidebar
      setSidebarDocked(newDockedState); // Set layout immediately to reserve space
      setSidebarHidden(false); // Then show sidebar in the reserved space
    }
  };



  const layoutContent = (
    <ThemeProvider theme={theme}>
      <HeaderToolbarProvider>
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
            sharedTransition={sharedTransition}
            transitionDuration={transitionDuration}
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
      </HeaderToolbarProvider>
    </ThemeProvider>
  );

  return (
    <DashboardVariableWrapper>
      {layoutContent}
    </DashboardVariableWrapper>
  );
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


