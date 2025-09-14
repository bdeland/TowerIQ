import { Breadcrumbs as MuiBreadcrumbs, Link, Typography, Box, useTheme, useMediaQuery } from '@mui/material';
import { NavigateNext as NavigateNextIcon } from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useDashboard } from '../contexts/DashboardContext';
import { useEffect, useState, useMemo } from 'react';
import { defaultDashboard } from '../config/defaultDashboard';

interface BreadcrumbItem {
  label: string;
  path: string;
}

export function Breadcrumbs() {
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const isSmallScreen = useMediaQuery(theme.breakpoints.down('sm'));

  const { fetchDashboard, dashboards } = useDashboard();
  const [dashboardTitle, setDashboardTitle] = useState<string>('');
  const [isLoadingDashboard, setIsLoadingDashboard] = useState<boolean>(false);
  const [panelTitle, setPanelTitle] = useState<string>('');

  // Memoize URL parsing
  const { dashboardId, panelId } = useMemo(() => {
    const pathSegments = location.pathname.split('/').filter(Boolean);
    
    let dId = null;
    // Check for both 'dashboards' (plural) and 'dashboard' (singular)
    const dashboardIndex = pathSegments.findIndex(segment => segment === 'dashboards' || segment === 'dashboard');
    if (dashboardIndex !== -1 && pathSegments[dashboardIndex + 1]) {
      dId = pathSegments[dashboardIndex + 1];
    }

    let pId = null;
    const panelIndex = pathSegments.findIndex(segment => segment === 'panels');
    if (panelIndex !== -1 && pathSegments[panelIndex + 1]) {
      pId = pathSegments[panelIndex + 1];
    }
    
    return { dashboardId: dId, panelId: pId };
  }, [location.pathname]);

  // Update data fetching effects
  useEffect(() => {
    if (dashboardId) {
      // Check if this is the default dashboard first
      if (dashboardId === 'default-dashboard') {
        setDashboardTitle(defaultDashboard.title);
        return;
      }
      
      const dashboard = dashboards.find(d => d.id === dashboardId);
      if (dashboard) {
        setDashboardTitle(dashboard.title);
      } else {
        setIsLoadingDashboard(true);
        fetchDashboard(dashboardId).then(dashboard => {
          if (dashboard) setDashboardTitle(dashboard.title);
        }).catch(error => {
          console.error('Breadcrumb: Error fetching dashboard:', error);
        }).finally(() => {
          setIsLoadingDashboard(false);
        });
      }
    } else {
      setDashboardTitle('');
    }
  }, [dashboardId, dashboards, fetchDashboard]);

  useEffect(() => {
    if (panelId) {
      let foundPanel = null;
      
      // Check default dashboard first
      const defaultPanel = defaultDashboard.config?.panels?.find((p: any) => p.id === panelId);
      if (defaultPanel) {
        foundPanel = defaultPanel;
      } else if (dashboards.length > 0) {
        // Then check other dashboards
        for (const dashboard of dashboards) {
          const panel = dashboard.config?.panels?.find((p: any) => p.id === panelId);
          if (panel) {
            foundPanel = panel;
            break;
          }
        }
      }
      
      setPanelTitle(foundPanel?.title || '');
    } else {
      setPanelTitle('');
    }
  }, [panelId, dashboards]);

  // Generate breadcrumb items declaratively
  const breadcrumbItems = useMemo((): BreadcrumbItem[] => {
    const pathSegments = location.pathname.split('/').filter(Boolean);
    const items: BreadcrumbItem[] = [{ label: 'Home', path: '/' }];

    // Handle different page types
    if (pathSegments.length === 0) {
      // Home page - already handled above
      return items;
    }

    const firstSegment = pathSegments[0];

    // Handle dashboard-related pages
    if (firstSegment === 'dashboards' || firstSegment === 'dashboard') {
      items.push({ label: 'Dashboards', path: '/dashboards' });

      if (dashboardId) {
        const title = isLoadingDashboard ? 'Loading...' : (dashboardTitle || 'Dashboard');
        // Use the same pattern as the current URL (dashboard vs dashboards)
        const basePath = firstSegment === 'dashboard' ? '/dashboard' : '/dashboards';
        items.push({ label: title, path: `${basePath}/${dashboardId}` });

        if (panelId) {
          // Use the same pattern as the current URL (dashboard vs dashboards)
          const basePath = firstSegment === 'dashboard' ? '/dashboard' : '/dashboards';
          const panelViewPath = `${basePath}/${dashboardId}/panels/${panelId}/view`;
          items.push({ label: panelTitle || 'Panel', path: panelViewPath });

          if (pathSegments.includes('edit')) {
            items.push({ label: 'Edit', path: location.pathname });
          }
        }
      }
    }
    // Handle other pages
    else if (firstSegment === 'connection') {
      items.push({ label: 'Connection', path: '/connection' });
    }
    else if (firstSegment === 'explore') {
      items.push({ label: 'Explore', path: '/explore' });
    }
    else if (firstSegment === 'history') {
      items.push({ label: 'History', path: '/history' });
    }
    else if (firstSegment === 'settings') {
      items.push({ label: 'Settings', path: '/settings' });
    }
    
    return items;
  }, [location.pathname, dashboardId, panelId, dashboardTitle, panelTitle, isLoadingDashboard]);

  // Implement the render logic
  const handleClick = (path: string) => {
    navigate(path);
  };

  const maxItems = isMobile ? 4 : 8;
  const itemMaxWidth = isSmallScreen ? '120px' : '200px';

  return (
    <Box sx={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
      <MuiBreadcrumbs
        maxItems={maxItems}
        itemsBeforeCollapse={1}
        itemsAfterCollapse={2}
        separator={<NavigateNextIcon fontSize="small" />}
        aria-label="breadcrumb"
        sx={{
          width: '100%',
          overflow: 'hidden',
          whiteSpace: 'nowrap',
          '& .MuiBreadcrumbs-ol': { flexWrap: 'nowrap' },
          '& .MuiBreadcrumbs-li': { minWidth: 0 },
          '& .MuiTypography-root, & .MuiLink-root': {
            color: 'inherit',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            maxWidth: itemMaxWidth,
          },
        }}
      >
        {breadcrumbItems.map((item, index) => {
          const isLast = index === breadcrumbItems.length - 1;
          return isLast ? (
            <Typography key={item.path} color="text.primary">
              {item.label}
            </Typography>
          ) : (
            <Link
              key={item.path}
              underline="hover"
              color="inherit"
              href={item.path}
              onClick={(e) => {
                e.preventDefault();
                handleClick(item.path);
              }}
            >
              {item.label}
            </Link>
          );
        })}
      </MuiBreadcrumbs>
    </Box>
  );
}
