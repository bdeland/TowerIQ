import { Breadcrumbs as MuiBreadcrumbs, Link, Typography, Box, useTheme, useMediaQuery, IconButton, Menu, MenuItem } from '@mui/material';
import { NavigateNext as NavigateNextIcon, MoreVert as MoreVertIcon } from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useDashboard } from '../contexts/DashboardContext';
import { useDeveloper } from '../contexts/DeveloperContext';
import { useEffect, useState, useMemo } from 'react';
import { defaultDashboard } from '../config/defaultDashboard';
import { databaseHealthDashboard } from '../config/databaseHealthDashboard';

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
  const { isDevMode, breadcrumbCopy } = useDeveloper();
  const [dashboardTitle, setDashboardTitle] = useState<string>('');
  const [isLoadingDashboard, setIsLoadingDashboard] = useState<boolean>(false);
  const [panelTitle, setPanelTitle] = useState<string>('');
  
  // Developer menu state
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [isHovered, setIsHovered] = useState(false);

  const showDevMenu = isDevMode && breadcrumbCopy;

  // Memoize URL parsing
  const { dashboardId, panelId } = useMemo(() => {
    const pathSegments = location.pathname.split('/').filter(Boolean);
    
    let dId = null;
    // Check for 'dashboards' (plural)
    const dashboardIndex = pathSegments.findIndex(segment => segment === 'dashboards');
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
      
      // Check if this is the database health dashboard
      if (dashboardId === 'database-health-dashboard') {
        setDashboardTitle(databaseHealthDashboard.title);
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
      
      // Handle settings sub-pages
      if (pathSegments.length > 1) {
        const settingsPage = pathSegments[1];
        if (settingsPage === 'database') {
          items.push({ label: 'Database', path: '/settings/database' });
        } else if (settingsPage === 'appearance') {
          items.push({ label: 'Appearance', path: '/settings/appearance' });
        } else if (settingsPage === 'other') {
          items.push({ label: 'Other', path: '/settings/other' });
        }
      }
    }
    
    return items;
  }, [location.pathname, dashboardId, panelId, dashboardTitle, panelTitle, isLoadingDashboard]);

  // Developer menu handlers
  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    if ( !showDevMenu) return; 
    setAnchorEl(event.currentTarget);
  };
  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  useEffect(() => {
    if ( !showDevMenu) { 
      setAnchorEl(null);
    }
  }, [showDevMenu]);

  const formatBreadcrumbString = () => {
    return breadcrumbItems.map(item => item.label).join(' > ');
  };

  const handleCopyAll = async () => {
    const breadcrumbString = formatBreadcrumbString();
    const fullUrl = window.location.href;
    const textToCopy = `${breadcrumbString}\n${fullUrl}`;
    
    try {
      await navigator.clipboard.writeText(textToCopy);
      console.log('Copied to clipboard:', textToCopy);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = textToCopy;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
    }
    handleMenuClose();
  };

  // Implement the render logic
  const handleClick = (path: string) => {
    navigate(path);
  };

  const maxItems = isMobile ? 4 : 8;
  const itemMaxWidth = isSmallScreen ? '120px' : '200px';

  return (
    <Box 
      sx={{ 
        flex: 1, 
        minWidth: 0, 
        overflow: 'hidden',
        display: 'flex',
        alignItems: 'center',
        gap: 1
      }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
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
      
      {/* Developer Menu - only show in dev mode when hovered */}
      {showDevMenu && isHovered && (
        <IconButton
          size="small"
          onClick={handleMenuOpen}
          sx={{
            opacity: 0.7,
            '&:hover': {
              opacity: 1,
            },
          }}
        >
          <MoreVertIcon fontSize="small" />
        </IconButton>
      )}
      
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl) && showDevMenu}
        onClose={handleMenuClose}
        PaperProps={{
          sx: {
            minWidth: 300,
          },
        }}
      >
        <MenuItem onClick={handleCopyAll}>
          <Typography variant="body2" fontWeight="bold">
            Copy All
          </Typography>
        </MenuItem>
        <MenuItem disabled>
          <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'normal' }}>
            {formatBreadcrumbString()}
          </Typography>
        </MenuItem>
        <MenuItem disabled>
          <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'normal', wordBreak: 'break-all' }}>
            {window.location.href}
          </Typography>
        </MenuItem>
      </Menu>
    </Box>
  );
}





