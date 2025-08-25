import { Breadcrumbs as MuiBreadcrumbs, Link, Typography, Box, useTheme, useMediaQuery } from '@mui/material';
import { NavigateNext as NavigateNextIcon } from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useDashboard } from '../contexts/DashboardContext';
import { useEffect, useState } from 'react';

interface BreadcrumbItem {
  label: string;
  path: string;
  icon?: React.ReactNode;
}

interface BreadcrumbsProps {
}

export function Breadcrumbs({}: BreadcrumbsProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const isSmallScreen = useMediaQuery(theme.breakpoints.down('sm'));
  const isExtraSmall = useMediaQuery(theme.breakpoints.down('xs'));
  const { fetchDashboard, dashboards } = useDashboard();
  const [dashboardTitle, setDashboardTitle] = useState<string>('');
  const [isLoadingDashboard, setIsLoadingDashboard] = useState<boolean>(false);
  const [panelTitle, setPanelTitle] = useState<string>('');

  // Get dashboard ID from URL
  const getDashboardIdFromUrl = () => {
    const pathSegments = location.pathname.split('/').filter(Boolean);
    const dashboardIndex = pathSegments.findIndex(segment => segment === 'dashboard');
    if (dashboardIndex !== -1 && pathSegments[dashboardIndex + 1]) {
      return pathSegments[dashboardIndex + 1];
    }
    return null;
  };

  // Get panel ID from URL
  const getPanelIdFromUrl = () => {
    const pathSegments = location.pathname.split('/').filter(Boolean);
    const panelIndex = pathSegments.findIndex(segment => segment === 'panels');
    if (panelIndex !== -1 && pathSegments[panelIndex + 1]) {
      return pathSegments[panelIndex + 1];
    }
    return null;
  };

  // Fetch dashboard title when URL changes
  useEffect(() => {
    const dashboardId = getDashboardIdFromUrl();
    
    if (dashboardId) {
      console.log('Breadcrumb: Fetching dashboard for ID:', dashboardId);
      setIsLoadingDashboard(true);
      setDashboardTitle(''); // Clear previous title
      
      fetchDashboard(dashboardId).then(dashboard => {
        if (dashboard) {
          console.log('Breadcrumb: Got dashboard title:', dashboard.title);
          setDashboardTitle(dashboard.title);
        } else {
          console.log('Breadcrumb: No dashboard found');
          setDashboardTitle('');
        }
      }).catch(error => {
        console.error('Breadcrumb: Error fetching dashboard:', error);
        setDashboardTitle('');
      }).finally(() => {
        setIsLoadingDashboard(false);
      });
    } else {
      setDashboardTitle('');
      setIsLoadingDashboard(false);
    }
  }, [location.pathname, fetchDashboard]);

  // Find panel title from dashboards
  useEffect(() => {
    const panelId = getPanelIdFromUrl();
    if (panelId && dashboards.length > 0) {
      let foundPanel = null;
      for (const dashboard of dashboards) {
        const panel = dashboard.config?.panels?.find((p: any) => p.id === panelId);
        if (panel) {
          foundPanel = panel;
          break;
        }
      }
      setPanelTitle(foundPanel?.title || 'Panel');
    } else {
      setPanelTitle('');
    }
  }, [location.pathname, dashboards]);

  // Generate breadcrumb items based on current path
  const getBreadcrumbItems = (): BreadcrumbItem[] => {
    const pathSegments = location.pathname.split('/').filter(Boolean);
    
    if (pathSegments.length === 0) {
      return [{ label: 'Home', path: '/' }];
    }

    const items: BreadcrumbItem[] = [
      { label: 'Home', path: '/' }
    ];

    // Special handling for panel edit page
    if (pathSegments[0] === 'dashboard' && pathSegments[2] === 'panels' && pathSegments[4] === 'edit') {
      // Panel edit page: Home > Dashboards > [Dashboard Name] > [Panel Name] > Edit
      items.push({ label: 'Dashboards', path: '/dashboards' });
      
      if (dashboardTitle) {
        const dashboardId = getDashboardIdFromUrl();
        items.push({ label: dashboardTitle, path: `/dashboards/${dashboardId}` });
      }
      
      if (panelTitle) {
        const dashboardId = getDashboardIdFromUrl();
        const panelId = getPanelIdFromUrl();
        items.push({ label: panelTitle, path: `/dashboard/${dashboardId}/panels/${panelId}/view` });
      }
      
      items.push({ label: 'Edit', path: location.pathname });
      return items;
    }

    // Special handling for panel view page
    if (pathSegments[0] === 'dashboard' && pathSegments[2] === 'panels' && pathSegments[4] === 'view') {
      // Panel view page: Home > Dashboards > [Dashboard Name] > [Panel Name]
      items.push({ label: 'Dashboards', path: '/dashboards' });
      
      if (dashboardTitle) {
        const dashboardId = getDashboardIdFromUrl();
        items.push({ label: dashboardTitle, path: `/dashboards/${dashboardId}` });
      }
      
      if (panelTitle) {
        items.push({ label: panelTitle, path: location.pathname });
      }
      return items;
    }

    let currentPath = '';
    pathSegments.forEach((segment, index) => {
      currentPath += `/${segment}`;
      
      // Special handling for dashboard view pages
      if (segment === 'dashboard' && pathSegments[index + 1]) {
        // This is a dashboard view page, show "Dashboards" as the label
        items.push({
          label: 'Dashboards',
          path: '/dashboards'
        });
      } else if (pathSegments[index - 1] === 'dashboard') {
        // This is the dashboard ID segment, show the dashboard title
        const title = dashboardTitle || (isLoadingDashboard ? 'Loading...' : 'Dashboard');
        items.push({
          label: title,
          path: currentPath
        });
      } else {
        // Regular segment handling
        const label = segment.charAt(0).toUpperCase() + segment.slice(1);
        items.push({
          label,
          path: currentPath
        });
      }
    });

    return items;
  };

  const breadcrumbItems = getBreadcrumbItems();

  const handleClick = (path: string) => {
    navigate(path);
  };

  // Progressive responsive maxItems based on screen size
  const getMaxItems = () => {
    if (isExtraSmall) return 2;
    if (isSmallScreen) return 4;
    if (isMobile) return 6;
    return 8;
  };

  // Progressive responsive maxWidth for individual items
  const getItemMaxWidth = () => {
    if (isExtraSmall) return '80px';
    if (isSmallScreen) return '120px';
    if (isMobile) return '160px';
    return '200px';
  };

  // Progressive collapse settings
  const getCollapseSettings = () => {
    if (isExtraSmall) {
      return { itemsAfterCollapse: 1, itemsBeforeCollapse: 1 };
    }
    if (isSmallScreen) {
      return { itemsAfterCollapse: 2, itemsBeforeCollapse: 1 };
    }
    if (isMobile) {
      return { itemsAfterCollapse: 2, itemsBeforeCollapse: 1 };
    }
    return { itemsAfterCollapse: 2, itemsBeforeCollapse: 1 };
  };

  const collapseSettings = getCollapseSettings();

  // Custom breadcrumb items with progressive collapse
  const getVisibleBreadcrumbItems = () => {
    const maxItems = getMaxItems();
    const totalItems = breadcrumbItems.length;
    
    if (totalItems <= maxItems) {
      return breadcrumbItems;
    }
    
    // Show first item (Home) and last items, collapse middle
    const itemsToShowAfter = collapseSettings.itemsAfterCollapse;
    const itemsToShowBefore = collapseSettings.itemsBeforeCollapse;
    
    const visibleItems = [];
    
    // Always show first item
    visibleItems.push(breadcrumbItems[0]);
    
    // Add collapse indicator if needed
    if (totalItems > maxItems) {
      visibleItems.push({ label: '...', path: '', isCollapsed: true });
    }
    
    // Show last items
    const lastItems = breadcrumbItems.slice(-itemsToShowAfter);
    visibleItems.push(...lastItems);
    
    return visibleItems;
  };

  const visibleBreadcrumbItems = getVisibleBreadcrumbItems();

  return (
    <Box sx={{ 
      display: 'flex', 
      alignItems: 'center',
      minWidth: 0,
      overflow: 'hidden',
      flex: 1,
      maxWidth: '100%',
      paddingRight: 2, // Add right padding
      [theme.breakpoints.down('xs')]: {
        maxWidth: '200px',
      },
      [theme.breakpoints.down('sm')]: {
        maxWidth: '300px',
      },
      [theme.breakpoints.down('md')]: {
        maxWidth: '450px',
      }
    }}>
      <MuiBreadcrumbs
        maxItems={visibleBreadcrumbItems.length}
        separator={<NavigateNextIcon fontSize="small" />}
        aria-label="breadcrumb"
        sx={{ 
          width: '100%',
          overflow: 'hidden',
          whiteSpace: 'nowrap',
          '& .MuiBreadcrumbs-ol': { 
            color: 'inherit',
            flexWrap: 'nowrap',
            overflow: 'hidden',
            whiteSpace: 'nowrap',
            width: '100%',
            '& .MuiTypography-root': { 
              color: 'inherit',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              maxWidth: getItemMaxWidth(),
              minWidth: 'fit-content'
            },
            '& .MuiLink-root': { 
              color: 'inherit',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              maxWidth: getItemMaxWidth(),
              minWidth: 'fit-content'
            }
          }
        }}
      >
        {visibleBreadcrumbItems.map((item, index) => {
          const isLast = index === visibleBreadcrumbItems.length - 1;
          const isCollapsed = (item as any).isCollapsed;
          
          if (isCollapsed) {
            return (
              <Typography
                key={`collapsed-${index}`}
                color="inherit"
                sx={{ 
                  display: 'flex', 
                  alignItems: 'center',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  maxWidth: getItemMaxWidth(),
                  minWidth: 'fit-content',
                  cursor: 'default'
                }}
              >
                {item.label}
              </Typography>
            );
          }
          
          return isLast ? (
            <Typography
              key={item.path}
              color="inherit"
              sx={{ 
                display: 'flex', 
                alignItems: 'center',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                maxWidth: getItemMaxWidth(),
                minWidth: 'fit-content'
              }}
            >
              {item.icon && <Box sx={{ mr: 0.5, display: 'flex', alignItems: 'center' }}>{item.icon}</Box>}
              {item.label}
            </Typography>
          ) : (
            <Link
              key={item.path}
              color="inherit"
              href="#"
              onClick={(e) => {
                e.preventDefault();
                handleClick(item.path);
              }}
              sx={{
                display: 'flex',
                alignItems: 'center',
                textDecoration: 'none',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                maxWidth: getItemMaxWidth(),
                minWidth: 'fit-content',
                '&:hover': {
                  textDecoration: 'underline',
                },
              }}
            >
              {item.icon && <Box sx={{ mr: 0.5, display: 'flex', alignItems: 'center' }}>{item.icon}</Box>}
              {item.label}
            </Link>
          );
        })}
      </MuiBreadcrumbs>
    </Box>
  );
}
