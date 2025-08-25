import { Breadcrumbs as MuiBreadcrumbs, Link, Typography, Box } from '@mui/material';
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
  const { fetchDashboard } = useDashboard();
  const [dashboardTitle, setDashboardTitle] = useState<string>('');
  const [isLoadingDashboard, setIsLoadingDashboard] = useState<boolean>(false);

  // Get dashboard ID from URL
  const getDashboardIdFromUrl = () => {
    const pathSegments = location.pathname.split('/').filter(Boolean);
    const dashboardIndex = pathSegments.findIndex(segment => segment === 'dashboard');
    if (dashboardIndex !== -1 && pathSegments[dashboardIndex + 1]) {
      return pathSegments[dashboardIndex + 1];
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

  // Generate breadcrumb items based on current path
  const getBreadcrumbItems = (): BreadcrumbItem[] => {
    const pathSegments = location.pathname.split('/').filter(Boolean);
    
    if (pathSegments.length === 0) {
      return [{ label: 'Home', path: '/' }];
    }

    const items: BreadcrumbItem[] = [
      { label: 'Home', path: '/' }
    ];

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

  return (
    <Box sx={{ 
      display: 'flex', 
      alignItems: 'center',
      minWidth: 0,
      overflow: 'hidden',
      flex: 1,
      maxWidth: '100%'
    }}>
      <MuiBreadcrumbs
        maxItems={2}
        itemsAfterCollapse={1}
        itemsBeforeCollapse={1}
        separator={<NavigateNextIcon fontSize="small" />}
        aria-label="breadcrumb"
        sx={{ 
          width: '100%',
          maxWidth: '300px',
          overflow: 'hidden',
          '& .MuiBreadcrumbs-ol': { 
            color: 'inherit',
            flexWrap: 'nowrap',
            overflow: 'hidden',
            '& .MuiTypography-root': { color: 'inherit' },
            '& .MuiLink-root': { color: 'inherit' }
          }
        }}
      >
        {breadcrumbItems.map((item, index) => {
          const isLast = index === breadcrumbItems.length - 1;
          
          return isLast ? (
            <Typography
              key={item.path}
              color="inherit"
              sx={{ display: 'flex', alignItems: 'center' }}
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
