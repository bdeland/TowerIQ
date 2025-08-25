import { 
  Box, 
  Drawer, 
  IconButton, 
  List, 
  ListItem, 
  ListItemButton, 
  ListItemIcon, 
  ListItemText, 
  Tooltip 
} from '@mui/material';
import {
  Menu as MenuIcon,
  ViewSidebar as ViewSidebarIcon,
  ViewSidebarOutlined as ViewSidebarOutlinedIcon,
} from '@mui/icons-material';
import { useLocation, useNavigate } from 'react-router-dom';

interface NavigationItem {
  text: string;
  icon: React.ReactNode;
  path: string;
  position?: string;
}

interface SidebarProps {
  sidebarDocked: boolean;
  sidebarHidden: boolean;
  onSidebarToggle: () => void;
  onDockToggle: () => void;
  navigationItems: NavigationItem[];
  layout: {
    drawerWidth: number;
    appBarHeight: number;
    border: string;
  };
  listItemButtonStyles: any;
  listItemIconStyles: any;
  listItemTextStyles: any;
  sidebarHeaderStyles: any;
}

export function Sidebar({
  sidebarDocked,
  sidebarHidden,
  onSidebarToggle,
  onDockToggle,
  navigationItems,
  layout,
  listItemButtonStyles,
  listItemIconStyles,
  listItemTextStyles,
  sidebarHeaderStyles
}: SidebarProps) {
  const navigate = useNavigate();
  const location = useLocation();

  const handleNavigation = (path: string) => {
    navigate(path);
    // Close sidebar when not docked (overlay mode)
    if (!sidebarDocked) {
      onSidebarToggle();
    }
  };

  return (
    <Box
      component="nav"
      sx={{ 
        width: sidebarDocked ? (sidebarHidden ? 0 : layout.drawerWidth) : 0, 
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
            onSidebarToggle();
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
              width: sidebarHidden ? 0 : layout.drawerWidth,
              overflowX: 'hidden',
              // When not docked, ensure it overlays content and spans full height
              position: sidebarDocked ? 'relative' : 'fixed',
              top: sidebarDocked ? 'auto' : 0,
              height: sidebarDocked ? '100vh' : '100vh',
              zIndex: sidebarDocked ? 'auto' : 9999,
              // Add right border to separate sidebar from main content
              borderRight: layout.border,
              transition: (theme) => theme.transitions.create(['width'], {
                easing: theme.transitions.easing.sharp,
                duration: theme.transitions.duration.enteringScreen,
              }),
            },
        }}
      >
        {/* Sidebar Header */}
        <Box sx={sidebarHeaderStyles}>
          {/* Hamburger Menu Toggle - Always show in sidebar when visible */}
          <IconButton
            color="inherit"
            aria-label="toggle sidebar"
            onClick={onSidebarToggle}
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
              onClick={onDockToggle}
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
  );
}
