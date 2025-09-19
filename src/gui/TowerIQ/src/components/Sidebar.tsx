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
  ViewSidebar as ViewSidebarIcon,
  ViewSidebarOutlined as ViewSidebarOutlinedIcon,
} from '@mui/icons-material';
import { useLocation, useNavigate } from 'react-router-dom';
import { TowerIQLogo } from './TowerIQLogo';

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
  sharedTransition: (theme: any) => any;
  transitionDuration: number;
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
  sidebarHeaderStyles,
  sharedTransition,
  transitionDuration
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
        variant="temporary" // Always use temporary to ensure slide transitions work
        open={!sidebarHidden}
        onClose={() => {
          if (!sidebarDocked) {
            onSidebarToggle();
          }
        }}
        transitionDuration={{
          enter: transitionDuration,
          exit: transitionDuration,
        }}
        SlideProps={{
          timeout: {
            enter: transitionDuration,
            exit: transitionDuration,
          },
        }}
        PaperProps={{
          sx: {
            transition: sharedTransition, // Use our shared transition for paper
          },
        }}
        ModalProps={{
          keepMounted: true,
          // Add backdrop for overlay mode
          BackdropProps: {
            invisible: sidebarDocked, // Hide backdrop when docked
          },
        }}
        sx={{
          '& .MuiDrawer-paper': { 
              boxSizing: 'border-box', 
              width: sidebarHidden ? 0 : layout.drawerWidth,
              overflowX: 'hidden',
              // Position and height settings
              position: 'fixed',
              top: 0,
              height: '100vh',
              zIndex: sidebarDocked ? (theme) => theme.zIndex.drawer : 9999,
              // Add borders to define sidebar boundaries
              borderLeft: layout.border,
              borderRight: layout.border,
              // Remove MUI's default transition and use our shared one
              transition: (theme) => `${sharedTransition(theme)} !important`,
              // Override any default MUI transitions
              '&.MuiDrawer-paperAnchorLeft': {
                transition: (theme) => `${sharedTransition(theme)} !important`,
              },
            },
        }}
      >
        {/* Sidebar Header */}
        <Box sx={{
          ...sidebarHeaderStyles,
          paddingLeft: '12px', // Override left padding - adjust this value as needed
          paddingRight: '0px', // Override right padding to allow button closer to edge
        }}>
          {/* Hamburger Menu Toggle - Always show in sidebar when visible */}
          <IconButton
            color="inherit"
            aria-label="toggle sidebar"
            onClick={onSidebarToggle}
            sx={{ 
              color: 'text.primary',
              width: 28,
              height: 28,
              alignSelf: 'center',
              padding: 0, // Remove default IconButton padding
              marginRight: '12px', // Add spacing between logo and text
              '&:hover': {
                backgroundColor: 'rgba(255, 255, 255, 0.04)',
              },
            }}
          >
            <TowerIQLogo sx={{ fontSize: 28 }} />
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
                marginRight: '0px !important', // Override inherited margin-right from listItemIconStyles
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
