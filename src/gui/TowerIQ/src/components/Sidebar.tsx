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
        variant={sidebarDocked ? "persistent" : "temporary"} // Use persistent when docked to avoid overlay
        open={!sidebarHidden}
        onClose={() => {
          if (!sidebarDocked) {
            onSidebarToggle();
          }
        }}
        transitionDuration={{
          enter: sidebarDocked ? 0 : transitionDuration, // No transition when docked (persistent), normal when undocked (temporary)
          exit: transitionDuration,  // Always use transition when closing/undocking
        }}
        SlideProps={{
          timeout: {
            enter: sidebarDocked ? 0 : transitionDuration, // No transition when docked
            exit: transitionDuration,
          },
          easing: {
            enter: 'cubic-bezier(0.4, 0, 0.2, 1)', // Material-UI sharp easing to match sharedTransition
            exit: 'cubic-bezier(0.4, 0, 0.2, 1)',
          },
        }}
        PaperProps={{
          sx: {
            // Remove custom transition to prevent conflicts with MUI's slide transition
            // The drawer's built-in slide transition will handle the timing
          },
        }}
        ModalProps={{
          keepMounted: true,
          // Always hide backdrop to prevent dimming during transitions
          BackdropProps: {
            invisible: true, // Always hide backdrop to prevent screen dimming
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
              // Let MUI handle the slide transition timing - don't override with custom transitions
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
