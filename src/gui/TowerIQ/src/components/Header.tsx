import { AppBar, Toolbar, Box, IconButton } from '@mui/material';
import { Menu as MenuIcon } from '@mui/icons-material';
import { Breadcrumbs } from './Breadcrumbs';
import { SearchBar } from './SearchBar';

interface HeaderProps {
  sidebarDocked: boolean;
  sidebarHidden: boolean;
  onSidebarToggle: () => void;
  layoutStyles: {
    appBar: any;
  };
  layout: {
    appBarHeight: number;
    border: string;
  };
  listItemIconStyles: any;
}

export function Header({ 
  sidebarDocked, 
  sidebarHidden, 
  onSidebarToggle, 
  layoutStyles, 
  layout, 
  listItemIconStyles 
}: HeaderProps) {
  return (
    <AppBar
      position="fixed"
      sx={{
        ...layoutStyles.appBar,
        // Match sidebar: exactly 80px total with top/bottom borders, no internal border
        borderTop: layout.border,
        borderBottom: layout.border,
        height: `${layout.appBarHeight * 2}px`, // Exactly 80px total
        minHeight: `${layout.appBarHeight * 2}px`,
        maxHeight: `${layout.appBarHeight * 2}px`,
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column',
        padding: 0,
        '& .MuiToolbar-root': {
          // Default height for toolbars without internal borders
          minHeight: `${layout.appBarHeight}px`,
          height: `${layout.appBarHeight}px`,
          maxHeight: `${layout.appBarHeight}px`,
          paddingLeft: 1,
          paddingRight: 1.5,
          paddingTop: 0,
          paddingBottom: 0,
          boxSizing: 'border-box',
          borderRight: layout.border, // Add right border to all toolbars
          flex: 'none', // Prevent flex growing/shrinking
        }
      }}
    >
      {/* First Toolbar */}
      <Toolbar sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        borderBottom: layout.border,
        boxSizing: 'border-box',
      }}>
        {/* Main Menu Toggle Icon - Show when not docked or when docked and hidden */}
        <IconButton
          aria-label="toggle sidebar"
          onClick={onSidebarToggle}
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

      {/* Second Toolbar */}
      <Toolbar sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        borderBottom: layout.border, // Add bottom border to second toolbar
        boxSizing: 'border-box',
        }}>
        {/* Secondary toolbar content - currently empty */}
        <Box sx={{ flexGrow: 1, display: 'flex', alignItems: 'center' }}>
          {/* Empty for now - add your controls here */}
        </Box>
      </Toolbar>
    </AppBar>
  );
}
