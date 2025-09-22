import React from 'react';
import { AppBar, Toolbar, Box, IconButton } from '@mui/material';
import { Breadcrumbs } from './Breadcrumbs';
import { SearchBar } from './SearchBar';
import { TowerIQLogo } from './TowerIQLogo';
import { useHeaderToolbar } from '../contexts/HeaderToolbarContext';
import { colors } from '../theme/toweriqTheme';

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
}

export function Header({
  sidebarDocked,
  sidebarHidden,
  onSidebarToggle,
  layoutStyles,
  layout,
}: HeaderProps) {
  const { secondaryLeft, secondaryRight } = useHeaderToolbar();

  const renderSecondaryItems = (items: { id: string; node: React.ReactNode }[]) =>
    items.map(item => <React.Fragment key={item.id}>{item.node}</React.Fragment>);

  return (
    <AppBar 
      position="fixed" 
      color="default"
      sx={{ 
        ...layoutStyles.appBar,
        backgroundColor: '#181b1f !important',
        backgroundImage: 'none !important', // Remove the Paper overlay that's covering our color
        '&.MuiAppBar-root': {
          backgroundColor: '#181b1f !important',
          backgroundImage: 'none !important',
        },
        '&.MuiAppBar-colorDefault': {
          backgroundColor: '#181b1f !important',
          backgroundImage: 'none !important',
        },
        borderLeft: sidebarDocked ? 'none' : layout.border, 
        borderRight: layout.border 
      }}>
      <Toolbar
        sx={{
          minHeight: `${layout.appBarHeight + 1}px !important`, // +2px for top and bottom borders
          maxHeight: `${layout.appBarHeight + 1}px !important`,
          height: `${layout.appBarHeight + 1}px !important`,
          borderTop: layout.border,
          borderBottom: layout.border,
          boxSizing: 'border-box',
          padding: '0px 0px',
          '&.MuiToolbar-root': {
            paddingLeft: sidebarDocked && !sidebarHidden ? '14px !important' : '24px !important',
            paddingRight: '8px !important',
          },
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {/* TowerIQ Logo as Menu Button */}
          <IconButton
            edge="start"
            color="inherit"
            aria-label="menu"
            onClick={onSidebarToggle}
            sx={{
              color: 'text.primary',
              display: sidebarDocked ? (sidebarHidden ? 'flex' : 'none') : 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '0px',
              borderRadius: '6px',
              height: 'auto',
              minHeight: 'auto',
              '&:hover': {
                backgroundColor: 'transparent !important', // Completely remove any hover background
              },
            }}
          >
            <TowerIQLogo 
              sx={{ 
                fontSize: 28,
                color: 'primary.main', // Use theme brand primary color
                filter: 'brightness(1.0) drop-shadow(0 0 0px transparent)', // Base state with no glow
                transition: 'filter 0.1s ease-in-out',
                display: 'flex',
                alignItems: 'center',
                verticalAlign: 'middle',
                '&:hover': {
                  filter: 'brightness(1.2) drop-shadow(0 0 2px var(--tiq-brand-primary)) drop-shadow(0 0 4px rgba(57, 181, 224, 0.6))',
                },
              }} 
            />
          </IconButton>

          <Breadcrumbs />
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SearchBar />
        </Box>
      </Toolbar>

      <Toolbar
        sx={{
          minHeight: `${layout.appBarHeight}px !important`, // +1px for bottom border
          maxHeight: `${layout.appBarHeight}px !important`,
          height: `${layout.appBarHeight}px !important`,
          borderBottom: layout.border,
          boxSizing: 'border-box',
          padding: '0px 0px',
          '&.MuiToolbar-root': {
            paddingLeft: '8px !important',
            paddingRight: '8px !important',
          },
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
          {secondaryLeft.length > 0 ? renderSecondaryItems(secondaryLeft) : null}
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          {secondaryRight.length > 0 ? renderSecondaryItems(secondaryRight) : null}
        </Box>
      </Toolbar>
    </AppBar>
  );
}
