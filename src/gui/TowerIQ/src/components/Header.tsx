import React from 'react';
import { AppBar, Toolbar, Box, IconButton } from '@mui/material';
import { Breadcrumbs } from './Breadcrumbs';
import { SearchBar } from './SearchBar';
import { TowerIQLogo } from './TowerIQLogo';
import { useHeaderToolbar } from '../contexts/HeaderToolbarContext';

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
    <AppBar position="fixed" sx={{ ...layoutStyles.appBar, backgroundColor: 'background.paper', borderLeft: sidebarDocked ? 'none' : layout.border, borderRight: layout.border }}>
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
                backgroundColor: 'rgba(255, 255, 255, 0.04)',
              },
            }}
          >
            <TowerIQLogo 
              sx={{ 
                fontSize: 28,
                color: '#39b5e0', // Use the blue color for brand consistency
                filter: 'brightness(1.1)', // Slightly brighten for better visibility
                transition: 'all 0.2s ease-in-out',
                display: 'flex',
                alignItems: 'center',
                verticalAlign: 'middle',
                '&:hover': {
                  filter: 'brightness(1.3)',
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
