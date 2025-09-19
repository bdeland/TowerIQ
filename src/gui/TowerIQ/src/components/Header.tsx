import React from 'react';
import { AppBar, Toolbar, Box, IconButton } from '@mui/material';
import { Menu as MenuIcon } from '@mui/icons-material';
import { Breadcrumbs } from './Breadcrumbs';
import { SearchBar } from './SearchBar';
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
    <AppBar position="fixed" sx={{ ...layoutStyles.appBar, backgroundColor: 'background.paper' }}>
      <Toolbar
        sx={{
          minHeight: `${layout.appBarHeight}px !important`,
          maxHeight: `${layout.appBarHeight}px !important`,
          borderTop: layout.border,
          borderBottom: layout.border,
          boxSizing: 'border-box',
          padding: '0 16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <IconButton
            edge="start"
            color="inherit"
            aria-label="menu"
            onClick={onSidebarToggle}
            sx={{
              color: 'text.primary',
              display: sidebarDocked ? (sidebarHidden ? 'block' : 'none') : 'block',
              '&:hover': {
                backgroundColor: 'action.hover',
              },
            }}
          >
            <MenuIcon />
          </IconButton>

          <Breadcrumbs />
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SearchBar />
        </Box>
      </Toolbar>

      <Toolbar
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: layout.border,
          boxSizing: 'border-box',
          minHeight: `${layout.appBarHeight}px !important`,
          maxHeight: `${layout.appBarHeight}px !important`,
          padding: '0px 16px 0 16px',
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
