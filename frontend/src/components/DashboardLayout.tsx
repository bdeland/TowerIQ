import React from 'react';
import { Box } from '@mui/material';

interface DashboardLayoutProps {
  children: React.ReactNode;
  fullscreen?: boolean;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({ 
  children, 
  fullscreen = false 
}) => {
  return (
    <Box
      sx={{
        width: '100%',
        height: fullscreen ? '100vh' : 'auto',
        display: 'flex',
        flexDirection: 'column',
        overflow: fullscreen ? 'hidden' : 'visible',
        backgroundColor: 'background.default',
        ...(fullscreen && {
          position: 'fixed',
          top: 0,
          left: 0,
          zIndex: 9999,
        })
      }}
    >
      {children}
    </Box>
  );
};
