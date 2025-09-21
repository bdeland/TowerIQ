/**
 * connectionPageUtils.tsx - Utility functions for ConnectionPage
 * 
 * Contains constants, helper functions, and utility logic
 */

import React from 'react';
import { Box, Typography, List, ListItem } from '@mui/material';

// Application constants for auto-selection - these define the target game
export const TARGET_PROCESS_PACKAGE = 'com.TechTreeGames.TheTower';
export const TARGET_PROCESS_NAME = 'The Tower';

// Connection flow state type - defines the different states of the connection process
export type ConnectionFlowState = 'IDLE' | 'CONNECTING_DEVICE' | 'SEARCHING_PROCESS' | 'CONFIGURING_FRIDA' | 'STARTING_HOOK' | 'MONITORING_ACTIVE' | 'ERROR';

// Helper function for generating device status tooltip content
export const getDeviceStatusTooltip = (status: string) => {
  switch (status) {
    case 'unauthorized':
      return (
        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>Device Unauthorized</Typography>
          <Typography variant="body2">Your computer is not trusted. Please follow these steps:</Typography>
          <List dense sx={{ listStyleType: 'decimal', pl: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>Check your device for an "Allow USB debugging?" popup.</ListItem>
            <ListItem sx={{ display: 'list-item' }}>Accept the prompt (check "Always allow").</ListItem>
            <ListItem sx={{ display: 'list-item' }}>If you don't see it, unplug and reconnect the cable.</ListItem>
          </List>
        </Box>
      );
    case 'offline':
    case 'disconnected':
      return (
        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>Device Offline</Typography>
          <Typography variant="body2">The connection is unresponsive. Try the following:</Typography>
          <List dense sx={{ listStyleType: 'decimal', pl: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>Reboot your Android device.</ListItem>
            <ListItem sx={{ display: 'list-item' }}>Use a different USB cable and port.</ListItem>
            <ListItem sx={{ display: 'list-item' }}>Use the "Restart ADB Server" control below.</ListItem>
          </List>
        </Box>
      );
    case 'no permissions':
      return <Typography>Your system is blocking access to this USB device. (Linux/macOS issue)</Typography>;
    case 'device':
    case 'connected':
      return <Typography>Device is connected and ready.</Typography>;
    case 'error':
      return <Typography>Device connection error. Try restarting the ADB server.</Typography>;
    default:
      return <Typography>Status: {status}</Typography>;
  }
};
