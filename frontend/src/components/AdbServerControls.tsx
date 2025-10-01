/**
 * AdbServerControls.tsx - ADB server management component
 * 
 * Handles ADB server start, kill, restart operations and status display
 */

import React from 'react';
import {
  Box,
  Button,
  Typography,
} from '@mui/material';
import { AdbStatus } from '../hooks/useBackend';

interface AdbServerControlsProps {
  adbStatus: AdbStatus | null;
  isAdbRestarting: boolean;
  onStartAdbServer: () => Promise<void>;
  onKillAdbServer: () => Promise<void>;
  onRestartAdbServer: () => Promise<void>;
}

export function AdbServerControls({
  adbStatus,
  isAdbRestarting,
  onStartAdbServer,
  onKillAdbServer,
  onRestartAdbServer
}: AdbServerControlsProps) {
  return (
    <>
      {/* ADB Status Row */}
      <Box sx={{ mb: 1 }}>
        <Typography variant="subtitle2" sx={{ mb: 0.5 }}>ADB Server Status</Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Typography variant="body2" color={adbStatus?.running ? 'success.main' : 'text.secondary'}>
            {adbStatus?.running ? 'Running' : 'Stopped'}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {adbStatus?.version ? adbStatus.version : 'Version: Unknown'}
          </Typography>
        </Box>
      </Box>

      {/* Control Buttons */}
      <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
        <Button
          variant="outlined"
          size="small"
          onClick={onStartAdbServer}
          disabled={isAdbRestarting || adbStatus === null || adbStatus?.running === true}
        >
          Start ADB Server
        </Button>
        <Button
          variant="outlined"
          size="small"
          onClick={onKillAdbServer}
          disabled={isAdbRestarting || adbStatus === null || adbStatus?.running === false}
        >
          Kill ADB Server
        </Button>
        <Button
          variant="outlined"
          size="small"
          onClick={onRestartAdbServer}
          disabled={isAdbRestarting || adbStatus === null || adbStatus?.running === false}
        >
          Restart ADB Server
        </Button>
      </Box>
    </>
  );
}
