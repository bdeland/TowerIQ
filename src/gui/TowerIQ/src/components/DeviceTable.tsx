/**
 * DeviceTable.tsx - Device selection table component
 * 
 * Handles device listing, selection, and status display
 */

import React from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Radio,
  Typography,
  Tooltip,
  Skeleton,
  CircularProgress,
  Box,
} from '@mui/material';
import {
  Smartphone as SmartphoneIcon,
} from '@mui/icons-material';
import { Device } from '../hooks/useBackend';

interface DeviceTableProps {
  devices: Device[];
  selectedDevice: Device | null;
  onDeviceSelection: (device: Device) => void;
  devicesLoading: boolean;
  isAdbRestarting: boolean;
  getDeviceStatusTooltip: (status: string) => React.ReactNode;
}

export function DeviceTable({
  devices,
  selectedDevice,
  onDeviceSelection,
  devicesLoading,
  isAdbRestarting,
  getDeviceStatusTooltip
}: DeviceTableProps) {
  return (
    <Table stickyHeader size="small">
        <TableHead>
          <TableRow>
            <TableCell>Select</TableCell>
            <TableCell>Device</TableCell>
            <TableCell>Model</TableCell>
            <TableCell>Android</TableCell>
            <TableCell>Type</TableCell>
            <TableCell>Status</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {/* Loading States */}
          {(devicesLoading || isAdbRestarting) ? (
            Array.from({ length: 3 }).map((_, index) => (
              <TableRow key={index}>
                <TableCell><Skeleton /></TableCell>
                <TableCell><Skeleton /></TableCell>
                <TableCell><Skeleton /></TableCell>
                <TableCell><Skeleton /></TableCell>
                <TableCell><Skeleton /></TableCell>
                <TableCell><Skeleton /></TableCell>
              </TableRow>
            ))
          ) : isAdbRestarting ? (
            <TableRow>
              <TableCell colSpan={6} align="center">
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
                  <CircularProgress size={16} />
                  <Typography variant="body2" color="text.secondary">
                    ADB server is rebooting... Please wait.
                  </Typography>
                </Box>
              </TableCell>
            </TableRow>
          ) : devices.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} align="center">
                <Typography variant="body2" color="text.secondary">
                  No devices found. Please ensure your device is connected and USB debugging is enabled.
                </Typography>
              </TableCell>
            </TableRow>
          ) : (
            /* Device Rows */
            devices.map((device) => (
              <TableRow 
                key={device.id}
                sx={{ 
                  backgroundColor: selectedDevice?.id === device.id ? 'action.selected' : 'inherit',
                  '&:hover': { backgroundColor: 'action.hover' }
                }}
              >
                <TableCell>
                  <Radio
                    checked={selectedDevice?.id === device.id}
                    onChange={() => onDeviceSelection(device)}
                    disabled={device.status !== 'device' && device.status !== 'connected'}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <SmartphoneIcon fontSize="small" />
                    <Typography variant="body2" fontFamily="monospace">
                      {device.id}
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  <Typography variant="body2">
                    {device.model || 'Unknown'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2">
                    {device.android_version} (API {device.api_level})
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color={device.type === 'emulator' ? 'secondary.main' : 'primary.main'}>
                    {device.type === 'emulator' ? 'Emulator' : 'Physical'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Tooltip title={getDeviceStatusTooltip(device.status)} arrow>
                    <Typography variant="body2" color={(device.status === 'device' || device.status === 'connected') ? 'success.main' : 'warning.main'}>
                      {device.status.charAt(0).toUpperCase() + device.status.slice(1)}
                    </Typography>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
  );
}
