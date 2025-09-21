/**
 * DeviceInformation.tsx - Device details display component
 * 
 * Shows detailed device specifications and system information
 */

import React from 'react';
import {
  Box,
  Typography,
} from '@mui/material';
import { Device } from '../hooks/useBackend';

interface DeviceInformationProps {
  selectedDevice: Device | null;
}

export function DeviceInformation({ selectedDevice }: DeviceInformationProps) {
  const getValue = (value: any, fallback: string = 'N/A') => {
    return value || fallback;
  };

  const getChipValue = (value: any, fallback: string = 'N/A') => {
    if (!selectedDevice) return fallback;
    return value || fallback;
  };

  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
        {/* Basic Device Info */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Device ID:</Typography>
          <Typography variant="body2" fontFamily="monospace">
            {getValue(selectedDevice?.id)}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Device Name:</Typography>
          <Typography variant="body2">
            {getValue(selectedDevice?.device_name || selectedDevice?.name)}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Brand:</Typography>
          <Typography variant="body2">
            {getValue(selectedDevice?.brand)}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Model:</Typography>
          <Typography variant="body2">
            {getValue(selectedDevice?.model)}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Device Type:</Typography>
          <Typography variant="body2">
            {selectedDevice ? (selectedDevice.type === 'emulator' ? 'Emulator' : 'Physical Device') : 'N/A'}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Connection Type:</Typography>
          <Typography variant="body2">
            {selectedDevice ? (selectedDevice.is_network_device ? 'Network' : 'USB') : 'N/A'}
          </Typography>
        </Box>
        
        {/* System Information */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Android Version:</Typography>
          <Typography variant="body2">
            {selectedDevice?.android_version && selectedDevice?.api_level 
              ? `${selectedDevice.android_version} (API ${selectedDevice.api_level})`
              : 'N/A'
            }
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Architecture:</Typography>
          <Typography variant="body2">
            {getValue(selectedDevice?.architecture)}
          </Typography>
        </Box>
        
        {/* Network Information - Always show, but with N/A when not applicable */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">IP Address:</Typography>
          <Typography variant="body2" fontFamily="monospace">
            {selectedDevice?.is_network_device ? getValue(selectedDevice?.ip_address) : 'N/A'}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Port:</Typography>
          <Typography variant="body2" fontFamily="monospace">
            {selectedDevice?.is_network_device ? getValue(selectedDevice?.port) : 'N/A'}
          </Typography>
        </Box>
        
        {/* Status Information */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Status:</Typography>
          <Typography variant="body2" color={selectedDevice && (selectedDevice.status === 'device' || selectedDevice.status === 'connected') ? 'success.main' : 'text.secondary'}>
            {selectedDevice ? selectedDevice.status.charAt(0).toUpperCase() + selectedDevice.status.slice(1) : 'N/A'}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">Serial:</Typography>
          <Typography variant="body2" fontFamily="monospace">
            {getValue(selectedDevice?.serial || selectedDevice?.id)}
          </Typography>
        </Box>
      </Box>
  );
}
