/**
 * FridaServerControls.tsx - Frida server management component
 * 
 * Handles Frida server installation, start, stop, and status display
 */

import React from 'react';
import {
  Box,
  Button,
  Typography,
  CircularProgress,
  Alert,
} from '@mui/material';
import { Device, FridaStatus } from '../hooks/useBackend';

interface FridaServerControlsProps {
  selectedDevice: Device | null;
  fridaStatus: FridaStatus | null;
  fridaStatusLoading: boolean;
  fridaError: string | null;
  loading: boolean;
  onProvisionFrida: () => Promise<void>;
  onStartFrida: () => Promise<void>;
  onStopFrida: () => Promise<void>;
  onRemoveFrida: () => Promise<void>;
}

export function FridaServerControls({
  selectedDevice,
  fridaStatus,
  fridaStatusLoading,
  fridaError,
  loading,
  onProvisionFrida,
  onStartFrida,
  onStopFrida,
  onRemoveFrida
}: FridaServerControlsProps) {
  const getValue = (value: any, fallback: string = 'N/A') => {
    return value || fallback;
  };

  return (
    <>
      {/* Frida Server Status - Always show */}
      <Box sx={{ mb: 2 }}>
        {!selectedDevice ? (
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Server Status:</Typography>
              <Typography variant="body2" color="text.secondary">
                N/A
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Installation Status:</Typography>
              <Typography variant="body2" color="text.secondary">
                N/A
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Installed Version:</Typography>
              <Typography variant="body2" fontFamily="monospace">
                N/A
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Required Version:</Typography>
              <Typography variant="body2" fontFamily="monospace">
                N/A
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Architecture:</Typography>
              <Typography variant="body2">
                N/A
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Update Needed:</Typography>
              <Typography variant="body2" color="text.secondary">
                N/A
              </Typography>
            </Box>
          </Box>
        ) : fridaStatusLoading ? (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CircularProgress size={16} />
            <Typography variant="body2" color="text.secondary">Loading status...</Typography>
          </Box>
        ) : fridaStatus ? (
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Server Status:</Typography>
              <Typography variant="body2" color={fridaStatus.is_running ? 'success.main' : 'text.secondary'}>
                {fridaStatus.is_running ? 'Running' : 'Stopped'}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Installation Status:</Typography>
              <Typography variant="body2" color={fridaStatus.is_installed ? 'success.main' : 'text.secondary'}>
                {fridaStatus.is_installed ? 'Installed' : 'Not installed'}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Installed Version:</Typography>
              <Typography variant="body2" fontFamily="monospace">
                {getValue(fridaStatus.version)}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Required Version:</Typography>
              <Typography variant="body2" fontFamily="monospace">
                {getValue(fridaStatus.required_version)}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Architecture:</Typography>
              <Typography variant="body2">
                {getValue(fridaStatus.architecture)}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Update Needed:</Typography>
              <Typography variant="body2" color={fridaStatus.needs_update ? 'warning.main' : 'success.main'}>
                {fridaStatus.needs_update ? 'Yes' : 'No'}
              </Typography>
            </Box>
          </Box>
        ) : (
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Server Status:</Typography>
              <Typography variant="body2" color="error.main">
                Error
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Installation Status:</Typography>
              <Typography variant="body2" color="error.main">
                Error
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Installed Version:</Typography>
              <Typography variant="body2" fontFamily="monospace">
                Error
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Required Version:</Typography>
              <Typography variant="body2" fontFamily="monospace">
                Error
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Architecture:</Typography>
              <Typography variant="body2">
                Error
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.secondary">Update Needed:</Typography>
              <Typography variant="body2" color="error.main">
                Error
              </Typography>
            </Box>
          </Box>
        )}
      </Box>

      {/* Control Buttons */}
      <Box sx={{ display: 'flex', gap: 1, mb: 0, flexWrap: 'wrap' }}>
        <Box sx={{ position: 'relative' }}>
          <Button
            variant="outlined"
            size="small"
            onClick={onProvisionFrida}
            disabled={!selectedDevice || loading || (fridaStatus?.is_installed === true)}
            title={fridaStatus?.is_installed ? 'Frida server is already installed' : undefined}
            sx={{ minWidth: 160 }}
          >
            Install Frida Server
          </Button>
          {loading && (
            <CircularProgress size={16} sx={{ position: 'absolute', top: '50%', left: '50%', mt: '-8px', ml: '-8px' }} />
          )}
        </Box>
        
        <Box sx={{ position: 'relative' }}>
          <Button
            variant="outlined"
            size="small"
            onClick={onStartFrida}
            disabled={!selectedDevice || loading || !fridaStatus?.is_installed || fridaStatus?.is_running === true}
            title={
              !fridaStatus?.is_installed ? 'Frida server must be installed first' :
              fridaStatus?.is_running ? 'Frida server is already running' : undefined
            }
            sx={{ minWidth: 160 }}
          >
            Start Frida Server
          </Button>
          {loading && (
            <CircularProgress size={16} sx={{ position: 'absolute', top: '50%', left: '50%', mt: '-8px', ml: '-8px' }} />
          )}
        </Box>
        
        <Box sx={{ position: 'relative' }}>
          <Button
            variant="outlined"
            size="small"
            onClick={onStopFrida}
            disabled={!selectedDevice || loading || !fridaStatus?.is_running}
            title={!fridaStatus?.is_running ? 'Frida server is not running' : undefined}
            sx={{ minWidth: 160 }}
          >
            Stop Frida Server
          </Button>
          {loading && (
            <CircularProgress size={16} sx={{ position: 'absolute', top: '50%', left: '50%', mt: '-8px', ml: '-8px' }} />
          )}
        </Box>
        
        <Box sx={{ position: 'relative' }}>
          <Button
            variant="outlined"
            size="small"
            onClick={onRemoveFrida}
            disabled={!selectedDevice || loading || !fridaStatus?.is_installed}
            title={!fridaStatus?.is_installed ? 'Frida server is not installed' : undefined}
            sx={{ minWidth: 160 }}
          >
            Remove Frida Server
          </Button>
          {loading && (
            <CircularProgress size={16} sx={{ position: 'absolute', top: '50%', left: '50%', mt: '-8px', ml: '-8px' }} />
          )}
        </Box>
      </Box>

      {/* Error Display */}
      {fridaError && (
        <Alert severity="error" sx={{ mt: 2 }}>
          <Typography variant="body2">
            {fridaError}
          </Typography>
        </Alert>
      )}
    </>
  );
}
