import { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  Alert,
  CircularProgress,
  IconButton,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Schedule as ScheduleIcon,
  Code as CodeIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';

interface ScriptStatus {
  is_active: boolean;
  last_heartbeat?: string;
  heartbeat_interval_seconds: number;
  is_game_reachable: boolean;
  script_name?: string;
  injection_time?: string;
  error_count: number;
  last_error?: string;
}

interface ScriptStatusWidgetProps {
  scriptStatus?: ScriptStatus | null;
  isLoading?: boolean;
  onRefresh?: () => void;
}

export function ScriptStatusWidget({ scriptStatus, isLoading = false, onRefresh }: ScriptStatusWidgetProps) {
  const [timeSinceHeartbeat, setTimeSinceHeartbeat] = useState<number>(0);

  // Update time since last heartbeat every second
  useEffect(() => {
    if (!scriptStatus?.last_heartbeat) {
      setTimeSinceHeartbeat(0);
      return;
    }

    const updateTime = () => {
      const lastHeartbeat = new Date(scriptStatus.last_heartbeat!);
      const now = new Date();
      const diffMs = now.getTime() - lastHeartbeat.getTime();
      setTimeSinceHeartbeat(Math.floor(diffMs / 1000));
    };

    updateTime(); // Initial calculation
    const interval = setInterval(updateTime, 1000);

    return () => clearInterval(interval);
  }, [scriptStatus?.last_heartbeat]);

  const formatTimeSince = (seconds: number): string => {
    if (seconds < 60) {
      return `${seconds}s ago`;
    } else if (seconds < 3600) {
      const minutes = Math.floor(seconds / 60);
      return `${minutes}m ${seconds % 60}s ago`;
    } else {
      const hours = Math.floor(seconds / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      return `${hours}h ${minutes}m ago`;
    }
  };

  const isHealthy = (): boolean => {
    if (!scriptStatus?.is_active || !scriptStatus?.last_heartbeat) {
      return false;
    }
    
    // Consider unhealthy if no heartbeat for 3x the expected interval
    const timeoutSeconds = scriptStatus.heartbeat_interval_seconds * 3;
    return timeSinceHeartbeat <= timeoutSeconds;
  };

  const getStatusColor = (): 'success' | 'error' | 'warning' | 'default' => {
    if (!scriptStatus?.is_active) {
      return 'default';
    }
    
    if (isHealthy()) {
      return 'success';
    }
    
    // Check if it's been too long since last heartbeat
    const timeoutSeconds = scriptStatus.heartbeat_interval_seconds * 3;
    if (timeSinceHeartbeat > timeoutSeconds) {
      return 'error';
    }
    
    return 'warning';
  };

  const getStatusIcon = () => {
    if (!scriptStatus?.is_active) {
      return <CodeIcon />;
    }
    
    if (isHealthy()) {
      return <CheckCircleIcon />;
    }
    
    const timeoutSeconds = scriptStatus.heartbeat_interval_seconds * 3;
    if (timeSinceHeartbeat > timeoutSeconds) {
      return <ErrorIcon />;
    }
    
    return <WarningIcon />;
  };

  const getStatusText = (): string => {
    if (!scriptStatus?.is_active) {
      return 'Not Active';
    }
    
    if (isHealthy()) {
      return 'Active & Healthy';
    }
    
    const timeoutSeconds = scriptStatus.heartbeat_interval_seconds * 3;
    if (timeSinceHeartbeat > timeoutSeconds) {
      return 'Unhealthy - No Heartbeat';
    }
    
    return 'Warning - Late Heartbeat';
  };

  if (isLoading) {
    return (
      <Card variant="outlined">
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <CircularProgress size={20} />
            <Typography variant="h6">Script Status</Typography>
          </Box>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Loading script status...
          </Typography>
        </CardContent>
      </Card>
    );
  }

  if (!scriptStatus) {
    return (
      <Card variant="outlined">
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Script Status
          </Typography>
          <Alert severity="info">
            No script is currently active. Activate a hook script to see status information.
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card variant="outlined">
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          {getStatusIcon()}
          <Typography variant="h6">Script Status</Typography>
          <Chip
            label={getStatusText()}
            color={getStatusColor()}
            size="small"
          />
          {onRefresh && (
            <IconButton
              size="small"
              onClick={onRefresh}
              sx={{ ml: 'auto' }}
              title="Refresh status"
            >
              <RefreshIcon />
            </IconButton>
          )}
        </Box>

        {scriptStatus.is_active && (
          <>
            {/* Script Name */}
            {scriptStatus.script_name && (
              <Box sx={{ mb: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Script: {scriptStatus.script_name}
                </Typography>
              </Box>
            )}

            {/* Injection Time */}
            {scriptStatus.injection_time && (
              <Box sx={{ mb: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Injected: {new Date(scriptStatus.injection_time).toLocaleString()}
                </Typography>
              </Box>
            )}

            {/* Heartbeat Status */}
            <Box sx={{ mb: 1 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ScheduleIcon fontSize="small" color="action" />
                <Typography variant="body2" color="text.secondary">
                  Last Heartbeat: {scriptStatus.last_heartbeat ? formatTimeSince(timeSinceHeartbeat) : 'Never'}
                </Typography>
              </Box>
              <Typography variant="caption" color="text.secondary">
                Expected every {scriptStatus.heartbeat_interval_seconds} seconds
              </Typography>
            </Box>

            {/* Game Reachability */}
            <Box sx={{ mb: 1 }}>
              <Chip
                label={`Game: ${scriptStatus.is_game_reachable ? 'Reachable' : 'Not Reachable'}`}
                color={scriptStatus.is_game_reachable ? 'success' : 'error'}
                size="small"
                variant="outlined"
              />
            </Box>

            {/* Error Count */}
            {scriptStatus.error_count > 0 && (
              <Box sx={{ mb: 1 }}>
                <Typography variant="body2" color="error">
                  Errors: {scriptStatus.error_count}
                </Typography>
                {scriptStatus.last_error && (
                  <Typography variant="caption" color="error" display="block">
                    Last: {scriptStatus.last_error}
                  </Typography>
                )}
              </Box>
            )}

            {/* Health Status Alert */}
            {!isHealthy() && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  Script heartbeat is overdue. This may indicate the script has crashed or the game has closed.
                </Typography>
              </Alert>
            )}

            {/* Success Status Alert */}
            {isHealthy() && (
              <Alert severity="success" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  Script is running normally and receiving heartbeats.
                </Typography>
              </Alert>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
