import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Button,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  CircularProgress,
  Box,
  Tooltip,
  LinearProgress,
  Typography,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ArrowDropDown as ArrowDropDownIcon,
} from '@mui/icons-material';
import { colors } from '../theme/toweriqTheme';
import { formatTimeRemaining } from '../utils/formattingUtils';

export interface RefreshInterval {
  label: string;
  value: string;
  seconds?: number;
}

const REFRESH_INTERVALS: RefreshInterval[] = [
  { label: 'Off', value: 'off' },
  { label: 'Auto', value: 'auto' },
  { label: '1s', value: '1s', seconds: 1 },
  { label: '5s', value: '5s', seconds: 5 },
  { label: '10s', value: '10s', seconds: 10 },
  { label: '30s', value: '30s', seconds: 30 },
  { label: '1m', value: '1m', seconds: 60 },
  { label: '5m', value: '5m', seconds: 300 },
  { label: '15m', value: '15m', seconds: 900 },
  { label: '30m', value: '30m', seconds: 1800 },
  { label: '1h', value: '1h', seconds: 3600 },
  { label: '2h', value: '2h', seconds: 7200 },
  { label: '1d', value: '1d', seconds: 86400 },
];

interface RefreshButtonProps {
  onRefresh: () => void;
  onIntervalChange: (interval: RefreshInterval) => void;
  isRefreshing?: boolean;
  currentInterval?: RefreshInterval;
}

export function RefreshButton({
  onRefresh,
  onIntervalChange,
  isRefreshing = false,
  currentInterval = REFRESH_INTERVALS[0], // Default to 'Off'
}: RefreshButtonProps) {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [interval, setInterval] = useState<RefreshInterval>(currentInterval);
  const [lastRefreshTime, setLastRefreshTime] = useState<Date | null>(null);
  const [progress, setProgress] = useState<number>(0);
  const [isHovered, setIsHovered] = useState<boolean>(false);
  const intervalTimerRef = useRef<number | null>(null);
  const progressTimerRef = useRef<number | null>(null);

  const open = Boolean(anchorEl);

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleIntervalSelect = (selectedInterval: RefreshInterval) => {
    setInterval(selectedInterval);
    onIntervalChange(selectedInterval);
    handleClose();
  };

  const handleRefreshClick = () => {
    setLastRefreshTime(new Date());
    onRefresh();
  };

  const handleMouseEnter = () => {
    setIsHovered(true);
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
  };


  // Set up interval timer when interval changes
  useEffect(() => {
    // Clear existing timer
    if (intervalTimerRef.current) {
      window.clearInterval(intervalTimerRef.current);
      intervalTimerRef.current = null;
    }

    // Set up new timer if interval is not 'off' or 'auto'
    if (interval.value !== 'off' && interval.value !== 'auto' && interval.seconds) {
      const timer = window.setInterval(() => {
        setLastRefreshTime(new Date());
        onRefresh();
      }, interval.seconds * 1000);
      intervalTimerRef.current = timer;
    }

    // Cleanup on unmount
    return () => {
      if (intervalTimerRef.current) {
        window.clearInterval(intervalTimerRef.current);
        intervalTimerRef.current = null;
      }
    };
  }, [interval, onRefresh]);

  // Progress tracking effect
  useEffect(() => {
    // Clear existing progress timer
    if (progressTimerRef.current) {
      window.clearInterval(progressTimerRef.current);
      progressTimerRef.current = null;
    }

    // Set up progress timer if we have an active interval and last refresh time
    if (interval.value !== 'off' && interval.value !== 'auto' && interval.seconds && lastRefreshTime) {
      const updateProgress = () => {
        const now = new Date();
        const elapsed = (now.getTime() - lastRefreshTime.getTime()) / 1000;
        const progressPercent = Math.min((elapsed / interval.seconds!) * 100, 100);
        setProgress(progressPercent);
      };

      // Update immediately
      updateProgress();

      // Update every 100ms for smooth animation
      const timer = window.setInterval(updateProgress, 100);
      progressTimerRef.current = timer;
    } else {
      setProgress(0);
    }

    // Cleanup on unmount
    return () => {
      if (progressTimerRef.current) {
        window.clearInterval(progressTimerRef.current);
        progressTimerRef.current = null;
      }
    };
  }, [interval, lastRefreshTime]);

  // Tooltip content
  const getTooltipContent = () => {
    if (interval.value === 'off') {
      return (
        <Box sx={{ p: 1 }}>
          <Typography variant="caption" sx={{ color: colors.text.primary }}>
            Auto-refresh is disabled
          </Typography>
        </Box>
      );
    }

    if (interval.value === 'auto') {
      return (
        <Box sx={{ p: 1 }}>
          <Typography variant="caption" sx={{ color: colors.text.primary }}>
            Auto-refresh interval is automatic
          </Typography>
        </Box>
      );
    }

    if (!lastRefreshTime || !interval.seconds) {
      return (
        <Box sx={{ p: 1 }}>
          <Typography variant="caption" sx={{ color: colors.text.primary }}>
            No refresh data available
          </Typography>
        </Box>
      );
    }

    const now = new Date();
    const nextUpdate = new Date(lastRefreshTime.getTime() + interval.seconds * 1000);
    const timeUntilNext = Math.max(0, Math.ceil((nextUpdate.getTime() - now.getTime()) / 1000));

    return (
      <Box sx={{ p: 1, minWidth: '200px' }}>
        <Typography variant="caption" sx={{ color: colors.text.primary, display: 'block', mb: 1 }}>
          Last updated: {lastRefreshTime.toLocaleTimeString()}
        </Typography>
        <Typography variant="caption" sx={{ color: colors.text.primary, display: 'block', mb: 1 }}>
          Next update: {nextUpdate.toLocaleTimeString()}
        </Typography>
        <Typography variant="caption" sx={{ color: colors.text.primary, display: 'block', mb: 1 }}>
          Time remaining: {formatTimeRemaining(timeUntilNext)}
        </Typography>
        <LinearProgress
          variant="determinate"
          value={progress}
          sx={{
            height: 4,
            borderRadius: 2,
            backgroundColor: colors.borders.primary,
            '& .MuiLinearProgress-bar': {
              backgroundColor: colors.brand.primary,
              transition: 'transform 0.1s linear',
            },
          }}
        />
      </Box>
    );
  };

  return (
    <Box 
      sx={{ 
        display: 'flex', 
        alignItems: 'center',
        position: 'relative',
        '&::after': {
          content: '""',
          position: 'absolute',
          bottom: 0,
          left: 0,
          height: '2px',
          width: `${progress}%`,
          backgroundColor: colors.brand.primary,
          transition: 'width 0.1s linear, opacity 0.2s ease',
          opacity: !isHovered && interval.value !== 'off' && interval.value !== 'auto' && lastRefreshTime ? 1 : 0,
          zIndex: 1,
        }
      }}
    >
      <Tooltip
        title={getTooltipContent()}
        placement="bottom-end"
        onOpen={handleMouseEnter}
        onClose={handleMouseLeave}
        componentsProps={{
          tooltip: {
            sx: {
              backgroundColor: colors.backgrounds.elevated,
              border: `1px solid ${colors.borders.primary}`,
              borderRadius: '0 0 4px 4px',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
              marginTop: '0px !important',
              marginBottom: '0px !important',
            },
          },
          popper: {
            sx: {
              '& .MuiTooltip-tooltip': {
                marginTop: '0px !important',
                marginBottom: '0px !important',
              },
            },
          },
        }}
      >
        <Button
         variant="outlined"
         size="small"
         onClick={handleRefreshClick}
         disabled={isRefreshing}
         sx={{
           color: colors.text.primary,
           borderColor: colors.borders.primary,
           height: '30px',
           minWidth: '30px', // Square button for icon only
           padding: '0px',
           borderRadius: '2px 0 0 2px',
           borderRight: `1px solid ${colors.borders.primary}`,
           opacity: isRefreshing ? 0.5 : 1,
           transition: 'opacity 0.2s ease',
           '&:hover': {
             borderColor: colors.borders.interactive,
             backgroundColor: colors.action.hover,
           },
           '&:disabled': {
             opacity: 0.5,
             '&:hover': {
               borderColor: colors.borders.primary,
               backgroundColor: 'transparent',
             },
           },
         }}
       >
         <RefreshIcon sx={{ fontSize: '16px' }} />
       </Button>
      </Tooltip>
      
      <Button
         variant="outlined"
         size="small"
         endIcon={<ArrowDropDownIcon sx={{ fontSize: '16px' }} />}
         onClick={handleClick}
         sx={{
           color: colors.text.primary,
           borderColor: colors.borders.primary,
           height: '30px',
           minWidth: '64px',
           width: '64px',
           padding: '0px 8px',
           borderRadius: '0 2px 2px 0',
           borderLeft: 'none',
           justifyContent: 'space-between',
           '& .MuiButton-endIcon': {
             marginLeft: 'auto',
             marginRight: '0px',
           },
           '&:hover': {
             borderColor: colors.borders.interactive,
             backgroundColor: colors.action.hover,
           },
         }}
       >
         {interval.label}
       </Button>

       <Menu
         anchorEl={anchorEl}
         open={open}
         onClose={handleClose}
         PaperProps={{
           sx: {
             backgroundColor: colors.backgrounds.elevated,
             border: `1px solid ${colors.borders.primary}`,
             minWidth: '60px',
             borderRadius: '0 0px 2px 2px',
           },
         }}
         transformOrigin={{ horizontal: 'right', vertical: 'top' }}
         anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
       >
         {REFRESH_INTERVALS.map((option) => (
           <MenuItem
             key={option.value}
             onClick={() => handleIntervalSelect(option)}
             selected={option.value === interval.value}
             sx={{
               color: colors.text.primary,
               fontSize: '0.75rem',
               minHeight: '32px',
               py: 0.5,
               px: 1,
               '&:hover': {
                 backgroundColor: colors.action.hover,
               },
               '&.Mui-selected': {
                 backgroundColor: colors.action.selected,
                 '&:hover': {
                   backgroundColor: colors.action.brandHover,
                 },
               },
             }}
           >
             <ListItemText primary={option.label} />
           </MenuItem>
         ))}
      </Menu>
    </Box>
  );
}
