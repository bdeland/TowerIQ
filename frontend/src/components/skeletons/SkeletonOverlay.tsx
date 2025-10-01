import React, { useEffect, useState } from 'react';
import { Box, Fade } from '@mui/material';
import { ChartSkeleton, ChartType } from './ChartSkeleton';

interface SkeletonOverlayProps {
  isLoading: boolean;
  chartType: ChartType;
  width?: string | number;
  height?: string | number;
  children: React.ReactNode;
  fadeInDuration?: number;
  fadeOutDuration?: number;
  debounceDelay?: number;
}

/**
 * SkeletonOverlay component that provides smooth fade-in/fade-out transitions
 * for skeleton loading animations over chart content.
 * 
 * Features:
 * - Immediate fade-in when loading starts
 * - Debounced fade-out to prevent flashing during quick state changes
 * - Overlay positioning that doesn't affect layout
 * - Customizable transition durations
 */
export const SkeletonOverlay: React.FC<SkeletonOverlayProps> = ({
  isLoading,
  chartType,
  width = '100%',
  height = '100%',
  children,
  fadeInDuration = 300,
  fadeOutDuration = 300,
  debounceDelay = 100
}) => {
  const [showSkeleton, setShowSkeleton] = useState(false);
  const [debouncedLoading, setDebouncedLoading] = useState(false);

  // Handle loading state changes with debouncing for fade-out
  useEffect(() => {
    let timeoutId: number;

    if (isLoading) {
      // Immediate show when loading starts
      setShowSkeleton(true);
      setDebouncedLoading(true);
    } else {
      // Debounced hide when loading stops to prevent flashing
      timeoutId = window.setTimeout(() => {
        setDebouncedLoading(false);
      }, debounceDelay);
    }

    return () => {
      if (timeoutId) {
        window.clearTimeout(timeoutId);
      }
    };
  }, [isLoading, debounceDelay]);

  // Handle skeleton visibility after fade-out completes
  const handleFadeOutComplete = () => {
    if (!debouncedLoading) {
      setShowSkeleton(false);
    }
  };

  return (
    <Box
      sx={{
        position: 'relative',
        width,
        height,
        overflow: 'hidden',
      }}
    >
      {/* Main content */}
      <Box
        sx={{
          width: '100%',
          height: '100%',
          opacity: debouncedLoading ? 0 : 1,
          transition: `opacity ${debouncedLoading ? fadeInDuration : fadeOutDuration}ms ease-in-out`,
        }}
      >
        {children}
      </Box>

      {/* Skeleton overlay */}
      {showSkeleton && (
        <Fade
          in={debouncedLoading}
          timeout={{
            enter: fadeInDuration,
            exit: fadeOutDuration,
          }}
          onExited={handleFadeOutComplete}
        >
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              zIndex: 1000,
              pointerEvents: 'none', // Allow interactions with content when not loading
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <ChartSkeleton
              type={chartType}
              width="100%"
              height="100%"
            />
          </Box>
        </Fade>
      )}
    </Box>
  );
};

export default SkeletonOverlay;
