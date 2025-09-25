import React from 'react';
import { Box, styled, keyframes } from '@mui/material';

// Wave animation keyframes for skeleton loading effect
const waveAnimation = keyframes`
  0% {
    transform: translateX(-100%);
  }
  50% {
    transform: translateX(100%);
  }
  100% {
    transform: translateX(100%);
  }
`;

// Bar height animation keyframes for simple oscillation
const barHeightAnimation = keyframes`
  0% {
    transform: scaleY(0.1);
  }
  50% {
    transform: scaleY(0.9);
  }
  100% {
    transform: scaleY(0.1);
  }
`;

// Base skeleton element with wave animation
const SkeletonElement = styled(Box)(({ theme }) => ({
  backgroundColor: 'rgba(255, 255, 255, 0.1)',
  borderRadius: '4px',
  position: 'relative',
  overflow: 'hidden',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    background: `linear-gradient(
      90deg,
      transparent,
      rgba(255, 255, 255, 0.2),
      transparent
    )`,
    animation: `${waveAnimation} 2s infinite`,
  },
}));

// Chart type definitions
export type ChartType = 'bar' | 'line' | 'pie' | 'timeseries' | 'calendar' | 'treemap' | 'stat' | 'table' | 'ridgeline';

interface ChartSkeletonProps {
  type: ChartType;
  width?: string | number;
  height?: string | number;
  // Bar chart specific animation props
  animationDuration?: number;
  waveOffset?: number;
  skeletonDelay?: number;
  barCount?: number;
  minHeight?: number;
  maxHeight?: number;
}


// Bar Chart Skeleton - vertical bars with CSS-animated heights
interface BarChartSkeletonProps {
  width?: string | number;
  height?: string | number;
  animationDuration?: number; // total animation duration in seconds
  waveOffset?: number; // offset between bars for wave effect (in seconds)
  skeletonDelay?: number; // delay for skeleton wave effect (in seconds)
  barCount?: number;
  minHeight?: number; // minimum bar height percentage
  maxHeight?: number; // maximum bar height percentage
}

//TODO: format skeletons to be responsive and fit the container/panel size

const BarChartSkeleton: React.FC<BarChartSkeletonProps> = ({ 
  width = '100%', 
  height = '100%',
  animationDuration = 1.25, // 1.25 seconds default
  waveOffset = 0.15, // 0.15 seconds offset between bars
  skeletonDelay = 0.15, // 0 seconds default for skeleton wave
  barCount = 8,
  minHeight = 20,
  maxHeight = 90
}) => {
  return (
    <Box
      sx={{
        width,
        height,
        display: 'flex',
        alignItems: 'flex-end',
        gap: '8px',
        padding: '18px',
        justifyContent: 'space-around',
      }}
    >
      {Array.from({ length: barCount }).map((_, index) => {
        // Calculate wave offset for this bar - each bar starts its animation later
        const barDelay = index * waveOffset;
        
        return (
          <SkeletonElement
            key={index}
            sx={{
              width: '100%',
              height: `${(maxHeight - minHeight) + minHeight}%`,
              minHeight: '20px',
              transformOrigin: 'bottom',
              animation: `${barHeightAnimation} ${animationDuration}s ease-in-out infinite`,
              animationDelay: `${barDelay}s`,
              willChange: 'transform',
              '&::before': {
                animationDelay: `${skeletonDelay + index * waveOffset}s`,
              },
            }}
          />
        );
      })}
    </Box>
  );
};

// Line Chart Skeleton - connected line segments
const LineChartSkeleton: React.FC<{ width?: string | number; height?: string | number }> = ({ 
  width = '100%', 
  height = '100%' 
}) => {
  const points = [
    { x: 10, y: 90 },
    { x: 20, y: 80 },
    { x: 30, y: 70 },
    { x: 40, y: 60 },
    { x: 50, y: 50 },
    { x: 60, y: 40 },
    { x: 70, y: 30 },
    { x: 80, y: 20 },
    { x: 90, y: 10 },
  ];

  return (
    <Box
      sx={{
        width,
        height,
        position: 'relative',
        padding: '20px',
      }}
    >
      {/* Connected line through all points */}
      <Box
        sx={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            background: `linear-gradient(
              90deg,
              transparent,
              rgba(255, 255, 255, 0.2),
              transparent
            )`,
            animation: `${waveAnimation} 2s infinite`,
            clipPath: `polygon(${points.map((point, index) => 
              `${point.x}% ${point.y}%`
            ).join(', ')})`,
          },
        }}
      />
      
      {/* Data points */}
      {points.map((point, index) => (
        <SkeletonElement
          key={index}
          sx={{
            position: 'absolute',
            left: `${point.x}%`,
            top: `${point.y}%`,
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            animationDelay: `${index * 0.1}s`,
            transform: 'translate(-50%, -50%)',
          }}
        />
      ))}
    </Box>
  );
};

// Pie Chart Skeleton - circular segments
const PieChartSkeleton: React.FC<{ width?: string | number; height?: string | number }> = ({ 
  width = '100%', 
  height = '100%' 
}) => (
  <Box
    sx={{
      width,
      height,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      position: 'relative',
    }}
  >
    <Box
      sx={{
        width: '150px',
        height: '150px',
        borderRadius: '50%',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {[
        { start: 0, size: 25 },
        { start: 25, size: 35 },
        { start: 60, size: 20 },
        { start: 80, size: 20 },
      ].map((segment, index) => (
        <SkeletonElement
          key={index}
          sx={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            clipPath: `polygon(50% 50%, ${50 + 50 * Math.cos((segment.start / 100) * 2 * Math.PI - Math.PI / 2)}% ${50 + 50 * Math.sin((segment.start / 100) * 2 * Math.PI - Math.PI / 2)}%, ${50 + 50 * Math.cos(((segment.start + segment.size) / 100) * 2 * Math.PI - Math.PI / 2)}% ${50 + 50 * Math.sin(((segment.start + segment.size) / 100) * 2 * Math.PI - Math.PI / 2)}%)`,
            animationDelay: `${index * 0.2}s`,
          }}
        />
      ))}
    </Box>
  </Box>
);

// Timeseries Skeleton - similar to line but with time axis indicators
const TimeseriesSkeleton: React.FC<{ width?: string | number; height?: string | number }> = ({ 
  width = '100%', 
  height = '100%' 
}) => (
  <Box
    sx={{
      width,
      height,
      position: 'relative',
      padding: '20px',
    }}
  >
    {/* Time axis indicators */}
    {Array.from({ length: 6 }).map((_, index) => (
      <SkeletonElement
        key={`axis-${index}`}
        sx={{
          position: 'absolute',
          left: `${15 + index * 14}%`,
          bottom: '10px',
          width: '30px',
          height: '8px',
          animationDelay: `${index * 0.1}s`,
        }}
      />
    ))}
    
    {/* Data line */}
    <Box
      sx={{
        position: 'absolute',
        top: '20px',
        left: '20px',
        right: '20px',
        bottom: '40px',
      }}
    >
      {[
        { x: 0, y: 60 },
        { x: 16, y: 40 },
        { x: 32, y: 75 },
        { x: 48, y: 30 },
        { x: 64, y: 85 },
        { x: 80, y: 50 },
        { x: 96, y: 70 },
      ].map((point, index) => (
        <SkeletonElement
          key={index}
          sx={{
            position: 'absolute',
            left: `${point.x}%`,
            top: `${point.y}%`,
            width: '6px',
            height: '6px',
            borderRadius: '50%',
            animationDelay: `${index * 0.1}s`,
          }}
        />
      ))}
    </Box>
  </Box>
);

// Calendar Skeleton - grid of calendar cells
const CalendarSkeleton: React.FC<{ width?: string | number; height?: string | number }> = ({ 
  width = '100%', 
  height = '100%' 
}) => (
  <Box
    sx={{
      width,
      height,
      padding: '20px',
    }}
  >
    {/* Month header */}
    <SkeletonElement
      sx={{
        width: '150px',
        height: '20px',
        marginBottom: '20px',
        marginLeft: 'auto',
        marginRight: 'auto',
      }}
    />
    
    {/* Calendar grid */}
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: 'repeat(7, 1fr)',
        gap: '4px',
        maxWidth: '300px',
        margin: '0 auto',
      }}
    >
      {Array.from({ length: 35 }).map((_, index) => (
        <SkeletonElement
          key={index}
          sx={{
            width: '30px',
            height: '30px',
            animationDelay: `${(index % 7) * 0.05}s`,
          }}
        />
      ))}
    </Box>
  </Box>
);

// Treemap Skeleton - rectangular blocks of varying sizes
const TreemapSkeleton: React.FC<{ width?: string | number; height?: string | number }> = ({ 
  width = '100%', 
  height = '100%' 
}) => (
  <Box
    sx={{
      width,
      height,
      display: 'grid',
      gridTemplateColumns: 'repeat(4, 1fr)',
      gridTemplateRows: 'repeat(3, 1fr)',
      gap: '4px',
      padding: '20px',
    }}
  >
    <SkeletonElement sx={{ gridColumn: '1 / 3', gridRow: '1 / 3', animationDelay: '0s' }} />
    <SkeletonElement sx={{ gridColumn: '3 / 5', gridRow: '1', animationDelay: '0.1s' }} />
    <SkeletonElement sx={{ gridColumn: '3', gridRow: '2', animationDelay: '0.2s' }} />
    <SkeletonElement sx={{ gridColumn: '4', gridRow: '2', animationDelay: '0.3s' }} />
    <SkeletonElement sx={{ gridColumn: '1', gridRow: '3', animationDelay: '0.4s' }} />
    <SkeletonElement sx={{ gridColumn: '2 / 4', gridRow: '3', animationDelay: '0.5s' }} />
    <SkeletonElement sx={{ gridColumn: '4', gridRow: '3', animationDelay: '0.6s' }} />
  </Box>
);

// Stat Skeleton - large number with label
const StatSkeleton: React.FC<{ width?: string | number; height?: string | number }> = ({ 
  width = '100%', 
  height = '100%' 
}) => (
  <Box
    sx={{
      width,
      height,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '16px',
      padding: '20px',
    }}
  >
    {/* Large stat number */}
    <SkeletonElement
      sx={{
        width: '120px',
        height: '40px',
        animationDelay: '0s',
      }}
    />
    
    {/* Stat label */}
    <SkeletonElement
      sx={{
        width: '80px',
        height: '16px',
        animationDelay: '0.2s',
      }}
    />
    
    {/* Optional trend indicator */}
    <SkeletonElement
      sx={{
        width: '60px',
        height: '12px',
        animationDelay: '0.4s',
      }}
    />
  </Box>
);

// Table Skeleton - rows and columns
const TableSkeleton: React.FC<{ width?: string | number; height?: string | number }> = ({ 
  width = '100%', 
  height = '100%' 
}) => (
  <Box
    sx={{
      width,
      height,
      padding: '20px',
    }}
  >
    {/* Table header */}
    <Box
      sx={{
        display: 'flex',
        gap: '12px',
        marginBottom: '16px',
      }}
    >
      {[120, 80, 100, 90].map((width, index) => (
        <SkeletonElement
          key={`header-${index}`}
          sx={{
            width: `${width}px`,
            height: '20px',
            animationDelay: `${index * 0.1}s`,
          }}
        />
      ))}
    </Box>
    
    {/* Table rows */}
    {Array.from({ length: 5 }).map((_, rowIndex) => (
      <Box
        key={`row-${rowIndex}`}
        sx={{
          display: 'flex',
          gap: '12px',
          marginBottom: '12px',
        }}
      >
        {[120, 80, 100, 90].map((width, colIndex) => (
          <SkeletonElement
            key={`cell-${rowIndex}-${colIndex}`}
            sx={{
              width: `${width}px`,
              height: '16px',
              animationDelay: `${(rowIndex * 4 + colIndex) * 0.05}s`,
            }}
          />
        ))}
      </Box>
    ))}
  </Box>
);

// Ridgeline Skeleton - multiple stacked line plots
const RidgelineSkeleton: React.FC<{ width?: string | number; height?: string | number }> = ({ 
  width = '100%', 
  height = '100%' 
}) => (
  <Box
    sx={{
      width,
      height,
      padding: '20px',
      display: 'flex',
      flexDirection: 'column',
      gap: '8px',
    }}
  >
    {/* Multiple ridge lines stacked vertically */}
    {Array.from({ length: 6 }).map((_, ridgeIndex) => (
      <Box
        key={`ridge-${ridgeIndex}`}
        sx={{
          flex: 1,
          display: 'flex',
          alignItems: 'flex-end',
          gap: '2px',
          opacity: 0.8 - ridgeIndex * 0.1, // Fade out lower ridges
        }}
      >
        {/* Individual data points creating a ridge line */}
        {Array.from({ length: 20 }).map((_, pointIndex) => {
          // Create a wave-like pattern for each ridge
          const baseHeight = Math.sin((pointIndex / 20) * Math.PI * 2) * 0.5 + 0.5;
          const ridgeHeight = baseHeight * (0.8 - ridgeIndex * 0.1);
          return (
            <SkeletonElement
              key={`point-${ridgeIndex}-${pointIndex}`}
              sx={{
                width: '4px',
                height: `${Math.max(ridgeHeight * 100, 10)}%`,
                borderRadius: '2px',
                animationDelay: `${(ridgeIndex * 0.2 + pointIndex * 0.05)}s`,
                transform: `translateY(${ridgeIndex * 10}px)`, // Offset each ridge
              }}
            />
          );
        })}
      </Box>
    ))}
  </Box>
);

// Main ChartSkeleton component that renders the appropriate skeleton based on type
export const ChartSkeleton: React.FC<ChartSkeletonProps> = ({ 
  type, 
  width = '100%', 
  height = '100%',
  animationDuration,
  waveOffset,
  skeletonDelay,
  barCount,
  minHeight,
  maxHeight
}) => {
  const renderSkeleton = () => {
    switch (type) {
      case 'bar':
        return (
          <BarChartSkeleton 
            width={width} 
            height={height}
            animationDuration={animationDuration}
            waveOffset={waveOffset}
            skeletonDelay={skeletonDelay}
            barCount={barCount}
            minHeight={minHeight}
            maxHeight={maxHeight}
          />
        );
      case 'line':
        return <LineChartSkeleton width={width} height={height} />;
      case 'pie':
        return <PieChartSkeleton width={width} height={height} />;
      case 'timeseries':
        return <TimeseriesSkeleton width={width} height={height} />;
      case 'calendar':
        return <CalendarSkeleton width={width} height={height} />;
      case 'treemap':
        return <TreemapSkeleton width={width} height={height} />;
      case 'stat':
        return <StatSkeleton width={width} height={height} />;
      case 'table':
        return <TableSkeleton width={width} height={height} />;
      case 'ridgeline':
        return <RidgelineSkeleton width={width} height={height} />;
      default:
        return (
          <BarChartSkeleton 
            width={width} 
            height={height}
            animationDuration={animationDuration}
            waveOffset={waveOffset}
            skeletonDelay={skeletonDelay}
            barCount={barCount}
            minHeight={minHeight}
            maxHeight={maxHeight}
          />
        );
    }
  };

  return (
    <Box
      sx={{
        width,
        height,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'transparent',
        overflow: 'hidden',
      }}
    >
      {renderSkeleton()}
    </Box>
  );
};

export default ChartSkeleton;
