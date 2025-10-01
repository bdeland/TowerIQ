import React from 'react';
import { Box, Typography } from '@mui/material';
import { useDeveloper } from '../contexts/DeveloperContext';

export const DashboardDebugPreview: React.FC = () => {
  const { debugBorderSettings } = useDeveloper();

  // Helper to get border style based on settings
  const getBorderStyle = (borderSetting: { enabled: boolean; color: string }) => {
    if (!borderSetting.enabled || borderSetting.color === 'off') {
      return {};
    }
    return {
      border: '1px solid',
      borderColor: borderSetting.color,
    };
  };

  // Grid cell style - no longer used for background
  const getGridCellBorderStyle = () => {
    if (!debugBorderSettings.gridCells.enabled || debugBorderSettings.gridCells.color === 'off') {
      return {};
    }
    return {
      border: '1px solid',
      borderColor: debugBorderSettings.gridCells.color,
    };
  };

  return (
    <Box
      sx={{
        width: '100%',
        aspectRatio: '16/9', // Fixed 16:9 aspect ratio
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 0,
        backgroundColor: 'background.default',
        overflow: 'hidden',
        position: 'relative',
        minWidth: 0, // Prevent overflow in narrow containers
      }}
    >
      {/* Header mimic - two stacked bars */}
      <Box>
        {/* First header bar */}
        <Box
          sx={{
            height: '50%',
            backgroundColor: '#181b1f',
            borderBottom: '1px solid',
            borderColor: 'divider',
            display: 'flex',
            alignItems: 'center',
            px: '3%',
          }}
        >
          <Box
            sx={{
              width: '5%',
              height: '60%',
              backgroundColor: 'primary.main',
              borderRadius: '2px',
              mr: '3%',
            }}
          />
          <Box
            sx={{
              height: '30%',
              width: '20%',
              backgroundColor: 'text.secondary',
              borderRadius: '2px',
              opacity: 0.3,
            }}
          />
        </Box>

        {/* Second header bar */}
        <Box
          sx={{
            height: '10%',
            backgroundColor: '#181b1f',
            borderBottom: '1px solid',
            borderColor: 'divider',
            display: 'flex',
            alignItems: 'center',
            px: '3%',
          }}
        >
          <Box
            sx={{
              height: '25%',
              width: '12%',
              backgroundColor: 'text.secondary',
              borderRadius: '2px',
              opacity: 0.3,
              mr: '3%',
            }}
          />
          <Box
            sx={{
              height: '25%',
              width: '10%',
              backgroundColor: 'text.secondary',
              borderRadius: '2px',
              opacity: 0.3,
            }}
          />
        </Box>
      </Box>

      {/* Grid container area */}
      <Box
        sx={{
          flex: 1,
          height: '78%', // Remaining space after headers (100% - 12% - 10% = 78%)
          position: 'relative',
          backgroundColor: 'background.paper',
          ...getBorderStyle(debugBorderSettings.gridContainer),
          padding: '3%',
          display: 'grid',
          gridTemplateColumns: 'repeat(12, 1fr)',
          gridTemplateRows: 'repeat(6, 1fr)',
          gap: '2%',
        }}
      >
        {/* Render individual grid cells */}
        {Array.from({ length: 72 }, (_, index) => {
          const col = (index % 12) + 1;
          const row = Math.floor(index / 12) + 1;
          
          // Panel occupies cells 1-6 on rows 1-4
          const isPanelCell = col >= 1 && col <= 6 && row >= 1 && row <= 4;
          
          if (isPanelCell && col === 1 && row === 1) {
            // Render the panel spanning multiple cells
            return (
              <Box
                key={`panel-${index}`}
                sx={{
                  gridColumn: '1 / 7', // Span columns 1-6
                  gridRow: '1 / 5',    // Span rows 1-4
                  backgroundColor: 'background.paper',
                  borderRadius: 0.5,
                  display: 'flex',
                  flexDirection: 'column',
                  overflow: 'hidden',
                  ...getBorderStyle(debugBorderSettings.panels),
                }}
              >
                {/* Panel header */}
                <Box
                  sx={{
                    height: '20%',
                    backgroundColor: 'background.paper',
                    borderBottom: '1px solid',
                    borderColor: 'divider',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    px: '5%',
                  }}
                >
                  <Typography variant="caption" sx={{ fontWeight: 500, fontSize: '0.65rem' }}>
                    Sample Panel
                  </Typography>
                  <Box sx={{ display: 'flex', gap: '3%' }}>
                    <Box
                      sx={{
                        width: '6px',
                        height: '6px',
                        backgroundColor: 'text.secondary',
                        borderRadius: '50%',
                        opacity: 0.5,
                      }}
                    />
                    <Box
                      sx={{
                        width: '6px',
                        height: '6px',
                        backgroundColor: 'text.secondary',
                        borderRadius: '50%',
                        opacity: 0.5,
                      }}
                    />
                  </Box>
                </Box>

                {/* Panel content area */}
                <Box
                  sx={{
                    flex: 1,
                    p: '5%',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'flex-end',
                  }}
                >
                  {/* Mock chart bars */}
                  <Box sx={{ display: 'flex', alignItems: 'end', gap: '3%', height: '60%' }}>
                    {[0.8, 0.4, 0.7, 0.3, 0.6].map((height, barIndex) => (
                      <Box
                        key={barIndex}
                        sx={{
                          flex: 1,
                          height: `${height * 100}%`,
                          backgroundColor: 'primary.main',
                          opacity: 0.7,
                          borderRadius: '1px',
                        }}
                      />
                    ))}
                  </Box>
                </Box>
              </Box>
            );
          } else if (isPanelCell) {
            // Skip other cells that are part of the panel
            return null;
          } else {
            // Render empty grid cell
            return (
              <Box
                key={`cell-${index}`}
                sx={{
                  backgroundColor: 'transparent',
                  borderRadius: 0.5,
                  ...getGridCellBorderStyle(),
                  opacity: 0.3,
                }}
              />
            );
          }
        })}

        {/* Additional visual indicator for empty area */}
        <Box
          sx={{
            gridColumn: '8 / 10',
            gridRow: '1 / 3',
            border: '1px dashed',
            borderColor: 'divider',
            borderRadius: 1,
            display: { xs: 'none', sm: 'flex' },
            alignItems: 'center',
            justifyContent: 'center',
            opacity: 0.3,
          }}
        >
          <Typography variant="caption" sx={{ fontSize: '0.45rem', color: 'text.secondary' }}>
            Empty
          </Typography>
        </Box>
      </Box>
    </Box>
  );
};
