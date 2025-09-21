/**
 * SectionCard.tsx - Reusable card component for ConnectionPage sections
 * 
 * This component provides a consistent card layout for all sections on the ConnectionPage,
 * including a standardized header with title, info icon, refresh button, and flexible
 * additional header items, plus a content area for section-specific content.
 */

import React, { ReactNode } from 'react';
import {
  Box,
  Typography,
  IconButton,
  Tooltip,
  Divider,
} from '@mui/material';
import {
  InfoOutline as InfoOutlineIcon,
} from '@mui/icons-material';
import RefreshIcon from '@mui/icons-material/Refresh';

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================

interface SectionCardProps {
  // Required props
  title: string;
  children: ReactNode;
  
  // Optional props
  infoTooltip?: string | ReactNode;
  onRefresh?: () => void;
  refreshDisabled?: boolean;
  refreshSpinning?: boolean;
  additionalHeaderItems?: ReactNode;
  
  // Style customization
  sx?: object;
  contentSx?: object;
}

// ============================================================================
// COMPONENT
// ============================================================================

export function SectionCard({
  title,
  children,
  infoTooltip,
  onRefresh,
  refreshDisabled = false,
  refreshSpinning = false,
  additionalHeaderItems,
  sx = {},
  contentSx = {},
}: SectionCardProps) {
  return (
    <Box sx={{ 
      mb: 2,
      px: { xs: 1, sm: 2 },
      py: 2,
      borderRadius: 0.5,
      border: 1,
      borderColor: 'divider',
      backgroundColor: 'background.paper',
      ...sx
    }}>
      {/* CARD HEADER - Title, info icon, additional items, and refresh button */}
      <Box sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between', 
        mb: 2,
        px: 1,
      }}>
        {/* Left side - Title and info icon */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="h6" component="h2">
            {title}
          </Typography>
          {infoTooltip && (
            <Tooltip title={infoTooltip} arrow>
              <InfoOutlineIcon 
                sx={{ fontSize: "medium" }} 
                color="action" 
              />
            </Tooltip>
          )}
        </Box>
        
        {/* Right side - Additional header items and refresh button */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {additionalHeaderItems}
          {onRefresh && (
            <IconButton
              onClick={onRefresh}
              disabled={refreshDisabled}
              size="small"
            >
              <RefreshIcon 
                sx={{ 
                  transform: refreshSpinning ? 'rotate(360deg)' : 'rotate(0deg)',
                  transition: 'transform 0.6s cubic-bezier(0.4, 0, 0.2, 1)',
                }} 
              />
            </IconButton>
          )}
        </Box>
      </Box>
      
      {/* HORIZONTAL DIVIDER */}
      <Divider sx={{ mb: 2 }} />
      
      {/* CARD CONTENT - Section-specific content */}
      <Box sx={{ 
        px: 1,
        ...contentSx
      }}>
        {children}
      </Box>
    </Box>
  );
}
