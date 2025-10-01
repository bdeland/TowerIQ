import React from 'react';
import { Box, Typography } from '@mui/material';
import { DebugBorderColorPicker } from './DebugBorderColorPicker';

interface DebugBorderSettingProps {
  label: string;
  value: string;
  onChange: (color: string) => void;
  minWidth?: string;
}

export function DebugBorderSetting({ 
  label, 
  value, 
  onChange, 
  minWidth = '100px' 
}: DebugBorderSettingProps) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Typography variant="body2" sx={{ minWidth }}>
        {label}
      </Typography>
      <DebugBorderColorPicker
        value={value}
        onChange={onChange}
      />
    </Box>
  );
}
