import React, { useState } from 'react';
import {
  Select,
  MenuItem,
  FormControl,
  Box,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Chip,
} from '@mui/material';
import {
  ColorPicker,
  ColorPickerSelection,
  ColorPickerHue,
  ColorPickerAlpha,
  ColorPickerOutput,
  ColorPickerEyeDropper,
} from './ui/color-picker';

// Predefined color palette
const PREDEFINED_COLORS = [
  { name: 'Off', value: 'off' },
  { name: 'Deep Blue', value: '#003f5c' },
  { name: 'Purple Blue', value: '#2f4b7c' },
  { name: 'Dark Purple', value: '#665191' },
  { name: 'Magenta', value: '#a05195' },
  { name: 'Pink', value: '#d45087' },
  { name: 'Coral', value: '#f95d6a' },
  { name: 'Orange', value: '#ff7c43' },
  { name: 'Yellow Orange', value: '#ffa600' },
];

interface DebugBorderColorPickerProps {
  value: string;
  onChange: (color: string) => void;
  disabled?: boolean;
}

export function DebugBorderColorPicker({ value, onChange, disabled = false }: DebugBorderColorPickerProps) {
  const [isCustomPickerOpen, setIsCustomPickerOpen] = useState(false);
  const [customColor, setCustomColor] = useState(value);

  // Find if current value matches a predefined color
  const currentPredefinedColor = PREDEFINED_COLORS.find(color => color.value.toLowerCase() === value.toLowerCase());
  const displayValue = currentPredefinedColor ? currentPredefinedColor.name : 'Custom';

  const handleColorSelect = (selectedValue: string) => {
    if (selectedValue === 'custom') {
      setCustomColor(value);
      setIsCustomPickerOpen(true);
    } else {
      onChange(selectedValue);
    }
  };

  const handleCustomColorSave = () => {
    onChange(customColor);
    setIsCustomPickerOpen(false);
  };

  const handleCustomColorCancel = () => {
    setCustomColor(value);
    setIsCustomPickerOpen(false);
  };

  return (
    <>
      <FormControl size="small" disabled={disabled} sx={{ minWidth: 120 }}>
        <Select
          value={currentPredefinedColor ? currentPredefinedColor.value : 'custom'}
          onChange={(e) => handleColorSelect(e.target.value)}
          renderValue={() => (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              {value !== 'off' && (
                <Box
                  sx={{
                    width: 16,
                    height: 16,
                    borderRadius: '2px',
                    backgroundColor: value,
                    border: '1px solid rgba(255, 255, 255, 0.3)',
                  }}
                />
              )}
              {displayValue}
            </Box>
          )}
          sx={{
            '& .MuiSelect-select': {
              py: 0.5,
              px: 1,
              fontSize: '0.75rem',
              display: 'flex',
              alignItems: 'center',
            },
          }}
        >
          {PREDEFINED_COLORS.map((color) => (
            <MenuItem key={color.value} value={color.value}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {color.value !== 'off' && (
                  <Box
                    sx={{
                      width: 16,
                      height: 16,
                      borderRadius: '2px',
                      backgroundColor: color.value,
                      border: '1px solid rgba(255, 255, 255, 0.3)',
                    }}
                  />
                )}
                {color.name}
              </Box>
            </MenuItem>
          ))}
          <MenuItem value="custom">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box
                sx={{
                  width: 16,
                  height: 16,
                  borderRadius: '2px',
                  backgroundColor: currentPredefinedColor ? '#666' : value,
                  border: '1px solid rgba(255, 255, 255, 0.3)',
                }}
              />
              Custom...
            </Box>
          </MenuItem>
        </Select>
      </FormControl>

      {/* Custom Color Picker Dialog */}
      <Dialog
        open={isCustomPickerOpen}
        onClose={handleCustomColorCancel}
        maxWidth="sm"
        fullWidth
        PaperProps={{
          sx: {
            backgroundColor: 'background.paper',
            border: '1px solid',
            borderColor: 'divider',
          }
        }}
      >
        <DialogTitle>
          Choose Custom Color
        </DialogTitle>
        <DialogContent>
          <Box sx={{ p: 2 }}>
            <ColorPicker
              value={customColor}
              onChange={setCustomColor}
            >
              <ColorPickerSelection />
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 2 }}>
                <ColorPickerEyeDropper />
                <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <ColorPickerHue />
                  <ColorPickerAlpha />
                </Box>
              </Box>
              <Box sx={{ mt: 2 }}>
                <ColorPickerOutput />
              </Box>
            </ColorPicker>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCustomColorCancel}>
            Cancel
          </Button>
          <Button onClick={handleCustomColorSave} variant="contained">
            Apply
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
