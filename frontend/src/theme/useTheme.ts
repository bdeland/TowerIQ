/**
 * Custom hook for accessing TowerIQ theme values
 * Provides easy access to colors, spacing, typography, and other theme constants
 */

import { useTheme as useMuiTheme } from '@mui/material/styles';
import { TOWERIQ_COLORS, TOWERIQ_SPACING, TOWERIQ_TYPOGRAPHY, TOWERIQ_SHADOWS } from './toweriqTheme';

export function useTowerIQTheme() {
  const muiTheme = useMuiTheme();
  
  return {
    // Material-UI theme for sx prop and theme-aware components
    mui: muiTheme,
    
    // TowerIQ specific theme constants
    colors: TOWERIQ_COLORS,
    spacing: TOWERIQ_SPACING,
    typography: TOWERIQ_TYPOGRAPHY,
    shadows: TOWERIQ_SHADOWS,
    
    // Convenience methods for common patterns
    getBorderStyle: (type: 'primary' | 'interactive' | 'focus' | 'subtle' = 'primary') => 
      `1px solid ${TOWERIQ_COLORS.borders[type]}`,
    
    getTextColor: (variant: 'primary' | 'secondary' | 'tertiary' | 'disabled' = 'primary') => 
      TOWERIQ_COLORS.text[variant],
    
    getBackgroundColor: (variant: 'main' | 'paper' | 'elevated' | 'hover' = 'paper') => 
      TOWERIQ_COLORS.backgrounds[variant],
    
    getSemanticColor: (type: 'success' | 'warning' | 'error' | 'info', variant: 'main' | 'bright' | 'muted' | 'light' | 'dark' = 'main') => {
      const colorGroup = TOWERIQ_COLORS.semantic[type];
      return (colorGroup as any)[variant] || colorGroup.main;
    },
    
    // CSS custom property helpers
    getCSSVar: (property: string) => `var(--tiq-${property})`,
    
    // Common style objects
    cardStyle: {
      backgroundColor: TOWERIQ_COLORS.backgrounds.paper,
      border: `1px solid ${TOWERIQ_COLORS.borders.primary}`,
      borderRadius: TOWERIQ_SPACING.layout.borderRadius,
    },
    
    buttonStyle: {
      primary: {
        backgroundColor: TOWERIQ_COLORS.brand.primary,
        color: TOWERIQ_COLORS.backgrounds.main,
        '&:hover': {
          backgroundColor: TOWERIQ_COLORS.button.primaryHover,
        },
        '&:active': {
          backgroundColor: TOWERIQ_COLORS.button.primaryActive,
        },
      },
      secondary: {
        backgroundColor: 'transparent',
        color: TOWERIQ_COLORS.text.primary,
        border: `1px solid ${TOWERIQ_COLORS.borders.interactive}`,
        '&:hover': {
          backgroundColor: TOWERIQ_COLORS.action.hover,
        },
      },
    },
    
    inputStyle: {
      backgroundColor: TOWERIQ_COLORS.form.inputBg,
      border: `1px solid ${TOWERIQ_COLORS.form.inputBorder}`,
      color: TOWERIQ_COLORS.form.inputText,
      '&:focus': {
        borderColor: TOWERIQ_COLORS.form.inputBorderFocus,
        boxShadow: `0 0 0 2px rgba(57, 181, 224, 0.2)`,
      },
      '&::placeholder': {
        color: TOWERIQ_COLORS.form.inputPlaceholder,
      },
    },
  };
}

// Re-export theme constants for direct import
export {
  TOWERIQ_COLORS as colors,
  TOWERIQ_SPACING as spacing,
  TOWERIQ_TYPOGRAPHY as typography,
  TOWERIQ_SHADOWS as shadows,
} from './toweriqTheme';

// Default export for convenience
export default useTowerIQTheme;
