/**
 * TowerIQ Centralized Theme System
 * Single source of truth for all styling based on docs/style_guidelines.md
 * 
 * This theme implements the complete TowerIQ style guidelines including:
 * - WCAG 2.1 AA compliant colors
 * - Grafana-inspired dark theme
 * - Consistent spacing, typography, and component styling
 */

import { createTheme, ThemeOptions } from '@mui/material/styles';

// ===== COLOR PALETTE (from style_guidelines.md) =====

export const TOWERIQ_COLORS = {
  // Background Colors
  backgrounds: {
    main: '#111217',      // Main application background - darkest
    paper: '#181b1f',     // Cards, sidebars, elevated surfaces
    elevated: '#22252b',  // Accordions, dropdowns, modals
    hover: '#2a2d33',     // Hover states for elevated elements
  },

  // Border & Divider Colors
  borders: {
    primary: '#313238',     // Primary borders, dividers, outlines (IMPROVED)
    interactive: '#555555', // Form elements, interactive borders
    focus: '#39b5e0',      // Focus states, active borders
    subtle: '#2e3136',     // Subtle dividers, deprecated borders
  },

  // Brand & Accent Colors
  brand: {
    primary: '#39b5e0',    // Main brand color - TowerIQ blue
    secondary: '#e18b3d',  // Secondary brand color - warm orange
    tertiary: '#e06339',   // Tertiary brand color - warm red-orange
  },

  accent: {
    primary: '#00a7e1',    // Primary accent - Material UI primary
    secondary: '#ff6464',  // Secondary accent - red/pink
  },

  // Accessibility-Compliant Semantic Colors
  semantic: {
    success: {
      main: '#4caf50',     // IMPROVED (4.1:1 contrast)
      bright: '#66bb6a',   // For emphasis (5.2:1 contrast)
      muted: '#388e3c',    // For backgrounds (3.1:1 contrast)
    },
    warning: {
      main: '#ff9800',     // IMPROVED (4.9:1 contrast)
      bright: '#ffb74d',   // For emphasis (6.8:1 contrast)
      muted: '#f57c00',    // For backgrounds (3.9:1 contrast)
    },
    error: {
      main: '#f44336',     // IMPROVED (4.8:1 contrast)
      bright: '#ef5350',   // For emphasis (5.1:1 contrast)
      muted: '#c62828',    // For backgrounds (3.2:1 contrast)
    },
    info: {
      main: '#29b6f6',     // IMPROVED (4.2:1 contrast)
      light: '#4fc3f7',    // Lighter info variant
      dark: '#0277bd',     // Darker info variant
    },
  },

  // Text Colors (WCAG 2.1 AA Compliant)
  text: {
    primary: '#ffffff',    // IMPROVED (15.8:1 contrast)
    secondary: '#b0b0b0',  // IMPROVED (4.6:1 contrast)
    tertiary: '#9e9e9e',   // Less critical text (3.8:1 contrast)
    disabled: '#666666',   // Disabled text (2.4:1 contrast)
  },

  // Interactive Text
  interactive: {
    link: '#39b5e0',       // Links, clickable text
    linkHover: '#4dd0ff',  // Link hover states
    active: '#00a7e1',     // Active/selected text
  },

  // Interactive States
  action: {
    active: '#ffffff',                         // Active elements
    hover: 'rgba(255, 255, 255, 0.08)',      // Hover backgrounds
    selected: 'rgba(255, 255, 255, 0.12)',   // Selected backgrounds
    disabled: 'rgba(255, 255, 255, 0.06)',   // Disabled backgrounds
    
    // Brand color interactive states
    brandHover: 'rgba(57, 181, 224, 0.08)',  // Brand color hover
    brandActive: 'rgba(57, 181, 224, 0.12)', // Brand color active
  },

  // Button States
  button: {
    primaryHover: '#4dd0ff',    // Lighter brand color
    primaryActive: '#0099cc',   // Darker brand color
    secondaryHover: '#ff8080',  // Lighter secondary
    secondaryActive: '#cc5050', // Darker secondary
  },

  // Focus & Selection
  focus: {
    ring: '#39b5e0',                          // Focus indicators
    selectionBg: 'rgba(57, 181, 224, 0.15)', // Selection backgrounds
    selectionText: '#ffffff',                 // Text on selection backgrounds
  },

  // Data Visualization Colors (Colorblind-Friendly)
  data: {
    primary: '#39b5e0',      // Brand blue
    secondary: '#ff6b35',    // Orange (complementary)
    tertiary: '#4ecdc4',     // Teal
    quaternary: '#45b7d1',   // Light blue
    quinary: '#96ceb4',      // Mint green
    senary: '#feca57',       // Yellow
    
    // Status-specific data colors
    positive: '#4caf50',     // Green for positive metrics
    negative: '#f44336',     // Red for negative metrics
    neutral: '#b0b0b0',      // Gray for neutral metrics
    
    // Chart infrastructure
    grid: '#404040',         // Chart grid lines
    chartText: '#b0b0b0',    // Chart labels, axes
  },

  // Component-Specific Colors
  navigation: {
    background: '#181b1f',   // Sidebar background
    itemHover: '#2a2d33',    // Navigation item hover
    itemActive: '#39b5e0',   // Active navigation item
    headerBg: '#181b1f',     // Header/toolbar background
  },

  // Form Elements
  form: {
    inputBg: '#111217',      // Input field backgrounds
    inputBorder: '#555555',  // Input field borders
    inputBorderFocus: '#39b5e0', // Focused input borders
    inputText: '#ffffff',    // Input text color
    inputPlaceholder: '#9e9e9e', // Placeholder text
  },
} as const;

// ===== SPACING SYSTEM (8px base unit) =====

export const TOWERIQ_SPACING = {
  xs: 4,     // 0.5 units
  sm: 8,     // 1 unit
  md: 16,    // 2 units
  lg: 24,    // 3 units
  xl: 32,    // 4 units
  xxl: 48,   // 6 units
  
  // Component-specific spacing
  layout: {
    headerHeight: 40,
    sidebarWidth: 180,
    borderRadius: 8,
    borderRadiusSm: 4,
  },
} as const;

// ===== TYPOGRAPHY SYSTEM =====

export const TOWERIQ_TYPOGRAPHY = {
  fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
  fontFamilyMono: '"Roboto Mono", "Consolas", "Monaco", monospace',
  fontSize: 14, // Base font size
  
  // Font sizes and weights
  h1: { fontSize: 32, fontWeight: 600 },   // 2rem
  h2: { fontSize: 28, fontWeight: 600 },   // 1.75rem
  h3: { fontSize: 24, fontWeight: 600 },   // 1.5rem
  h4: { fontSize: 20, fontWeight: 600 },   // 1.25rem
  h5: { fontSize: 18, fontWeight: 600 },   // 1.125rem
  h6: { fontSize: 16, fontWeight: 600 },   // 1rem
  
  body1: { fontSize: 14, fontWeight: 400 }, // 0.875rem
  body2: { fontSize: 13, fontWeight: 400 }, // 0.8rem
  caption: { fontSize: 12, fontWeight: 400 }, // 0.75rem
} as const;

// ===== SHADOW SYSTEM =====

export const TOWERIQ_SHADOWS = {
  sm: '0px 2px 1px rgba(0, 0, 0, 0.2)',     // Cards, buttons
  md: '0px 3px 1px rgba(0, 0, 0, 0.2)',     // Hover states
  lg: '0px 3px 3px rgba(0, 0, 0, 0.2)',     // Selected, elevated
  xl: '0px 4px 8px rgba(0, 0, 0, 0.3)',     // Modals, dropdowns
  
  // Glow effects
  brandGlow: '0 0 2px #39b5e0, 0 0 4px rgba(57, 181, 224, 0.6)',
  primaryGlow: '0 0 2px #00a7e1, 0 0 4px rgba(0, 167, 225, 0.6)',
} as const;

// ===== MATERIAL-UI THEME CONFIGURATION =====

const themeOptions: ThemeOptions = {
  palette: {
    mode: 'dark', // Enable dark mode for proper Material-UI defaults
    primary: {
      main: TOWERIQ_COLORS.brand.primary,
      dark: TOWERIQ_COLORS.button.primaryActive,
      light: TOWERIQ_COLORS.button.primaryHover,
    },
    secondary: {
      main: TOWERIQ_COLORS.accent.secondary,
      dark: TOWERIQ_COLORS.button.secondaryActive,
      light: TOWERIQ_COLORS.button.secondaryHover,
    },
    // Add custom brand colors to palette
    tertiary: {
      main: TOWERIQ_COLORS.brand.tertiary,
      contrastText: '#ffffff',
    } as any, // TypeScript workaround for custom palette colors
    background: {
      default: TOWERIQ_COLORS.backgrounds.main,
      paper: TOWERIQ_COLORS.backgrounds.paper,
    },
    text: {
      primary: TOWERIQ_COLORS.text.primary,
      secondary: TOWERIQ_COLORS.text.secondary,
      disabled: TOWERIQ_COLORS.text.disabled,
    },
    divider: TOWERIQ_COLORS.borders.primary,
    action: {
      active: TOWERIQ_COLORS.action.active,
      hover: TOWERIQ_COLORS.action.hover,
      selected: TOWERIQ_COLORS.action.selected,
      disabled: TOWERIQ_COLORS.action.disabled,
      disabledBackground: TOWERIQ_COLORS.action.disabled,
    },
    success: {
      main: TOWERIQ_COLORS.semantic.success.main,
      light: TOWERIQ_COLORS.semantic.success.bright,
      dark: TOWERIQ_COLORS.semantic.success.muted,
    },
    warning: {
      main: TOWERIQ_COLORS.semantic.warning.main,
      light: TOWERIQ_COLORS.semantic.warning.bright,
      dark: TOWERIQ_COLORS.semantic.warning.muted,
    },
    error: {
      main: TOWERIQ_COLORS.semantic.error.main,
      light: TOWERIQ_COLORS.semantic.error.bright,
      dark: TOWERIQ_COLORS.semantic.error.muted,
    },
    info: {
      main: TOWERIQ_COLORS.semantic.info.main,
      light: TOWERIQ_COLORS.semantic.info.light,
      dark: TOWERIQ_COLORS.semantic.info.dark,
    },
  },
  
  typography: {
    fontFamily: TOWERIQ_TYPOGRAPHY.fontFamily,
    fontSize: TOWERIQ_TYPOGRAPHY.fontSize,
    h1: {
      fontSize: `${TOWERIQ_TYPOGRAPHY.h1.fontSize}px`,
      fontWeight: TOWERIQ_TYPOGRAPHY.h1.fontWeight,
    },
    h2: {
      fontSize: `${TOWERIQ_TYPOGRAPHY.h2.fontSize}px`,
      fontWeight: TOWERIQ_TYPOGRAPHY.h2.fontWeight,
    },
    h3: {
      fontSize: `${TOWERIQ_TYPOGRAPHY.h3.fontSize}px`,
      fontWeight: TOWERIQ_TYPOGRAPHY.h3.fontWeight,
    },
    h4: {
      fontSize: `${TOWERIQ_TYPOGRAPHY.h4.fontSize}px`,
      fontWeight: TOWERIQ_TYPOGRAPHY.h4.fontWeight,
    },
    h5: {
      fontSize: `${TOWERIQ_TYPOGRAPHY.h5.fontSize}px`,
      fontWeight: TOWERIQ_TYPOGRAPHY.h5.fontWeight,
    },
    h6: {
      fontSize: `${TOWERIQ_TYPOGRAPHY.h6.fontSize}px`,
      fontWeight: TOWERIQ_TYPOGRAPHY.h6.fontWeight,
    },
    body1: {
      fontSize: `${TOWERIQ_TYPOGRAPHY.body1.fontSize}px`,
      fontWeight: TOWERIQ_TYPOGRAPHY.body1.fontWeight,
    },
    body2: {
      fontSize: `${TOWERIQ_TYPOGRAPHY.body2.fontSize}px`,
      fontWeight: TOWERIQ_TYPOGRAPHY.body2.fontWeight,
    },
    caption: {
      fontSize: `${TOWERIQ_TYPOGRAPHY.caption.fontSize}px`,
      fontWeight: TOWERIQ_TYPOGRAPHY.caption.fontWeight,
    },
  },
  
  shape: {
    borderRadius: TOWERIQ_SPACING.layout.borderRadius,
  },
  
  spacing: TOWERIQ_SPACING.sm, // 8px base unit
  
  shadows: [
    'none',
    TOWERIQ_SHADOWS.sm,
    TOWERIQ_SHADOWS.md,
    TOWERIQ_SHADOWS.lg,
    TOWERIQ_SHADOWS.xl,
    // Fill remaining shadow levels (Material-UI requires exactly 25 shadow levels)
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
    TOWERIQ_SHADOWS.xl,
  ] as const,
  
  components: {
    // CSS Baseline for global styles
    MuiCssBaseline: {
      styleOverrides: {
        ':root': {
          // Expose all theme colors as CSS custom properties
          '--tiq-bg-main': TOWERIQ_COLORS.backgrounds.main,
          '--tiq-bg-paper': TOWERIQ_COLORS.backgrounds.paper,
          '--tiq-bg-elevated': TOWERIQ_COLORS.backgrounds.elevated,
          '--tiq-bg-hover': TOWERIQ_COLORS.backgrounds.hover,
          
          '--tiq-border-primary': TOWERIQ_COLORS.borders.primary,
          '--tiq-border-interactive': TOWERIQ_COLORS.borders.interactive,
          '--tiq-border-focus': TOWERIQ_COLORS.borders.focus,
          '--tiq-border-subtle': TOWERIQ_COLORS.borders.subtle,
          
          '--tiq-brand-primary': TOWERIQ_COLORS.brand.primary,
          '--tiq-brand-secondary': TOWERIQ_COLORS.brand.secondary,
          '--tiq-brand-tertiary': TOWERIQ_COLORS.brand.tertiary,
          
          '--tiq-text-primary': TOWERIQ_COLORS.text.primary,
          '--tiq-text-secondary': TOWERIQ_COLORS.text.secondary,
          '--tiq-text-tertiary': TOWERIQ_COLORS.text.tertiary,
          '--tiq-text-disabled': TOWERIQ_COLORS.text.disabled,
          
          '--tiq-success-main': TOWERIQ_COLORS.semantic.success.main,
          '--tiq-warning-main': TOWERIQ_COLORS.semantic.warning.main,
          '--tiq-error-main': TOWERIQ_COLORS.semantic.error.main,
          '--tiq-info-main': TOWERIQ_COLORS.semantic.info.main,
          
          '--tiq-action-hover': TOWERIQ_COLORS.action.hover,
          '--tiq-action-selected': TOWERIQ_COLORS.action.selected,
          '--tiq-action-disabled': TOWERIQ_COLORS.action.disabled,
          
          '--tiq-nav-bg': TOWERIQ_COLORS.navigation.background,
          '--tiq-nav-item-hover': TOWERIQ_COLORS.navigation.itemHover,
          '--tiq-nav-item-active': TOWERIQ_COLORS.navigation.itemActive,
          
          '--tiq-form-input-bg': TOWERIQ_COLORS.form.inputBg,
          '--tiq-form-input-border': TOWERIQ_COLORS.form.inputBorder,
          '--tiq-form-input-border-focus': TOWERIQ_COLORS.form.inputBorderFocus,
          
          '--tiq-data-grid': TOWERIQ_COLORS.data.grid,
          
          // Spacing
          '--tiq-spacing-xs': `${TOWERIQ_SPACING.xs}px`,
          '--tiq-spacing-sm': `${TOWERIQ_SPACING.sm}px`,
          '--tiq-spacing-md': `${TOWERIQ_SPACING.md}px`,
          '--tiq-spacing-lg': `${TOWERIQ_SPACING.lg}px`,
          '--tiq-spacing-xl': `${TOWERIQ_SPACING.xl}px`,
          '--tiq-spacing-xxl': `${TOWERIQ_SPACING.xxl}px`,
          
          // Layout
          '--tiq-layout-header-height': `${TOWERIQ_SPACING.layout.headerHeight}px`,
          '--tiq-layout-sidebar-width': `${TOWERIQ_SPACING.layout.sidebarWidth}px`,
          '--tiq-layout-border-radius': `${TOWERIQ_SPACING.layout.borderRadius}px`,
          '--tiq-layout-border-radius-sm': `${TOWERIQ_SPACING.layout.borderRadiusSm}px`,
        },
        
        body: {
          '&::-webkit-scrollbar': {
            width: '0px',
            background: 'transparent',
          },
        },
        
        '*': {
          '&::-webkit-scrollbar': {
            width: '0px',
            background: 'transparent',
          },
        },
        
      },
    },
    
    // AppBar styling - using object-based overrides for MUI v7 compatibility
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: `${TOWERIQ_COLORS.navigation.headerBg} !important`,
          backgroundImage: 'none !important', // Remove Paper overlay that covers background color
          boxShadow: 'none',
          borderColor: TOWERIQ_COLORS.borders.primary,
          // Override the default dark theme background specifically
          '&.MuiAppBar-colorPrimary': {
            backgroundColor: `${TOWERIQ_COLORS.navigation.headerBg} !important`,
            backgroundImage: 'none !important',
          },
          // Ensure it works for any color variant
          '&.MuiAppBar-colorDefault': {
            backgroundColor: `${TOWERIQ_COLORS.navigation.headerBg} !important`,
            backgroundImage: 'none !important',
          },
          '&.MuiAppBar-colorSecondary': {
            backgroundColor: `${TOWERIQ_COLORS.navigation.headerBg} !important`,
            backgroundImage: 'none !important',
          },
          '&.MuiAppBar-colorInherit': {
            backgroundColor: `${TOWERIQ_COLORS.navigation.headerBg} !important`,
            backgroundImage: 'none !important',
          },
          '&.MuiAppBar-colorTransparent': {
            backgroundColor: `${TOWERIQ_COLORS.navigation.headerBg} !important`,
            backgroundImage: 'none !important',
          },
        },
      },
    },
    
    // Drawer styling
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: `${TOWERIQ_COLORS.navigation.background} !important`, // Force override Material-UI defaults
          backgroundImage: 'none !important', // Remove Paper overlay that covers background color
          borderColor: TOWERIQ_COLORS.borders.primary,
        },
      },
    },
    
    // List item styling
    MuiListItemButton: {
      styleOverrides: {
        root: {
          '&.Mui-selected': {
            backgroundColor: TOWERIQ_COLORS.action.brandActive,
            borderLeft: `4px solid ${TOWERIQ_COLORS.brand.primary}`,
            color: TOWERIQ_COLORS.brand.primary,
            '&:hover': {
              backgroundColor: TOWERIQ_COLORS.action.brandHover,
            },
          },
          '&:hover': {
            backgroundColor: TOWERIQ_COLORS.action.hover,
          },
        },
      },
    },
    
    // Button styling
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none', // Don't uppercase button text
          borderRadius: TOWERIQ_SPACING.layout.borderRadius,
        },
        contained: {
          boxShadow: TOWERIQ_SHADOWS.sm,
          '&:hover': {
            boxShadow: TOWERIQ_SHADOWS.md,
          },
        },
        outlined: {
          borderColor: TOWERIQ_COLORS.borders.interactive,
          '&:hover': {
            borderColor: TOWERIQ_COLORS.borders.focus,
            backgroundColor: TOWERIQ_COLORS.action.hover,
          },
        },
      },
    },
    
    // Card styling
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: TOWERIQ_COLORS.backgrounds.paper,
          borderRadius: TOWERIQ_SPACING.layout.borderRadius,
          border: `1px solid ${TOWERIQ_COLORS.borders.primary}`,
          boxShadow: TOWERIQ_SHADOWS.sm,
        },
      },
    },
    
    // TextField styling
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            backgroundColor: TOWERIQ_COLORS.form.inputBg,
            '& fieldset': {
              borderColor: TOWERIQ_COLORS.form.inputBorder,
            },
            '&:hover fieldset': {
              borderColor: TOWERIQ_COLORS.borders.interactive,
            },
            '&.Mui-focused fieldset': {
              borderColor: TOWERIQ_COLORS.form.inputBorderFocus,
            },
          },
          '& .MuiInputLabel-root': {
            color: TOWERIQ_COLORS.text.secondary,
          },
          '& .MuiOutlinedInput-input::placeholder': {
            color: TOWERIQ_COLORS.form.inputPlaceholder,
            opacity: 1,
          },
        },
      },
    },
    
    // Tooltip styling
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          backgroundColor: TOWERIQ_COLORS.backgrounds.elevated,
          color: TOWERIQ_COLORS.text.primary,
          border: `1px solid ${TOWERIQ_COLORS.borders.primary}`,
          fontSize: TOWERIQ_TYPOGRAPHY.caption.fontSize,
        },
      },
    },
    
    // Menu styling (for dropdowns, selects, etc.)
    MuiMenu: {
      styleOverrides: {
        paper: {
          backgroundColor: `${TOWERIQ_COLORS.backgrounds.elevated} !important`,
          border: `1px solid ${TOWERIQ_COLORS.borders.primary}`,
        },
      },
    },
    
    // MenuItem styling
    MuiMenuItem: {
      styleOverrides: {
        root: {
          color: TOWERIQ_COLORS.text.primary,
          '&:hover': {
            backgroundColor: TOWERIQ_COLORS.action.hover,
          },
          '&.Mui-selected': {
            backgroundColor: TOWERIQ_COLORS.action.selected,
            '&:hover': {
              backgroundColor: TOWERIQ_COLORS.action.brandHover,
            },
          },
        },
      },
    },
    
    // Checkbox styling
    MuiCheckbox: {
      styleOverrides: {
        root: {
          color: TOWERIQ_COLORS.text.secondary,
          '&.Mui-checked': {
            color: TOWERIQ_COLORS.brand.primary,
          },
          '&:hover': {
            backgroundColor: TOWERIQ_COLORS.action.hover,
          },
        },
      },
    },
    
    // Select styling
    MuiSelect: {
      styleOverrides: {
        root: {
          backgroundColor: TOWERIQ_COLORS.form.inputBg,
          color: TOWERIQ_COLORS.text.primary,
        },
        icon: {
          color: TOWERIQ_COLORS.text.secondary,
        },
      },
    },
    
    // Chip styling
    MuiChip: {
      styleOverrides: {
        root: {
          backgroundColor: TOWERIQ_COLORS.backgrounds.elevated,
          color: TOWERIQ_COLORS.text.primary,
          border: `1px solid ${TOWERIQ_COLORS.borders.primary}`,
        },
        deleteIcon: {
          color: TOWERIQ_COLORS.text.secondary,
          '&:hover': {
            color: TOWERIQ_COLORS.text.primary,
          },
        },
      },
    },
    
    // IconButton styling
    MuiIconButton: {
      styleOverrides: {
        root: {
          color: TOWERIQ_COLORS.text.secondary,
          '&:hover': {
            backgroundColor: TOWERIQ_COLORS.action.hover,
            color: TOWERIQ_COLORS.text.primary,
          },
        },
      },
    },
    
    // CircularProgress styling
    MuiCircularProgress: {
      styleOverrides: {
        root: {
          color: TOWERIQ_COLORS.brand.primary,
        },
      },
    },
    
    // Dialog styling
    MuiDialog: {
      styleOverrides: {
        paper: {
          backgroundColor: TOWERIQ_COLORS.backgrounds.paper,
          border: `1px solid ${TOWERIQ_COLORS.borders.primary}`,
        },
      },
    },
    
    // Snackbar styling
    MuiSnackbar: {
      styleOverrides: {
        root: {
          '& .MuiPaper-root': {
            backgroundColor: TOWERIQ_COLORS.backgrounds.elevated,
            color: TOWERIQ_COLORS.text.primary,
          },
        },
      },
    },
  },
};

// Create and export the theme - single creation to avoid composition issues
const toweriqTheme = createTheme(themeOptions);

// Debug: Log theme creation
console.log('TowerIQ Theme created:', {
  headerBg: TOWERIQ_COLORS.navigation.headerBg,
  appBarOverrides: toweriqTheme.components?.MuiAppBar?.styleOverrides?.root
});

// Export individual color and style constants for use in components
export {
  TOWERIQ_COLORS as colors,
  TOWERIQ_SPACING as spacing,
  TOWERIQ_TYPOGRAPHY as typography,
  TOWERIQ_SHADOWS as shadows,
};

// Export the composed theme
export { toweriqTheme };

// Default export
export default toweriqTheme;
