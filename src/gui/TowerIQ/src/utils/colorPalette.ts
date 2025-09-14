/**
 * Standardized color palette for TowerIQ charts and visualizations
 * Provides consistent categorical colors and theming utilities
 */

// Primary categorical color palette - use these colors in order for categorical data
export const CATEGORICAL_COLORS = [
  '#8a3ffc', // 01. Purple 60
  '#33b1ff', // 02. Cyan 40
  '#007d79', // 03. Teal 60
  '#ff7eb6', // 04. Magenta 40
  '#fa4d56', // 05. Red 50
  '#fff1f1', // 06. Red 10
  '#6fdc8c', // 07. Green 30
  '#4589ff', // 08. Blue 50
  '#d12771', // 09. Magenta 60
  '#d2a106', // 10. Yellow 40
  '#08bdba', // 11. Teal 40
  '#bae6ff', // 12. Cyan 20
  '#ba4e00', // 13. Orange 60
  '#d4bbff', // 14. Purple 30
] as const;

// Color names for reference and debugging
export const COLOR_NAMES = [
  'Purple 60',
  'Cyan 40',
  'Teal 60',
  'Magenta 40',
  'Red 50',
  'Red 10',
  'Green 30',
  'Blue 50',
  'Magenta 60',
  'Yellow 40',
  'Teal 40',
  'Cyan 20',
  'Orange 60',
  'Purple 30',
] as const;

// Additional semantic colors for specific use cases (dark theme)
export const SEMANTIC_COLORS = {
  // Status colors
  success: '#6fdc8c',    // Green 30
  warning: '#d2a106',    // Yellow 40
  error: '#fa4d56',      // Red 50
  info: '#4589ff',       // Blue 50
  
  // Neutral colors
  primary: '#8a3ffc',    // Purple 60
  secondary: '#33b1ff',  // Cyan 40
  
  // Background and text (dark theme)
  background: 'transparent', // Let the parent container handle background
  surface: '#2d2d2d',
  text: '#ffffff',
  textSecondary: '#b3b3b3',
  
  // Chart specific (dark theme)
  gridLines: '#404040',
  axisLines: '#666666',
} as const;

/**
 * Gets a categorical color by index, cycling through the palette if index exceeds available colors
 * @param index - The index of the color to retrieve
 * @returns Hex color string
 */
export function getCategoricalColor(index: number): string {
  return CATEGORICAL_COLORS[index % CATEGORICAL_COLORS.length];
}

/**
 * Gets multiple categorical colors for a given count
 * @param count - Number of colors needed
 * @returns Array of hex color strings
 */
export function getCategoricalColors(count: number): string[] {
  return Array.from({ length: count }, (_, i) => getCategoricalColor(i));
}

/**
 * Gets a color palette suitable for tier-based coloring (maps tier numbers to colors)
 * @param maxTier - Maximum tier number to generate colors for
 * @returns Object mapping tier numbers to colors
 */
export function getTierColorPalette(maxTier: number = 10): Record<number, string> {
  const palette: Record<number, string> = {};
  
  for (let tier = 1; tier <= maxTier; tier++) {
    palette[tier] = getCategoricalColor(tier - 1);
  }
  
  return palette;
}

/**
 * Generates ECharts-compatible color array
 * @param count - Number of colors needed (defaults to full palette)
 * @returns Array of colors for ECharts series
 */
export function getEChartsColorArray(count?: number): string[] {
  if (count === undefined) {
    return [...CATEGORICAL_COLORS];
  }
  return getCategoricalColors(count);
}

/**
 * Creates a color mapping function for categorical data
 * @param categories - Array of category values
 * @returns Function that maps category to color
 */
export function createCategoryColorMapper<T extends string | number>(
  categories: T[]
): (category: T) => string {
  const colorMap = new Map<T, string>();
  
  categories.forEach((category, index) => {
    colorMap.set(category, getCategoricalColor(index));
  });
  
  return (category: T) => colorMap.get(category) || SEMANTIC_COLORS.text;
}

/**
 * Gets a color with opacity applied
 * @param color - Hex color string
 * @param opacity - Opacity value between 0 and 1
 * @returns RGBA color string
 */
export function getColorWithOpacity(color: string, opacity: number): string {
  // Remove # if present
  const hex = color.replace('#', '');
  
  // Parse RGB values
  const r = parseInt(hex.substring(0, 2), 16);
  const g = parseInt(hex.substring(2, 4), 16);
  const b = parseInt(hex.substring(4, 6), 16);
  
  return `rgba(${r}, ${g}, ${b}, ${opacity})`;
}

/**
 * Creates a gradient color array between two colors
 * @param startColor - Starting hex color
 * @param endColor - Ending hex color  
 * @param steps - Number of steps in the gradient
 * @returns Array of hex colors representing the gradient
 */
export function createColorGradient(
  startColor: string, 
  endColor: string, 
  steps: number
): string[] {
  const start = startColor.replace('#', '');
  const end = endColor.replace('#', '');
  
  const startR = parseInt(start.substring(0, 2), 16);
  const startG = parseInt(start.substring(2, 4), 16);
  const startB = parseInt(start.substring(4, 6), 16);
  
  const endR = parseInt(end.substring(0, 2), 16);
  const endG = parseInt(end.substring(2, 4), 16);
  const endB = parseInt(end.substring(4, 6), 16);
  
  const colors: string[] = [];
  
  for (let i = 0; i < steps; i++) {
    const ratio = i / (steps - 1);
    
    const r = Math.round(startR + (endR - startR) * ratio);
    const g = Math.round(startG + (endG - startG) * ratio);
    const b = Math.round(startB + (endB - startB) * ratio);
    
    colors.push(`#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`);
  }
  
  return colors;
}

/**
 * Default chart theme configuration using the color palette (dark theme)
 */
export const DEFAULT_CHART_THEME = {
  color: CATEGORICAL_COLORS,
  backgroundColor: SEMANTIC_COLORS.background, // transparent to inherit
  textStyle: {
    color: SEMANTIC_COLORS.text,
    fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  title: {
    textStyle: {
      color: SEMANTIC_COLORS.text,
      fontSize: 16,
      fontWeight: 600,
    },
  },
  legend: {
    textStyle: {
      color: SEMANTIC_COLORS.text,
    },
  },
  grid: {
    borderColor: SEMANTIC_COLORS.gridLines,
  },
  categoryAxis: {
    axisLine: {
      lineStyle: {
        color: SEMANTIC_COLORS.axisLines,
      },
    },
    axisTick: {
      lineStyle: {
        color: SEMANTIC_COLORS.axisLines,
      },
    },
    axisLabel: {
      color: SEMANTIC_COLORS.textSecondary,
    },
    splitLine: {
      lineStyle: {
        color: SEMANTIC_COLORS.gridLines,
      },
    },
  },
  valueAxis: {
    axisLine: {
      lineStyle: {
        color: SEMANTIC_COLORS.axisLines,
      },
    },
    axisTick: {
      lineStyle: {
        color: SEMANTIC_COLORS.axisLines,
      },
    },
    axisLabel: {
      color: SEMANTIC_COLORS.textSecondary,
    },
    splitLine: {
      lineStyle: {
        color: SEMANTIC_COLORS.gridLines,
      },
    },
  },
  tooltip: {
    backgroundColor: SEMANTIC_COLORS.surface,
    borderColor: SEMANTIC_COLORS.gridLines,
    textStyle: {
      color: SEMANTIC_COLORS.text,
    },
  },
} as const;

/**
 * Validates that all colors in the palette are valid hex colors
 * @returns Array of any invalid colors found
 */
export function validateColorPalette(): string[] {
  const hexColorRegex = /^#[0-9A-F]{6}$/i;
  const invalidColors: string[] = [];
  
  CATEGORICAL_COLORS.forEach((color, index) => {
    if (!hexColorRegex.test(color)) {
      invalidColors.push(`Index ${index}: ${color}`);
    }
  });
  
  return invalidColors;
}

// Validate colors on module load (development check)
if (process.env.NODE_ENV === 'development') {
  const invalidColors = validateColorPalette();
  if (invalidColors.length > 0) {
    console.warn('Invalid colors found in palette:', invalidColors);
  }
}
