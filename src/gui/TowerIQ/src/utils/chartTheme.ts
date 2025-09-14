/**
 * Chart theme utilities for consistent styling across all TowerIQ charts
 * Provides pre-configured ECharts options using the standardized color palette
 */

import { 
  CATEGORICAL_COLORS, 
  SEMANTIC_COLORS, 
  DEFAULT_CHART_THEME,
  getCategoricalColors
} from './colorPalette';

/**
 * Base chart configuration that should be applied to all charts
 */
export const BASE_CHART_CONFIG = {
  color: CATEGORICAL_COLORS,
  backgroundColor: SEMANTIC_COLORS.background, // transparent to inherit from parent
  textStyle: {
    fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    color: SEMANTIC_COLORS.text,
  },
  grid: {
    left: '10%',
    right: '10%',
    top: '15%',
    bottom: '15%',
    containLabel: true,
  },
  tooltip: {
    backgroundColor: SEMANTIC_COLORS.surface,
    borderColor: SEMANTIC_COLORS.gridLines,
    borderWidth: 1,
    textStyle: {
      color: SEMANTIC_COLORS.text,
    },
    extraCssText: 'box-shadow: 0 4px 12px rgba(0,0,0,0.3); border-radius: 4px;',
  },
};

/**
 * Creates a bar chart theme configuration
 */
export function createBarChartTheme(options: {
  showDataLabels?: boolean;
  labelPosition?: 'top' | 'inside' | 'insideTop';
  colorCount?: number;
} = {}) {
  const { showDataLabels = true, labelPosition = 'top', colorCount } = options;
  
  return {
    ...BASE_CHART_CONFIG,
    color: colorCount ? getCategoricalColors(colorCount) : CATEGORICAL_COLORS,
    xAxis: {
      type: 'category',
      axisLine: {
        show: true,
        lineStyle: {
          color: SEMANTIC_COLORS.axisLines,
        },
        onZero: false,
      },
      axisTick: {
        lineStyle: {
          color: SEMANTIC_COLORS.axisLines,
        },
      },
      axisLabel: {
        color: SEMANTIC_COLORS.textSecondary,
        fontSize: 12,
      },
      splitLine: {
        show: false,
      },
      z: 10, // Higher z-level to draw on top of bars
    },
    yAxis: {
      type: 'value',
      axisLine: {
        show: false,
      },
      axisTick: {
        show: false,
      },
      axisLabel: {
        color: SEMANTIC_COLORS.textSecondary,
        fontSize: 12,
      },
      splitLine: {
        lineStyle: {
          color: SEMANTIC_COLORS.gridLines,
          type: 'dashed',
        },
      },
    },
    series: [{
      type: 'bar',
      z: 1, // Lower z-level so bars draw behind axis
      label: {
        show: showDataLabels,
        position: labelPosition,
        color: SEMANTIC_COLORS.text,
        fontSize: 11,
        fontWeight: 500,
        z: 15, // Labels should be on top of everything
      },
      itemStyle: {
        borderRadius: [2, 2, 0, 0],
        borderColor: '#000000',
        borderWidth: 1,
      },
      emphasis: {
        itemStyle: {
          shadowBlur: 8,
          shadowColor: 'rgba(0,0,0,0.2)',
          borderWidth: 2,
        },
      },
    }],
  };
}

/**
 * Creates a line/timeseries chart theme configuration
 */
export function createTimeseriesChartTheme(options: {
  smooth?: boolean;
  showArea?: boolean;
  colorCount?: number;
} = {}) {
  const { smooth = true, showArea = false, colorCount } = options;
  
  return {
    ...BASE_CHART_CONFIG,
    color: colorCount ? getCategoricalColors(colorCount) : CATEGORICAL_COLORS,
    xAxis: {
      type: 'time',
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
        fontSize: 12,
      },
      splitLine: {
        show: false,
      },
    },
    yAxis: {
      type: 'value',
      axisLine: {
        show: false,
      },
      axisTick: {
        show: false,
      },
      axisLabel: {
        color: SEMANTIC_COLORS.textSecondary,
        fontSize: 12,
      },
      splitLine: {
        lineStyle: {
          color: SEMANTIC_COLORS.gridLines,
          type: 'dashed',
        },
      },
    },
    series: [{
      type: 'line',
      smooth,
      symbol: 'circle',
      symbolSize: 4,
      lineStyle: {
        width: 2,
      },
      areaStyle: showArea ? {
        opacity: 0.1,
      } : undefined,
      emphasis: {
        lineStyle: {
          width: 3,
        },
        symbolSize: 6,
      },
    }],
  };
}

/**
 * Creates a pie chart theme configuration
 */
export function createPieChartTheme(options: {
  showLabels?: boolean;
  radius?: string | [string, string];
  colorCount?: number;
} = {}) {
  const { showLabels = true, radius = '60%', colorCount } = options;
  
  return {
    ...BASE_CHART_CONFIG,
    color: colorCount ? getCategoricalColors(colorCount) : CATEGORICAL_COLORS,
    series: [{
      type: 'pie',
      radius,
      center: ['50%', '50%'],
      label: {
        show: showLabels,
        color: SEMANTIC_COLORS.text,
        fontSize: 12,
      },
      labelLine: {
        show: showLabels,
        lineStyle: {
          color: SEMANTIC_COLORS.textSecondary,
        },
      },
      itemStyle: {
        borderWidth: 2,
        borderColor: SEMANTIC_COLORS.background,
      },
      emphasis: {
        itemStyle: {
          shadowBlur: 10,
          shadowOffsetX: 0,
          shadowColor: 'rgba(0, 0, 0, 0.3)',
        },
        label: {
          fontSize: 14,
          fontWeight: 'bold',
        },
      },
    }],
  };
}

/**
 * Creates a stat/gauge chart theme configuration
 */
export function createStatChartTheme(options: {
  fontSize?: number;
  fontWeight?: string | number;
  color?: string;
} = {}) {
  const { fontSize = 24, fontWeight = 'bold', color = SEMANTIC_COLORS.primary } = options;
  
  return {
    ...BASE_CHART_CONFIG,
    graphic: [{
      type: 'text',
      left: 'center',
      top: 'center',
      style: {
        text: '',
        fontSize,
        fontWeight,
        fill: color,
        fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      },
    }],
  };
}

/**
 * Applies theme to an existing ECharts option object
 * @param option - Existing ECharts option
 * @param themeType - Type of chart theme to apply
 * @returns Merged option with theme applied
 */
export function applyChartTheme(
  option: any, 
  themeType: 'bar' | 'timeseries' | 'pie' | 'stat' = 'bar'
): any {
  let theme;
  
  switch (themeType) {
    case 'bar':
      theme = createBarChartTheme();
      break;
    case 'timeseries':
      theme = createTimeseriesChartTheme();
      break;
    case 'pie':
      theme = createPieChartTheme();
      break;
    case 'stat':
      theme = createStatChartTheme();
      break;
    default:
      theme = BASE_CHART_CONFIG;
  }
  
  return {
    ...theme,
    ...option,
    // Deep merge specific nested objects
    textStyle: {
      ...theme.textStyle,
      ...option.textStyle,
    },
    tooltip: {
      ...theme.tooltip,
      ...option.tooltip,
    },
    grid: {
      ...theme.grid,
      ...option.grid,
    },
    xAxis: {
      ...theme.xAxis,
      ...option.xAxis,
    },
    yAxis: {
      ...theme.yAxis,
      ...option.yAxis,
    },
  };
}

/**
 * Gets the standard color for a specific data category
 * @param category - Category identifier (string or number)
 * @param categories - Array of all categories to determine index
 * @returns Hex color string
 */
export function getCategoryColor(category: string | number, categories: (string | number)[]): string {
  const index = categories.indexOf(category);
  return index >= 0 ? getCategoricalColors(categories.length)[index] : SEMANTIC_COLORS.text;
}

/**
 * Creates a legend configuration using the standard theme
 */
export function createLegendConfig(position: 'top' | 'bottom' | 'left' | 'right' = 'bottom') {
  const positions = {
    top: { top: '5%', left: 'center' },
    bottom: { bottom: '5%', left: 'center' },
    left: { left: '5%', top: 'center', orient: 'vertical' },
    right: { right: '5%', top: 'center', orient: 'vertical' },
  };
  
  return {
    ...positions[position],
    textStyle: {
      color: SEMANTIC_COLORS.text,
      fontSize: 12,
    },
    itemGap: 20,
    icon: 'circle',
  };
}

export { CATEGORICAL_COLORS, SEMANTIC_COLORS, DEFAULT_CHART_THEME };
