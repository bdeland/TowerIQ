# Responsive Dashboard Grid System

This document explains how to use the responsive dashboard grid system that automatically adjusts the number of columns and row heights based on screen size.

## Overview

The responsive grid system consists of:
- `useResponsiveGrid` hook for detecting screen size and providing grid configurations
- `DashboardGrid` component with responsive capabilities
- `adjustPanelForBreakpoint` utility for adjusting panel positions when breakpoints change

## Breakpoints

| Breakpoint | Min Width | Columns | Row Height | Use Case |
|------------|-----------|---------|------------|----------|
| XS | 0px | 4 | 80px | Mobile portrait |
| SM | 600px | 6 | 90px | Mobile landscape, small tablets |
| MD | 900px | 8 | 100px | Tablets |
| LG | 1200px | 12 | 100px | Desktop |
| XL | 1536px | 16 | 100px | Large desktop, ultrawide monitors |

## Basic Usage

```tsx
import { DashboardGrid } from './components/DashboardGrid';
import { DashboardPanel } from './contexts/DashboardContext';

const MyDashboard = () => {
  const [panels, setPanels] = useState<DashboardPanel[]>([
    {
      id: 'panel-1',
      title: 'My Chart',
      type: 'chart',
      gridPos: { x: 0, y: 0, w: 6, h: 3 }, // Position and size
      query: 'SELECT * FROM data',
      echartsOption: {}
    }
  ]);

  return (
    <DashboardGrid
      panels={panels}
      isEditMode={false}
      isEditable={true}
      showMenu={true}
      showFullscreen={true}
      enableResponsive={true} // Enable responsive behavior
      onLayoutChange={(updatedPanels) => setPanels(updatedPanels)}
    />
  );
};
```

## Advanced Usage

### Custom Responsive Hook

```tsx
import { useResponsiveGrid } from './hooks/useResponsiveGrid';

const MyComponent = () => {
  const { breakpoint, columns, cellHeight, minPanelWidth } = useResponsiveGrid();
  
  return (
    <div>
      Current breakpoint: {breakpoint} ({columns} columns)
    </div>
  );
};
```

### Manual Panel Adjustment

```tsx
import { adjustPanelForBreakpoint } from './hooks/useResponsiveGrid';

// Manually adjust a panel when moving from 12 to 8 columns
const adjustedPanel = adjustPanelForBreakpoint(panel, 12, 8);
```

## Props

### DashboardGrid Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `panels` | `DashboardPanel[]` | - | Array of panels to display |
| `isEditMode` | `boolean` | - | Whether grid is in edit mode |
| `isEditable` | `boolean` | - | Whether panels can be edited |
| `showMenu` | `boolean` | - | Show panel context menus |
| `showFullscreen` | `boolean` | - | Show fullscreen buttons |
| `enableResponsive` | `boolean` | `true` | Enable responsive behavior |
| `onLayoutChange` | `(panels: DashboardPanel[]) => void` | - | Called when layout changes |

### useResponsiveGrid Return Values

| Property | Type | Description |
|----------|------|-------------|
| `breakpoint` | `'xs' \| 'sm' \| 'md' \| 'lg' \| 'xl'` | Current breakpoint |
| `columns` | `number` | Number of grid columns |
| `cellHeight` | `number` | Height of grid cells in pixels |
| `minPanelWidth` | `number` | Minimum recommended panel width |

## Panel Positioning

Panels are positioned using a grid coordinate system:

- `x`: Column position (0-based)
- `y`: Row position (0-based)
- `w`: Width in grid columns
- `h`: Height in grid rows

Example:
```tsx
gridPos: { x: 2, y: 1, w: 4, h: 3 }
// Places panel at column 2, row 1, spanning 4 columns and 3 rows
```

## Responsive Behavior

When the screen size changes:

1. **Smaller screens**: Panels are repositioned to fit within fewer columns
2. **Larger screens**: Panels are proportionally scaled to use more columns
3. **Panel adjustment**: Automatic adjustment prevents panels from going off-grid
4. **Smooth transitions**: CSS transitions provide smooth visual changes

### Panel Adjustment Logic

- **Shrinking**: Panels are moved left and resized to fit
- **Expanding**: Panels are proportionally scaled and repositioned
- **Collision prevention**: Panels are adjusted to prevent overlaps

## Best Practices

### Panel Design
- Design panels to work well at different sizes
- Use minimum width of 200-280px for readability
- Test panels at all breakpoints

### Grid Layout
- Start with desktop layout (12 columns)
- Ensure important panels are visible on mobile (4 columns)
- Group related panels for better mobile experience

### Performance
- Use `enableResponsive={false}` for static dashboards
- The grid uses memoization and throttled resize events
- Layout changes are batched to prevent excessive re-renders

## Customization

### Custom Breakpoints

Modify the `BREAKPOINTS` object in `useResponsiveGrid.ts`:

```typescript
const BREAKPOINTS = {
  xs: { width: 0, columns: 3, minPanelWidth: 180, cellHeight: 70 },
  sm: { width: 768, columns: 6, minPanelWidth: 200, cellHeight: 80 },
  // ... add more breakpoints
} as const;
```

### Custom Panel Adjustment

Override the `adjustPanelForBreakpoint` function for custom behavior:

```typescript
const customAdjustPanel = (panel, fromCols, toCols) => {
  // Your custom logic here
  return adjustedPanel;
};
```

## Troubleshooting

### Panels Overlapping
- Check panel positions after responsive changes
- Ensure `onLayoutChange` is properly handling updates
- Verify panel dimensions fit within grid bounds

### Performance Issues
- Disable responsive mode for static content
- Check for excessive re-renders in parent components
- Use React DevTools to profile component updates

### Layout Not Updating
- Ensure `onLayoutChange` callback is provided
- Check that panel state is being updated properly
- Verify responsive mode is enabled

## Examples

See `ResponsiveDashboardExample.tsx` for a complete working example with:
- Multiple panel types
- Edit mode functionality
- Responsive toggle
- Real-time breakpoint display
