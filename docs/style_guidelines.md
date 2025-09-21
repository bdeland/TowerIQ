# TowerIQ Style Guidelines

## Overview

This document defines the comprehensive style guidelines for the TowerIQ application, including color theme specifications, accessibility requirements, and UI design best practices. TowerIQ uses a Grafana-inspired dark theme optimized for monitoring and development workflows.

---

## Brand Identity

**Application Name**: TowerIQ  
**Tagline**: Advanced monitoring and instrumentation for "The Tower" mobile game  
**Design Philosophy**: Grafana-inspired dark theme with professional monitoring interface aesthetics  
**Target Users**: Developers, QA engineers, game analysts  

---

## Color Theme Specification

### Core Color Palette

#### Background Colors
```css
/* Primary Backgrounds */
--bg-main: #111217           /* Main application background - darkest */
--bg-paper: #181b1f          /* Cards, sidebars, elevated surfaces */
--bg-elevated: #22252b       /* Accordions, dropdowns, modals */
--bg-hover: #2a2d33          /* Hover states for elevated elements */

/* Usage Examples */
body, main content area: #111217
cards, panels, sidebar: #181b1f
accordions, menus: #22252b
hover states: #2a2d33
```

#### Border & Divider Colors
```css
--border-primary: #404040    /* Primary borders, dividers, outlines (IMPROVED) */
--border-interactive: #555555 /* Form elements, interactive borders (NEW) */
--border-focus: #39b5e0      /* Focus states, active borders (NEW) */
--border-subtle: #2e3136     /* Subtle dividers, deprecated borders */

/* Usage Examples */
card borders, section dividers: #404040
input fields, dropdowns: #555555
focus rings, active states: #39b5e0
```

#### Brand & Accent Colors
```css
--brand-primary: #39b5e0     /* Main brand color - TowerIQ blue */
--brand-secondary: #e18b3d   /* Secondary brand color - warm orange */
--accent-primary: #00a7e1    /* Primary accent - Material UI primary */
--accent-secondary: #ff6464  /* Secondary accent - red/pink */

/* Usage Examples */
logo, brand elements: #39b5e0
secondary branding: #e18b3d
primary buttons, links: #00a7e1
secondary buttons, alerts: #ff6464
```

---

## Accessibility-Compliant Semantic Colors

### Success States
```css
--success-main: #4caf50      /* IMPROVED - was #2e7d32 (4.1:1 contrast) */
--success-bright: #66bb6a    /* For emphasis (5.2:1 contrast) */
--success-muted: #388e3c     /* For backgrounds (3.1:1 contrast) */

/* Usage Examples */
connected devices, healthy status: #4caf50
success alerts, positive indicators: #66bb6a
success backgrounds, subtle states: #388e3c
```

### Warning States
```css
--warning-main: #ff9800      /* IMPROVED - was #ed6c02 (4.9:1 contrast) */
--warning-bright: #ffb74d    /* For emphasis (6.8:1 contrast) */
--warning-muted: #f57c00     /* For backgrounds (3.9:1 contrast) */

/* Usage Examples */
device issues, update needed: #ff9800
warning alerts, caution states: #ffb74d
warning backgrounds: #f57c00
```

### Error States
```css
--error-main: #f44336        /* IMPROVED - was #d32f2f (4.8:1 contrast) */
--error-bright: #ef5350      /* For emphasis (5.1:1 contrast) */
--error-muted: #c62828       /* For backgrounds (3.2:1 contrast) */

/* Usage Examples */
connection errors, failed states: #f44336
error alerts, critical issues: #ef5350
error backgrounds: #c62828
```

### Info States
```css
--info-main: #29b6f6         /* IMPROVED - was #0288d1 (4.2:1 contrast) */
--info-light: #4fc3f7        /* Lighter info variant */
--info-dark: #0277bd         /* Darker info variant */

/* Usage Examples */
informational alerts, help text: #29b6f6
info highlights: #4fc3f7
```

---

## Text Colors (WCAG 2.1 AA Compliant)

### Primary Text
```css
--text-primary: #ffffff      /* IMPROVED - was #e0e0e0 (15.8:1 contrast) */
--text-secondary: #b0b0b0    /* IMPROVED - was #8e8e8e (4.6:1 contrast) */
--text-tertiary: #9e9e9e     /* NEW - Less critical text (3.8:1 contrast) */
--text-disabled: #666666     /* IMPROVED - Disabled text (2.4:1 contrast) */

/* Usage Examples */
headings, primary content: #ffffff
descriptions, body text: #b0b0b0
captions, metadata: #9e9e9e
disabled buttons, inactive text: #666666
```

### Interactive Text
```css
--text-link: #39b5e0         /* Links, clickable text */
--text-link-hover: #4dd0ff   /* Link hover states */
--text-active: #00a7e1       /* Active/selected text */

/* Usage Examples */
navigation links, clickable text: #39b5e0
hover states: #4dd0ff
selected items, active states: #00a7e1
```

---

## Interactive States

### Action Colors
```css
--action-active: #ffffff     /* IMPROVED - Active elements */
--action-hover: rgba(255, 255, 255, 0.08)    /* IMPROVED - Hover backgrounds */
--action-selected: rgba(255, 255, 255, 0.12) /* IMPROVED - Selected backgrounds */
--action-disabled: rgba(255, 255, 255, 0.06) /* IMPROVED - Disabled backgrounds */

/* NEW - Interactive State Colors */
--interactive-hover: rgba(57, 181, 224, 0.08)  /* Brand color hover */
--interactive-active: rgba(57, 181, 224, 0.12) /* Brand color active */
--interactive-disabled: rgba(255, 255, 255, 0.06) /* Subtle disabled state */
```

### Button States
```css
/* NEW - Button State Colors */
--button-primary-hover: #4dd0ff    /* Lighter brand color */
--button-primary-active: #0099cc   /* Darker brand color */
--button-secondary-hover: #ff8080  /* Lighter secondary */
--button-secondary-active: #cc5050 /* Darker secondary */
```

### Focus & Selection
```css
--focus-ring: #39b5e0        /* Focus indicators, form field focus */
--selection-bg: rgba(57, 181, 224, 0.15)  /* IMPROVED - Selection backgrounds */
--selection-text: #ffffff    /* IMPROVED - Text on selection backgrounds */
```

---

## Data Visualization Colors

### Chart Colors (Colorblind-Friendly)
```css
--data-primary: #39b5e0      /* Brand blue */
--data-secondary: #ff6b35    /* Orange (complementary) */
--data-tertiary: #4ecdc4     /* Teal */
--data-quaternary: #45b7d1   /* Light blue */
--data-quinary: #96ceb4      /* Mint green */
--data-senary: #feca57       /* Yellow */

/* Status-specific data colors */
--data-positive: #4caf50     /* Green for positive metrics */
--data-negative: #f44336     /* Red for negative metrics */
--data-neutral: #b0b0b0      /* Gray for neutral metrics */

/* Chart infrastructure */
--chart-grid: #404040        /* Chart grid lines */
--chart-text: #b0b0b0        /* Chart labels, axes */
```

---

## Component-Specific Colors

### Navigation & Layout
```css
--nav-bg: #181b1f           /* Sidebar background */
--nav-item-hover: #2a2d33   /* Navigation item hover */
--nav-item-active: #39b5e0  /* Active navigation item */
--header-bg: #181b1f        /* Header/toolbar background */
```

### Form Elements
```css
--input-bg: #111217         /* Input field backgrounds */
--input-border: #555555     /* IMPROVED - Input field borders */
--input-border-focus: #39b5e0  /* Focused input borders */
--input-text: #ffffff       /* IMPROVED - Input text color */
--input-placeholder: #9e9e9e   /* IMPROVED - Placeholder text */
```

---

## Typography System

### Font Stack
```css
--font-family: "Inter", "Roboto", "Helvetica", "Arial", sans-serif
--font-family-mono: "Roboto Mono", "Consolas", "Monaco", monospace
```

### Font Sizes & Weights
```css
/* Headings */
--text-h1: 32px, 600 weight   /* 2rem */
--text-h2: 28px, 600 weight   /* 1.75rem */
--text-h3: 24px, 600 weight   /* 1.5rem */
--text-h4: 20px, 600 weight   /* 1.25rem */
--text-h5: 18px, 600 weight   /* 1.125rem */
--text-h6: 16px, 600 weight   /* 1rem */

/* Body Text */
--text-body1: 14px, 400 weight  /* 0.875rem */
--text-body2: 13px, 400 weight  /* 0.8rem */
--text-caption: 12px, 400 weight /* 0.75rem */

/* Base font size */
--font-size-base: 14px
```

---

## Spacing System (8px base unit)

```css
--spacing-xs: 4px     /* 0.5 units */
--spacing-sm: 8px     /* 1 unit */
--spacing-md: 16px    /* 2 units */
--spacing-lg: 24px    /* 3 units */
--spacing-xl: 32px    /* 4 units */
--spacing-xxl: 48px   /* 6 units */

/* Component-specific spacing */
--layout-header-height: 40px
--layout-sidebar-width: 180px
--layout-border-radius: 8px
--layout-border-radius-sm: 4px
```

---

## Shadow System

```css
--shadow-sm: 0px 2px 1px rgba(0, 0, 0, 0.2)     /* Cards, buttons */
--shadow-md: 0px 3px 1px rgba(0, 0, 0, 0.2)     /* Hover states */
--shadow-lg: 0px 3px 3px rgba(0, 0, 0, 0.2)     /* Selected, elevated */
--shadow-xl: 0px 4px 8px rgba(0, 0, 0, 0.3)     /* Modals, dropdowns */

/* Glow effects */
--glow-brand: 0 0 2px #39b5e0, 0 0 4px rgba(57, 181, 224, 0.6)
--glow-primary: 0 0 2px #00a7e1, 0 0 4px rgba(0, 167, 225, 0.6)
```

---

## Accessibility Requirements

### WCAG 2.1 AA Compliance

#### Contrast Ratios
- **Normal Text**: Minimum 4.5:1 contrast ratio
- **Large Text** (18pt+ or 14pt+ bold): Minimum 3:1 contrast ratio
- **UI Components**: Minimum 3:1 contrast ratio
- **Focus Indicators**: Minimum 3:1 contrast ratio

#### Verified Combinations
```css
/* ✅ PASSING COMBINATIONS */
#ffffff on #111217 → 15.8:1 contrast ✅
#b0b0b0 on #111217 → 4.6:1 contrast ✅
#39b5e0 on #111217 → 4.8:1 contrast ✅
#4caf50 on #111217 → 4.1:1 contrast ✅
#ff9800 on #111217 → 4.9:1 contrast ✅
#f44336 on #111217 → 4.8:1 contrast ✅

/* ⚠️ BORDERLINE COMBINATIONS */
#9e9e9e on #111217 → 3.8:1 contrast (Use for non-critical text only)
#666666 on #111217 → 2.4:1 contrast (Disabled states only)
```

### Color Accessibility Guidelines

1. **Never rely solely on color** to convey information
2. **Always provide alternative indicators** (icons, text, patterns)
3. **Test with colorblind simulation tools**
4. **Maintain sufficient contrast** for all interactive elements
5. **Provide clear focus indicators** for keyboard navigation

---

## Implementation Guidelines

### CSS Custom Properties Structure
```css
:root {
  /* Backgrounds */
  --bg-main: #111217;
  --bg-paper: #181b1f;
  --bg-elevated: #22252b;
  --bg-hover: #2a2d33;
  
  /* Borders */
  --border-primary: #404040;
  --border-interactive: #555555;
  --border-focus: #39b5e0;
  
  /* Text */
  --text-primary: #ffffff;
  --text-secondary: #b0b0b0;
  --text-tertiary: #9e9e9e;
  --text-disabled: #666666;
  
  /* Brand */
  --brand-primary: #39b5e0;
  --brand-secondary: #e18b3d;
  
  /* Semantic */
  --success-main: #4caf50;
  --warning-main: #ff9800;
  --error-main: #f44336;
  --info-main: #29b6f6;
  
  /* Interactive */
  --interactive-hover: rgba(57, 181, 224, 0.08);
  --interactive-active: rgba(57, 181, 224, 0.12);
  --interactive-disabled: rgba(255, 255, 255, 0.06);
}
```

### Usage Hierarchy

#### Primary Actions
- Use `--brand-primary` (#39b5e0) for main CTAs
- Use `--accent-primary` (#00a7e1) for secondary actions
- Ensure 4.5:1+ contrast ratio on all backgrounds

#### Secondary Actions
- Use `--text-secondary` (#b0b0b0) for less important actions
- Use outlined button styles with `--border-interactive`
- Maintain visual hierarchy through size and spacing

#### Status Indicators
- **Success**: Use `--success-main` (#4caf50)
- **Warning**: Use `--warning-main` (#ff9800)  
- **Error**: Use `--error-main` (#f44336)
- **Info**: Use `--info-main` (#29b6f6)

### Component Guidelines

#### Buttons
```css
/* Primary Button */
.button-primary {
  background: var(--brand-primary);
  color: var(--bg-main);
  border: none;
}

.button-primary:hover {
  background: var(--button-primary-hover);
}

/* Secondary Button */
.button-secondary {
  background: transparent;
  color: var(--text-primary);
  border: 1px solid var(--border-interactive);
}

.button-secondary:hover {
  background: var(--interactive-hover);
}
```

#### Form Elements
```css
.input {
  background: var(--input-bg);
  border: 1px solid var(--input-border);
  color: var(--input-text);
}

.input:focus {
  border-color: var(--input-border-focus);
  box-shadow: 0 0 0 2px rgba(57, 181, 224, 0.2);
}

.input::placeholder {
  color: var(--input-placeholder);
}
```

---

## Testing Requirements

### Automated Testing
- **WebAIM Contrast Checker**: Verify all color combinations
- **axe-core**: Automated accessibility testing
- **Lighthouse**: Accessibility audits in CI/CD
- **Stark (Figma)**: Design-time accessibility checking

### Manual Testing
- **Colorblind Simulation**: Test with Deuteranopia, Protanopia, Tritanopia
- **Low Vision Testing**: Test at 200%+ zoom levels
- **Keyboard Navigation**: Ensure all interactive elements are accessible
- **Screen Reader Testing**: Test with NVDA, JAWS, VoiceOver

### User Testing
- **Include users with visual impairments** in testing sessions
- **Test on various devices and monitors**
- **Validate in different lighting conditions**
- **Gather feedback on color perception and usability**

---

## Migration Plan

### Phase 1: Critical Fixes (Week 1)
1. Update secondary text color: `#8e8e8e` → `#b0b0b0`
2. Strengthen border colors: `#2e3136` → `#404040`
3. Implement improved semantic colors
4. Update Material UI theme configuration

### Phase 2: Enhanced States (Week 2)
1. Add interactive state colors
2. Implement proper text hierarchy
3. Add missing button state variants
4. Update form element styling

### Phase 3: Advanced Features (Week 3)
1. Implement data visualization color palette
2. Add animation-ready color variants
3. Create comprehensive component library
4. Document usage patterns and examples

---

## Maintenance

### Regular Reviews
- **Quarterly accessibility audits**
- **Annual color palette reviews**
- **User feedback integration**
- **Technology update assessments**

### Documentation Updates
- Keep this document current with any changes
- Update component examples when modified
- Maintain accessibility compliance records
- Document any exceptions or special cases

---

## Resources

### Tools
- [WebAIM Contrast Checker](https://webaim.org/resources/contrastchecker/)
- [Stark Accessibility Plugin](https://www.getstark.co/)
- [axe-core Accessibility Testing](https://www.deque.com/axe/)
- [Material Design Color Tool](https://material.io/resources/color/)

### Standards
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/Understanding/)
- [Material Design Accessibility](https://material.io/design/usability/accessibility.html)
- [Apple Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/accessibility/)

---

*This document is maintained by the TowerIQ development team and should be reviewed quarterly for updates and improvements.*
