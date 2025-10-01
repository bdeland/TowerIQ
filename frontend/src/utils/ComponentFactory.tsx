/**
 * Component Factory for A/B Testing Dashboard Refactor
 * 
 * Provides feature flag-controlled component selection between legacy and new
 * dashboard implementations. Enables gradual rollout and easy rollback.
 */

import React, { Suspense, ComponentType } from 'react';
import { Box, CircularProgress } from '@mui/material';
import { featureFlags } from '../config/featureFlags';

// Lazy load new components to avoid import errors when feature flag is disabled
const NewDashboardViewPage = React.lazy(() => 
  import('../pages/NewDashboardViewPage').then(module => ({ 
    default: module.NewDashboardViewPage 
  }))
);

const NewDashboardPanelView = React.lazy(() => 
  import('../components/NewDashboardPanelView').then(module => ({ 
    default: module.NewDashboardPanelView 
  }))
);

const NewDashboardGrid = React.lazy(() => 
  import('../components/NewDashboardGrid').then(module => ({ 
    default: module.NewDashboardGrid 
  }))
);

const NewDashboardHeader = React.lazy(() => 
  import('../components/NewDashboardHeader').then(module => ({ 
    default: module.NewDashboardHeader 
  }))
);

const NewDashboardVariableControls = React.lazy(() => 
  import('../components/NewDashboardVariableControls').then(module => ({ 
    default: module.NewDashboardVariableControls 
  }))
);

// Lazy load legacy components for performance
const LegacyDashboardViewPage = React.lazy(() => 
  import('../pages/DashboardViewPage').then(module => ({ 
    default: module.DashboardViewPage 
  }))
);

const LegacyDashboardPanelView = React.lazy(() => 
  import('../components/DashboardPanelView').then(module => ({ 
    default: module.default 
  }))
);

const LegacyDashboardGrid = React.lazy(() => 
  import('../components/DashboardGrid').then(module => ({ 
    default: module.DashboardGrid 
  }))
);

// Loading fallback component
const ComponentLoadingFallback: React.FC = () => (
  <Box sx={{ 
    display: 'flex', 
    justifyContent: 'center', 
    alignItems: 'center', 
    height: '200px' 
  }}>
    <CircularProgress />
  </Box>
);

// Full page loading fallback
const PageLoadingFallback: React.FC = () => (
  <Box sx={{ 
    display: 'flex', 
    justifyContent: 'center', 
    alignItems: 'center', 
    height: '50vh' 
  }}>
    <CircularProgress size={60} />
  </Box>
);

/**
 * Component factory that returns the appropriate component based on feature flags
 */
export class ComponentFactory {
  /**
   * Get dashboard view page component
   */
  static DashboardViewPage(): ComponentType<any> {
    if (featureFlags.dashboardRefactorEnabled) {
      return (props) => (
        <Suspense fallback={<PageLoadingFallback />}>
          <NewDashboardViewPage {...props} />
        </Suspense>
      );
    }
    
    return (props) => (
      <Suspense fallback={<PageLoadingFallback />}>
        <LegacyDashboardViewPage {...props} />
      </Suspense>
    );
  }
  
  /**
   * Get dashboard panel view component
   */
  static DashboardPanelView(): ComponentType<any> {
    if (featureFlags.dashboardRefactorEnabled) {
      return (props) => (
        <Suspense fallback={<ComponentLoadingFallback />}>
          <NewDashboardPanelView {...props} />
        </Suspense>
      );
    }
    
    return (props) => (
      <Suspense fallback={<ComponentLoadingFallback />}>
        <LegacyDashboardPanelView {...props} />
      </Suspense>
    );
  }
  
  /**
   * Get dashboard grid component
   */
  static DashboardGrid(): ComponentType<any> {
    if (featureFlags.dashboardRefactorEnabled) {
      return (props) => (
        <Suspense fallback={<ComponentLoadingFallback />}>
          <NewDashboardGrid {...props} />
        </Suspense>
      );
    }
    
    return (props) => (
      <Suspense fallback={<ComponentLoadingFallback />}>
        <LegacyDashboardGrid {...props} />
      </Suspense>
    );
  }
  
  /**
   * Get dashboard header component
   */
  static DashboardHeader(): ComponentType<any> {
    if (featureFlags.dashboardRefactorEnabled) {
      return (props) => (
        <Suspense fallback={<ComponentLoadingFallback />}>
          <NewDashboardHeader {...props} />
        </Suspense>
      );
    }
    
    // Legacy doesn't have a separate header component, return null
    return () => null;
  }
  
  /**
   * Get dashboard variable controls component
   */
  static DashboardVariableControls(): ComponentType<any> {
    if (featureFlags.dashboardRefactorEnabled) {
      return (props) => (
        <Suspense fallback={<ComponentLoadingFallback />}>
          <NewDashboardVariableControls {...props} />
        </Suspense>
      );
    }
    
    // Legacy uses DashboardVariableContext, return null for now
    return () => null;
  }
}

/**
 * Hook-based component factory for use in functional components
 */
export function useComponentFactory() {
  const isDashboardRefactorEnabled = featureFlags.dashboardRefactorEnabled;
  
  return {
    DashboardViewPage: ComponentFactory.DashboardViewPage(),
    DashboardPanelView: ComponentFactory.DashboardPanelView(),
    DashboardGrid: ComponentFactory.DashboardGrid(),
    DashboardHeader: ComponentFactory.DashboardHeader(),
    DashboardVariableControls: ComponentFactory.DashboardVariableControls(),
    
    // Utility flags
    isNewImplementation: isDashboardRefactorEnabled,
    isLegacyImplementation: !isDashboardRefactorEnabled,
  };
}

/**
 * Higher-order component for feature flag controlled rendering
 */
export function withFeatureFlag<P extends object>(
  NewComponent: ComponentType<P>,
  LegacyComponent: ComponentType<P>,
  fallback?: ComponentType<P>
) {
  return (props: P) => {
    if (featureFlags.dashboardRefactorEnabled) {
      return <NewComponent {...props} />;
    }
    
    const Component = LegacyComponent;
    const FallbackComponent = fallback || ComponentLoadingFallback;
    
    return (
      <Suspense fallback={<FallbackComponent {...props} />}>
        <Component {...props} />
      </Suspense>
    );
  };
}

/**
 * Feature flag controlled router for different implementations
 */
export const FeatureFlagRouter = {
  /**
   * Route to appropriate dashboard view based on feature flag
   */
  DashboardView: (props: any) => {
    if (featureFlags.dashboardRefactorEnabled) {
      return (
        <Suspense fallback={<PageLoadingFallback />}>
          <NewDashboardViewPage {...props} />
        </Suspense>
      );
    }
    
    return (
      <Suspense fallback={<PageLoadingFallback />}>
        <LegacyDashboardViewPage {...props} />
      </Suspense>
    );
  },
  
  /**
   * Route to appropriate panel view based on feature flag
   */
  PanelView: (props: any) => {
    if (featureFlags.dashboardRefactorEnabled) {
      return (
        <Suspense fallback={<ComponentLoadingFallback />}>
          <NewDashboardPanelView {...props} />
        </Suspense>
      );
    }
    
    return (
      <Suspense fallback={<ComponentLoadingFallback />}>
        <LegacyDashboardPanelView {...props} />
      </Suspense>
    );
  },
};

/**
 * Utility functions for feature flag management
 */
export const FeatureFlagUtils = {
  /**
   * Check if dashboard refactor is enabled
   */
  isDashboardRefactorEnabled(): boolean {
    return featureFlags.dashboardRefactorEnabled;
  },
  
  /**
   * Get current implementation name
   */
  getCurrentImplementation(): 'new' | 'legacy' {
    return featureFlags.dashboardRefactorEnabled ? 'new' : 'legacy';
  },
  
  /**
   * Log current feature flag state (for debugging)
   */
  logFeatureFlagState(): void {
    console.log('Dashboard Refactor Feature Flags:', {
      dashboardRefactorEnabled: featureFlags.dashboardRefactorEnabled,
      currentImplementation: this.getCurrentImplementation(),
      timestamp: new Date().toISOString(),
    });
  },
  
  /**
   * Validate feature flag configuration
   */
  validateConfiguration(): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (typeof featureFlags.dashboardRefactorEnabled !== 'boolean') {
      errors.push('dashboardRefactorEnabled must be a boolean');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
    };
  },
};
