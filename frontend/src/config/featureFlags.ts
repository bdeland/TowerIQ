// Centralized feature flags configuration
export const featureFlags = {
  enableAdHocDashboards: false, // Set to false to hide ad-hoc dashboard features
  dashboardRefactorEnabled: false, // Controls whether new hierarchical dashboard system is active
} as const;

export type FeatureFlags = typeof featureFlags;
