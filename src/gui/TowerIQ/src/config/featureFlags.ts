// Centralized feature flags configuration
export const featureFlags = {
  enableAdHocDashboards: false, // Set to false to hide ad-hoc dashboard features
} as const;

export type FeatureFlags = typeof featureFlags;
