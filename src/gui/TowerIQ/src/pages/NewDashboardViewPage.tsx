import React, { useEffect, useCallback, useMemo, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Box, Typography, Alert, CircularProgress, Skeleton } from '@mui/material';
import { useDashboard } from '../hooks/useDashboard';
import { useNewDashboard } from '../contexts/NewDashboardContext';
import { NewDashboardGrid } from '../components/NewDashboardGrid';
import { NewDashboardHeader } from '../components/NewDashboardHeader';
import { DashboardLayout } from '../components/DashboardLayout';
import { useDeveloper } from '../contexts/DeveloperContext';

interface NewDashboardViewPageProps {
  dashboardId?: string;
}

export const NewDashboardViewPage: React.FC<NewDashboardViewPageProps> = ({ dashboardId: propDashboardId }) => {
  const { id: paramDashboardId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { isDevMode } = useDeveloper();
  
  const dashboardId = propDashboardId || paramDashboardId;
  
  // Use the new domain model hook
  const { 
    dashboard, 
    loading, 
    error, 
    panelStates, 
    metadata,
    panels,
    variables,
    actions,
    subscribe 
  } = useDashboard({ 
    dashboardId, 
    autoLoad: true 
  });

  // Loading state
  if (loading && !dashboard) {
    return <DashboardSkeleton />;
  }

  // Error state
  if (error && !dashboard) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert 
          severity="error" 
          action={
            <button onClick={() => dashboardId && actions.loadDashboard(dashboardId)}>
              Retry
            </button>
          }
        >
          Failed to load dashboard: {error.message}
        </Alert>
      </Box>
    );
  }

  // No dashboard found
  if (!dashboard && !loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning">
          Dashboard not found. 
          <button onClick={() => navigate('/dashboards')}>
            Go to Dashboards
          </button>
        </Alert>
      </Box>
    );
  }

  if (!dashboard) return null;

  return (
    <DashboardLayout>
      <NewDashboardHeader 
        dashboard={dashboard}
        variables={variables}
        onVariableChange={actions.updateVariable}
        onRefresh={actions.refreshDashboard}
        isDevMode={isDevMode}
      />
      <NewDashboardGrid 
        panels={panels}
        panelStates={panelStates}
        onPanelRefresh={actions.refreshPanel}
        onPanelUpdate={actions.updatePanel}
        onPanelDelete={actions.removePanel}
        dashboard={dashboard}
        isDevMode={isDevMode}
      />
    </DashboardLayout>
  );
};

// Skeleton loading component
const DashboardSkeleton: React.FC = () => {
  return (
    <Box sx={{ p: 2 }}>
      {/* Header skeleton */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Skeleton variant="text" width={300} height={40} />
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Skeleton variant="rectangular" width={100} height={32} />
          <Skeleton variant="rectangular" width={100} height={32} />
        </Box>
      </Box>
      
      {/* Variables skeleton */}
      <Box sx={{ mb: 3, display: 'flex', gap: 2 }}>
        <Skeleton variant="rectangular" width={150} height={40} />
        <Skeleton variant="rectangular" width={120} height={40} />
      </Box>
      
      {/* Grid skeleton */}
      <Box sx={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(24, 1fr)',
        gap: 1,
        minHeight: '600px'
      }}>
        {/* Mock panel skeletons */}
        <Box sx={{ gridColumn: 'span 12', gridRow: 'span 4' }}>
          <Skeleton variant="rectangular" width="100%" height="100%" />
        </Box>
        <Box sx={{ gridColumn: 'span 12', gridRow: 'span 4' }}>
          <Skeleton variant="rectangular" width="100%" height="100%" />
        </Box>
        <Box sx={{ gridColumn: 'span 8', gridRow: 'span 3' }}>
          <Skeleton variant="rectangular" width="100%" height="100%" />
        </Box>
        <Box sx={{ gridColumn: 'span 8', gridRow: 'span 3' }}>
          <Skeleton variant="rectangular" width="100%" height="100%" />
        </Box>
        <Box sx={{ gridColumn: 'span 8', gridRow: 'span 3' }}>
          <Skeleton variant="rectangular" width="100%" height="100%" />
        </Box>
      </Box>
    </Box>
  );
};

// Feature flag controlled wrapper component
export const DashboardViewPageWrapper: React.FC = () => {
  const { featureFlags } = useFeatureFlags();
  
  if (featureFlags.dashboardRefactorEnabled) {
    return <NewDashboardViewPage />;
  }
  
  // Import and render legacy component
  const LegacyDashboardViewPage = React.lazy(() => 
    import('./DashboardViewPage').then(module => ({ default: module.DashboardViewPage }))
  );
  
  return (
    <React.Suspense fallback={<DashboardSkeleton />}>
      <LegacyDashboardViewPage />
    </React.Suspense>
  );
};

// Hook for feature flags (will need to be implemented)
function useFeatureFlags() {
  // This would come from the existing feature flags system
  return {
    featureFlags: {
      dashboardRefactorEnabled: false, // Will be controlled by the existing system
    }
  };
}
