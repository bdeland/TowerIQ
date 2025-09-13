import { Box, CircularProgress, Alert } from '@mui/material';
import { ReactNode } from 'react';

interface PageStatusContainerProps {
  loading: boolean;
  error: string | null;
  onClearError: () => void;
  children: ReactNode;
}

export function PageStatusContainer({ 
  loading, 
  error, 
  onClearError, 
  children 
}: PageStatusContainerProps) {
  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {/* Error Alert */}
      {error && (
        <Alert severity="error" onClose={onClearError} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {children}
    </Box>
  );
}
