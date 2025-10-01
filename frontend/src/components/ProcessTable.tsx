/**
 * ProcessTable.tsx - Process listing and search component
 * 
 * Handles process discovery, filtering, and target process identification
 */

import React from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  CircularProgress,
  Box,
  TextField,
  Alert,
  List,
  ListItem,
} from '@mui/material';
import {
  Search as SearchIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
} from '@mui/icons-material';
import { Process } from '../hooks/useBackend';

interface ProcessTableProps {
  processes: Process[];
  processesLoading: boolean;
  processSearchTerm: string;
  onProcessSearchChange: (term: string) => void;
  targetProcessPackage: string;
  targetProcessName: string;
}

export function ProcessTable({
  processes,
  processesLoading,
  processSearchTerm,
  onProcessSearchChange,
  targetProcessPackage,
  targetProcessName
}: ProcessTableProps) {
  const filteredProcesses = processes.filter(process => 
    processSearchTerm === '' || 
    process.name.toLowerCase().includes(processSearchTerm.toLowerCase()) ||
    (process.package && process.package.toLowerCase().includes(processSearchTerm.toLowerCase()))
  );

  const filteredProcessesSorted = [...filteredProcesses].sort((a, b) => {
    const aIsTarget = a.package === targetProcessPackage;
    const bIsTarget = b.package === targetProcessPackage;
    if (aIsTarget && !bIsTarget) return -1;
    if (!aIsTarget && bIsTarget) return 1;
    return 0;
  });

  return (
    <>
      {/* Search Box */}
      <Box sx={{ mb: 2 }}>
        <TextField
          fullWidth
          size="small"
          placeholder="Search processes by name or package..."
          value={processSearchTerm}
          onChange={(e) => onProcessSearchChange(e.target.value)}
          InputProps={{
            startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
          }}
          sx={{ mb: 1 }}
        />
      </Box>
      
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        All available processes on the selected device. Use the search box above to filter processes. The Tower game should be highlighted in green if found.
      </Typography>
      
      {processesLoading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
          <CircularProgress />
        </Box>
      ) : (
        <TableContainer sx={{ maxHeight: 400, mb: 3 }}>
          <Table stickyHeader size="small">
            <TableHead>
              <TableRow>
                <TableCell>App Name</TableCell>
                <TableCell>Package</TableCell>
                <TableCell>Version</TableCell>
                <TableCell>PID</TableCell>
                <TableCell>Type</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(() => {
                if (processes.length === 0) {
                  return (
                    <TableRow>
                      <TableCell colSpan={5} align="center">
                        <Typography variant="body2" color="text.secondary">
                          No processes found. Try refreshing or check device connection.
                        </Typography>
                      </TableCell>
                    </TableRow>
                  );
                } else if (filteredProcesses.length === 0) {
                  return (
                    <TableRow>
                      <TableCell colSpan={5} align="center">
                        <Typography variant="body2" color="text.secondary">
                          No processes match your search criteria.
                        </Typography>
                      </TableCell>
                    </TableRow>
                  );
                } else {
                  return filteredProcessesSorted.map((process) => (
                    <TableRow 
                      key={process.pid}
                      sx={{ 
                        backgroundColor: process.package === targetProcessPackage ? 'success.light' : 'inherit',
                        '&:hover': { backgroundColor: 'action.hover' }
                      }}
                    >
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {process.package === targetProcessPackage && (
                            <CheckCircleIcon color="success" fontSize="small" />
                          )}
                          {process.name}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ fontFamily: 'monospace' }}>{process.package}</TableCell>
                      <TableCell>{process.version}</TableCell>
                      <TableCell>{process.pid}</TableCell>
                      <TableCell>
                        <Typography variant="body2" color="primary.main">
                          User
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ));
                }
              })()}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      
      {/* Debug Information */}
      {processes.length === 0 && !processesLoading && (
        <Alert severity="info" sx={{ mt: 2 }}>
          <Typography variant="body2">
            No processes found. This could be due to:
          </Typography>
          <List dense sx={{ mt: 1 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body2">The device may not have any user applications running</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body2">The game "The Tower" may not be installed or running</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body2">ADB permissions may be insufficient to list processes</Typography>
            </ListItem>
          </List>
          <Typography variant="body2" sx={{ mt: 1 }}>
            Try refreshing the process list or ensure the game is running on the device.
          </Typography>
        </Alert>
      )}
      
      {/* Target Process Status */}
      {processes.length > 0 && (
        <Box sx={{ mt: 2, p: 2, borderRadius: 0.5, border: 1, borderColor: 'divider' }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Target Process Status: {targetProcessName}
          </Typography>
          {processes.find(p => p.package === targetProcessPackage) ? (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CheckCircleIcon color="success" />
              <Typography variant="body2" color="success.main">
                ✓ Found! The Tower game is running and ready for connection.
              </Typography>
            </Box>
          ) : (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CancelIcon color="error" />
              <Typography variant="body2" color="error.main">
                ✗ Not found. Please ensure "The Tower" game is installed and running on the device.
              </Typography>
            </Box>
          )}
        </Box>
      )}
    </>
  );
}
