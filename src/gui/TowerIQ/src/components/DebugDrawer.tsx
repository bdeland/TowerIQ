// ============================================================================
// DEBUG DRAWER COMPONENT - Panel debugging information and query transformation
// ============================================================================

import React, { useState, useCallback, useRef, useEffect } from 'react';
// Material-UI components for UI elements
import { 
  Box, 
  Typography, 
  CircularProgress, 
  IconButton, 
  Tooltip,
  Drawer,
  Divider,
  Paper,
  Button,
  Snackbar,
  Alert
} from '@mui/material';
// Material-UI icons
import { 
  BugReport as BugReportIcon,
  DataObject as DataObjectIcon,
  ContentCopy as ContentCopyIcon
} from '@mui/icons-material';
// Internal imports
import { DashboardPanel } from '../contexts/DashboardContext';
import { useDashboardVariable } from '../contexts/DashboardVariableContext';
import { composeQuery } from '../utils/queryComposer';
import { format } from 'sql-formatter';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { API_CONFIG } from '../config/environment';
import { useDebugDrawerWidth } from '../hooks/useDebugDrawerWidth';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

interface DebugDrawerProps {
  open: boolean;
  onClose: () => void;
  panel: DashboardPanel;
  queryResult: { data: any[] };
  loading: boolean;
  error: string | null;
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

/**
 * Debug Drawer Component
 * Shows query transformation information and panel debug details
 * Only visible in development mode
 */
const DebugDrawer: React.FC<DebugDrawerProps> = ({
  open,
  onClose,
  panel,
  queryResult,
  loading,
  error
}) => {
  // Toast state for copy notifications
  const [toastOpen, setToastOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  
  // Global drawer width management
  const { drawerWidth, updateDrawerWidth, persistDrawerWidth, DEFAULT_WIDTH, SNAP_THRESHOLD } = useDebugDrawerWidth();
  
  // Resize state and refs
  const [isResizing, setIsResizing] = useState(false);
  const resizeRef = useRef<HTMLDivElement>(null);
  const startXRef = useRef<number>(0);
  const startWidthRef = useRef<number>(DEFAULT_WIDTH);
  // Get dashboard variables for query transformation
  let selectedValues = {};
  try {
    const dashboardVariableContext = useDashboardVariable();
    selectedValues = dashboardVariableContext.selectedValues;
  } catch (error) {
    // Dashboard variable context not available, use empty values
    selectedValues = {};
  }

  // Transform the query to show the difference
  const originalQuery = panel.query || '';
  const transformedQuery = originalQuery ? composeQuery(originalQuery, selectedValues) : '';

  // Debug logging
  if (import.meta.env.DEV) {
    console.log('Debug drawer - Panel query info:', {
      panelId: panel.id,
      hasQuery: !!panel.query,
      queryLength: originalQuery.length,
      queryPreview: originalQuery.substring(0, 100),
      transformedLength: transformedQuery.length
    });
  }


  // Resize handlers
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    setIsResizing(true);
    startXRef.current = e.clientX;
    startWidthRef.current = drawerWidth;
    
    const handleMouseMove = (e: MouseEvent) => {
      e.preventDefault();
      
      // Calculate delta - for right-anchored drawer, moving left increases width
      const deltaX = startXRef.current - e.clientX;
      let newWidth = Math.max(300, Math.min(1200, startWidthRef.current + deltaX)); // Min 300px, Max 1200px
      
      // Snap to default width if within threshold
      if (Math.abs(newWidth - DEFAULT_WIDTH) <= SNAP_THRESHOLD) {
        newWidth = DEFAULT_WIDTH;
      }
      
      updateDrawerWidth(newWidth);
    };
    
    const handleMouseUp = (e: MouseEvent) => {
      e.preventDefault();
      setIsResizing(false);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = 'default';
      document.body.style.userSelect = 'auto';
      
      // Save the final width to database
      const currentWidth = drawerWidth;
      persistDrawerWidth(currentWidth);
    };
    
    // Prevent text selection during drag
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [drawerWidth, updateDrawerWidth, persistDrawerWidth, DEFAULT_WIDTH, SNAP_THRESHOLD]);

  // Helper function to format SQL queries
  const formatSqlQuery = (query: string): string => {
    if (!query.trim()) return query;
    
    try {
      // First, temporarily replace placeholders to make the query parseable
      let tempQuery = query;
      const placeholders: { [key: string]: string } = {};
      
      // Find and replace placeholders like ${variable_name}
      const placeholderMatches = query.match(/\$\{[^}]+\}/g) || [];
      placeholderMatches.forEach((placeholder, index) => {
        const tempReplacement = `PLACEHOLDER_${index}`;
        placeholders[tempReplacement] = placeholder;
        tempQuery = tempQuery.replace(placeholder, tempReplacement);
      });
      
      // Format the query with SQLite dialect
      const formatted = format(tempQuery, {
        language: 'sqlite',
        keywordCase: 'upper',
        linesBetweenQueries: 2,
        indentStyle: 'standard'
      });
      
      // Restore the original placeholders
      let finalQuery = formatted;
      Object.entries(placeholders).forEach(([temp, original]) => {
        finalQuery = finalQuery.replace(new RegExp(temp, 'g'), original);
      });
      
      if (import.meta.env.DEV) {
        console.log('SQL formatted successfully for panel:', panel.id);
      }
      return finalQuery;
    } catch (error) {
      // If formatting fails, return original query with basic cleanup
      console.warn('SQL formatting failed for panel:', panel.id, 'Error:', error);
      // At least provide basic indentation cleanup
      return query
        .replace(/\s+/g, ' ') // Replace multiple spaces with single space
        .replace(/,\s*/g, ',\n    ') // Add line breaks after commas
        .replace(/\bFROM\b/gi, '\nFROM')
        .replace(/\bWHERE\b/gi, '\nWHERE')
        .replace(/\bORDER BY\b/gi, '\nORDER BY')
        .replace(/\bGROUP BY\b/gi, '\nGROUP BY')
        .replace(/\bHAVING\b/gi, '\nHAVING')
        .trim();
    }
  };

  // Helper function to render SQL with copy button
  const renderSqlWithVariables = (query: string, label: string = 'Query') => {
    if (!query.trim()) return null;
    
    const formattedQuery = formatSqlQuery(query);

    // Copy to clipboard function
    const handleCopy = async () => {
      try {
        await navigator.clipboard.writeText(query);
        setToastMessage(`${label} copied to clipboard`);
        setToastOpen(true);
        if (import.meta.env.DEV) {
          console.log(`${label} copied to clipboard`);
        }
      } catch (err) {
        console.error('Failed to copy to clipboard:', err);
        // Fallback for older browsers
        try {
          const textArea = document.createElement('textarea');
          textArea.value = query;
          document.body.appendChild(textArea);
          textArea.select();
          document.execCommand('copy');
          document.body.removeChild(textArea);
          setToastMessage(`${label} copied to clipboard`);
          setToastOpen(true);
        } catch (fallbackErr) {
          console.error('Fallback copy also failed:', fallbackErr);
          setToastMessage('Failed to copy to clipboard');
          setToastOpen(true);
        }
      }
    };
    
    return (
      <Box sx={{ position: 'relative' }}>
        {/* Copy button */}
        <IconButton
          onClick={handleCopy}
          size="small"
          sx={{
            position: 'absolute',
            top: 8,
            right: 8,
            zIndex: 10,
            color: 'text.secondary',
            width: 28,
            height: 28,
            backgroundColor: 'transparent',
            '&:hover': {
              backgroundColor: 'action.hover',
              color: 'text.primary'
            }
          }}
        >
          <ContentCopyIcon sx={{ fontSize: 14 }} />
        </IconButton>

        {/* SyntaxHighlighter with orange variable highlighting */}
        <SyntaxHighlighter
          language="sql"
          style={vscDarkPlus}
          customStyle={{
            margin: 0,
            padding: '16px',
            paddingRight: '48px', // Make room for copy button
            backgroundColor: 'transparent',
            fontSize: '0.875rem'
          }}
          wrapLongLines={true}
          PreTag={({ children, ...props }) => {
            // Process the content to highlight variables in orange
            if (typeof children === 'string') {
              // Split by variable patterns and highlight them
              const parts = children.split(/(\$\{[^}]+\}|AND tier IN \([^)]+\)|LIMIT \d+)/g);
              const processedContent = parts.map((part, index) => {
                // Check if this part is a variable placeholder
                if (part.match(/^\$\{[^}]+\}$/)) {
                  return (
                    <span key={index} style={{ color: '#e06339', fontWeight: 'bold' }}>
                      {part}
                    </span>
                  );
                }
                // Check for transformed variable values (tier filtering and limits)
                if (part.match(/^AND tier IN \([^)]+\)$/) || part.match(/^LIMIT \d+$/)) {
                  return (
                    <span key={index} style={{ color: '#e06339', fontWeight: 'bold' }}>
                      {part}
                    </span>
                  );
                }
                return <span key={index}>{part}</span>;
              });
              
              return <pre {...props}>{processedContent}</pre>;
            }
            return <pre {...props}>{children}</pre>;
          }}
        >
          {formattedQuery}
        </SyntaxHighlighter>
      </Box>
    );
  };

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      variant="temporary"
      sx={{
        '& .MuiDrawer-paper': {
          width: drawerWidth,
          padding: 0,
          backgroundColor: 'background.paper',
          position: 'fixed',
          right: 0,
          top: 0,
          height: '100vh'
        }
      }}
    >
      {/* Resize Handle */}
      <Box
        ref={resizeRef}
        onMouseDown={handleMouseDown}
        sx={{
          position: 'absolute',
          left: -2, // Extend slightly outside for easier grabbing
          top: 0,
          bottom: 0,
          width: '6px', // Slightly wider for easier interaction
          cursor: 'col-resize',
          backgroundColor: isResizing ? 'primary.main' : 'transparent',
          borderLeft: '2px solid',
          borderLeftColor: isResizing ? 'primary.main' : 'divider',
          zIndex: 1001,
          '&:hover': {
            backgroundColor: 'primary.main',
            borderLeftColor: 'primary.main',
            opacity: 0.8
          },
          '&:active': {
            backgroundColor: 'primary.main',
            borderLeftColor: 'primary.main'
          },
          transition: 'all 0.2s ease'
        }}
      />
      <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', paddingLeft: '4px', padding: 2 }}>
        {/* Header */}
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <BugReportIcon sx={{ mr: 1, color: 'primary.main' }} />
          <Typography variant="h6" component="h2">
            Panel Debug Information
          </Typography>
        </Box>
        
        <Divider sx={{ mb: 2 }} />

        {/* Panel Information */}
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
            Panel Details
          </Typography>
          <Paper sx={{ p: 2, backgroundColor: 'background.default', border: '1px solid', borderColor: 'divider' }}>
            <Typography variant="body2" sx={{ mb: 1, color: 'text.primary' }}>
              <strong>ID:</strong> {panel.id}
            </Typography>
            <Typography variant="body2" sx={{ mb: 1, color: 'text.primary' }}>
              <strong>Title:</strong> {panel.title}
            </Typography>
            <Typography variant="body2" sx={{ mb: 1, color: 'text.primary' }}>
              <strong>Type:</strong> {panel.type}
            </Typography>
            {panel.columnMapping && (
              <Typography variant="body2" sx={{ color: 'text.primary' }}>
                <strong>Column Mapping:</strong> {JSON.stringify(panel.columnMapping, null, 2)}
              </Typography>
            )}
          </Paper>
        </Box>

        {/* Query Transformation */}
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
            Query Transformation
          </Typography>
          
          {/* Variables */}
          {Object.keys(selectedValues).length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" sx={{ fontWeight: 500, mb: 1 }}>
                Variables:
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                {Object.entries(selectedValues).map(([key, value]) => (
                  <Box
                    key={key}
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      backgroundColor: '#e06339',
                      color: 'white',
                      borderRadius: '16px',
                      padding: '4px 12px',
                      fontSize: '0.8125rem',
                      fontWeight: 500,
                      gap: 1
                    }}
                  >
                    {/* Icon */}
                    <DataObjectIcon sx={{ fontSize: '14px', color: 'white' }} />
                    
                    {/* Vertical divider */}
                    <Box
                      sx={{
                        width: '1px',
                        height: '16px',
                        backgroundColor: 'rgba(255, 255, 255, 0.3)',
                        flexShrink: 0
                      }}
                    />
                    
                    {/* Variable name */}
                    <Typography
                      variant="body2"
                      sx={{
                        color: 'white',
                        fontSize: 'inherit',
                        fontWeight: 'inherit',
                        lineHeight: 1
                      }}
                    >
                      {key}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </Box>
          )}

          {/* Original Query */}
          <Box sx={{ mb: 2 }}>
            <Typography variant="body2" sx={{ fontWeight: 500, mb: 1 }}>
              Original Query:
            </Typography>
            <Paper 
              sx={{ 
                p: 0, 
                backgroundColor: 'background.default',
                overflow: 'auto',
                border: '1px solid',
                borderColor: 'divider'
              }}
            >
              {originalQuery.trim() ? (
                renderSqlWithVariables(originalQuery, 'Original Query')
              ) : (
                <Box sx={{ p: 2, color: 'text.secondary', fontStyle: 'italic' }}>
                  No query defined
                </Box>
              )}
            </Paper>
          </Box>

          {/* Transformed Query */}
          {originalQuery && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" sx={{ fontWeight: 500, mb: 1 }}>
                Transformed Query:
              </Typography>
              <Paper 
                sx={{ 
                  p: 0, 
                  backgroundColor: 'background.default',
                  overflow: 'auto',
                  border: '1px solid',
                  borderColor: 'divider'
                }}
              >
                {renderSqlWithVariables(transformedQuery, 'Transformed Query')}
              </Paper>
            </Box>
          )}
        </Box>

        {/* Data Information */}
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
            Data Information
          </Typography>
          <Paper sx={{ p: 2, backgroundColor: 'background.default', border: '1px solid', borderColor: 'divider' }}>
            {loading ? (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <CircularProgress size={16} />
                <Typography variant="body2" sx={{ color: 'text.primary' }}>
                  <strong>Loading data...</strong>
                </Typography>
              </Box>
            ) : (
              <>
                <Typography variant="body2" sx={{ mb: 1, color: 'text.primary' }}>
                  <strong>Rows:</strong> {queryResult.data?.length || 0}
                </Typography>
                {queryResult.data?.length > 0 && (
                  <Typography variant="body2" sx={{ mb: 1, color: 'text.primary' }}>
                    <strong>Columns:</strong> {Object.keys(queryResult.data[0]).join(', ')}
                  </Typography>
                )}
              </>
            )}
            <Typography variant="body2" sx={{ color: 'text.primary' }}>
              <strong>Status:</strong> {loading ? 'Loading...' : 'Ready'}
            </Typography>
            {error && (
              <Typography variant="body2" sx={{ color: 'error.main' }}>
                <strong>Error:</strong> {error}
              </Typography>
            )}
          </Paper>
        </Box>

        {/* Close button */}
        <Box sx={{ mt: 'auto', pt: 2 }}>
          <Button 
            variant="contained" 
            onClick={onClose}
            fullWidth
          >
            Close
          </Button>
        </Box>
      </Box>

      {/* Toast notification for copy actions */}
      <Snackbar 
        open={toastOpen} 
        autoHideDuration={2000} 
        onClose={() => setToastOpen(false)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert 
          onClose={() => setToastOpen(false)} 
          severity={toastMessage.includes('Failed') ? 'error' : 'success'} 
          sx={{ width: '100%' }}
        >
          {toastMessage}
        </Alert>
      </Snackbar>
    </Drawer>
  );
};

export default DebugDrawer;
