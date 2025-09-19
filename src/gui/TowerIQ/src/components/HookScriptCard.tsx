import {
  Box,
  Typography,
  Chip,
  Radio,
  Paper,
} from '@mui/material';
import { HookScript } from '../hooks/useBackend';

interface HookScriptCardProps {
  script: HookScript;
  selected: boolean;
  onSelect: (script: HookScript) => void;
}

export function HookScriptCard({ script, selected, onSelect }: HookScriptCardProps) {
  return (
    <Paper
      elevation={selected ? 3 : 1}
      sx={{
        p: 2,
        border: 2,
        borderColor: selected ? 'primary.main' : 'divider',
        borderRadius: 2,
        cursor: 'pointer',
        transition: 'all 0.2s ease-in-out',
        '&:hover': {
          elevation: 2,
          borderColor: 'primary.light',
        },
        backgroundColor: selected ? 'primary.light' : 'background.paper',
      }}
      onClick={() => onSelect(script)}
    >
      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
        <Radio
          checked={selected}
          onChange={() => onSelect(script)}
          onClick={(e) => e.stopPropagation()}
          size="small"
          sx={{ mt: 0.5 }}
        />
        
        <Box sx={{ flex: 1 }}>
          <Typography variant="h6" sx={{ mb: 1, fontWeight: 'bold' }}>
            {script.name}
          </Typography>
          
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {script.description}
          </Typography>
          
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {script.fileName && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="caption" color="text.secondary">
                  File:
                </Typography>
                <Typography variant="caption" fontFamily="monospace" sx={{ fontWeight: 'bold' }}>
                  {script.fileName}
                </Typography>
              </Box>
            )}
            
            {script.targetPackage && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="caption" color="text.secondary">
                  Target Package:
                </Typography>
                <Typography variant="caption" fontFamily="monospace" sx={{ fontWeight: 'bold' }}>
                  {script.targetPackage}
                </Typography>
              </Box>
            )}
            
            {script.targetApp && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="caption" color="text.secondary">
                  Target App:
                </Typography>
                <Typography variant="caption" sx={{ fontWeight: 'bold' }}>
                  {script.targetApp}
                </Typography>
              </Box>
            )}
            
            {script.supportedVersions && script.supportedVersions.length > 0 && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                <Typography variant="caption" color="text.secondary">
                  Supported versions:
                </Typography>
                {script.supportedVersions.map((version, index) => (
                  <Chip
                    key={index}
                    label={version}
                    size="small"
                    variant="outlined"
                    sx={{ height: 20, fontSize: '0.7rem' }}
                  />
                ))}
              </Box>
            )}
          </Box>
        </Box>
      </Box>
    </Paper>
  );
}
