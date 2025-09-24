import React, { useState, useCallback, useMemo } from 'react';
import {
  Box,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  OutlinedInput,
  TextField,
  Slider,
  Switch,
  FormControlLabel,
  Alert,
  Tooltip,
  Typography,
  CircularProgress,
} from '@mui/material';
import { SelectChangeEvent } from '@mui/material/Select';
import { 
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon 
} from '@mui/icons-material';
import { DashboardVariables } from '../domain/dashboard/DashboardVariables';
import type { 
  VariableDefinition, 
  VariableValues, 
  VariableValidationResult,
  VariableOption 
} from '../domain/dashboard/types';

interface NewDashboardVariableControlsProps {
  variables: DashboardVariables;
  selectedValues: VariableValues;
  onChange: (name: string, value: any) => void;
  disabled?: boolean;
  showValidation?: boolean;
}

export const NewDashboardVariableControls: React.FC<NewDashboardVariableControlsProps> = ({
  variables,
  selectedValues,
  onChange,
  disabled = false,
  showValidation = true,
}) => {
  const [loadingOptions, setLoadingOptions] = useState<Set<string>>(new Set());
  const [validationResults, setValidationResults] = useState<Map<string, VariableValidationResult>>(new Map());

  // Get all variable definitions
  const variableDefinitions = useMemo(() => {
    return Array.from(variables.definitions.entries());
  }, [variables.definitions]);

  // Validate a variable value
  const validateVariable = useCallback(async (name: string, value: any) => {
    if (!showValidation) return;
    
    try {
      const result = variables.validate(name, value);
      setValidationResults(prev => new Map(prev.set(name, result)));
    } catch (error) {
      console.error(`Error validating variable ${name}:`, error);
    }
  }, [variables, showValidation]);

  // Handle variable change with validation
  const handleVariableChange = useCallback(async (name: string, value: any) => {
    onChange(name, value);
    await validateVariable(name, value);
  }, [onChange, validateVariable]);

  // Load dynamic options for a variable
  const loadVariableOptions = useCallback(async (name: string) => {
    setLoadingOptions(prev => new Set(prev.add(name)));
    
    try {
      await variables.loadDynamicOptions(name);
    } catch (error) {
      console.error(`Error loading options for variable ${name}:`, error);
    } finally {
      setLoadingOptions(prev => {
        const newSet = new Set(prev);
        newSet.delete(name);
        return newSet;
      });
    }
  }, [variables]);

  // Render validation indicator
  const renderValidationIndicator = (name: string) => {
    if (!showValidation) return null;
    
    const result = validationResults.get(name);
    if (!result) return null;

    const icon = result.isValid ? (
      <CheckCircleIcon color="success" fontSize="small" />
    ) : (
      <ErrorIcon color="error" fontSize="small" />
    );

    const tooltip = result.isValid ? 
      'Valid value' : 
      result.errors.join(', ');

    return (
      <Tooltip title={tooltip}>
        <Box sx={{ display: 'flex', alignItems: 'center', ml: 1 }}>
          {icon}
        </Box>
      </Tooltip>
    );
  };

  // Render individual variable control
  const renderVariableControl = (name: string, definition: VariableDefinition) => {
    const currentValue = selectedValues[name] ?? definition.defaultValue;
    const options = variables.getOptions(name);
    const isLoading = loadingOptions.has(name);
    const validationResult = validationResults.get(name);
    const hasError = validationResult && !validationResult.isValid;

    switch (definition.type) {
      case 'static':
        return (
          <FormControl 
            key={name} 
            size="small" 
            disabled={disabled}
            error={hasError}
            sx={{ minWidth: 150 }}
          >
            <InputLabel>{definition.label}</InputLabel>
            <Select
              value={currentValue || ''}
              onChange={(e) => handleVariableChange(name, e.target.value)}
              input={<OutlinedInput label={definition.label} />}
              endAdornment={
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  {isLoading && <CircularProgress size={16} />}
                  {renderValidationIndicator(name)}
                </Box>
              }
            >
              {options.map((option) => (
                <MenuItem key={String(option.value)} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        );

      case 'multiselect':
        return (
          <FormControl 
            key={name} 
            size="small" 
            disabled={disabled}
            error={hasError}
            sx={{ minWidth: 200 }}
          >
            <InputLabel>{definition.label}</InputLabel>
            <Select
              multiple
              value={Array.isArray(currentValue) ? currentValue : []}
              onChange={(e) => handleVariableChange(name, e.target.value)}
              input={<OutlinedInput label={definition.label} />}
              renderValue={(selected) => (
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {(selected as any[]).map((value) => {
                    const option = options.find(opt => opt.value === value);
                    return (
                      <Chip 
                        key={String(value)} 
                        label={option?.label || String(value)} 
                        size="small" 
                      />
                    );
                  })}
                </Box>
              )}
              endAdornment={
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  {isLoading && <CircularProgress size={16} />}
                  {renderValidationIndicator(name)}
                </Box>
              }
            >
              {options.map((option) => (
                <MenuItem key={String(option.value)} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        );

      case 'query':
        // Query-backed variable with dynamic options
        return (
          <FormControl 
            key={name} 
            size="small" 
            disabled={disabled}
            error={hasError}
            sx={{ minWidth: 150 }}
            onFocus={() => !isLoading && options.length === 0 && loadVariableOptions(name)}
          >
            <InputLabel>{definition.label}</InputLabel>
            <Select
              value={currentValue || ''}
              onChange={(e) => handleVariableChange(name, e.target.value)}
              input={<OutlinedInput label={definition.label} />}
              endAdornment={
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  {isLoading && <CircularProgress size={16} />}
                  {renderValidationIndicator(name)}
                </Box>
              }
            >
              {isLoading && options.length === 0 ? (
                <MenuItem disabled>
                  <CircularProgress size={16} sx={{ mr: 1 }} />
                  Loading options...
                </MenuItem>
              ) : (
                options.map((option) => (
                  <MenuItem key={String(option.value)} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))
              )}
            </Select>
          </FormControl>
        );

      case 'range':
        const rangeConfig = definition.config?.range;
        if (!rangeConfig) return null;
        
        return (
          <Box key={name} sx={{ minWidth: 200, px: 2 }}>
            <Typography variant="caption" color="text.secondary" gutterBottom>
              {definition.label}
            </Typography>
            <Slider
              value={currentValue || rangeConfig.min}
              onChange={(_, value) => handleVariableChange(name, value)}
              min={rangeConfig.min}
              max={rangeConfig.max}
              step={rangeConfig.step || 1}
              marks={rangeConfig.marks}
              valueLabelDisplay="auto"
              disabled={disabled}
              sx={{ 
                ...(hasError && {
                  color: 'error.main'
                })
              }}
            />
            {renderValidationIndicator(name)}
          </Box>
        );

      case 'boolean':
        return (
          <FormControlLabel
            key={name}
            control={
              <Switch
                checked={Boolean(currentValue)}
                onChange={(e) => handleVariableChange(name, e.target.checked)}
                disabled={disabled}
                color={hasError ? 'error' : 'primary'}
              />
            }
            label={
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                {definition.label}
                {renderValidationIndicator(name)}
              </Box>
            }
          />
        );

      case 'text':
        return (
          <TextField
            key={name}
            label={definition.label}
            value={currentValue || ''}
            onChange={(e) => handleVariableChange(name, e.target.value)}
            size="small"
            disabled={disabled}
            error={hasError}
            helperText={hasError ? validationResult?.errors.join(', ') : undefined}
            sx={{ minWidth: 150 }}
            InputProps={{
              endAdornment: renderValidationIndicator(name),
            }}
          />
        );

      default:
        return null;
    }
  };

  // Show validation errors summary if any
  const validationErrors = Array.from(validationResults.values())
    .filter(result => !result.isValid)
    .flatMap(result => result.errors);

  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'center' }}>
      {variableDefinitions.map(([name, definition]) => 
        renderVariableControl(name, definition)
      )}
      
      {/* Validation errors summary */}
      {showValidation && validationErrors.length > 0 && (
        <Alert 
          severity="error" 
          icon={<WarningIcon />}
          sx={{ mt: 1, width: '100%' }}
        >
          <Typography variant="caption">
            Variable validation errors: {validationErrors.join(', ')}
          </Typography>
        </Alert>
      )}
      
      {/* No variables message */}
      {variableDefinitions.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          No variables defined for this dashboard
        </Typography>
      )}
    </Box>
  );
};
