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
  VariableOption,
  VariableSet,
  ValidationResult
} from '../domain/dashboard/types';

interface NewDashboardVariableControlsProps {
  variables: DashboardVariables;
  selectedValues: VariableSet;
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
  const [validationResults, setValidationResults] = useState<Map<string, ValidationResult>>(new Map());

  const variableDefinitions = useMemo<VariableDefinition[]>(() => variables.getAllDefinitions(), [variables]);

  const renderValidationIndicator = useCallback(
    (name: string) => {
      if (!showValidation) return null;

      const result = validationResults.get(name);
      if (!result) return null;

      const icon = result.isValid ? (
        <CheckCircleIcon color="success" fontSize="small" />
      ) : (
        <ErrorIcon color="error" fontSize="small" />
      );

      const tooltip = result.isValid ? 'Valid value' : (result.errors.join(', ') || 'Validation error');

      return (
        <Tooltip title={tooltip}>
          <Box sx={{ display: 'flex', alignItems: 'center', ml: 0.5 }}>
            {icon}
          </Box>
        </Tooltip>
      );
    },
    [showValidation, validationResults]
  );

  const validateVariable = useCallback(
    (name: string) => {
      if (!showValidation) {
        return;
      }

      try {
        const result = variables.validate(name);
        setValidationResults((prev) => {
          const next = new Map(prev);
          next.set(name, result);
          return next;
        });
      } catch (error) {
        console.error(`Error validating variable ${name}:`, error);
      }
    },
    [variables, showValidation]
  );

  const handleVariableChange = useCallback(
    (name: string, value: any) => {
      onChange(name, value);
      validateVariable(name);
    },
    [onChange, validateVariable]
  );

  const loadVariableOptions = useCallback(
    async (name: string) => {
      setLoadingOptions((prev) => {
        const next = new Set(prev);
        next.add(name);
        return next;
      });

      try {
        await variables.loadDynamicOptions(name);
      } catch (error) {
        console.error(`Error loading options for variable ${name}:`, error);
      } finally {
        setLoadingOptions((prev) => {
          const next = new Set(prev);
          next.delete(name);
          return next;
        });
      }
    },
    [variables]
  );

  const renderVariableControl = (definition: VariableDefinition) => {
    const name = definition.name;
    const currentValue = selectedValues[name] ?? definition.defaultValue;
    const storedOptions = variables.getOptions(name);
    const options: VariableOption[] = storedOptions.length > 0 ? storedOptions : (definition.options ?? []);
    const isLoading = loadingOptions.has(name);
    const validationResult = validationResults.get(name);
    const hasError = Boolean(validationResult && !validationResult.isValid);
    const validationIndicator = renderValidationIndicator(name);

    switch (definition.type) {
      case 'static':
      case 'query': {
        const allowMultiple = Array.isArray(currentValue);
        const selectValue = allowMultiple
          ? (Array.isArray(currentValue) ? currentValue : [])
          : (currentValue ?? '');

        const handleSelectChange = (event: SelectChangeEvent<unknown>) => {
          const value = event.target.value;
          if (allowMultiple) {
            const nextValue = Array.isArray(value) ? value : [value];
            handleVariableChange(name, nextValue);
          } else {
            handleVariableChange(name, value);
          }
        };

        return (
          <Box
            key={name}
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              minWidth: 220,
            }}
          >
            <FormControl
              size="small"
              disabled={disabled}
              error={hasError}
              sx={{ flex: 1 }}
            >
              <InputLabel>{definition.label}</InputLabel>
              <Select
                multiple={allowMultiple}
                value={selectValue as any}
                onChange={handleSelectChange}
                onOpen={() => {
                  if (definition.type === 'query' && options.length === 0 && !isLoading) {
                    void loadVariableOptions(name);
                  }
                }}
                input={<OutlinedInput label={definition.label} />}
                renderValue={
                  allowMultiple
                    ? (selected) => (
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {Array.isArray(selected)
                            ? selected.map((value) => {
                                const option = options.find((opt) => opt.value === value);
                                return (
                                  <Chip
                                    key={String(value)}
                                    label={option?.label ?? String(value)}
                                    size="small"
                                  />
                                );
                              })
                            : null}
                        </Box>
                      )
                    : undefined
                }
              >
                {options.map((option) => (
                  <MenuItem key={String(option.value)} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
                {definition.type === 'query' && options.length === 0 && !isLoading && (
                  <MenuItem disabled>No options available</MenuItem>
                )}
              </Select>
            </FormControl>
            {definition.type === 'query' && isLoading && <CircularProgress size={16} />}
            {validationIndicator}
          </Box>
        );
      }

      case 'range': {
        const range = definition.rangeOptions;
        if (!range) {
          return null;
        }

        const value = typeof currentValue === 'number' ? currentValue : range.min;

        return (
          <Box key={name} sx={{ minWidth: 220, px: 2 }}>
            <Typography variant="caption" color="text.secondary" gutterBottom>
              {definition.label}
            </Typography>
            <Slider
              value={value}
              onChange={(_, newValue) => {
                const normalizedValue = Array.isArray(newValue) ? newValue[0] : newValue;
                handleVariableChange(name, normalizedValue);
              }}
              min={range.min}
              max={range.max}
              step={range.step ?? 1}
              valueLabelDisplay="auto"
              disabled={disabled}
              sx={{ ...(hasError && { color: 'error.main' }) }}
            />
            {validationIndicator}
          </Box>
        );
      }

      case 'custom': {
        if (typeof currentValue === 'boolean') {
          return (
            <FormControlLabel
              key={name}
              control={
                <Switch
                  checked={Boolean(currentValue)}
                  onChange={(event) => handleVariableChange(name, event.target.checked)}
                  disabled={disabled}
                  color={hasError ? 'error' : 'primary'}
                />
              }
              label={
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  {definition.label}
                  {validationIndicator}
                </Box>
              }
            />
          );
        }

        return (
          <TextField
            key={name}
            label={definition.label}
            value={currentValue ?? ''}
            onChange={(event) => handleVariableChange(name, event.target.value)}
            size="small"
            disabled={disabled}
            error={hasError}
            helperText={hasError ? validationResult?.errors.join(', ') : undefined}
            sx={{ minWidth: 180 }}
            InputProps={{
              endAdornment: validationIndicator,
            }}
          />
        );
      }

      default:
        return null;
    }
  };

  const validationErrors = useMemo(() => {
    if (!showValidation) {
      return [];
    }

    return Array.from(validationResults.values())
      .filter((result) => !result.isValid)
      .flatMap((result) => result.errors);
  }, [validationResults, showValidation]);

  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'center' }}>
      {variableDefinitions.map((definition) => renderVariableControl(definition))}

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

      {variableDefinitions.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          No variables defined for this dashboard
        </Typography>
      )}
    </Box>
  );
};
