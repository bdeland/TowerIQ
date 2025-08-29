import React, { useState, useCallback } from 'react';
import {
  Box,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  Chip,
  Switch,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Button,
  IconButton,
  Tooltip,
  Autocomplete
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Help as HelpIcon,
  Calculate as CalculateIcon,
  AccessTime as AccessTimeIcon,
  FontDownload as FontDownloadIcon,
  CheckCircle as CheckCircleIcon,
  Category as CategoryIcon,
  Delete as DeleteIcon,
  Add as AddIcon
} from '@mui/icons-material';
import { 
  TransformationConfig, 
  getAvailableFieldsForConversion, 
  getAvailableTargetTypes,
  addConversionRow,
  removeConversionRow,
  updateConversionRow
} from '../services/transformationService';

interface FieldInfo {
  name: string;
  type: 'number' | 'string' | 'date' | 'time' | 'boolean' | 'enum' | 'other';
}

interface TransformationRowProps {
  config: TransformationConfig;
  index: number;
  onUpdate: (index: number, updatedConfig: TransformationConfig) => void;
  onDelete: (index: number) => void;
  availableFields?: FieldInfo[];
}

export default function TransformationRow({ config, index, onUpdate, onDelete, availableFields = [] }: TransformationRowProps) {
  const [localOptions, setLocalOptions] = useState(config.options || {});

  const handleOptionChange = useCallback((optionKey: string, value: any) => {
    const updatedOptions = {
      ...localOptions,
      [optionKey]: value
    };
    setLocalOptions(updatedOptions);
    
    const updatedConfig: TransformationConfig = {
      ...config,
      options: updatedOptions
    };
    
    onUpdate(index, updatedConfig);
  }, [config, index, localOptions, onUpdate]);

  // Helper function to render field dropdown
  const renderFieldSelect = (
    label: string, 
    value: string, 
    onChange: (value: string) => void, 
    filterType?: 'number' | 'string' | 'time' | 'boolean' | 'enum' | 'all',
    helperText?: string
  ) => {
    const filteredFields = filterType && filterType !== 'all' 
      ? availableFields.filter(f => f.type === filterType)
      : availableFields;

    return (
      <Autocomplete
        options={filteredFields}
        getOptionLabel={(option) => typeof option === 'string' ? option : option.name}
        value={filteredFields.find(f => f.name === value) || null}
        onChange={(_, newValue) => {
          if (newValue && typeof newValue === 'object') {
            onChange(newValue.name);
          } else if (typeof newValue === 'string') {
            onChange(newValue);
          } else {
            onChange('');
          }
        }}
        freeSolo
        renderInput={(params) => (
          <TextField
            {...params}
            label={label}
            size="small"
            helperText={helperText}
          />
        )}
                 renderOption={(props, option) => (
           <li {...props}>
             <Box sx={{ display: 'flex', alignItems: 'center' }}>
               {getFieldTypeIcon(option.type)}
               <Typography variant="body2">
                 {option.name} ({option.type})
               </Typography>
             </Box>
           </li>
         )}
        isOptionEqualToValue={(option, value) => 
          option.name === (typeof value === 'string' ? value : value?.name)
        }
      />
    );
  };

  // Helper function to render multi-field select with chips
  const renderMultiFieldSelect = (
    label: string,
    values: string[],
    onChange: (values: string[]) => void,
    filterType?: 'number' | 'string' | 'time' | 'boolean' | 'enum' | 'all'
  ) => {
    const filteredFields = filterType && filterType !== 'all' 
      ? availableFields.filter(f => f.type === filterType)
      : availableFields;

    // Convert string values to field objects for display
    const selectedFields = (values || []).map(value => {
      const field = filteredFields.find(f => f.name === value);
      return field || { name: value, type: 'other' as const };
    });

    return (
      <Autocomplete
        multiple
        options={filteredFields}
        getOptionLabel={(option) => typeof option === 'string' ? option : option.name}
        value={selectedFields}
        onChange={(_, newValues) => {
          const stringValues = newValues.map(v => typeof v === 'string' ? v : v.name);
          onChange(stringValues);
        }}
        freeSolo
        renderInput={(params) => (
          <TextField
            {...params}
            label={label}
            size="small"
          />
        )}
        renderTags={(tagValue, getTagProps) =>
          tagValue.map((option, index) => (
            <Chip
              {...getTagProps({ index })}
              key={option.name}
              label={
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  {getFieldTypeIcon(option.type)}
                  <Typography variant="caption">
                    {option.name}
                  </Typography>
                </Box>
              }
              size="small"
            />
          ))
        }
        renderOption={(props, option) => (
          <li {...props}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              {getFieldTypeIcon(option.type)}
              <Typography variant="body2">
                {option.name} ({option.type})
              </Typography>
            </Box>
          </li>
        )}
        isOptionEqualToValue={(option, value) => 
          option.name === (typeof value === 'string' ? value : value?.name)
        }
      />
    );
  };

  // Helper function to get field type icon
  const getFieldTypeIcon = (type: string) => {
    switch (type) {
      case 'number':
        return <CalculateIcon sx={{ fontSize: '16px', mr: 1 }} />;
      case 'time':
      case 'date':
        return <AccessTimeIcon sx={{ fontSize: '16px', mr: 1 }} />;
      case 'string':
        return <FontDownloadIcon sx={{ fontSize: '16px', mr: 1 }} />;
      case 'boolean':
        return <CheckCircleIcon sx={{ fontSize: '16px', mr: 1 }} />;
      case 'enum':
        return <CategoryIcon sx={{ fontSize: '16px', mr: 1 }} />;
      default:
        return <FontDownloadIcon sx={{ fontSize: '16px', mr: 1 }} />;
    }
  };

  // Render different UI based on transformation type
  const renderTransformationOptions = () => {
    switch (config.id) {
      case 'reduce':
        return (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <FormControl fullWidth size="small">
              <InputLabel>Reducer</InputLabel>
              <Select
                value={localOptions.reducer || 'mean'}
                label="Reducer"
                onChange={(e) => handleOptionChange('reducer', e.target.value)}
              >
                <MenuItem value="mean">Mean</MenuItem>
                <MenuItem value="sum">Sum</MenuItem>
                <MenuItem value="min">Min</MenuItem>
                <MenuItem value="max">Max</MenuItem>
                <MenuItem value="count">Count</MenuItem>
                <MenuItem value="last">Last</MenuItem>
                <MenuItem value="first">First</MenuItem>
              </Select>
            </FormControl>
            
            {renderMultiFieldSelect(
              'Fields to reduce',
              localOptions.fields || [],
              (values) => handleOptionChange('fields', values),
              'number'
            )}
            <Typography variant="caption" color="text.secondary">
              Leave empty to include all numeric fields
            </Typography>
          </Box>
        );

      case 'filterByValue':
        return (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {renderFieldSelect(
              'Field to filter by',
              localOptions.field || '',
              (value) => handleOptionChange('field', value),
              'all',
              'Select the field to apply the filter condition to'
            )}
            
            <FormControl fullWidth size="small">
              <InputLabel>Condition</InputLabel>
              <Select
                value={localOptions.condition || 'eq'}
                label="Condition"
                onChange={(e) => handleOptionChange('condition', e.target.value)}
              >
                <MenuItem value="eq">Equals</MenuItem>
                <MenuItem value="ne">Not equals</MenuItem>
                <MenuItem value="gt">Greater than</MenuItem>
                <MenuItem value="gte">Greater than or equal</MenuItem>
                <MenuItem value="lt">Less than</MenuItem>
                <MenuItem value="lte">Less than or equal</MenuItem>
                <MenuItem value="regex">Regex</MenuItem>
              </Select>
            </FormControl>
            
            <TextField
              label="Value"
              size="small"
              fullWidth
              value={localOptions.value || ''}
              onChange={(e) => handleOptionChange('value', e.target.value)}
              helperText="Enter the value to compare against"
            />
          </Box>
        );

      case 'groupBy':
        return (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {renderMultiFieldSelect(
              'Group by fields',
              localOptions.fields || [],
              (values) => handleOptionChange('fields', values),
              'all'
            )}
            
            <Typography variant="subtitle2" sx={{ mt: 1, mb: 1 }}>
              Aggregations
            </Typography>
            
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Button
                size="small"
                variant="outlined"
                onClick={() => {
                  const aggregations = localOptions.aggregations || [];
                  handleOptionChange('aggregations', [
                    ...aggregations,
                    { field: '', operation: 'mean' }
                  ]);
                }}
              >
                Add Aggregation
              </Button>
            </Box>
            
            {localOptions.aggregations?.map((agg: any, aggIndex: number) => (
              <Box key={aggIndex} sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <TextField
                  label="Field"
                  size="small"
                  value={agg.field || ''}
                  onChange={(e) => {
                    const aggregations = [...localOptions.aggregations];
                    aggregations[aggIndex] = { ...agg, field: e.target.value };
                    handleOptionChange('aggregations', aggregations);
                  }}
                />
                <FormControl size="small" sx={{ minWidth: 120 }}>
                  <InputLabel>Operation</InputLabel>
                  <Select
                    value={agg.operation || 'mean'}
                    label="Operation"
                    onChange={(e) => {
                      const aggregations = [...localOptions.aggregations];
                      aggregations[aggIndex] = { ...agg, operation: e.target.value };
                      handleOptionChange('aggregations', aggregations);
                    }}
                  >
                    <MenuItem value="mean">Mean</MenuItem>
                    <MenuItem value="sum">Sum</MenuItem>
                    <MenuItem value="min">Min</MenuItem>
                    <MenuItem value="max">Max</MenuItem>
                    <MenuItem value="count">Count</MenuItem>
                  </Select>
                </FormControl>
                <IconButton
                  size="small"
                  onClick={() => {
                    const aggregations = localOptions.aggregations.filter((_: any, i: number) => i !== aggIndex);
                    handleOptionChange('aggregations', aggregations);
                  }}
                >
                  <ExpandMoreIcon />
                </IconButton>
              </Box>
            ))}
          </Box>
        );

      case 'organize':
        return (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {renderMultiFieldSelect(
              'Include fields',
              localOptions.includeByName || [],
              (values) => handleOptionChange('includeByName', values),
              'all'
            )}
            <Typography variant="caption" color="text.secondary">
              Leave empty to include all fields
            </Typography>
            
            {renderMultiFieldSelect(
              'Exclude fields',
              localOptions.excludeByName || [],
              (values) => handleOptionChange('excludeByName', values),
              'all'
            )}
            
            <FormControlLabel
              control={
                <Switch
                  checked={localOptions.renameByName?.enabled || false}
                  onChange={(e) => handleOptionChange('renameByName', { ...localOptions.renameByName, enabled: e.target.checked })}
                />
              }
              label="Enable field renaming"
            />
          </Box>
        );

      case 'sortBy':
        return (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {renderFieldSelect(
              'Sort by field',
              localOptions.field || '',
              (value) => handleOptionChange('field', value),
              'all',
              'Select the field to sort the data by'
            )}
            
            <FormControl fullWidth size="small">
              <InputLabel>Direction</InputLabel>
              <Select
                value={localOptions.desc ? 'desc' : 'asc'}
                label="Direction"
                onChange={(e) => handleOptionChange('desc', e.target.value === 'desc')}
              >
                <MenuItem value="asc">Ascending</MenuItem>
                <MenuItem value="desc">Descending</MenuItem>
              </Select>
            </FormControl>
          </Box>
        );

             case 'convertFieldType':
         return (
           <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {/* Convert existing single field format to new multi-field format if needed */}
            {React.useEffect(() => {
              if (localOptions.field && !localOptions.conversions) {
                const conversions = [{
                  field: localOptions.field,
                  targetType: localOptions.targetType || 'string',
                  format: localOptions.format || ''
                }];
                handleOptionChange('conversions', conversions);
                // Clear old format
                handleOptionChange('field', '');
                handleOptionChange('targetType', '');
                handleOptionChange('format', '');
              }
            }, [])}
            
            {/* Render conversion rows */}
            {(localOptions.conversions || []).map((conversion: any, conversionIndex: number) => {
                             // Get available fields excluding already selected ones
               const selectedFields = (localOptions.conversions || [])
                 .map((c: any) => c.field)
                 .filter((f: string) => f && f !== conversion.field);
               
               const availableFieldsForConversion = availableFields
                 .filter(field => !selectedFields.includes(field.name))
                 .map(field => ({
                   name: field.name,
                   type: field.type
                 }));
               
               // Only add the currently selected field if it's not already in the filtered list
               const allAvailableFields = conversion.field 
                 ? availableFieldsForConversion.some(f => f.name === conversion.field)
                   ? availableFieldsForConversion
                   : [...availableFieldsForConversion, { name: conversion.field, type: availableFields.find(f => f.name === conversion.field)?.type || 'other' }]
                 : availableFieldsForConversion;
              
              const targetTypes = getAvailableTargetTypes();
              
                             return (
                 <Box key={conversionIndex} sx={{ 
                   display: 'flex', 
                   alignItems: 'center', 
                   gap: 0.5,
                   py: 0.5
                 }}>
                  <Button
                    variant="outlined"
                    size="small"
                                         sx={{ height: '28px', textTransform: 'none', borderRadius: 0.25 }}
                    disabled
                  >
                    Convert
                  </Button>
                  
                  <Autocomplete
                    options={allAvailableFields}
                    getOptionLabel={(option) => typeof option === 'string' ? option : option.name}
                    value={allAvailableFields.find(f => f.name === conversion.field) || null}
                    onChange={(_, newValue) => {
                      const updatedConversions = updateConversionRow(
                        localOptions.conversions || [],
                        conversionIndex,
                        { field: newValue?.name || '' }
                      );
                      handleOptionChange('conversions', updatedConversions);
                    }}
                    clearIcon={null}
                                         renderInput={(params) => (
                       <TextField
                         {...params}
                         placeholder="Select field"
                         size="small"
                                                   sx={{ 
                            minWidth: '150px',
                            '& .MuiOutlinedInput-root': {
                              height: '28px',
                              borderRadius: 0.25,
                              backgroundColor: '#111217'
                            }
                          }}
                       />
                     )}
                    renderOption={(props, option) => (
                      <li {...props}>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          {getFieldTypeIcon(option.type)}
                          <Typography variant="body2">
                            {option.name}
                          </Typography>
                        </Box>
                      </li>
                    )}
                    isOptionEqualToValue={(option, value) => 
                      option.name === (typeof value === 'string' ? value : value?.name)
                    }
                  />
                  
                                     <Button
                     variant="outlined"
                     size="small"
                     sx={{ width: '28px', height: '28px', textTransform: 'none', borderRadius: 0.25, p: 0, minWidth: '28px' }}
                     disabled
                   >
                     to
                   </Button>
                  
                  <FormControl size="small" sx={{ 
                    minWidth: '120px',
                    '& .MuiOutlinedInput-root': {
                      height: '28px',
                      borderRadius: 0.25,
                      backgroundColor: '#111217'
                    }
                  }}>
                    <Select
                      value={conversion.targetType || 'string'}
                      onChange={(e) => {
                        const updatedConversions = updateConversionRow(
                          localOptions.conversions || [],
                          conversionIndex,
                          { targetType: e.target.value }
                        );
                        handleOptionChange('conversions', updatedConversions);
                      }}
                      displayEmpty
                    >
                      {targetTypes.map((type) => (
                        <MenuItem key={type.value} value={type.value}>
                          <Box sx={{ display: 'flex', alignItems: 'center', }}>
                            {getFieldTypeIcon(type.value)}
                            <Typography>{type.label}</Typography>
                          </Box>
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                  
                                     <Button
                     variant="outlined"
                     size="small"
                     sx={{ width: '28px',height: '28px', textTransform: 'none', borderRadius: 0.25 }}
                     onClick={() => {
                       const updatedConversions = removeConversionRow(
                         localOptions.conversions || [],
                         conversionIndex
                       );
                       handleOptionChange('conversions', updatedConversions);
                     }}
                   >
                     <DeleteIcon sx={{ fontSize: '16px' }} />
                   </Button>
                </Box>
              );
            })}
            
                         {/* Add new conversion row button */}
             <Button
               variant="outlined"
               size="small"
               startIcon={<AddIcon />}
               onClick={() => {
                 const updatedConversions = addConversionRow(localOptions.conversions || []);
                 handleOptionChange('conversions', updatedConversions);
               }}
               sx={{ alignSelf: 'flex-start', mt: 0.5, height: '28px',  borderRadius: 0.25 }}
             >
               Convert field type
             </Button>
          </Box>
        );

      case 'formatTime':
        return (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {renderFieldSelect(
              'Time field',
              localOptions.field || '',
              (value) => handleOptionChange('field', value),
              'time',
              'Select the date/time field to format'
            )}
            
            <FormControl fullWidth size="small">
              <InputLabel>Format</InputLabel>
              <Select
                value={localOptions.format || 'ISO'}
                label="Format"
                onChange={(e) => handleOptionChange('format', e.target.value)}
              >
                <MenuItem value="ISO">ISO String (2023-12-25T10:30:00.000Z)</MenuItem>
                <MenuItem value="ISO_LOCAL">Local String (12/25/2023, 10:30:00 AM)</MenuItem>
                <MenuItem value="DATE_ONLY">Date Only (Mon Dec 25 2023)</MenuItem>
                <MenuItem value="TIME_ONLY">Time Only (10:30:00 GMT+0000)</MenuItem>
                <MenuItem value="UNIX_TIMESTAMP">Unix Timestamp (seconds)</MenuItem>
                <MenuItem value="UNIX_TIMESTAMP_MS">Unix Timestamp (milliseconds)</MenuItem>
                <MenuItem value="YYYY-MM-DD">YYYY-MM-DD (2023-12-25)</MenuItem>
                <MenuItem value="MM/DD/YYYY">MM/DD/YYYY (12/25/2023)</MenuItem>
                <MenuItem value="DD/MM/YYYY">DD/MM/YYYY (25/12/2023)</MenuItem>
              </Select>
            </FormControl>
            
            <FormControl fullWidth size="small">
              <InputLabel>Timezone</InputLabel>
              <Select
                value={localOptions.timezone || 'UTC'}
                label="Timezone"
                onChange={(e) => handleOptionChange('timezone', e.target.value)}
              >
                <MenuItem value="UTC">UTC</MenuItem>
                <MenuItem value="local">Local Timezone</MenuItem>
              </Select>
            </FormControl>
            
            <Typography variant="caption" color="text.secondary">
              Formats date/time fields according to the selected format. Supports various common date formats and timezone options.
            </Typography>
          </Box>
        );

      default:
        return (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Typography variant="body2" color="text.secondary">
              Configuration options for "{config.id}" transformation
            </Typography>
            
            <TextField
              label="Custom Options (JSON)"
              multiline
              rows={4}
              size="small"
              fullWidth
              value={JSON.stringify(localOptions, null, 2)}
              onChange={(e) => {
                try {
                  const parsed = JSON.parse(e.target.value);
                  setLocalOptions(parsed);
                  onUpdate(index, { ...config, options: parsed });
                } catch (error) {
                  // Invalid JSON, don't update
                }
              }}
              helperText="Enter transformation options as JSON"
            />
          </Box>
        );
    }
  };

  return (
    <Box sx={{ mt: 0, ml: 3 }}>
      {config.id !== 'convertFieldType' && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Configure the "{config.id}" transformation:
        </Typography>
      )}
      {renderTransformationOptions()}
    </Box>
  );
}
