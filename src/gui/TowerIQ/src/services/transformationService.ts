// src/services/transformationService.ts
import { DataFrame, toDataFrame } from '@grafana/data';

// This is the structure you'll save in your panel's JSON config
export interface TransformationConfig {
  id: string; // e.g., 'reduce'
  name?: string; // Display name with numbering e.g., "1 - Reduce"
  options: any; // The options for that specific transformation
}

/**
 * Applies a series of transformations to raw data.
 * @param rawData The raw JSON array of objects from the Python API.
 * @param configs An array of transformation configurations defined by the user.
 * @returns A transformed DataFrame ready for visualization.
 */
export function applyTransformations(rawData: any[], configs: TransformationConfig[]): DataFrame[] {
  console.log('🔧 TransformationService - Input data:', rawData);
  console.log('🔧 TransformationService - Configs:', configs);
  
  if (!configs || configs.length === 0) {
    console.log('🔧 TransformationService - No transformations, returning original data as DataFrame');
    return [toDataFrame(rawData)];
  }

  // Start with the original data
  let processedData = [...rawData];
  
  // Apply each transformation in sequence
  for (const config of configs) {
    console.log('🔧 Applying transformation:', config.id, 'with options:', config.options);
    
    switch (config.id) {
      case 'reduce':
        processedData = applyReduceTransformation(processedData, config.options);
        break;
      case 'filterByValue':
        processedData = applyFilterTransformation(processedData, config.options);
        break;
      case 'sortBy':
        processedData = applySortTransformation(processedData, config.options);
        break;
      case 'organize':
        processedData = applyOrganizeTransformation(processedData, config.options);
        break;
      case 'convertFieldType':
        processedData = applyConvertFieldTypeTransformation(processedData, config.options);
        break;
      case 'formatTime':
        processedData = applyFormatTimeTransformation(processedData, config.options);
        break;
      default:
        console.warn('🔧 Unknown transformation:', config.id);
    }
    
    console.log('🔧 Data after', config.id, ':', processedData);
  }

  const dataFrame = toDataFrame(processedData);
  console.log('🔧 TransformationService - Final DataFrame:', dataFrame);
  return [dataFrame];
}

// Helper function to apply reduce transformation
function applyReduceTransformation(data: any[], options: any): any[] {
  const { reducer = 'mean', fields = [] } = options;
  
  if (data.length === 0) return data;
  
  // If no specific fields specified, find numeric fields
  const targetFields = fields.length > 0 ? fields : 
    Object.keys(data[0]).filter(key => typeof data[0][key] === 'number');
  
  if (targetFields.length === 0) return data;
  
  const result: any = {};
  
  for (const field of targetFields) {
    const values = data.map(row => row[field]).filter(v => v != null && typeof v === 'number');
    
    if (values.length === 0) continue;
    
    switch (reducer) {
      case 'mean':
        result[field] = values.reduce((a, b) => a + b, 0) / values.length;
        break;
      case 'sum':
        result[field] = values.reduce((a, b) => a + b, 0);
        break;
      case 'min':
        result[field] = Math.min(...values);
        break;
      case 'max':
        result[field] = Math.max(...values);
        break;
      case 'count':
        result[field] = values.length;
        break;
      case 'last':
        result[field] = values[values.length - 1];
        break;
      case 'first':
        result[field] = values[0];
        break;
      default:
        result[field] = values[0];
    }
  }
  
  return [result];
}

// Helper function to apply filter transformation
function applyFilterTransformation(data: any[], options: any): any[] {
  const { field, condition = 'eq', value } = options;
  
  if (!field || value === undefined || value === '') return data;
  
  return data.filter(row => {
    const rowValue = row[field];
    
    switch (condition) {
      case 'eq':
        return rowValue == value;
      case 'ne':
        return rowValue != value;
      case 'gt':
        return rowValue > value;
      case 'gte':
        return rowValue >= value;
      case 'lt':
        return rowValue < value;
      case 'lte':
        return rowValue <= value;
      case 'regex':
        try {
          return new RegExp(value).test(String(rowValue));
        } catch {
          return false;
        }
      default:
        return true;
    }
  });
}

// Helper function to apply sort transformation
function applySortTransformation(data: any[], options: any): any[] {
  const { field, desc = false } = options;
  
  if (!field) return data;
  
  return [...data].sort((a, b) => {
    const aVal = a[field];
    const bVal = b[field];
    
    if (aVal < bVal) return desc ? 1 : -1;
    if (aVal > bVal) return desc ? -1 : 1;
    return 0;
  });
}

// Helper function to apply organize transformation
function applyOrganizeTransformation(data: any[], options: any): any[] {
  const { includeByName = [], excludeByName = [] } = options;
  
  if (data.length === 0) return data;
  
  return data.map(row => {
    const result: any = {};
    
    for (const [key, value] of Object.entries(row)) {
      // If includeByName is specified, only include those fields
      if (includeByName.length > 0 && !includeByName.includes(key)) {
        continue;
      }
      
      // If excludeByName is specified, exclude those fields
      if (excludeByName.length > 0 && excludeByName.includes(key)) {
        continue;
      }
      
      result[key] = value;
    }
    
    return result;
  });
}

// Helper function to apply convert field type transformation
function applyConvertFieldTypeTransformation(data: any[], options: any): any[] {
  const { conversions = [] } = options;
  
  if (!conversions || conversions.length === 0 || data.length === 0) return data;
  
  return data.map(row => {
    const result = { ...row };
    
    // Apply each conversion in sequence
    for (const conversion of conversions) {
      const { field, targetType, format = '' } = conversion;
      
      if (!field || !targetType) continue;
      
      const value = row[field];
      
      if (value === null || value === undefined) {
        continue;
      }
      
      try {
        switch (targetType) {
          case 'number':
            result[field] = Number(value);
            break;
          case 'string':
            result[field] = String(value);
            break;
          case 'boolean':
            if (typeof value === 'string') {
              result[field] = value.toLowerCase() === 'true' || value === '1';
            } else {
              result[field] = Boolean(value);
            }
            break;
          case 'time':
            if (value instanceof Date) {
              result[field] = value;
            } else {
              const date = new Date(value);
              if (!isNaN(date.getTime())) {
                result[field] = date;
              }
            }
            break;
          case 'enum':
            // For enum, treat as string but could be extended for validation
            result[field] = String(value);
            break;
          case 'other':
            // Keep as is for other types
            result[field] = value;
            break;
          default:
            // Keep original value for unknown types
            break;
        }
      } catch (error) {
        console.warn(`Failed to convert field ${field} to ${targetType}:`, error);
      }
    }
    
    return result;
  });
}

// Helper function to apply format time transformation
function applyFormatTimeTransformation(data: any[], options: any): any[] {
  const { field, format = 'ISO', timezone = 'UTC' } = options;
  
  if (!field || data.length === 0) return data;
  
  return data.map(row => {
    const result = { ...row };
    const value = row[field];
    
    if (value === null || value === undefined) {
      return result;
    }
    
    try {
      let date: Date;
      
      // Parse the date value
      if (value instanceof Date) {
        date = value;
      } else if (typeof value === 'string' || typeof value === 'number') {
        date = new Date(value);
        if (isNaN(date.getTime())) {
          return result; // Invalid date, keep original
        }
      } else {
        return result; // Not a date-like value
      }
      
      // Apply timezone if specified
      if (timezone !== 'UTC') {
        // Simple timezone offset handling (for more complex timezone support, consider using a library like date-fns-tz)
        const utcTime = date.getTime() + (date.getTimezoneOffset() * 60000);
        date = new Date(utcTime);
      }
      
      // Format the date based on the specified format
      switch (format) {
        case 'ISO':
          result[field] = date.toISOString();
          break;
        case 'ISO_LOCAL':
          result[field] = date.toLocaleString();
          break;
        case 'DATE_ONLY':
          result[field] = date.toDateString();
          break;
        case 'TIME_ONLY':
          result[field] = date.toTimeString();
          break;
        case 'UNIX_TIMESTAMP':
          result[field] = Math.floor(date.getTime() / 1000);
          break;
        case 'UNIX_TIMESTAMP_MS':
          result[field] = date.getTime();
          break;
        case 'YYYY-MM-DD':
          result[field] = date.toISOString().split('T')[0];
          break;
        case 'MM/DD/YYYY':
          const month = String(date.getMonth() + 1).padStart(2, '0');
          const day = String(date.getDate()).padStart(2, '0');
          const year = date.getFullYear();
          result[field] = `${month}/${day}/${year}`;
          break;
        case 'DD/MM/YYYY':
          const day2 = String(date.getDate()).padStart(2, '0');
          const month2 = String(date.getMonth() + 1).padStart(2, '0');
          const year2 = date.getFullYear();
          result[field] = `${day2}/${month2}/${year2}`;
          break;
        default:
          // Custom format or keep as ISO
          result[field] = date.toISOString();
          break;
      }
    } catch (error) {
      console.warn(`Failed to format time for field ${field}:`, error);
    }
    
    return result;
  });
}

/**
 * Get list of available transformations
 */
export function getAvailableTransformations() {
  // Return a simplified list of transformations for now
  return [
    { id: 'reduce', name: 'Reduce', description: 'Reduce data to single values', categories: [] },
    { id: 'filterByValue', name: 'Filter by value', description: 'Filter data by field values', categories: [] },
    { id: 'groupBy', name: 'Group by', description: 'Group data by field values', categories: [] },
    { id: 'organize', name: 'Organize fields', description: 'Include, exclude, and rename fields', categories: [] },
    { id: 'sortBy', name: 'Sort by', description: 'Sort data by field values', categories: [] },
    { id: 'convertFieldType', name: 'Convert field type', description: 'Convert field data types', categories: [] },
    { id: 'formatTime', name: 'Format time', description: 'Format date/time fields', categories: [] },
  ];
}

/**
 * Get default options for a transformation
 */
export function getDefaultTransformationOptions(transformationId: string): any {
  const defaults: Record<string, any> = {
    reduce: { reducer: 'mean', fields: [] },
    filterByValue: { field: '', condition: 'eq', value: '' },
    groupBy: { fields: [], aggregations: [] },
    organize: { includeByName: [], excludeByName: [], renameByName: { enabled: false } },
    sortBy: { field: '', desc: false },
    convertFieldType: { conversions: [{ field: '', targetType: 'string', format: '' }] },
    formatTime: { field: '', format: 'ISO', timezone: 'UTC' },
  };
  
  return defaults[transformationId] || {};
}

/**
 * Get available fields for conversion, excluding already selected fields
 */
export function getAvailableFieldsForConversion(data: any[], selectedFields: string[] = []): string[] {
  if (!data || data.length === 0) return [];
  
  const allFields = Object.keys(data[0]);
  return allFields.filter(field => !selectedFields.includes(field));
}

/**
 * Get available target types for field conversion
 */
export function getAvailableTargetTypes(): Array<{ value: string; label: string; icon?: string }> {
  return [
    { value: 'string', label: 'String', icon: 'A' },
    { value: 'number', label: 'Number', icon: '#' },
    { value: 'boolean', label: 'Boolean', icon: 'toggle' },
    { value: 'time', label: 'Time', icon: 'clock' },
    { value: 'enum', label: 'Enum', icon: 'list' },
    { value: 'other', label: 'Other', icon: 'more' },
  ];
}

/**
 * Add a new conversion row to the existing conversions
 */
export function addConversionRow(conversions: any[] = []): any[] {
  return [...conversions, { field: '', targetType: 'string', format: '' }];
}

/**
 * Remove a conversion row by index
 */
export function removeConversionRow(conversions: any[] = [], index: number): any[] {
  if (index < 0 || index >= conversions.length) return conversions;
  return conversions.filter((_, i) => i !== index);
}

/**
 * Update a conversion row by index
 */
export function updateConversionRow(conversions: any[] = [], index: number, updates: any): any[] {
  if (index < 0 || index >= conversions.length) return conversions;
  
  const updated = [...conversions];
  updated[index] = { ...updated[index], ...updates };
  return updated;
}
