/**
 * Database-aware formatting utilities for TowerIQ
 * Works with the comprehensive column metadata system
 */

import { formatCurrency, formatNumber, formatDataSize } from './formattingUtils';

// Data type constants (matching Python)
export const DATA_TYPES = {
  INTEGER: 'integer',
  TEXT: 'string',
  BLOB: 'binary',
  REAL: 'float',
  BOOLEAN: 'boolean',
  TIMESTAMP: 'timestamp',
  CURRENCY: 'currency',
  DURATION: 'duration',
  PERCENTAGE: 'percentage',
  COUNT: 'count',
  ENUM: 'enum'
} as const;

// Unit constants (matching Python)
export const UNITS = {
  // Time units
  MILLISECONDS: 'ms',
  SECONDS: 's',
  MINUTES: 'm',
  HOURS: 'h',
  DAYS: 'd',
  
  // Currency units
  COINS: 'coins',
  GEMS: 'gems',
  CELLS: 'cells',
  CASH: 'cash',
  STONES: 'stones',
  
  // Count units
  COUNT: 'count',
  WAVES: 'waves',
  TAPS: 'taps',
  CLAIMS: 'claims',
  
  // Rate units
  COINS_PER_HOUR: 'coins/h',
  WAVES_PER_MINUTE: 'waves/min',
  
  // Percentage
  PERCENT: '%',
  
  // Raw values
  RAW: 'raw',
  SCALED: 'scaled'
} as const;

// Column metadata interface
export interface ColumnMetadata {
  data_type: string;
  unit: string;
  description: string;
  is_primary_key?: boolean;
  is_nullable?: boolean;
  is_foreign_key?: boolean;
  references?: string;
  scaling_factor?: number;
  formatting: {
    display_as: string;
    precision?: number;
    use_commas?: boolean;
    suffix?: string;
    timezone?: string;
    max_length?: number;
  };
}

// Table metadata interface
export interface TableMetadata {
  [columnName: string]: ColumnMetadata;
}

// Database metadata interface
export interface DatabaseMetadata {
  [tableName: string]: TableMetadata;
}

/**
 * Convert a stored database value to its display value using column metadata
 */
export function convertStoredToDisplayValue(
  value: any,
  tableName: string,
  columnName: string,
  metadata: DatabaseMetadata
): any {
  if (value === null || value === undefined) {
    return null;
  }

  const columnMeta = metadata[tableName]?.[columnName];
  if (!columnMeta) {
    return value;
  }

  // Apply scaling factor if present
  const scalingFactor = columnMeta.scaling_factor;
  if (scalingFactor && typeof value === 'number') {
    return value / scalingFactor;
  }

  return value;
}

/**
 * Convert a display value to its stored database value using column metadata
 */
export function convertDisplayToStoredValue(
  value: any,
  tableName: string,
  columnName: string,
  metadata: DatabaseMetadata
): any {
  if (value === null || value === undefined) {
    return null;
  }

  const columnMeta = metadata[tableName]?.[columnName];
  if (!columnMeta) {
    return value;
  }

  // Apply scaling factor if present
  const scalingFactor = columnMeta.scaling_factor;
  if (scalingFactor && typeof value === 'number') {
    return Math.round(value * scalingFactor);
  }

  return value;
}

/**
 * Format a value for display using column metadata and formatting rules
 */
export function formatValueForDisplay(
  value: any,
  tableName: string,
  columnName: string,
  metadata: DatabaseMetadata,
  formatType: 'default' | 'chart' | 'tooltip' = 'default'
): string {
  if (value === null || value === undefined) {
    return 'N/A';
  }

  // Convert stored value to display value first
  const displayValue = convertStoredToDisplayValue(value, tableName, columnName, metadata);

  const columnMeta = metadata[tableName]?.[columnName];
  if (!columnMeta) {
    return String(displayValue);
  }

  const formatting = columnMeta.formatting;
  const displayAs = formatting.display_as;

  switch (displayAs) {
    case 'currency':
      return formatCurrencyValue(displayValue, formatting, formatType);
    case 'duration':
      return formatDurationValue(displayValue, formatting);
    case 'datetime':
      return formatDateTimeValue(displayValue, formatting);
    case 'number':
      return formatNumberValue(displayValue, formatting, formatType);
    case 'uuid':
      return formatUuidValue(displayValue, formatting);
    case 'json':
      return formatJsonValue(displayValue, formatting);
    default:
      return String(displayValue);
  }
}

/**
 * Format a currency value using existing formatting utilities
 */
function formatCurrencyValue(
  value: number,
  formatting: ColumnMetadata['formatting'],
  formatType: string
): string {
  const precision = formatting.precision || 3;
  const suffix = formatting.suffix || '';

  let decimals: number;
  if (formatType === 'chart') {
    decimals = 1;
  } else if (formatType === 'tooltip') {
    decimals = 2;
  } else {
    decimals = precision;
  }

  const formatted = formatCurrency(value, decimals, false);
  return suffix ? `${formatted} ${suffix}` : formatted;
}

/**
 * Format a duration value
 */
function formatDurationValue(
  value: number,
  formatting: ColumnMetadata['formatting']
): string {
  const seconds = Math.floor(value);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (days > 0) {
    return `${days.toString().padStart(2, '0')}:${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  } else {
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }
}

/**
 * Format a datetime value
 */
function formatDateTimeValue(
  value: number,
  formatting: ColumnMetadata['formatting']
): string {
  // Convert milliseconds to seconds if needed
  let timestamp = value;
  if (timestamp > 1e12) { // Likely milliseconds
    timestamp = timestamp / 1000;
  }

  const date = new Date(timestamp * 1000);
  const timezone = formatting.timezone || 'UTC';

  if (timezone !== 'UTC') {
    // For non-UTC timezones, you might want to use a library like date-fns-tz
    // For now, we'll just use the local timezone
    return date.toLocaleString('en-US', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }

  return date.toISOString().replace('T', ' ').replace('Z', '').substring(0, 19);
}

/**
 * Format a number value
 */
function formatNumberValue(
  value: number,
  formatting: ColumnMetadata['formatting'],
  formatType: string
): string {
  const precision = formatting.precision || 0;
  const useCommas = formatting.use_commas || false;
  const suffix = formatting.suffix || '';

  let actualPrecision = precision;
  if (formatType === 'chart') {
    actualPrecision = Math.min(precision, 1);
  }

  let formatted: string;
  if (actualPrecision > 0) {
    formatted = value.toFixed(actualPrecision);
  } else {
    formatted = Math.round(value).toString();
  }

  if (useCommas && Math.abs(value) >= 1000) {
    // Add comma separators
    const parts = formatted.split('.');
    parts[0] = parseInt(parts[0]).toLocaleString();
    formatted = parts.join('.');
  }

  return suffix ? `${formatted} ${suffix}` : formatted;
}

/**
 * Format a UUID value
 */
function formatUuidValue(
  value: Uint8Array | string,
  formatting: ColumnMetadata['formatting']
): string {
  if (value instanceof Uint8Array) {
    // Convert bytes to hex string and format as UUID
    const hex = Array.from(value)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    return [
      hex.substring(0, 8),
      hex.substring(8, 12),
      hex.substring(12, 16),
      hex.substring(16, 20),
      hex.substring(20, 32)
    ].join('-');
  }
  
  return String(value);
}

/**
 * Format a JSON value
 */
function formatJsonValue(
  value: string,
  formatting: ColumnMetadata['formatting']
): string {
  try {
    const parsed = JSON.parse(value);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return String(value);
  }
}

/**
 * Get scaling factor for a column
 */
export function getScalingFactor(
  tableName: string,
  columnName: string,
  metadata: DatabaseMetadata
): number {
  return metadata[tableName]?.[columnName]?.scaling_factor || 1;
}

/**
 * Get unit for a column
 */
export function getUnit(
  tableName: string,
  columnName: string,
  metadata: DatabaseMetadata
): string {
  return metadata[tableName]?.[columnName]?.unit || 'raw';
}

/**
 * Get data type for a column
 */
export function getDataType(
  tableName: string,
  columnName: string,
  metadata: DatabaseMetadata
): string {
  return metadata[tableName]?.[columnName]?.data_type || 'integer';
}

/**
 * Validate column metadata
 */
export function validateColumnMetadata(metadata: DatabaseMetadata): {
  valid: boolean;
  errors: string[];
  warnings: string[];
} {
  const results = {
    valid: true,
    errors: [] as string[],
    warnings: [] as string[]
  };

  // Check that all columns have required metadata
  const requiredFields = ['data_type', 'unit', 'description'];
  
  for (const [tableName, columns] of Object.entries(metadata)) {
    for (const [columnName, columnMeta] of Object.entries(columns)) {
      for (const field of requiredFields) {
        if (!(field in columnMeta)) {
          results.warnings.push(`Column '${tableName}.${columnName}' missing required field '${field}'`);
        }
      }
    }
  }

  return results;
}

/**
 * Create a formatter function for a specific column
 */
export function createColumnFormatter(
  tableName: string,
  columnName: string,
  metadata: DatabaseMetadata
) {
  return (value: any, formatType: 'default' | 'chart' | 'tooltip' = 'default') => {
    return formatValueForDisplay(value, tableName, columnName, metadata, formatType);
  };
}

/**
 * Batch format multiple values for a table
 */
export function formatTableData(
  data: Record<string, any>[],
  tableName: string,
  metadata: DatabaseMetadata,
  formatType: 'default' | 'chart' | 'tooltip' = 'default'
): Record<string, string>[] {
  return data.map(row => {
    const formattedRow: Record<string, string> = {};
    
    for (const [columnName, value] of Object.entries(row)) {
      formattedRow[columnName] = formatValueForDisplay(
        value,
        tableName,
        columnName,
        metadata,
        formatType
      );
    }
    
    return formattedRow;
  });
}
