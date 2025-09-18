/**
 * Formatting utilities for currency, numbers, and data sizes
 * Supports extremely large numbers up to centillion with unique abbreviations
 */

interface CurrencyScale {
  value: number;
  suffix: string;
  name: string;
}

// Currency scales with unique abbreviations to avoid confusion
// Carefully designed to ensure no duplicates across all scales
const CURRENCY_SCALES: CurrencyScale[] = [
  { value: 1e100, suffix: 'Ct', name: 'Centillion' },
  { value: 1e99, suffix: 'NCt', name: 'Novenonagintillion' },
  { value: 1e96, suffix: 'OCt', name: 'Octononagintillion' },
  { value: 1e93, suffix: 'SCt', name: 'Septennonagintillion' },
  { value: 1e90, suffix: 'SxCt', name: 'Sexnonagintillion' },
  { value: 1e87, suffix: 'QnCt', name: 'Quinnonagintillion' },
  { value: 1e84, suffix: 'QdCt', name: 'Quattuornonagintillion' },
  { value: 1e81, suffix: 'TrCt', name: 'Trenonagintillion' },
  { value: 1e78, suffix: 'DuCt', name: 'Duononagintillion' },
  { value: 1e75, suffix: 'UnCt', name: 'Unnonagintillion' },
  { value: 1e72, suffix: 'NgCt', name: 'Nonagintillion' },
  { value: 1e69, suffix: 'OcCt', name: 'Octogintillion' },
  { value: 1e66, suffix: 'SpCt', name: 'Septogintillion' },
  { value: 1e63, suffix: 'Vg', name: 'Vigintillion' },
  { value: 1e60, suffix: 'Nv', name: 'Novemdecillion' },
  { value: 1e57, suffix: 'Od', name: 'Octodecillion' },
  { value: 1e54, suffix: 'Sd', name: 'Septendecillion' },
  { value: 1e51, suffix: 'Sxd', name: 'Sexdecillion' },
  { value: 1e48, suffix: 'Qnd', name: 'Quindecillion' },
  { value: 1e45, suffix: 'Qrd', name: 'Quattuordecillion' },
  { value: 1e42, suffix: 'Trd', name: 'Tredecillion' },
  { value: 1e39, suffix: 'Dd', name: 'Duodecillion' },
  { value: 1e36, suffix: 'Ud', name: 'Undecillion' },
  { value: 1e33, suffix: 'Dc', name: 'Decillion' },
  { value: 1e30, suffix: 'No', name: 'Nonillion' },
  { value: 1e27, suffix: 'Oc', name: 'Octillion' },
  { value: 1e24, suffix: 'Sp', name: 'Septillion' },
  { value: 1e21, suffix: 'Sx', name: 'Sextillion' },
  { value: 1e18, suffix: 'Qt', name: 'Quintillion' },
  { value: 1e15, suffix: 'Qd', name: 'Quadrillion' },
  { value: 1e12, suffix: 'T', name: 'Trillion' },
  { value: 1e9, suffix: 'B', name: 'Billion' },
  { value: 1e6, suffix: 'M', name: 'Million' },
  { value: 1e3, suffix: 'K', name: 'Thousand' },
];

/**
 * Formats a number as currency with appropriate scaling and unique abbreviations
 * @param value - The number to format
 * @param decimals - Number of decimal places (default: 1)
 * @param showFullOnHover - Whether to show full number in title attribute (default: false)
 * @returns Formatted currency string
 */
export function formatCurrency(
  value: number, 
  decimals: number = 1, 
  showFullOnHover: boolean = false
): string {
  if (value === 0) return '0';
  if (!isFinite(value) || isNaN(value)) return 'N/A';

  const absValue = Math.abs(value);
  const isNegative = value < 0;
  
  // Find the appropriate scale
  for (const scale of CURRENCY_SCALES) {
    if (absValue >= scale.value) {
      const scaledValue = absValue / scale.value;
      const formattedValue = scaledValue.toFixed(decimals);
      
      // Remove trailing zeros after decimal point
      const cleanValue = parseFloat(formattedValue).toString();
      
      const result = `${isNegative ? '-' : ''}${cleanValue}${scale.suffix}`;
      
      if (showFullOnHover) {
        return `<span title="${value.toLocaleString()}">${result}</span>`;
      }
      
      return result;
    }
  }
  
  // For numbers less than 1000, show as-is with specified decimal places
  if (absValue < 1000) {
    if (decimals === 0) {
      return Math.round(value).toString();
    } else {
      return value.toFixed(decimals);
    }
  }
  
  return value.toString();
}

/**
 * Formats currency for chart labels (shorter format)
 * @param value - The number to format
 * @returns Formatted currency string optimized for chart labels
 */
export function formatCurrencyForChart(value: number): string {
  return formatCurrency(value, 1, false);
}

/**
 * Formats currency for tooltips (with more detail)
 * @param value - The number to format
 * @returns Formatted currency string with full value on hover
 */
export function formatCurrencyForTooltip(value: number): string {
  const formatted = formatCurrency(value, 2, false);
  const fullValue = value.toLocaleString();
  return `${formatted} (${fullValue})`;
}

/**
 * Formats a number with appropriate scaling (same logic as currency but without $ symbol)
 * @param value - The number to format
 * @param decimals - Number of decimal places (default: 1)
 * @param showFullOnHover - Whether to show full number in title attribute (default: false)
 * @returns Formatted number string
 */
export function formatNumber(
  value: number, 
  decimals: number = 1, 
  showFullOnHover: boolean = false
): string {
  // Reuse the currency formatting logic but without currency context
  return formatCurrency(value, decimals, showFullOnHover);
}

/**
 * Formats a number for chart labels (shorter format)
 * @param value - The number to format
 * @returns Formatted number string optimized for chart labels
 */
export function formatNumberForChart(value: number): string {
  return formatNumber(value, 1, false);
}

/**
 * Gets the scale information for a given value
 * @param value - The number to analyze
 * @returns Scale information or null if no scale applies
 */
export function getCurrencyScale(value: number): CurrencyScale | null {
  const absValue = Math.abs(value);
  
  for (const scale of CURRENCY_SCALES) {
    if (absValue >= scale.value) {
      return scale;
    }
  }
  
  return null;
}

/**
 * Validates that all abbreviations are unique
 * @returns Array of any duplicate abbreviations found
 */
export function validateUniqueAbbreviations(): string[] {
  const suffixes = CURRENCY_SCALES.map(scale => scale.suffix);
  const duplicates: string[] = [];
  const seen = new Set<string>();
  
  for (const suffix of suffixes) {
    if (seen.has(suffix)) {
      duplicates.push(suffix);
    }
    seen.add(suffix);
  }
  
  return duplicates;
}

// Validate abbreviations on module load (development check)
if (process.env.NODE_ENV === 'development') {
  const duplicates = validateUniqueAbbreviations();
  if (duplicates.length > 0) {
    console.warn('Duplicate currency abbreviations found:', duplicates);
  }
}

// ============================================================================
// DATA SIZE FORMATTING
// ============================================================================

interface DataSizeScale {
  value: number;
  suffix: string;
  name: string;
}

// Data size scales (binary: 1024-based)
const DATA_SIZE_SCALES: DataSizeScale[] = [
  { value: Math.pow(1024, 8), suffix: 'YiB', name: 'Yobibyte' },
  { value: Math.pow(1024, 7), suffix: 'ZiB', name: 'Zebibyte' },
  { value: Math.pow(1024, 6), suffix: 'EiB', name: 'Exbibyte' },
  { value: Math.pow(1024, 5), suffix: 'PiB', name: 'Pebibyte' },
  { value: Math.pow(1024, 4), suffix: 'TiB', name: 'Tebibyte' },
  { value: Math.pow(1024, 3), suffix: 'GiB', name: 'Gibibyte' },
  { value: Math.pow(1024, 2), suffix: 'MiB', name: 'Mebibyte' },
  { value: 1024, suffix: 'KiB', name: 'Kibibyte' },
];

// Data size scales (decimal: 1000-based) - more commonly used for storage
const DATA_SIZE_SCALES_DECIMAL: DataSizeScale[] = [
  { value: Math.pow(1000, 8), suffix: 'YB', name: 'Yottabyte' },
  { value: Math.pow(1000, 7), suffix: 'ZB', name: 'Zettabyte' },
  { value: Math.pow(1000, 6), suffix: 'EB', name: 'Exabyte' },
  { value: Math.pow(1000, 5), suffix: 'PB', name: 'Petabyte' },
  { value: Math.pow(1000, 4), suffix: 'TB', name: 'Terabyte' },
  { value: Math.pow(1000, 3), suffix: 'GB', name: 'Gigabyte' },
  { value: Math.pow(1000, 2), suffix: 'MB', name: 'Megabyte' },
  { value: 1000, suffix: 'KB', name: 'Kilobyte' },
];

/**
 * Formats a data size in bytes with appropriate scaling
 * @param bytes - The number of bytes to format
 * @param decimals - Number of decimal places (default: 1)
 * @param binary - Use binary (1024-based) vs decimal (1000-based) scaling (default: false for decimal)
 * @returns Formatted data size string
 */
export function formatDataSize(
  bytes: number,
  decimals: number = 1,
  binary: boolean = false
): string {
  if (bytes === 0) return '0 B';
  if (!isFinite(bytes) || isNaN(bytes)) return 'N/A';

  const absBytes = Math.abs(bytes);
  const isNegative = bytes < 0;
  const scales = binary ? DATA_SIZE_SCALES : DATA_SIZE_SCALES_DECIMAL;
  
  // Find the appropriate scale
  for (const scale of scales) {
    if (absBytes >= scale.value) {
      const scaledValue = absBytes / scale.value;
      const formattedValue = scaledValue.toFixed(decimals);
      
      // Remove trailing zeros after decimal point
      const cleanValue = parseFloat(formattedValue).toString();
      
      return `${isNegative ? '-' : ''}${cleanValue} ${scale.suffix}`;
    }
  }
  
  // For bytes less than the smallest scale, show as bytes
  return `${Math.round(bytes)} B`;
}

/**
 * Formats data size for chart labels (compact format)
 * @param bytes - The number of bytes to format
 * @param binary - Use binary vs decimal scaling (default: false)
 * @returns Formatted data size string optimized for charts
 */
export function formatDataSizeForChart(bytes: number, binary: boolean = false): string {
  return formatDataSize(bytes, 1, binary);
}

/**
 * Formats data size for tooltips (with more detail)
 * @param bytes - The number of bytes to format
 * @param binary - Use binary vs decimal scaling (default: false)
 * @returns Formatted data size string with full byte count
 */
export function formatDataSizeForTooltip(bytes: number, binary: boolean = false): string {
  const formatted = formatDataSize(bytes, 2, binary);
  const fullValue = bytes.toLocaleString();
  return `${formatted} (${fullValue} bytes)`;
}

/**
 * Gets the data size scale information for a given byte value
 * @param bytes - The number of bytes to analyze
 * @param binary - Use binary vs decimal scaling (default: false)
 * @returns Scale information or null if no scale applies
 */
export function getDataSizeScale(bytes: number, binary: boolean = false): DataSizeScale | null {
  const absBytes = Math.abs(bytes);
  const scales = binary ? DATA_SIZE_SCALES : DATA_SIZE_SCALES_DECIMAL;
  
  for (const scale of scales) {
    if (absBytes >= scale.value) {
      return scale;
    }
  }
  
  return null;
}
