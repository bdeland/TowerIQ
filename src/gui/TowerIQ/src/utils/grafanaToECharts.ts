import { DataFrame } from '@grafana/data';

export interface EChartsDataPoint {
  [key: string]: any;
}

export interface EChartsSeriesData {
  name: string;
  type: string;
  data: any[];
}

/**
 * Converts Grafana DataFrame(s) to ECharts-compatible format
 */
export function grafanaToECharts(dataFrames: DataFrame[], panelType: string): {
  xAxisData?: any[];
  series: EChartsSeriesData[];
  sourceData: EChartsDataPoint[];
} {
  console.log('📊 grafanaToECharts - Input dataFrames:', dataFrames);
  console.log('📊 grafanaToECharts - Panel type:', panelType);
  
  if (!dataFrames || dataFrames.length === 0) {
    console.log('📊 grafanaToECharts - No dataFrames, returning empty');
    return { series: [], sourceData: [] };
  }

  // For now, we'll work with the first DataFrame
  // In the future, this could be enhanced to handle multiple DataFrames
  const dataFrame = dataFrames[0];
  console.log('📊 grafanaToECharts - Working with DataFrame:', dataFrame);
  
  if (!dataFrame.fields || dataFrame.fields.length === 0) {
    return { series: [], sourceData: [] };
  }

  // Convert DataFrame to array of objects
  const sourceData: EChartsDataPoint[] = [];
  const length = dataFrame.length;

  for (let i = 0; i < length; i++) {
    const row: EChartsDataPoint = {};
    dataFrame.fields.forEach((field) => {
      row[field.name] = field.values.get(i);
    });
    sourceData.push(row);
  }

  // Detect column types and mappings
  const fields = dataFrame.fields;
  const timeField = fields.find(f => f.type === 'time');
  const numberFields = fields.filter(f => f.type === 'number');
  const stringFields = fields.filter(f => f.type === 'string');

  // Generate series based on panel type
  const series: EChartsSeriesData[] = [];
  let xAxisData: any[] | undefined;

  switch (panelType) {
    case 'timeseries': {
      // For timeseries, use time field as x-axis and numeric fields as series
      if (timeField && numberFields.length > 0) {
        xAxisData = timeField.values.toArray().map(v => new Date(v).getTime());
        
        numberFields.forEach(field => {
          series.push({
            name: field.name,
            type: 'line',
            data: field.values.toArray().map((value, index) => [
              timeField.values.get(index) ? new Date(timeField.values.get(index)).getTime() : index,
              value
            ])
          });
        });
      }
      break;
    }

    case 'bar': {
      // For bar charts, use first string field as categories, numeric fields as series
      const categoryField = stringFields[0] || fields[0];
      if (categoryField && numberFields.length > 0) {
        xAxisData = categoryField.values.toArray();
        
        numberFields.forEach(field => {
          series.push({
            name: field.name,
            type: 'bar',
            data: field.values.toArray()
          });
        });
      }
      break;
    }

    case 'pie': {
      // For pie charts, use first string field as names, first numeric field as values
      const nameField = stringFields[0] || fields[0];
      const valueField = numberFields[0] || fields[1];
      
      if (nameField && valueField) {
        const pieData = nameField.values.toArray().map((name, index) => ({
          name: name,
          value: valueField.values.get(index)
        }));
        
        series.push({
          name: valueField.name || 'Value',
          type: 'pie',
          data: pieData
        });
      }
      break;
    }

    case 'stat': {
      // For stat panels, calculate summary statistics
      if (numberFields.length > 0) {
        const field = numberFields[0];
        const values = field.values.toArray().filter(v => v != null);
        
        if (values.length > 0) {
          const sum = values.reduce((a, b) => a + b, 0);
          const avg = sum / values.length;
          const min = Math.min(...values);
          const max = Math.max(...values);
          const latest = values[values.length - 1];
          
          series.push({
            name: field.name,
            type: 'stat',
            data: [{ value: latest, sum, avg, min, max, count: values.length }]
          });
        }
      }
      break;
    }

    case 'table': {
      // For tables, return all data as-is
      xAxisData = sourceData.map((_, index) => index);
      
      fields.forEach(field => {
        series.push({
          name: field.name,
          type: 'table',
          data: field.values.toArray()
        });
      });
      break;
    }

    default: {
      // Default handling - create series for all numeric fields
      if (numberFields.length > 0) {
        const categoryField = stringFields[0] || timeField;
        if (categoryField) {
          xAxisData = categoryField.values.toArray();
        }
        
        numberFields.forEach(field => {
          series.push({
            name: field.name,
            type: 'line',
            data: field.values.toArray()
          });
        });
      }
      break;
    }
  }

  return { xAxisData, series, sourceData };
}

/**
 * Merges ECharts data with existing ECharts options
 */
export function mergeWithEChartsOption(
  echartsData: ReturnType<typeof grafanaToECharts>,
  existingOption: any,
  panelType: string
): any {
  const { xAxisData, series, sourceData } = echartsData;
  const option = { ...existingOption };

  // Update series data
  if (series.length > 0) {
    option.series = series.map((seriesItem, index) => ({
      ...option.series?.[index],
      ...seriesItem
    }));
  }

  // Update x-axis data if applicable
  if (xAxisData && panelType !== 'pie' && panelType !== 'stat') {
    if (!option.xAxis) option.xAxis = {};
    option.xAxis.data = xAxisData;
  }

  // Store source data for table panels
  if (panelType === 'table') {
    option.sourceData = sourceData;
  }

  return option;
}
