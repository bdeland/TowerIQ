import { Dashboard } from '../contexts/DashboardContext';
import { generateUUID } from '../utils/uuid';
import { formatCurrencyForChart, formatCurrencyForTooltip } from '../utils/currencyFormatter';
import { applyChartTheme } from '../utils/chartTheme';

export const defaultDashboard: Dashboard = {
  id: 'default-dashboard',
  uid: 'default-dashboard-uid',
  title: 'TowerIQ Overview123',
  description: 'Default pre-written dashboard, loaded from the frontend.',
  config: {
    panels: [
      {
        id: generateUUID(),
        type: 'bar',
        title: 'CPH vs. Run (Chronological)',
        gridPos: { x: 0, y: 0, w: 13, h: 5 },
        query: "SELECT row_number() OVER (ORDER BY start_time ASC) as run_number, CPH, tier FROM runs ${tier_filter} ORDER BY start_time ASC ${limit_clause}",
        echartsOption: applyChartTheme({
          tooltip: { 
            trigger: 'axis',
            formatter: (params: any) => {
              const data = params[0];
              const value = typeof data.data === 'object' ? data.data.value : data.data;
              const tier = typeof data.data === 'object' ? data.data.tier : 'N/A';
              const formattedValue = formatCurrencyForTooltip(value);
              return `Run ${data.axisValue}<br/>CPH: ${formattedValue}<br/>Tier: ${tier}`;
            }
          },
          xAxis: { 
            name: 'Run Number',
            nameLocation: 'middle',
            nameGap: 30,
            data: [] 
          },
          yAxis: { 
            name: 'CPH',
            nameLocation: 'middle',
            nameGap: 40,
            axisLabel: {
              formatter: (value: number) => formatCurrencyForChart(value)
            }
          },
          series: [{
            label: {
              formatter: (params: any) => {
                const value = typeof params.data === 'object' ? params.data.value : params.data;
                return formatCurrencyForChart(value);
              }
            }
          }]
        }, 'bar')
      },
      {
        id: generateUUID(),
        type: 'table',
        title: 'Recent Runs',
        gridPos: { x: 5, y: 10, w: 8, h: 4 },
        query: "SELECT run_id, tier, final_wave, CPH, duration_gametime FROM runs ${tier_filter} ORDER BY start_time DESC ${limit_clause}",
        echartsOption: {}
      },
      {
        id: generateUUID(),
        type: 'timeseries',
        title: 'Coins Per Hour (Last Runs)',
        gridPos: { x: 0, y: 5, w: 4, h: 4 },
        query: "SELECT start_time, CPH FROM runs ${tier_filter} ORDER BY start_time DESC ${limit_clause}",
        echartsOption: {
          xAxis: { type: 'time' },
          yAxis: { type: 'value', name: 'CPH' },
          tooltip: { trigger: 'axis' },
          series: [{
            type: 'line',
            name: 'CPH',
            smooth: true,
            data: []
          }]
        }
      },
      {
        id: generateUUID(),
        type: 'table',
        title: 'System Log',
        gridPos: { x: 4, y: 5, w: 8, h: 2 },
        query: "SELECT timestamp, level, event, source FROM logs ORDER BY timestamp DESC LIMIT 5",
        echartsOption: {}
      }
    ],
    time: { from: 'now-1h', to: 'now' },
    refresh: '30s'
  },
  variables: [
    {
      name: 'tier',
      label: 'Tier',
      type: 'multiselect',
      defaultValue: ['all'],
      options: [] // Populated dynamically at runtime
    },
    {
      name: 'num_runs',
      label: 'Number of Last Runs',
      type: 'singleselect',
      defaultValue: 10,
      options: [
        { label: 'All', value: 'all' },
        { label: '1', value: 1 },
        { label: '5', value: 5 },
        { label: '10', value: 10 },
        { label: '15', value: 15 },
        { label: '25', value: 25 },
        { label: '50', value: 50 },
      ]
    }
  ],
  tags: ['default', 'overview'],
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  created_by: 'system',
  is_default: true,
  schema_version: 1
};
