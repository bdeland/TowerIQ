import { Dashboard } from '../contexts/DashboardContext';
import { generateUUID } from '../utils/uuid';
import { formatCurrency, formatCurrencyForChart, formatCurrencyForTooltip } from '../utils/formattingUtils';
import { applyChartTheme } from '../utils/chartTheme';

export const liveRunTrackingDashboard: Dashboard = {
  id: 'live-run-tracking-dashboard',
  uid: 'live-run-tracking-dashboard-uid',
  title: 'Live Run Tracking',
  description: 'Live statistics and performance monitoring for the current game run.',
  config: {
    panels: [
      // ============================================================================
      // STAT PANELS ROW 1 - Basic Run Information
      // ============================================================================
      
      // Panel 1: Run ID
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Run ID',
        gridPos: { x: 0, y: 0, w: 2, h: 1 },
        query: `
          SELECT 
            CASE 
              WHEN LENGTH(run_id) = 16 THEN 
                lower(
                  substr(hex(run_id), 1, 8) || '-' ||
                  substr(hex(run_id), 9, 4) || '-' ||
                  substr(hex(run_id), 13, 4) || '-' ||
                  substr(hex(run_id), 17, 4) || '-' ||
                  substr(hex(run_id), 21, 12)
                )
              ELSE hex(run_id)
            END as run_id_display
          FROM runs 
          WHERE end_time IS NULL 
          ORDER BY start_time DESC 
          LIMIT 1
        `,
        echartsOption: {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: 'No Active Run',
              fontSize: 14,
              fontWeight: 'bold',
              fill: '#ffffff',
              textAlign: 'center'
            }
          }]
        }
      },
      
      // Panel 2: Current Wave
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Current Wave',
        gridPos: { x: 2, y: 0, w: 2, h: 1 },
        query: `
          SELECT m.current_wave
          FROM metrics m
          INNER JOIN runs r ON m.run_id = r.run_id
          WHERE r.end_time IS NULL
          ORDER BY m.real_timestamp DESC
          LIMIT 1
        `,
        echartsOption: {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: '0',
              fontSize: 28,
              fontWeight: 'bold',
              fill: '#ffffff',
              textAlign: 'center'
            }
          }]
        }
      },

      // Panel 3: Start Time
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Start Time',
        gridPos: { x: 4, y: 0, w: 2, h: 1 },
        query: `
          SELECT 
            datetime(start_time / 1000, 'unixepoch', 'localtime') as start_time_formatted
          FROM runs 
          WHERE end_time IS NULL 
          ORDER BY start_time DESC 
          LIMIT 1
        `,
        echartsOption: {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: 'No Active Run',
              fontSize: 14,
              fontWeight: 'bold',
              fill: '#ffffff',
              textAlign: 'center'
            }
          }]
        }
      },

      // Panel 4: Duration
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Duration',
        gridPos: { x: 6, y: 0, w: 2, h: 1 },
        query: `
          SELECT 
            printf('%02d:%02d:%02d',
              (strftime('%s', 'now') * 1000 - start_time) / 3600000,
              ((strftime('%s', 'now') * 1000 - start_time) % 3600000) / 60000,
              ((strftime('%s', 'now') * 1000 - start_time) % 60000) / 1000
            ) as duration_formatted
          FROM runs 
          WHERE end_time IS NULL 
          ORDER BY start_time DESC 
          LIMIT 1
        `,
        echartsOption: {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: '00:00:00',
              fontSize: 20,
              fontWeight: 'bold',
              fill: '#ffffff',
              textAlign: 'center'
            }
          }]
        }
      },

      // ============================================================================
      // STAT PANELS ROW 2 - Currency Information
      // ============================================================================

      // Panel 5: Total Coins Earned
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Total Coins',
        gridPos: { x: 0, y: 1, w: 2, h: 1 },
        query: `
          SELECT 
            ROUND(m.metric_value / 1000.0, 0) as coins_display
          FROM metrics m
          INNER JOIN runs r ON m.run_id = r.run_id
          INNER JOIN metric_names mn ON m.metric_name_id = mn.id
          WHERE r.end_time IS NULL
            AND mn.name = 'coins'
          ORDER BY m.real_timestamp DESC
          LIMIT 1
        `,
        echartsOption: {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: '0',
              fontSize: 24,
              fontWeight: 'bold',
              fill: '#FFD700',
              textAlign: 'center'
            }
          }]
        }
      },

      // Panel 6: Total Gems Earned
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Total Gems',
        gridPos: { x: 2, y: 1, w: 2, h: 1 },
        query: `
          SELECT 
            ROUND(m.metric_value / 1000.0, 0) as gems_display
          FROM metrics m
          INNER JOIN runs r ON m.run_id = r.run_id
          INNER JOIN metric_names mn ON m.metric_name_id = mn.id
          WHERE r.end_time IS NULL
            AND mn.name = 'gems'
          ORDER BY m.real_timestamp DESC
          LIMIT 1
        `,
        echartsOption: {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: '0',
              fontSize: 24,
              fontWeight: 'bold',
              fill: '#FF69B4',
              textAlign: 'center'
            }
          }]
        }
      },

      // Panel 7: Total Cells Earned
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Total Cells',
        gridPos: { x: 4, y: 1, w: 2, h: 1 },
        query: `
          SELECT 
            ROUND(m.metric_value / 1000.0, 0) as cells_display
          FROM metrics m
          INNER JOIN runs r ON m.run_id = r.run_id
          INNER JOIN metric_names mn ON m.metric_name_id = mn.id
          WHERE r.end_time IS NULL
            AND mn.name = 'cells'
          ORDER BY m.real_timestamp DESC
          LIMIT 1
        `,
        echartsOption: {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: '0',
              fontSize: 24,
              fontWeight: 'bold',
              fill: '#00CED1',
              textAlign: 'center'
            }
          }]
        }
      },

      // ============================================================================
      // LINE CHARTS - Currency Progression vs Wave
      // ============================================================================

      // Chart 1: Coins vs. Wave
      {
        id: generateUUID(),
        type: 'timeseries',
        title: 'Coins Earned vs. Wave',
        gridPos: { x: 0, y: 2, w: 4, h: 4 },
        query: `
          SELECT 
            m.current_wave as x_value,
            ROUND(m.metric_value / 1000.0, 0) as y_value
          FROM metrics m
          INNER JOIN runs r ON m.run_id = r.run_id
          INNER JOIN metric_names mn ON m.metric_name_id = mn.id
          WHERE r.end_time IS NULL
            AND mn.name = 'coins'
            AND m.current_wave IS NOT NULL
          ORDER BY m.current_wave ASC
        `,
        echartsOption: applyChartTheme({
          tooltip: {
            trigger: 'axis',
            formatter: (params: any) => {
              const data = params[0];
              const wave = data.axisValue || data.data[0];
              const coins = data.value || data.data[1];
              const formattedCoins = formatCurrency(coins, 0);
              return `Wave ${wave}<br/>Coins: ${formattedCoins}`;
            }
          },
          xAxis: {
            name: 'Wave',
            nameLocation: 'middle',
            nameGap: 30,
            type: 'value',
            axisLabel: {
              formatter: (value: number) => Math.round(value).toString()
            }
          },
          yAxis: {
            name: 'Coins',
            nameLocation: 'middle',
            nameGap: 50,
            axisLabel: {
              formatter: (value: number) => formatCurrencyForChart(value)
            }
          },
          series: [{
            type: 'line',
            smooth: true,
            symbol: 'circle',
            symbolSize: 4,
            lineStyle: { width: 2, color: '#FFD700' },
            areaStyle: { opacity: 0.1, color: '#FFD700' },
            data: []
          }],
          dataZoom: [
            {
              type: 'inside',
              xAxisIndex: 0,
              filterMode: 'none'
            }
          ]
        }, 'timeseries')
      },

      // Chart 2: Cells vs. Wave
      {
        id: generateUUID(),
        type: 'timeseries',
        title: 'Cells Earned vs. Wave',
        gridPos: { x: 4, y: 2, w: 4, h: 4 },
        query: `
          SELECT 
            m.current_wave as x_value,
            ROUND(m.metric_value / 1000.0, 0) as y_value
          FROM metrics m
          INNER JOIN runs r ON m.run_id = r.run_id
          INNER JOIN metric_names mn ON m.metric_name_id = mn.id
          WHERE r.end_time IS NULL
            AND mn.name = 'cells'
            AND m.current_wave IS NOT NULL
          ORDER BY m.current_wave ASC
        `,
        echartsOption: applyChartTheme({
          tooltip: {
            trigger: 'axis',
            formatter: (params: any) => {
              const data = params[0];
              const wave = data.axisValue || data.data[0];
              const cells = data.value || data.data[1];
              const formattedCells = formatCurrency(cells, 0);
              return `Wave ${wave}<br/>Cells: ${formattedCells}`;
            }
          },
          xAxis: {
            name: 'Wave',
            nameLocation: 'middle',
            nameGap: 30,
            type: 'value',
            axisLabel: {
              formatter: (value: number) => Math.round(value).toString()
            }
          },
          yAxis: {
            name: 'Cells',
            nameLocation: 'middle',
            nameGap: 50,
            axisLabel: {
              formatter: (value: number) => formatCurrencyForChart(value)
            }
          },
          series: [{
            type: 'line',
            smooth: true,
            symbol: 'circle',
            symbolSize: 4,
            lineStyle: { width: 2, color: '#00CED1' },
            areaStyle: { opacity: 0.1, color: '#00CED1' },
            data: []
          }],
          dataZoom: [
            {
              type: 'inside',
              xAxisIndex: 0,
              filterMode: 'none'
            }
          ]
        }, 'timeseries')
      },

      // Chart 3: Gems vs. Wave
      {
        id: generateUUID(),
        type: 'timeseries',
        title: 'Gems Earned vs. Wave',
        gridPos: { x: 8, y: 2, w: 4, h: 4 },
        query: `
          SELECT 
            m.current_wave as x_value,
            ROUND(m.metric_value / 1000.0, 0) as y_value
          FROM metrics m
          INNER JOIN runs r ON m.run_id = r.run_id
          INNER JOIN metric_names mn ON m.metric_name_id = mn.id
          WHERE r.end_time IS NULL
            AND mn.name = 'gems'
            AND m.current_wave IS NOT NULL
          ORDER BY m.current_wave ASC
        `,
        echartsOption: applyChartTheme({
          tooltip: {
            trigger: 'axis',
            formatter: (params: any) => {
              const data = params[0];
              const wave = data.axisValue || data.data[0];
              const gems = data.value || data.data[1];
              const formattedGems = formatCurrency(gems, 0);
              return `Wave ${wave}<br/>Gems: ${formattedGems}`;
            }
          },
          xAxis: {
            name: 'Wave',
            nameLocation: 'middle',
            nameGap: 30,
            type: 'value',
            axisLabel: {
              formatter: (value: number) => Math.round(value).toString()
            }
          },
          yAxis: {
            name: 'Gems',
            nameLocation: 'middle',
            nameGap: 50,
            axisLabel: {
              formatter: (value: number) => formatCurrencyForChart(value)
            }
          },
          series: [{
            type: 'line',
            smooth: true,
            symbol: 'circle',
            symbolSize: 4,
            lineStyle: { width: 2, color: '#FF69B4' },
            areaStyle: { opacity: 0.1, color: '#FF69B4' },
            data: []
          }],
          dataZoom: [
            {
              type: 'inside',
              xAxisIndex: 0,
              filterMode: 'none'
            }
          ]
        }, 'timeseries')
      }
    ],
    time: { from: 'now-1h', to: 'now' },
    refresh: '5s' // Refresh every 5 seconds for live tracking
  },
  variables: [],
  tags: ['live', 'tracking', 'current-run'],
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  created_by: 'system',
  is_default: true, // Set as default dashboard
  schema_version: 1
};
