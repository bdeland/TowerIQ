import { Dashboard } from '../contexts/DashboardContext';
import { generateUUID } from '../utils/uuid';
import { formatCurrency, formatCurrencyForChart, formatCurrencyForTooltip } from '../utils/formattingUtils';
import { applyChartTheme } from '../utils/chartTheme';
import { CHART_COLORS } from '../utils/colorPalette';

export const defaultDashboard: Dashboard = {
  id: 'default-dashboard',
  uid: 'default-dashboard-uid',
  title: 'TowerIQ Overview',
  description: 'Default pre-written dashboard, loaded from the frontend.',
  config: {
    panels: [
      {
        id: 'e395d348-2e44-4c3c-a20a-362a0abf0fc0',
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
              return `Run ${data.axisValue}<br/>CPH: ${formattedValue}<br/>Tier: ${tier}<br/><em>Click to drill down</em>`;
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
            },
            // Enable drilldown by making bars clickable
            cursor: 'pointer'
          }],
          // Add drilldown configuration
          drilldown: {
            enabled: true,
            type: 'line',
            title: 'Coins vs Wave - Run {run_number}',
            query: `
              SELECT 
                CAST(m.current_wave AS INTEGER) as x_value,
                m.metric_value as y_value
              FROM metrics m
              INNER JOIN (
                SELECT run_id
                FROM (
                  SELECT run_id, start_time, final_wave, 
                         row_number() OVER (ORDER BY start_time ASC) as rn
                  FROM runs 
                ) ranked_runs
                WHERE rn = {run_number}
                LIMIT 1
              ) rd ON m.run_id = rd.run_id
              WHERE m.metric_name = 'coins' AND m.current_wave IS NOT NULL AND m.current_wave < 1000
              ORDER BY m.current_wave
            `,
            echartsOption: applyChartTheme({
              tooltip: {
                trigger: 'axis',
                formatter: (params: any) => {
                  const data = params[0];
                  // Handle coordinate pair format [wave, coins]
                  const wave = Array.isArray(data.value) ? data.value[0] : data.axisValue;
                  const coins = Array.isArray(data.value) ? data.value[1] : data.value;
                  const formattedCoins = formatCurrency(coins, 2);
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
                symbolSize: 6,
                lineStyle: { width: 3 },
                areaStyle: { opacity: 0.1 },
                markPoint: {
                  data: [
                    { type: 'max', name: 'Peak' }
                  ]
                }
              }],
              // Enable zoom and pan functionality
              dataZoom: [
                {
                  type: 'inside', // Mouse wheel zoom and drag to pan
                  xAxisIndex: 0,
                  filterMode: 'none' // Don't filter data, just zoom view
                },
                {
                  type: 'slider', // Slider at bottom for zoom control
                  xAxisIndex: 0,
                  filterMode: 'none',
                  bottom: 10,
                  height: 20
                }
              ]
            }, 'timeseries')
          }
        }, 'bar')
      },
      {
        id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        type: 'table',
        title: 'Recent Runs',
        gridPos: { x: 5, y: 10, w: 8, h: 4 },
        query: "SELECT run_id, tier, final_wave, CPH, duration_gametime FROM runs ${tier_filter} ORDER BY start_time DESC ${limit_clause}",
        echartsOption: {}
      },
      {
        id: 'b2c3d4e5-f6g7-8901-bcde-f23456789012',
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
        id: 'c3d4e5f6-g7h8-9012-cdef-345678901234',
        type: 'table',
        title: 'System Log',
        gridPos: { x: 4, y: 5, w: 8, h: 2 },
        query: "SELECT timestamp, level, event, source FROM logs ORDER BY timestamp DESC LIMIT 5",
        echartsOption: {}
      },
      {
        id: 'd4e5f6g7-h8i9-0123-defg-456789012345',
        type: 'calendar',
        title: 'Daily Coins Earned - Calendar Heatmap',
        gridPos: { x: 0, y: 15, w: 12, h: 6 },
        query: `
          SELECT 
            DATE(start_time / 1000, 'unixepoch') as date,
            SUM(COALESCE(coins_earned, 0)) as total_coins
          FROM runs 
          WHERE start_time IS NOT NULL 
            AND DATE(start_time / 1000, 'unixepoch') >= (
              SELECT DATE(MIN(start_time) / 1000, 'unixepoch') 
              FROM runs 
              WHERE start_time IS NOT NULL
            )
            AND DATE(start_time / 1000, 'unixepoch') <= (
              SELECT DATE(MAX(start_time) / 1000, 'unixepoch') 
              FROM runs 
              WHERE start_time IS NOT NULL
            )
            \${tier_filter}
          GROUP BY DATE(start_time / 1000, 'unixepoch')
          ORDER BY date
        `,
        echartsOption: {
          // Minimal calendar configuration to avoid undefined errors
          calendar: {
            top: 60,
            left: 30,
            right: 30,
            cellSize: 15,
            range: [2024], // Default to current year, will be overridden
            itemStyle: {
              borderWidth: 1,
              borderColor: CHART_COLORS.borderColor,
              borderType: 'solid'
            },
            yearLabel: {
              show: true,
              fontSize: 14,
              color: CHART_COLORS.textPrimary,
              fontWeight: 'bold'
            },
            monthLabel: {
              show: true,
              fontSize: 12,
              color: CHART_COLORS.textSecondary,
              nameMap: 'EN'
            },
            dayLabel: {
              show: true,
              fontSize: 10,
              color: CHART_COLORS.textSecondary,
              nameMap: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
            },
            splitLine: {
              show: true,
              lineStyle: {
                color: CHART_COLORS.borderColor,
                width: 1,
                type: 'solid'
              }
            }
          },
          visualMap: {
            min: 0,
            max: 100,
            type: 'continuous',
            orient: 'horizontal',
            left: 'center',
            bottom: 20,
            calculable: true,
            inRange: {
              color: CHART_COLORS.heatmapRange
            },
            textStyle: {
              color: CHART_COLORS.textPrimary,
              fontSize: 12
            },
            controller: {
              inRange: {
                color: CHART_COLORS.brandAccent
              }
            }
          },
          series: [{
            type: 'heatmap',
            coordinateSystem: 'calendar',
            data: [],
            label: {
              show: false,
              color: CHART_COLORS.textPrimary,
              fontSize: 10
            },
            emphasis: {
              itemStyle: {
                shadowBlur: 5,
                shadowColor: 'rgba(0, 0, 0, 0.3)'
              }
            }
          }],
          tooltip: {
            backgroundColor: CHART_COLORS.tooltipBg,
            borderColor: CHART_COLORS.borderColor,
            borderWidth: 1,
            textStyle: {
              color: CHART_COLORS.textPrimary
            },
            extraCssText: 'box-shadow: 0 4px 12px rgba(0,0,0,0.3); border-radius: 4px;',
            confine: true,
            formatter: (params: any) => {
              const date = params.data[0];
              const coins = params.data[1];
              const formattedCoins = coins ? formatCurrency(coins, 0) : 'No runs';
              return `${date}<br/>Coins Earned: ${formattedCoins}<br/><em>Click to drill down</em>`;
            }
          },
          // Add hierarchical drilldown configuration
          drilldown: {
            enabled: true,
            type: 'calendar_hierarchical',
            levels: [
              {
                level: 'year',
                title: 'Daily Coins - {year}',
                query: `
                  SELECT 
                    DATE(start_time / 1000, 'unixepoch') as date,
                    SUM(COALESCE(coins_earned, 0)) as total_coins
                  FROM runs 
                  WHERE start_time IS NOT NULL 
                    AND strftime('%Y', DATE(start_time / 1000, 'unixepoch')) = '{year}'
                    \${tier_filter}
                  GROUP BY DATE(start_time / 1000, 'unixepoch')
                  ORDER BY date
                `,
                range: 'year'
              },
              {
                level: 'quarter',
                title: 'Daily Coins - Q{quarter} {year}',
                query: `
                  SELECT 
                    DATE(start_time / 1000, 'unixepoch') as date,
                    SUM(COALESCE(coins_earned, 0)) as total_coins
                  FROM runs 
                  WHERE start_time IS NOT NULL 
                    AND strftime('%Y', DATE(start_time / 1000, 'unixepoch')) = '{year}'
                    AND (
                      ('{quarter}' = '1' AND strftime('%m', DATE(start_time / 1000, 'unixepoch')) IN ('01','02','03')) OR
                      ('{quarter}' = '2' AND strftime('%m', DATE(start_time / 1000, 'unixepoch')) IN ('04','05','06')) OR
                      ('{quarter}' = '3' AND strftime('%m', DATE(start_time / 1000, 'unixepoch')) IN ('07','08','09')) OR
                      ('{quarter}' = '4' AND strftime('%m', DATE(start_time / 1000, 'unixepoch')) IN ('10','11','12'))
                    )
                    \${tier_filter}
                  GROUP BY DATE(start_time / 1000, 'unixepoch')
                  ORDER BY date
                `,
                range: 'quarter'
              },
              {
                level: 'month',
                title: 'Daily Coins - {month_name} {year}',
                query: `
                  SELECT 
                    DATE(start_time / 1000, 'unixepoch') as date,
                    SUM(COALESCE(coins_earned, 0)) as total_coins
                  FROM runs 
                  WHERE start_time IS NOT NULL 
                    AND strftime('%Y-%m', DATE(start_time / 1000, 'unixepoch')) = '{year}-{month}'
                    \${tier_filter}
                  GROUP BY DATE(start_time / 1000, 'unixepoch')
                  ORDER BY date
                `,
                range: 'month'
              },
              {
                level: 'week',
                title: 'Daily Coins - Week of {week_start}',
                query: `
                  SELECT 
                    DATE(start_time / 1000, 'unixepoch') as date,
                    SUM(COALESCE(coins_earned, 0)) as total_coins
                  FROM runs 
                  WHERE start_time IS NOT NULL 
                    AND DATE(start_time / 1000, 'unixepoch') BETWEEN '{week_start}' AND '{week_end}'
                    \${tier_filter}
                  GROUP BY DATE(start_time / 1000, 'unixepoch')
                  ORDER BY date
                `,
                range: 'week'
              },
              {
                level: 'day',
                title: 'Hourly Coins - {date}',
                query: `
                  SELECT 
                    strftime('%Y-%m-%d %H:00:00', datetime(start_time / 1000, 'unixepoch')) as hour,
                    SUM(COALESCE(coins_earned, 0)) as total_coins
                  FROM runs 
                  WHERE start_time IS NOT NULL 
                    AND DATE(start_time / 1000, 'unixepoch') = '{date}'
                    \${tier_filter}
                  GROUP BY strftime('%Y-%m-%d %H:00:00', datetime(start_time / 1000, 'unixepoch'))
                  ORDER BY hour
                `,
                range: 'day',
                chartType: 'bar'
              }
            ]
          }
        }
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
