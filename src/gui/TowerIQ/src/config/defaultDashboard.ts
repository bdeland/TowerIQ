import { Dashboard } from '../contexts/DashboardContext';
import { generateUUID } from '../utils/uuid';
import { formatCurrency, formatCurrencyForChart, formatCurrencyForTooltip } from '../utils/formattingUtils';
import { applyChartTheme } from '../utils/chartTheme';
import { CHART_COLORS, SEMANTIC_COLORS } from '../utils/colorPalette';

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
        title: 'Coins vs. Run (Chronological)',
        gridPos: { x: 0, y: 0, w: 8, h: 3 },
        query: "SELECT row_number() OVER (ORDER BY start_time ASC) as run_number, round_coins, CPH, tier FROM runs ${tier_filter} ORDER BY start_time ASC ${limit_clause}",
        echartsOption: {
          ...applyChartTheme({
            tooltip: { 
              trigger: 'axis',
              formatter: (params: any) => {
                let tooltip = `Run ${params[0].axisValue}<br/>`;
                params.forEach((param: any) => {
                  const value = typeof param.data === 'object' ? param.data.value : param.data;
                  const tier = typeof param.data === 'object' ? param.data.tier : 'N/A';
                  const formattedValue = formatCurrencyForTooltip(value);
                  if (param.seriesName === 'Total Coins') {
                    tooltip += `Total Coins: ${formattedValue}<br/>`;
                  } else if (param.seriesName === 'CPH') {
                    tooltip += `CPH: ${formattedValue}<br/>`;
                  }
                });
                tooltip += `Tier: ${params[0].data?.tier || 'N/A'}<br/><em>Click to drill down</em>`;
                return tooltip;
              }
            },
            xAxis: { 
              name: 'Run Number',
              nameLocation: 'middle',
              nameGap: 30,
              data: [] 
            }
          }, 'bar'),
          // Override yAxis with our dual-axis configuration
          yAxis: [
            {
              name: 'Total Coins',
              nameLocation: 'middle',
              nameGap: 50,
              type: 'value',
              axisLine: {
                show: false,
              },
              axisTick: {
                show: false,
              },
              axisLabel: {
                color: '#666',
                fontSize: 12,
                formatter: (value: number) => formatCurrencyForChart(value)
              },
              splitLine: {
                lineStyle: {
                  color: '#e0e0e0',
                  type: 'dashed',
                },
              },
            },
            {
              name: 'CPH',
              nameLocation: 'middle',
              nameGap: 50,
              type: 'value',
              axisLine: {
                show: false,
              },
              axisTick: {
                show: false,
              },
              axisLabel: {
                color: '#666',
                fontSize: 12,
                formatter: (value: number) => formatCurrencyForChart(value)
              },
              splitLine: {
                show: false, // Hide split lines for secondary axis
              },
            }
          ],
          series: [
            {
              name: 'Total Coins',
              type: 'bar',
              yAxisIndex: 0,
              label: {
                formatter: (params: any) => {
                  const value = typeof params.data === 'object' ? params.data.value : params.data;
                  return formatCurrencyForChart(value);
                }
              },
              // Enable drilldown by making bars clickable
              cursor: 'pointer'
            },
            {
              name: 'CPH',
              type: 'line',
              yAxisIndex: 1,
              smooth: true,
              symbol: 'circle',
              symbolSize: 6,
              lineStyle: { width: 3 },
              cursor: 'pointer'
            }
          ],
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
              INNER JOIN metric_names mn ON m.metric_name_id = mn.id
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
              WHERE mn.name = 'coins' AND m.current_wave IS NOT NULL AND m.current_wave < 1000
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
        }
      },
      {
        id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        type: 'table',
        title: 'Recent Runs',
        gridPos: { x: 8, y: 0, w: 8, h: 3 },
        query: "SELECT hex(run_id) as run_id, tier, final_wave, CPH, duration_gametime FROM runs ${tier_filter} ORDER BY start_time DESC ${limit_clause}",
        echartsOption: {}
      },
      {
        id: 'b2c3d4e5-f6g7-8901-bcde-f23456789012',
        type: 'timeseries',
        title: 'Coins Per Hour (Last Runs)',
        gridPos: { x: 0, y: 3, w: 8, h: 3 },
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
        gridPos: { x: 8, y: 3, w: 8, h: 3 },
        query: "SELECT timestamp, level, event, source FROM logs ORDER BY timestamp DESC LIMIT 5",
        echartsOption: {}
      },
      {
        id: 'd4e5f6g7-h8i9-0123-defg-456789012345',
        type: 'calendar',
        title: 'Daily Coins Earned - Calendar Heatmap',
        gridPos: { x: 0, y: 6, w: 8, h: 3 },
        query: `
          SELECT 
            DATE(start_time / 1000, 'unixepoch') as date,
            SUM(COALESCE(round_coins, 0)) as total_coins
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
                    SUM(COALESCE(round_coins, 0)) as total_coins
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
                    SUM(COALESCE(round_coins, 0)) as total_coins
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
                    SUM(COALESCE(round_coins, 0)) as total_coins
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
                    SUM(COALESCE(round_coins, 0)) as total_coins
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
                    SUM(COALESCE(round_coins, 0)) as total_coins
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
      },
      // PIE CHART PANEL - Runs Distribution by Tier
      {
        id: 'f0e1d2c3-b4a5-9687-3210-fedcba987654',
        type: 'pie',
        title: 'Runs Distribution by Tier',
        gridPos: { x: 8, y: 6, w: 8, h: 3 },
        query: "SELECT tier as label, COUNT(*) as value FROM runs ${tier_filter} GROUP BY tier ORDER BY tier",
        echartsOption: {
          ...applyChartTheme({
            tooltip: {
              trigger: 'item',
              formatter: (params: any) => {
                const percentage = params.percent;
                const value = params.value;
                const name = params.name;
                return `${name}<br/>Runs: ${value} (${percentage}%)`;
              }
            },
            legend: {
              orient: 'vertical',
              left: 'right',
              top: 'middle',
              textStyle: {
                color: CHART_COLORS.textPrimary,
                fontSize: 12
              }
            }
          }, 'pie'),
          series: [{
            name: 'Runs by Tier',
            type: 'pie',
            radius: ['30%', '70%'],
            center: ['40%', '50%'],
            data: [],
            emphasis: {
              itemStyle: {
                shadowBlur: 10,
                shadowOffsetX: 0,
                shadowColor: 'rgba(0, 0, 0, 0.5)'
              }
            },
            label: {
              show: true,
              formatter: '{b}: {c}',
              fontSize: 11,
              color: CHART_COLORS.textPrimary
            },
            labelLine: {
              show: true,
              lineStyle: {
                color: CHART_COLORS.borderColor
              }
            }
          }]
        }
      },
      // STAT PANELS - Key Performance Indicators
      {
        id: 'g1f2e3d4-c5b6-a798-4321-0fedcba98765',
        type: 'stat',
        title: 'Total Runs',
        gridPos: { x: 16, y: 2, w: 8, h: 1 },
        query: "SELECT COUNT(*) as value FROM runs ${tier_filter}",
        echartsOption: {
          textStyle: {
            fontSize: 32,
            fontWeight: 'bold',
            color: CHART_COLORS.textPrimary
          },
          valueFormatter: (value: number) => value.toLocaleString(),
          showTrend: false
        }
      },
      {
        id: 'h2g3f4e5-d6c7-b8a9-5432-10fedcba9876',
        type: 'stat',
        title: 'Average CPH',
        gridPos: { x: 16, y: 1, w: 8, h: 1 },
        query: "SELECT AVG(CPH) as value FROM runs WHERE CPH IS NOT NULL ${tier_filter}",
        echartsOption: {
          textStyle: {
            fontSize: 28,
            fontWeight: 'bold',
            color: SEMANTIC_COLORS.success
          },
          valueFormatter: (value: number) => formatCurrencyForChart(value),
          showTrend: false
        }
      },
      {
        id: 'i3h4g5f6-e7d8-c9ba-6543-210fedcba987',
        type: 'stat',
        title: 'Highest Wave Reached',
        gridPos: { x: 16, y: 0, w: 8, h: 1 },
        query: "SELECT MAX(final_wave) as value FROM runs WHERE final_wave IS NOT NULL ${tier_filter}",
        echartsOption: {
          textStyle: {
            fontSize: 28,
            fontWeight: 'bold',
            color: SEMANTIC_COLORS.warning
          },
          valueFormatter: (value: number) => `Wave ${Math.round(value)}`,
          showTrend: false
        }
      },
      // TREEMAP PANEL - Performance by Tier and Wave Range
      {
        id: 'j4i5h6g7-f8e9-dacb-7654-3210fedcba98',
        type: 'treemap',
        title: 'Performance Overview by Tier',
        gridPos: { x: 16, y: 3, w: 8, h: 3 },
        query: `
          SELECT 
            'Tier ' || tier as name,
            COUNT(*) as value,
            AVG(CPH) as avg_cph,
            MAX(final_wave) as max_wave
          FROM runs 
          WHERE tier IS NOT NULL \${tier_filter}
          GROUP BY tier 
          ORDER BY tier
        `,
        echartsOption: {
          backgroundColor: 'transparent',
          textStyle: {
            fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            color: CHART_COLORS.textPrimary,
          },
          tooltip: {
            trigger: 'item',
            backgroundColor: CHART_COLORS.tooltipBg,
            borderColor: CHART_COLORS.borderColor,
            borderWidth: 1,
            textStyle: {
              color: CHART_COLORS.textPrimary,
            },
            extraCssText: 'box-shadow: 0 4px 12px rgba(0,0,0,0.3); border-radius: 4px;',
            formatter: (params: any) => {
              const data = params.data;
              const runs = data.value;
              const avgCph = data.avg_cph ? formatCurrencyForChart(data.avg_cph) : 'N/A';
              const maxWave = data.max_wave ? Math.round(data.max_wave) : 'N/A';
              return `${data.name}<br/>Runs: ${runs}<br/>Avg CPH: ${avgCph}<br/>Max Wave: ${maxWave}`;
            }
          },
          series: [{
            name: 'Performance by Tier',
            type: 'treemap',
            data: [],
            roam: false,
            nodeClick: false,
            breadcrumb: {
              show: false
            },
            label: {
              show: true,
              formatter: (params: any) => {
                return `${params.name}\n${params.value} runs`;
              },
              fontSize: 12,
              color: CHART_COLORS.textPrimary
            },
            itemStyle: {
              borderColor: CHART_COLORS.borderColor,
              borderWidth: 1,
              gapWidth: 1
            },
            emphasis: {
              itemStyle: {
                shadowBlur: 5,
                shadowColor: 'rgba(0, 0, 0, 0.3)'
              }
            },
            levels: [
              {
                itemStyle: {
                  borderColor: CHART_COLORS.borderColor,
                  borderWidth: 2,
                  gapWidth: 2
                }
              }
            ]
          }]
        }
      },
      // RIDGELINE PANEL - Coins per Wave Distribution Across Recent Runs
      {
        id: 'k5j6i7h8-g9f0-eadb-8765-4321fedcba09',
        type: 'ridgeline',
        title: 'Coins Per Wave Distribution (Recent Runs)',
        gridPos: { x: 0, y: 9, w: 16, h: 4 },
        query: `
          SELECT 
            hex(m.run_id) as hex_run_id,
            m.current_wave,
            m.metric_value
          FROM metrics m
          INNER JOIN metric_names mn ON m.metric_name_id = mn.id
          INNER JOIN runs r ON m.run_id = r.run_id
          INNER JOIN (
            SELECT run_id, start_time,
                   row_number() OVER (ORDER BY start_time DESC) as rn
            FROM runs 
            WHERE 1=1 \${tier_filter}
            ORDER BY start_time DESC
            \${limit_clause}
          ) recent_runs ON m.run_id = recent_runs.run_id
          WHERE mn.name = 'coins' 
            AND m.current_wave IS NOT NULL 
            AND m.current_wave < 1000
          ORDER BY recent_runs.rn, m.current_wave
        `,
        echartsOption: {
          // Minimal configuration - the ridgeline rendering logic will handle the rest
          backgroundColor: 'transparent',
          textStyle: {
            fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            color: CHART_COLORS.textPrimary,
          },
          grid: {
            left: '15%',
            right: '10%',
            top: '10%',
            bottom: '15%'
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
