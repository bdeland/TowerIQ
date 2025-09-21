import { Dashboard } from '../contexts/DashboardContext';
import { generateUUID } from '../utils/uuid';
import { formatDataSize, formatDataSizeForChart, formatDataSizeForTooltip } from '../utils/formattingUtils';
import { CHART_COLORS } from '../utils/colorPalette';

export const databaseHealthDashboard: Dashboard = {
  id: 'database-health-dashboard',
  uid: 'database-health-dashboard-uid',
  title: 'Database Health & Usage',
  description: 'Comprehensive view of database health, size, and usage patterns.',
  config: {
    panels: [
      // KPI Stat Panels Row
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Total Database Size',
        gridPos: { x: 0, y: 0, w: 2, h: 1 },
        query: `
          SELECT 
            CASE 
              WHEN size_bytes < 1024 THEN ROUND(size_bytes, 2) || ' B'
              WHEN size_bytes < 1024 * 1024 THEN ROUND(size_bytes / 1024.0, 2) || ' KB'
              WHEN size_bytes < 1024 * 1024 * 1024 THEN ROUND(size_bytes / 1024.0 / 1024.0, 2) || ' MB'
              ELSE ROUND(size_bytes / 1024.0 / 1024.0 / 1024.0, 2) || ' GB'
            END as db_size_formatted
          FROM (
            SELECT 
              COALESCE(
                (SELECT dm.value 
                 FROM db_metrics dm 
                 JOIN db_metric_names dmn ON dm.metric_id = dmn.id 
                 WHERE dmn.name = 'database_size' 
                 ORDER BY dm.timestamp DESC LIMIT 1),
                (SELECT page_count FROM pragma_page_count()) * 
                (SELECT page_size FROM pragma_page_size())
              ) as size_bytes
          )
        `,
        echartsOption: {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: '0 B',
              fontSize: 24,
              fontWeight: 'bold',
              fill: '#ffffff',
              textAlign: 'center'
            }
          }]
        }
      },
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Total Runs',
        gridPos: { x: 2, y: 0, w: 2, h: 1 },
        query: "SELECT COUNT(*) as total_runs FROM runs",
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
              fill: '#ffffff',
              textAlign: 'center'
            }
          }]
        }
      },
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Total Metrics',
        gridPos: { x: 4, y: 0, w: 2, h: 1 },
        query: "SELECT COUNT(*) as total_metrics FROM metrics",
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
              fill: '#ffffff',
              textAlign: 'center'
            }
          }]
        }
      },
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Total Events',
        gridPos: { x: 6, y: 0, w: 2, h: 1 },
        query: "SELECT COUNT(*) as total_events FROM events",
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
              fill: '#ffffff',
              textAlign: 'center'
            }
          }]
        }
      },

      // Avg Metrics per Run stat panel
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Avg Metrics/Run',
        gridPos: { x: 8, y: 0, w: 2, h: 1 },
        query: `
          SELECT 
            ROUND(
              CAST((SELECT COUNT(*) FROM metrics) AS REAL) / 
              NULLIF((SELECT COUNT(*) FROM runs), 0), 
              1
            ) as avg_metrics_per_run
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
              fill: '#ffffff',
              textAlign: 'center'
            }
          }]
        }
      },

      // Database Size Breakdown (Treemap Chart)
      {
        id: generateUUID(),
        type: 'treemap',
        title: 'Database Size Breakdown',
        gridPos: { x: 0, y: 1, w: 6, h: 4 },
        query: `
          SELECT 
            'Metrics Table' as table_name,
            dm.value as actual_bytes
          FROM db_metrics dm
          JOIN db_metric_names dmn ON dm.metric_id = dmn.id
          JOIN db_monitored_objects dmo ON dm.object_id = dmo.id
          WHERE dmn.name = 'table_size_bytes' 
            AND dmo.name = 'metrics'
            AND dm.timestamp = (
              SELECT MAX(dm2.timestamp) 
              FROM db_metrics dm2 
              JOIN db_metric_names dmn2 ON dm2.metric_id = dmn2.id
              JOIN db_monitored_objects dmo2 ON dm2.object_id = dmo2.id
              WHERE dmn2.name = 'table_size_bytes' 
                AND dmo2.name = 'metrics'
            )
          UNION ALL
          SELECT 
            'Events Table' as table_name,
            dm.value as actual_bytes
          FROM db_metrics dm
          JOIN db_metric_names dmn ON dm.metric_id = dmn.id
          JOIN db_monitored_objects dmo ON dm.object_id = dmo.id
          WHERE dmn.name = 'table_size_bytes' 
            AND dmo.name = 'events'
            AND dm.timestamp = (
              SELECT MAX(dm2.timestamp) 
              FROM db_metrics dm2 
              JOIN db_metric_names dmn2 ON dm2.metric_id = dmn2.id
              JOIN db_monitored_objects dmo2 ON dm2.object_id = dmo2.id
              WHERE dmn2.name = 'table_size_bytes' 
                AND dmo2.name = 'events'
            )
          UNION ALL
          SELECT 
            'Runs Table' as table_name,
            dm.value as actual_bytes
          FROM db_metrics dm
          JOIN db_metric_names dmn ON dm.metric_id = dmn.id
          JOIN db_monitored_objects dmo ON dm.object_id = dmo.id
          WHERE dmn.name = 'table_size_bytes' 
            AND dmo.name = 'runs'
            AND dm.timestamp = (
              SELECT MAX(dm2.timestamp) 
              FROM db_metrics dm2 
              JOIN db_metric_names dmn2 ON dm2.metric_id = dmn2.id
              JOIN db_monitored_objects dmo2 ON dm2.object_id = dmo2.id
              WHERE dmn2.name = 'table_size_bytes' 
                AND dmo2.name = 'runs'
            )
          UNION ALL
          SELECT 
            'System & Indexes' as table_name,
            (
              SELECT dm.value 
              FROM db_metrics dm 
              JOIN db_metric_names dmn ON dm.metric_id = dmn.id 
              WHERE dmn.name = 'database_size' 
              ORDER BY dm.timestamp DESC LIMIT 1
            ) - 
            (
              SELECT SUM(dm.value)
              FROM db_metrics dm
              JOIN db_metric_names dmn ON dm.metric_id = dmn.id
              JOIN db_monitored_objects dmo ON dm.object_id = dmo.id
              WHERE dmn.name = 'table_size_bytes' 
                AND dmo.name IN ('metrics', 'events', 'runs')
                AND dm.timestamp = (
                  SELECT MAX(dm2.timestamp) 
                  FROM db_metrics dm2 
                  JOIN db_metric_names dmn2 ON dm2.metric_id = dmn2.id
                  WHERE dmn2.name = 'table_size_bytes' 
                    AND dm2.object_id = dm.object_id
                )
            ) as actual_bytes
          ORDER BY actual_bytes DESC
        `,
        echartsOption: {
          tooltip: {
            trigger: 'item',
            formatter: function(info: any) {
              try {
                const formattedSize = formatDataSizeForTooltip(info.value);
                return info.name + '<br/>Size: ' + formattedSize;
              } catch (error) {
                console.error('🌳 Tooltip formatting error:', error);
                return info.name + '<br/>Size: ' + info.value + ' bytes';
              }
            }
          },
          series: [{
            name: 'Database Size',
            type: 'treemap',
            width: '100%',
            height: '100%',
            roam: false,
            nodeClick: false,
            breadcrumb: { show: false },
            leafDepth: 1,
            drillDownIcon: '',
            label: {
              show: true,
              formatter: function(params: any) {
                try {
                  const formattedSize = formatDataSizeForChart(params.value);
                  return params.name + '\n' + formattedSize;
                } catch (error) {
                  console.error('🌳 Label formatting error:', error);
                  return params.name + '\n' + params.value + 'B';
                }
              },
              fontSize: 11,
              color: CHART_COLORS.textPrimary,
              fontWeight: 'bold',
              overflow: 'truncate',
              ellipsis: '...'
            },
            itemStyle: {
              borderColor: CHART_COLORS.textPrimary,
              borderWidth: 2,
              gapWidth: 2
            },
            levels: [
              {
                // Level 0 - Large sections
                itemStyle: {
                  borderColor: CHART_COLORS.textPrimary,
                  borderWidth: 2,
                  gapWidth: 2
                },
                label: {
                  show: true,
                  formatter: function(params: any) {
                    try {
                      const formattedSize = formatDataSizeForChart(params.value);
                      return params.name + '\n' + formattedSize;
                    } catch (error) {
                      console.error('🌳 Level 0 formatting error:', error);
                      return params.name + '\n' + params.value + 'B';
                    }
                  },
                  fontSize: 11,
                  color: CHART_COLORS.textPrimary,
                  fontWeight: 'bold'
                }
              },
              {
                // Level 1 - Medium sections
                itemStyle: {
                  borderColor: CHART_COLORS.textPrimary,
                  borderWidth: 1,
                  gapWidth: 1
                },
                label: {
                  show: true,
                  formatter: function(params: any) {
                    try {
                      const formattedSize = formatDataSizeForChart(params.value);
                      return params.name + '\n' + formattedSize;
                    } catch (error) {
                      console.error('🌳 Level 1 formatting error:', error);
                      return params.name + '\n' + params.value + 'B';
                    }
                  },
                  fontSize: 10,
                  color: CHART_COLORS.textPrimary,
                  fontWeight: 'normal'
                }
              },
              {
                // Level 2 - Small sections
                itemStyle: {
                  borderColor: CHART_COLORS.textPrimary,
                  borderWidth: 1,
                  gapWidth: 1
                },
                label: {
                  show: true,
                  formatter: function(params: any) {
                    try {
                      // For small sections, use compact format and abbreviated name
                      const formattedSize = formatDataSize(params.value, 0); // No decimals for small sections
                      const shortName = params.name.split(' ')[0]; // Take first word only
                      return shortName + '\n' + formattedSize;
                    } catch (error) {
                      console.error('🌳 Level 2 formatting error:', error);
                      const shortName = params.name.split(' ')[0];
                      return shortName + '\n' + params.value + 'B';
                    }
                  },
                  fontSize: 9,
                  color: CHART_COLORS.textPrimary,
                  fontWeight: 'normal'
                }
              }
            ],
            data: []
          }]
        }
      },

      // Most Frequent Metrics (Horizontal Bar)
      {
        id: generateUUID(),
        type: 'bar',
        title: 'Top 10 Most Frequent Metrics',
        gridPos: { x: 6, y: 1, w: 6, h: 4 },
        query: `
          SELECT
            mn.name as metric_name,
            COUNT(m.id) as total_count
          FROM metrics m
          JOIN metric_names mn ON m.metric_name_id = mn.id
          GROUP BY mn.name
          ORDER BY total_count DESC
          LIMIT 10
        `,
        echartsOption: {
          tooltip: { trigger: 'axis' },
          xAxis: { type: 'value' },
          yAxis: { type: 'category', data: [] },
          series: [{
            type: 'bar',
            data: []
          }]
        }
      },

      // Database Growth Over Time (Simple Line Chart) - Full Width
      {
        id: generateUUID(),
        type: 'timeseries',
        title: 'Daily Runs Over Time',
        gridPos: { x: 6, y: 9, w: 6, h: 4 },
        query: `
          SELECT 
            DATE(start_time / 1000, 'unixepoch') as date,
            COUNT(*) as daily_runs
          FROM runs 
          WHERE start_time IS NOT NULL
          GROUP BY DATE(start_time / 1000, 'unixepoch')
          ORDER BY date
        `,
        echartsOption: {
          xAxis: { type: 'time' },
          yAxis: { type: 'value', name: 'Daily Runs' },
          tooltip: { trigger: 'axis' },
          series: [{
            type: 'line',
            name: 'Daily Runs',
            smooth: true,
            data: []
          }]
        }
      },

      // Most Frequent Events (Horizontal Bar)
      {
        id: generateUUID(),
        type: 'bar',
        title: 'Top 10 Most Frequent Events',
        gridPos: { x: 0, y: 9, w: 6, h: 4 },
        query: `
          SELECT
            en.name as event_name,
            COUNT(e.id) as total_count
          FROM events e
          JOIN event_names en ON e.event_name_id = en.id
          GROUP BY en.name
          ORDER BY total_count DESC
          LIMIT 10
        `,
        echartsOption: {
          tooltip: { trigger: 'axis' },
          xAxis: { type: 'value' },
          yAxis: { type: 'category', data: [] },
          series: [{
            type: 'bar',
            data: []
          }]
        }
      },

      // Metrics Growth Over Time
      {
        id: generateUUID(),
        type: 'timeseries',
        title: 'Metrics Collection Over Time',
        gridPos: { x: 0, y: 13, w: 12, h: 4 },
        query: `
          SELECT 
            DATE(real_timestamp / 1000, 'unixepoch') as time,
            COUNT(*) as daily_metrics
          FROM metrics 
          WHERE real_timestamp IS NOT NULL
          GROUP BY DATE(real_timestamp / 1000, 'unixepoch')
          ORDER BY time
        `,
        echartsOption: {
          xAxis: { type: 'time' },
          yAxis: { type: 'value', name: 'Daily Metrics' },
          tooltip: { trigger: 'axis' },
          series: [{
            type: 'line',
            name: 'Daily Metrics',
            smooth: true,
            data: []
          }]
        }
      },

      // Table showing recent database activity
      {
        id: generateUUID(),
        type: 'table',
        title: 'Recent Database Activity',
        gridPos: { x: 0, y: 17, w: 6, h: 4 },
        query: `
          SELECT 
            'Run #' || run_id as activity,
            'Game Session' as type,
            datetime(start_time / 1000, 'unixepoch') as timestamp,
            final_wave as details
          FROM runs 
          WHERE start_time IS NOT NULL
          ORDER BY start_time DESC 
          LIMIT 10
        `,
        echartsOption: {}
      },

      // Database Health Status Table
      {
        id: generateUUID(),
        type: 'table',
        title: 'Database Health Metrics',
        gridPos: { x: 6, y: 17, w: 6, h: 4 },
        query: `
          SELECT 
            'table_count' as metric,
            COUNT(*) as value,
            'database' as table_scope,
            datetime('now') as last_updated
          FROM sqlite_master 
          WHERE type = 'table'
          UNION ALL
          SELECT 
            'total_runs' as metric,
            COUNT(*) as value,
            'runs' as table_scope,
            datetime('now') as last_updated
          FROM runs
          UNION ALL
          SELECT 
            'total_metrics' as metric,
            COUNT(*) as value,
            'metrics' as table_scope,
            datetime('now') as last_updated
          FROM metrics
        `,
        echartsOption: {}
      }
    ],
    time: { from: 'now-7d', to: 'now' },
    refresh: '1m'
  },
  variables: [],
  tags: ['database', 'health', 'monitoring'],
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  created_by: 'system',
  is_default: true,
  schema_version: 1
};
