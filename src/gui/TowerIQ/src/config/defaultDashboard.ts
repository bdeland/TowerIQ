import { Dashboard } from '../contexts/DashboardContext';
import { generateUUID } from '../utils/uuid';

export const defaultDashboard: Dashboard = {
  id: 'default-dashboard',
  uid: 'default-dashboard-uid',
  title: 'TowerIQ Overview123',
  description: 'Default pre-written dashboard, loaded from the frontend.',
  config: {
    panels: [
      {
        id: generateUUID(),
        type: 'stat',
        title: 'Welcome to TowerIQ',
        gridPos: { x: 0, y: 0, w: 2, h: 2 },
        query: "SELECT 'Ready to Monitor' AS value",
        echartsOption: {
          tooltip: { show: false },
          graphic: [{
            type: 'text',
            left: 'center',
            top: 'center',
            style: { text: '', fontSize: 28, fontWeight: 'bold' }
          }]
        }
      },
      {
        id: generateUUID(),
        type: 'table',
        title: 'Recent Runs',
        gridPos: { x: 5, y: 0, w: 8, h: 4 },
        query: "SELECT run_id, tier, final_wave, CPH, duration_gametime FROM runs ORDER BY start_time DESC LIMIT 10",
        echartsOption: {}
      },
      {
        id: generateUUID(),
        type: 'timeseries',
        title: 'Coins Per Hour (Last 10 Runs)',
        gridPos: { x: 0, y: 2, w: 4, h: 4 },
        query: "SELECT start_time, CPH FROM runs ORDER BY start_time DESC LIMIT 10",
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
        gridPos: { x: 4, y: 4, w: 8, h: 2 },
        query: "SELECT timestamp, level, event, source FROM logs ORDER BY timestamp DESC LIMIT 5",
        echartsOption: {}
      }
    ],
    time: { from: 'now-1h', to: 'now' },
    refresh: '30s'
  },
  tags: ['default', 'overview'],
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  created_by: 'system',
  is_default: true,
  schema_version: 1
};
