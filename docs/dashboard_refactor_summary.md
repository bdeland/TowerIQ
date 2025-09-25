# Dashboard Refactor Investigation & Remediation Summary

## Background
- The refactor introduced a hierarchical dashboard domain (DashboardManager -> Dashboard -> Panel) backed by new `/api/v2` endpoints and DB storage.
- The React app still consumed legacy REST responses (`/api/dashboards` with raw SQL strings), so the domain classes received incompatible data and failed before rendering.

## Key Breakages Identified
1. **Config shape mismatch** – `Panel.fetchData` expects `query` objects (`{ query, dataSourceId }`), but the app kept sending plain SQL strings from `defaultDashboard.ts` and the old API. The first `includes` call inside `composeQuery` hit `undefined`, crashing panel loads.
2. **Stale React orchestration** – `loadDashboard` in `NewDashboardContext` manually assembled dashboards, invoked `refreshAll()` via a closure bound to the previous state, and never awaited `dashboard.loadData()`. Panels remained in `idle` forever.
3. **Mixed transport layer** – Some paths used `${API_CONFIG.BASE_URL}/v2/...`, others hit relative `/api/...`. In packaged builds those relative calls miss the FastAPI server entirely, producing 404/CORS failures.
4. **Missing normalization layer** – The frontend never adapted the `/api/v2/dashboards` JSON shape (snake_case metadata, nested types) into the domain model (`Date` instances, `PanelConfig` structure), so even successful fetches produced unusable objects.

## Fixes Applied
### Domain Wiring
- Added adapter helpers in `DashboardManager.ts` (metadata extraction, panel/variable mapping, config normalization) and widened the type imports accordingly.
- Swapped legacy `/api/dashboards` fetches for `${API_CONFIG.BASE_URL}/v2/dashboards` and normalized every payload before instantiating dashboards.
- Parallelized user-dashboard hydration while avoiding double-registration by checking the manager cache first.

### Data Fetchers
- `Panel.executeQuery` and `DashboardVariables.executeOptionsQuery` now call `${API_CONFIG.BASE_URL}/v2/query`, ensuring all dashboard data requests go through the new backend route and consistent base URL.

### React Context
- Rebuilt `NewDashboardContext` around `DashboardManager` APIs:
  - `loadDashboard` awaits `manager.loadDashboard(id)` and `dashboard.loadData()` before mapping panel state for React consumers.
  - Added helpers to convert domain `PanelState` objects into the lightweight context shape and keep them in sync on refreshes and event emissions.
  - CRUD operations delegate to manager methods instead of duplicating REST helpers.
- Removed the bespoke fetch helpers (`fetchDashboardConfig`, etc.), so the UI state now mirrors the manager’s state machine.

## Why These Changes Matter
- Normalization lets the new domain layer work with migrated records stored in `dashboard_configs` without hand conversion.
- Centralizing lifecycle calls in the manager avoids diverging caches and guarantees React components observe the authoritative dashboard instance.
- Standardizing on `${API_CONFIG.BASE_URL}` eliminates origin/CORS issues and prepares the app for packaging.

## Follow-Up Recommendations
- Run `scripts/pre_migrate_dashboards.py` followed by `scripts/migrate_dashboards_to_v2.py` before flipping the feature flag in production.
- Add an integration test (or UI smoke) that boots the manager via the new context to catch regressions in the adapter layer.
- Audit remaining components/hooks for lingering `/api/dashboards` calls so the legacy endpoints can be retired cleanly.
