# Dashboard Data Query & Refresh Refactor Plan

## Background
- Current dashboards issue panel queries directly from component effects, making throttling, deduplication, and cache invalidation inconsistent.
- Manual intervals and auto-refresh logic work at the page level, so panels with new data force whole-dashboard refreshes.
- Fetch batching is bespoke per page, with no visibility into query health, duplicate requests, or backend load.

## Goals
- Provide a scalable client data layer that minimizes database load while keeping charts fresh.
- Fetch only the deltas that matter per panel, with panel-level refresh control and status visibility.
- Offer a clear contract between frontend and backend for caching, metadata, and conditional refreshes.
- Preserve flexibility for ad-hoc dashboards and future Grafana-like features (variables, overrides, alerts).

## Constraints & Assumptions
- Back-end exposes a POST `/query` endpoint today; we can add light metadata endpoints without major API versioning.
- All dashboard datasets are treated as append-only/immutable, so watermarks can rely on ingest order.
- Dashboards may define dozens of panels, so concurrency must stay below ~4-6 parallel network calls.
- Auto-refresh must coexist with manual intervals and obey user “Off/Auto/Ns” selections.

## SQLAlchemy Integration Feasibility & Plan
- **Current state**: Backend services rely on the stdlib `sqlite3` driver with manual connection management, string-formatted SQL, and bespoke batching logic exposed through the `/query` endpoint.
- **Feasibility**: `SQLAlchemy` 2.x (Core or ORM) supports SQLite and SQLCipher via custom creators, letting us keep encryption and pragmas while gaining an abstraction for composable, parameterized queries. It can coexist with raw SQL during migration.
- **Benefits**: Centralizes query construction, enforces parameter binding, unlocks schema reflection for dashboard metadata, simplifies migrations/versioning, and gives us pooled connections + consistent error handling.
- **Migration approach**:
  1. Add `SQLAlchemy` (and validate `sqlcipher3` compatibility via a `create_engine(..., creator=...)` hook or community dialect) and fold engine creation into `DatabaseService` with existing WAL/PRAGMA setup in `event.listen` hooks.
  2. Describe tables used by dashboards with `SQLAlchemy` metadata (declarative models or `Table` objects with reflection) so query builders can target columns safely.
  3. Introduce a `QueryBuilderService` that accepts panel variables and returns `Select` objects; let `composeQuery` emit the final SQL + bound parameters derived from these objects for the `/query` API.
  4. Refactor `/query` and `/query/meta` handlers to execute through a scoped `SQLAlchemy` session/connection manager with shared retry/error instrumentation.
  5. Incrementally replace direct `sqlite3` calls in `DatabaseService` with `SQLAlchemy` equivalents, retaining a short-term escape hatch through `text()` executions for legacy statements.
- **Risks & mitigations**: Monitor for WAL compatibility (apply pragmas on `connect`), compare performance for bulk writes, and add regression tests that diff `SQLAlchemy`-generated SQL/row counts against the existing implementation before cutover.

## Target Architecture Overview
1. **DashboardDataService** (frontend) orchestrates all panel requests, using shared scheduling, caching, and deduplication.
2. **PanelQueryContext** encapsulates the inputs for a request (panel id, composed SQL, variable hash, watermark snapshot, cache policy).
3. **RequestCache** adds stale-while-revalidate semantics and tracks payload + metadata.
4. Backend enriches responses with metadata (`etag`, `maxUpdatedAt`, `rowCount`, `ttlHint`) and supports `If-None-Match`/`sinceWatermark` parameters.
5. RefreshButton interacts with DashboardDataService (not the page) to trigger manual, interval, or auto refresh cycles.

## Component Ownership
- **Backend API**
  - `/query` accepts optional `watermark`/`generationId`, returns `{ data, meta }`.
  - `/query/meta` (new) returns metadata only for low-cost freshness checks.
  - Responses must include cache validators (ETag or hash), data watermark, and TTL hints.
- **Frontend Data Layer**
  - `DashboardDataContext` stores panel states: `{ data, status, lastUpdated, staleReason, meta }`.
  - `DashboardDataService` exposes `fetchPanel(panelId, options)` and `refreshPanels({ scope, reason })`.
  - `PanelScheduler` limits concurrency, batches compatible requests, and applies jitter/backoff.
  - `usePanelData(panelId)` hook consumes context, powering charts and status UI.
- **Utilities**
  - `composeQuery` upgraded to accept `QueryContext` (variables, watermark clause, pagination) and return `{ sql, cacheKeyParts }`.
  - `RequestCache` wrapper (`PanelCache`) maintains TTL, stale markers, pending promises, and invalidation helpers.

## Caching & Consistency Model
- Cache key: `panelId|variablesHash|watermarkKey|querySignature`.
- Entries store `{ data, meta: { etag, maxUpdatedAt, rowCount, fetchedAt, ttlHint }, status }`.
- Default policy: serve cached data if TTL valid, trigger background revalidation on expiry.
- Support manual `forceRefresh` to bypass cache and update watermark.
- Persist last-known watermarks in memory; optional `localStorage` persistence for warm reloads.

## Refresh Modes
- UI decision: keep refresh controls at the dashboard level; no per-panel manual buttons are required.
- **Manual**: `RefreshButton` calls `DashboardDataService.refresh({ scope: 'panel' | 'dashboard', reason: 'manual' })`.
- **Fixed Interval**: scheduler registers per-user interval; when triggered, it refreshes panels with `pollingPolicy !== 'manual'`.
- **Auto**:
  - Poll `/query/meta` for each panel (groupable by datasource) using exponential backoff with jitter.
  - On newer `etag`/`maxUpdatedAt`, enqueue full data fetch.
  - If backend later supports push (SSE/WebSocket), service can switch to event-driven updates without changing hook API.

## Implementation Phases
1. **Discovery & Contracts** (Backend + Frontend)
   - Document metadata contract and update dashboard schema to capture `watermarkColumn`, `pollingPolicy`, `staleAfter`, `autoMetaInterval`.
   - Confirm `SQLAlchemy` driver compatibility (SQLite + SQLCipher), pick Core vs ORM usage per query type, and draft a migration plan to phase out raw dashboard queries.
   - Introduce dashboard schema versioning and migration scripts to evolve metadata safely.
   - Build shared TypeScript types for `{ data, meta }` payloads.
2. **Infrastructure Setup**
   - Introduce `DashboardDataContext`, `DashboardDataService`, and `usePanelData` hook.
   - Wrap existing `RequestCache` to support stale-while-revalidate and metadata storage.
   - Implement `PanelScheduler` with concurrency controls and request dedupe.
3. **Backend Enhancements**
   - Add `etag`, `maxUpdatedAt`, `ttlHint` to `/query` responses; honor `If-None-Match` returning 304 when unchanged.
   - Stand up a shared `SQLAlchemy` engine/session layer that wraps `sqlcipher3` connections, carries existing PRAGMA configuration, and exposes helpers for transactional query execution.
   - Add `/query/meta` endpoint with cheap aggregation query.
   - Port the highest-traffic dashboard queries to SQLAlchemy Core expressions and expose a builder that can emit raw SQL when the frontend needs to preview queries.
   - Support optional `sinceWatermark` filter for delta fetches.
4. **Dashboard Migration**
   - Convert Default and Live Run dashboards to use `usePanelData`; remove bespoke batching effects.
   - Wire `RefreshButton` to new service; implement dashboard-level status bar showing active refreshes.
   - Validate interval + auto behavior, adjust scheduler knobs.
5. **Hardening & Extensions**
   - Implement telemetry/logging hooks (dev console + optional analytics) for cache stats and request durations.
   - Add persisted watermarks per panel (optional) and safeguards for variable changes (auto cache bust).
   - Remove remaining direct `sqlite3` call sites once SQLAlchemy coverage is complete and monitor for regressions via side-by-side query logging.
   - Cleanup legacy code paths and ensure backwards compatibility for custom dashboards.

## Testing Strategy
- **Unit Tests**
  - `composeQuery` permutations with variables, watermarks, and limits.
  - `DashboardDataService` cache hit/miss, dedupe, stale revalidation, concurrency gates.
  - `PanelScheduler` timing/backoff logic (fake timers).
  - Query inspector store reducers prune histories correctly and serialize inspector payloads for CSV export.
- **Integration / Component Tests**
  - React testing library: dashboard renders cached data immediately, refresh updates panel without affecting others.
  - Mock backend returning 304 to assert no redundant data loads.
  - Verify the Query Inspector drawer renders only in development builds, displays captured SQL/metadata per tab, and that exports/copy actions produce the expected artifacts.
- **Manual / Exploratory**
  - Stress test with high panel counts; measure network calls and timing.
  - Validate auto mode responds to simulated new data while other panels remain untouched.
  - Exercise the Query Inspector end-to-end: trigger successes, cached responses, and intentional failures to confirm tabs populate accurately and CSV exports remain performant on large datasets.
## Observability & Tooling
- Add verbose logging toggled via `import.meta.env.DEV` to surface cache and refresh events.
- Expose `DashboardDataService.getStats()` for developer console inspection.
- Channel inspector events into the same instrumentation pipeline so opening the drawer automatically captures new samples and can enable per-panel debug logging.
- Consider optional in-app developer overlay summarizing panel freshness, fetched rows, and last durations.

## Query Inspector (Development Mode)
- **Activation & entry point**: Render a Material UI `QueryStatsIcon` to the left of the fullscreen toggle when `import.meta.env.DEV` is true. Clicking the icon opens a right-anchored drawer scoped to the panel.
- **Captured telemetry**: Extend `DashboardDataService` to emit inspector events containing request id, panel id, SQL (compiled from `SQLAlchemy`), bound parameters, variable snapshot, timings (compose, network, transform), cache state, and raw/processed payload summaries.
- **Drawer layout & tabs**:
  - **Data**: Tabular view of the rows returned (raw and transformed), toggle field overrides, pagination, copy-to-clipboard, and CSV export (raw vs transformed). Support multi-query result selection when panels execute more than one request.
  - **Stats**: Display query execution time, server processing, network latency, rows returned, cache source (fresh/hit/stale), and scheduler metadata (batch id, retries).
  - **Query**: Show the SQL string, bound parameters, and raw response JSON. Provide quick-copy buttons for SQL and response.
  - **JSON**: Expose panel config JSON, variable context, and response meta (`etag`, `maxUpdatedAt`, `ttlHint`) for provisioning/debugging.
  - **Error**: Only present when the latest request failed; surface stack traces, SQLAlchemy/SQLite error codes, and retry suggestions.
- **Implementation steps**:
  1. Create an inspector store (context or Zustand) that records the latest N events per panel, with pruning to avoid unbounded memory use.
  2. Hook `DashboardDataService` request lifecycle (before send, after response, on error) to push inspector entries including diffed payloads.
  3. Build a `PanelQueryInspectorDrawer` component with tabbed content, code/highlight views, CSV export helpers, and clipboard utilities.
  4. Update `DashboardGrid` panel header to conditionally render the icon and pass inspector toggle handlers; ensure keyboard accessibility.
  5. Gate the entire feature behind `import.meta.env.DEV` (and optionally a user toggle) so production builds tree-shake the inspector.
- **Performance & hygiene**: Run heavy formatting (diffs, CSV generation) in web workers when datasets exceed thresholds, and exclude inspector telemetry from production logs.

## Risks & Mitigations
- **Inconsistent Metadata**: enforce metadata contract via shared types and backend schema validation.
- **Long-Running Queries**: scheduler applies backoff and can mark panel as degraded; allow panel config to opt out of auto meta polling.
- **Watermark Drift**: fallback to full refresh when `sinceWatermark` returns empty but metadata indicates newer data.
- **State Explosion**: limit persisted watermarks to recent dashboards; clear on logout or variable reset.

## Open Questions
- Define target data freshness windows (service-level objective) per dashboard (e.g., Live Run <= 5s, Default <= 60s) to tune default TTL and backoff; capture this in dashboard metadata alongside config.
## Appendix: Data Contracts
```ts
interface PanelMeta {
  etag: string;               // Stable hash of data payload
  maxUpdatedAt?: string;      // ISO timestamp for watermark
  rowCount: number;           // Rows returned
  ttlHint?: number;           // ms until considered stale
  processedAt: string;        // ISO timestamp from backend
}

interface PanelResponse<T> {
  data: T[];
  meta: PanelMeta;
}

interface PanelRequestOptions {
  panelId: string;
  sql: string;
  variablesHash: string;
  watermark?: string;
  forceRefresh?: boolean;
}
```















