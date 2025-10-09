# TowerIQ Codebase Audit

## Executive Summary

- The backend eagerly initializes configuration, logging, and database subsystems at import time, making startup brittle and duplicative while masking failures during app lifespan management.
- Several data-access pathways (backend SQL execution and frontend query composition) rely on manual string substitution, leaving the system open to SQL-injection-style bugs despite `SELECT` guards.
- Multiple long-lived singletons (restore-suggestion cache, device cache, polling timers) rely on mismatched globals or never-teared-down timers, leading to stale state and resource leaks.
- Frontend hooks disable critical polling by default and log noisy diagnostics in production pathways; observability is inconsistent across the stack.

## Backend Findings

### Duplicate configuration/logging bootstrap (High)

- `configure_logging()` instantiates `ConfigurationManager` and calls `setup_logging()` during module import, yet `lifespan()` repeats the entire sequence (`src/tower_iq/api_server.py:37`, `src/tower_iq/api_server.py:85`).
- Result: configuration is read twice, logging handlers are rebuilt each import, and unexpected side-effects occur before FastAPI has a running event loop. Hot reloading and unit tests will pay the latency cost repeatedly.
- Recommendation: lazily instantiate configuration/logging inside `lifespan()` only, pass shared instances through FastAPI state or dependency wiring, and delete the unused `sys` import and duplicate `if __name__ == "__main__"` entry point (`src/tower_iq/api_server.py:10`, `src/tower_iq/api_server.py:371`).

### Insecure CORS defaults (High)

- CORS middleware allows `"*"` origins while `allow_credentials=True` (`src/tower_iq/api_server.py:323`). Starlette rejects this combination, so the wildcard is silently ignored, leaving origin control unclear.
- Recommendation: enumerate trusted dev/prod origins explicitly, or disable credentials when using a wildcard to avoid misconfiguration.

### Restore-suggestion cache never hits (Medium)

- Startup stores `_restore_suggestion_cache` in module globals (`src/tower_iq/api_server.py:205`), but the router fetches from `builtins` (`src/tower_iq/api/routers/database.py:101`), so every request recomputes the suggestion and never returns the warm cache.
- Recommendation: keep the cache in one module (e.g., add `set_restore_suggestion()` in `tower_iq.api.dependencies`) or inject it through FastAPI state to maintain cohesion.

### SQL execution by string interpolation (Critical)

- `SQLiteExecutor.execute()` manually substitutes `${var}` tokens, then executes the raw SQL (`src/tower_iq/services/data_source_executors.py:150`). Attackers can smuggle clauses that bypass the `SELECT` guard.
- Recommendation: convert variable expansion to parameter binding (`cursor.execute(query, params)`), or move interpolation server-side using a safe templating layer.

### Event system inefficiencies (Low)

- `Signal` is declared a dataclass but manually manages state and fetches a structlog logger on each emit (`src/tower_iq/core/event_system.py:11`).
- Recommendation: remove `@dataclass`, instantiate a module-level logger once, and keep the class minimal for readability.

### Device-cache loop binding (Medium)

- `asyncio.Lock` and cache globals are created at import time (`src/tower_iq/api/cache_utils.py:15`), binding them to whichever event loop imports the module first.
- Recommendation: encapsulate cache state in a FastAPI dependency or a lightweight class, enabling per-app lifecycle management and test isolation.

## Frontend Findings

### Polling permanently disabled (High)

- `DISABLE_POLLING` defaults to `true`, preventing `useBackend` from ever starting the shared polling loop (`frontend/src/hooks/useBackend.ts:124`).
- Recommendation: gate the flag on `import.meta.env.DEV` or remove it entirely so components receive fresh backend status.

### Unbounded interval timers (Medium)

- Each `RequestCache` instance starts a `setInterval()` for cleanup without storing/clearing the handle (`frontend/src/utils/requestCache.ts:44`).
- Recommendation: capture the interval ID, expose `dispose()` to clear it, or implement a shared singleton to avoid timer leaks.

### Unsafe query composition (Critical)

- `composeQuery` interpolates dashboard variables directly into SQL strings (`frontend/src/utils/queryComposer.ts:10`).
- Recommendation: align with backend fixes—return structured parameters and run substitution server-side, or at minimum sanitize and whitelist values before interpolation.

### Noisy console logging (Low)

- `DashboardDataService` logs extensively with `console.log/error` even for expected flows (`frontend/src/services/DashboardDataService.ts:92`).
- Recommendation: funnel logs through a single debug logger and guard with `import.meta.env.DEV` to keep production consoles clean.

## Cross-Cutting Recommendations

1. Introduce a shared configuration/service locator so routers consume dependencies without module-level globals.
2. Standardize parameterized query execution across backend and frontend tooling to prevent injection vectors.
3. Replace ad-hoc globals and timers with lifecycle-aware objects tied to FastAPI and React component lifecycles.
4. Establish a logging guideline: backend via structlog, frontend via a small utility that no-ops outside development.
