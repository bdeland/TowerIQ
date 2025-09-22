# Dashboard Data Query & Refresh Refactor Plan
## Simplified & Practical Implementation Guide

### Executive Summary
This document provides a focused, practical approach to refactoring TowerIQ's dashboard data fetching architecture. The refactor addresses the core issues of code duplication and inefficient batching while avoiding over-engineering. This is a 3-week focused effort that delivers immediate value and sets a foundation for future enhancements.

### Current State Analysis
**Critical Issues Identified:**
1. **Duplicated Data Fetching Logic**: Each dashboard page (`DefaultDashboardPage`, `DatabaseHealthDashboardPage`, `LiveRunTrackingDashboardPage`, `DashboardViewPage`) implements its own `fetchAllPanelData` function with identical batching logic
2. **No Request Deduplication**: Multiple panels can trigger identical queries simultaneously
3. **Hardcoded Batching Parameters**: `BATCH_SIZE=3`, `DELAY_BETWEEN_REQUESTS=100ms`, `DELAY_BETWEEN_BATCHES=200ms` scattered across files
4. **No Caching Strategy**: Every refresh fetches all data regardless of staleness
5. **Poor Error Handling**: Limited error recovery and user feedback
6. **No Loading States**: Users have no indication of data fetching progress

### Business Goals & Success Metrics
**Primary Goals:**
- **Code Quality**: Eliminate 4 duplicate `fetchAllPanelData` implementations
- **Performance**: Optimize batching logic for 20-30% improvement in load times
- **User Experience**: Add loading states and better error handling
- **Maintainability**: Create reusable data fetching service
- **Developer Experience**: Simplify debugging with better logging

**Realistic Success Metrics:**
- Code duplication: Eliminate 4 identical `fetchAllPanelData` implementations ✅
- Request efficiency: Reduce duplicate requests by 50%
- User experience: Add loading states and error handling
- Performance: 20-30% improvement in dashboard load times
- Maintainability: Single source of truth for data fetching logic

### Technical Constraints & Assumptions
**Backend Constraints:**
- **Add SQLModel** for type-safe database queries and better code protection
- **Replace raw SQL queries** with SQLModel models and type-safe operations
- **Maintain SQLite3/SQLCipher** compatibility with SQLModel
- **Preserve existing security measures** while adding type safety
- **Keep backward compatibility** for existing dashboard configurations

**Frontend Constraints:**
- React/Tauri architecture with Material UI components
- Must support existing dashboard types: Default, Database Health, Live Run Tracking
- Refresh controls remain at dashboard level (no per-panel buttons)
- Maintain backward compatibility with existing dashboard configurations

**Performance Constraints:**
- Maximum 6 concurrent network requests (current batch size)
- Simple in-memory cache with configurable TTL (5 minutes default)
- Query timeout: 30 seconds maximum (existing)
- Focus on request deduplication and batching optimization

## Simplified Architecture Design

### 1. SQLModel Integration Strategy

**Why SQLModel:**
- **Type Safety**: Eliminates SQL injection risks and provides compile-time type checking
- **Code Protection**: Prevents malformed queries and provides better error handling
- **Simplified Queries**: Reduces raw SQL complexity with Python objects
- **FastAPI Compatibility**: Designed to work seamlessly with FastAPI
- **SQLAlchemy Foundation**: Built on proven SQLAlchemy with Pydantic validation

**SQLModel Models for Dashboard Data:**
```python
# src/tower_iq/models/dashboard_models.py
from sqlmodel import SQLModel, Field, Relationship
from typing import Optional, List, Dict, Any
from datetime import datetime

class Dashboard(SQLModel, table=True):
    id: Optional[str] = Field(default=None, primary_key=True)
    uid: str = Field(unique=True, index=True)
    title: str
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, sa_column_kwargs={"type_": "JSON"})
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationship to panels
    panels: List["DashboardPanel"] = Relationship(back_populates="dashboard")

class DashboardPanel(SQLModel, table=True):
    id: Optional[str] = Field(default=None, primary_key=True)
    dashboard_id: str = Field(foreign_key="dashboard.id")
    title: str
    query: str
    panel_type: str = Field(default="table")
    position: Optional[Dict[str, Any]] = Field(default_factory=dict, sa_column_kwargs={"type_": "JSON"})
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, sa_column_kwargs={"type_": "JSON"})
    
    # Relationship to dashboard
    dashboard: Optional[Dashboard] = Relationship(back_populates="panels")

# Query result models for type-safe responses
class QueryResult(SQLModel):
    data: List[Dict[str, Any]]
    row_count: int
    execution_time_ms: Optional[float] = None
    cache_hit: bool = False
```

**Enhanced Query Service with SQLModel:**
```python
# src/tower_iq/services/query_service.py
from sqlmodel import Session, select, text
from typing import List, Dict, Any, Optional
import time

class QueryService:
    def __init__(self, session: Session):
        self.session = session
    
    async def execute_dashboard_query(
        self, 
        panel: DashboardPanel, 
        variables: Dict[str, Any]
    ) -> QueryResult:
        """Execute a dashboard panel query with type safety"""
        start_time = time.time()
        
        try:
            # Compose query with variables (existing logic)
            final_query = compose_query(panel.query, variables)
            
            # Execute with SQLModel session for better error handling
            result = self.session.exec(text(final_query))
            data = [dict(row._mapping) for row in result]
            
            execution_time = (time.time() - start_time) * 1000
            
            return QueryResult(
            data=data,
                row_count=len(data),
                execution_time_ms=execution_time,
                cache_hit=False
            )
            
        except Exception as e:
            # Better error handling with SQLModel
            raise QueryExecutionError(f"Query failed for panel {panel.title}: {str(e)}")
    
    def get_dashboard_panels(self, dashboard_id: str) -> List[DashboardPanel]:
        """Get panels for a dashboard with type safety"""
        statement = select(DashboardPanel).where(DashboardPanel.dashboard_id == dashboard_id)
        return self.session.exec(statement).all()
```

### 2. Frontend Data Service Strategy

**Current State Analysis:**
- 4 identical `fetchAllPanelData` implementations across dashboard pages
- Hardcoded batching parameters scattered across files
- No request deduplication or caching
- Poor error handling and loading states

**Solution: Extract Shared Service**

**Week 1: Create DashboardDataService**
```typescript
// src/services/DashboardDataService.ts
import { composeQuery } from '../utils/queryComposer';

export class DashboardDataService {
  private cache = new Map<string, { data: any[], timestamp: number }>();
  private pendingRequests = new Map<string, Promise<any>>();
  private config = {
      batchSize: 6,
    delayBetweenRequests: 100,
    delayBetweenBatches: 200,
    cacheTTL: 5 * 60 * 1000, // 5 minutes
    maxRetries: 3
  };
  
  async fetchPanelData(panelId: string, query: string, variables: any) {
    // CRITICAL: Always compose query with variables to handle placeholders
    const finalQuery = composeQuery(query, variables);
    const cacheKey = this.generateCacheKey(panelId, finalQuery, variables);
    
    // Check cache first
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.config.cacheTTL) {
      return cached.data;
    }
    
    // Check for pending request (deduplication)
    if (this.pendingRequests.has(cacheKey)) {
      return this.pendingRequests.get(cacheKey);
    }
    
    // Make request with composed query (no placeholders)
    const promise = this.executeQuery(finalQuery);
    this.pendingRequests.set(cacheKey, promise);
    
    try {
      const result = await promise;
      this.cache.set(cacheKey, { data: result, timestamp: Date.now() });
      return result;
    } finally {
      this.pendingRequests.delete(cacheKey);
    }
  }
  
  async fetchAllPanels(panels: Panel[], variables: any) {
    const panelsWithQueries = panels.filter(panel => panel.query);
    
    for (let i = 0; i < panelsWithQueries.length; i += this.config.batchSize) {
      const batch = panelsWithQueries.slice(i, i + this.config.batchSize);
      
      await Promise.all(batch.map(panel => 
        this.fetchPanelData(panel.id, panel.query, variables)
      ));
      
      // Delay between batches
      if (i + this.config.batchSize < panelsWithQueries.length) {
        await this.delay(this.config.delayBetweenBatches);
      }
    }
  }
  
  // Helper method to check if query has unresolved placeholders
  hasUnresolvedPlaceholders(query: string, variables: any): boolean {
    const composedQuery = composeQuery(query, variables);
    return composedQuery.includes('${');
  }
}
```

### 2. React Hook Integration

**Week 2: Create usePanelData Hook**
```typescript
// src/hooks/usePanelData.ts
export const usePanelData = (panelId: string, query: string, variables: any) => {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dataService = useDashboardDataService();
  
  useEffect(() => {
    const fetchData = async () => {
      // Don't fetch if no query or if variables are still loading
      if (!query || !variables) {
        return;
      }
      
      setLoading(true);
      setError(null);
      
      try {
        // The service handles variable substitution internally
        const result = await dataService.fetchPanelData(panelId, query, variables);
        setData(result);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch data');
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, [panelId, query, JSON.stringify(variables)]);
  
  return { data, loading, error, refetch: () => fetchData() };
};
```

### 3. Dashboard Migration Strategy

**Week 3: Migrate Dashboard Pages**
```typescript
// Before: Duplicated fetchAllPanelData in each dashboard
const fetchAllPanelData = async () => {
  // 50+ lines of identical batching logic
  // Hardcoded parameters
  // No caching or deduplication
};

// After: Use shared service
const { data, loading, error } = usePanelData(panelId, query, variables);

// Or for dashboard-level fetching:
const dataService = useDashboardDataService();
await dataService.fetchAllPanels(panels, variables);
```

## Simplified Implementation Plan

### 4-Week Enhanced Approach (with SQLModel)

**Week 1: SQLModel Integration & Backend Enhancement**
- [ ] **Task 1.1**: Add SQLModel dependency and create SQLCipher-compatible engine
- [ ] **Task 1.2**: Create SQLModel models for Dashboard and DashboardPanel
- [ ] **Task 1.3**: Implement QueryService with type-safe query execution
- [ ] **Task 1.4**: Update `/query` endpoint to use SQLModel instead of raw SQL
- [ ] **Task 1.5**: Add comprehensive unit tests for SQLModel integration
- [ ] **Task 1.6**: Performance testing: SQLModel vs raw SQLite3

**Week 2: Frontend Data Service**
- [ ] **Task 2.1**: Create `DashboardDataService` class with basic caching and deduplication
- [ ] **Task 2.2**: Implement configurable batching parameters (batch size, delays)
- [ ] **Task 2.3**: Add request deduplication to prevent duplicate queries
- [ ] **Task 2.4**: Create simple in-memory cache with TTL
- [ ] **Task 2.5**: Add comprehensive unit tests for the service
- [ ] **Task 2.6**: Integration testing with SQLModel backend

**Week 3: React Integration**
- [ ] **Task 3.1**: Create `usePanelData` hook for individual panel data
- [ ] **Task 3.2**: Create `useDashboardData` hook for dashboard-level fetching
- [ ] **Task 3.3**: Add loading states and error handling
- [ ] **Task 3.4**: Implement retry mechanisms for failed requests
- [ ] **Task 3.5**: Add React component tests
- [ ] **Task 3.6**: Integration testing with existing dashboards

**Week 4: Dashboard Migration**
- [ ] **Task 4.1**: Migrate `DefaultDashboardPage` to use new service
- [ ] **Task 4.2**: Migrate `DatabaseHealthDashboardPage`
- [ ] **Task 4.3**: Migrate `LiveRunTrackingDashboardPage`
- [ ] **Task 4.4**: Migrate `DashboardViewPage`
- [ ] **Task 4.5**: Remove duplicate `fetchAllPanelData` implementations
- [ ] **Task 4.6**: End-to-end testing and performance validation

### Key Benefits of Enhanced Approach (with SQLModel)

1. **Type Safety**: Eliminates SQL injection risks and provides compile-time type checking
2. **Code Protection**: Prevents malformed queries and provides better error handling
3. **Simplified Queries**: Reduces raw SQL complexity with Python objects
4. **FastAPI Compatibility**: Designed to work seamlessly with existing FastAPI setup
5. **Maintainable**: Single source of truth for data fetching with type safety
6. **Extensible**: Foundation for future enhancements with robust data models
7. **Realistic**: 4-week timeline with measurable outcomes and better code quality

### Critical Fix: Variable Placeholder Loading Issue

**Problem Identified:**
- `DashboardPanelView` shows "Query contains placeholders - waiting for processed data" error
- This happens because the component checks for `${` placeholders before variable substitution
- The dashboard-level fetching properly uses `composeQuery()` but panel-level doesn't

**Solution:**
- **Always call `composeQuery()`** in `DashboardDataService.fetchPanelData()` before making API calls
- **Remove placeholder checks** from individual panel components
- **Ensure variables are available** before attempting to fetch data
- **Cache based on final composed query** to avoid duplicate requests

**Implementation:**
```typescript
// Before: Panel shows error for queries with variables
if (panel.query.includes('${')) {
  setError('Query contains placeholders - waiting for processed data');
  return;
}

// After: Service handles variable substitution automatically
const finalQuery = composeQuery(query, variables);
// No placeholders remain, clean API call
```

## Success Criteria & Testing

### Realistic Success Metrics
- [ ] **Code Duplication**: Eliminate 4 identical `fetchAllPanelData` implementations ✅
- [ ] **Variable Loading Fix**: Remove "Query contains placeholders" error for panels with variables ✅
- [ ] **Type Safety**: Replace raw SQL queries with SQLModel type-safe operations ✅
- [ ] **Code Protection**: Eliminate SQL injection risks with parameterized queries ✅
- [ ] **Request Efficiency**: Reduce duplicate requests by 50%
- [ ] **User Experience**: Add loading states and error handling
- [ ] **Performance**: 20-30% improvement in dashboard load times
- [ ] **Maintainability**: Single source of truth for data fetching logic

### Testing Strategy
- [ ] **SQLModel Tests**: Test type-safe query execution and model validation
- [ ] **Type Safety Tests**: Verify SQLModel prevents SQL injection and malformed queries
- [ ] **Unit Tests**: Test `DashboardDataService` with various scenarios
- [ ] **Variable Substitution Tests**: Verify `composeQuery()` handles all placeholder types correctly
- [ ] **Loading State Tests**: Ensure panels with variables show loading instead of placeholder errors
- [ ] **Integration Tests**: Test hooks with SQLModel backend
- [ ] **Performance Tests**: Measure load time improvements (SQLModel vs raw SQL)
- [ ] **User Acceptance**: Verify all dashboard types work correctly
- [ ] **Regression Tests**: Ensure no functionality is lost

## Risk Mitigation

### Low-Risk Approach
1. **SQLModel Integration**: Add SQLModel alongside existing system for gradual migration
2. **Gradual Migration**: Migrate one dashboard at a time
3. **Feature Flags**: Use feature flags for gradual rollout
4. **Rollback Plan**: Easy to revert to raw SQL if issues arise
5. **Monitoring**: Add comprehensive logging for debugging and performance tracking

### What We're Adding (SQLModel Benefits)
- ✅ **Type Safety**: Eliminates SQL injection risks with parameterized queries
- ✅ **Code Protection**: Prevents malformed queries with compile-time checking
- ✅ **Simplified Queries**: Reduces raw SQL complexity with Python objects
- ✅ **FastAPI Compatibility**: Designed to work seamlessly with existing setup
- ✅ **Better Error Handling**: More descriptive error messages and validation

### What We're Avoiding
- ❌ Complex caching systems (over-engineering)
- ❌ Watermark/ETag systems (premature optimization)
- ❌ Query inspector (console logging is sufficient)
- ❌ 10-week timeline (unrealistic scope)

---

## Summary

This enhanced refactor plan focuses on solving the actual problems while adding significant value:

1. **Core Issue**: 4 duplicate `fetchAllPanelData` implementations
2. **Solution**: Extract shared `DashboardDataService` with SQLModel type safety
3. **Timeline**: 4 weeks with significant code quality improvements
4. **Risk**: Low - gradual SQLModel integration with rollback capability
5. **Value**: Immediate improvement in code quality, type safety, and user experience

### Key Improvements with SQLModel:
- **Type Safety**: Eliminates SQL injection risks and provides compile-time type checking
- **Code Protection**: Prevents malformed queries with better error handling
- **Simplified Queries**: Reduces raw SQL complexity with Python objects
- **FastAPI Compatibility**: Designed to work seamlessly with existing setup

The approach follows the principle of **"solve today's problems today"** while adding robust type safety and code protection. This provides immediate value while setting a solid foundation for future enhancements based on real usage patterns.

**SQLModel Reference**: [https://github.com/fastapi/sqlmodel](https://github.com/fastapi/sqlmodel) - SQL databases in Python, designed for simplicity, compatibility, and robustness.