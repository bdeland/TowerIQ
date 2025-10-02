"""
Query Execution Router

Handles SQL query execution against the database:
- Query preview and validation
- Query execution (v1 and v2)
- Variable options resolution
"""

import asyncio
from typing import List
from fastapi import APIRouter, HTTPException

from ..models import QueryRequest, QueryResponse, QueryPreviewRequest, QueryPreviewResponse
from tower_iq.models.dashboard_models import QueryExecutionError

router = APIRouter()

# Module-level dependencies
logger = None
db_service = None
query_service = None


def initialize(log, db_svc, query_svc):
    """Initialize module-level dependencies."""
    global logger, db_service, query_service
    logger = log
    db_service = db_svc
    query_service = query_svc


@router.post("/api/query/preview", response_model=QueryPreviewResponse)
async def preview_query(request: QueryPreviewRequest):
    """Preview a SQL query to validate syntax and get execution plan without executing it."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        if not db_service.sqlite_conn:
            raise HTTPException(status_code=503, detail="Database connection not available")

        # Basic SQL injection protection - only allow SELECT statements
        query_stripped = request.query.strip().upper()
        if not query_stripped.startswith('SELECT'):
            raise HTTPException(status_code=400, detail="Only SELECT queries are allowed")

        # Additional protection against dangerous SQL operations
        dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'CREATE', 'ALTER', 'TRUNCATE', '--', ';']
        for keyword in dangerous_keywords:
            if keyword in query_stripped:
                raise HTTPException(status_code=400, detail=f"Query contains forbidden keyword: {keyword}")

        # Use EXPLAIN QUERY PLAN to validate syntax and get execution plan
        plan = await asyncio.to_thread(db_service.explain_query_plan, request.query)

        if logger:
            logger.info("Query preview successful",
                       query=request.query,
                       plan_rows=len(plan))

        return QueryPreviewResponse(
            status="success",
            message="Query syntax is valid.",
            plan=plan
        )

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error previewing query", query=request.query, error=str(e))
        return QueryPreviewResponse(
            status="error",
            message=f"Syntax error: {str(e)}"
        )


@router.post("/api/query", response_model=QueryResponse)
async def execute_query(request: QueryRequest):
    """Execute a SQL query against the database and return the results."""
    try:
        # Try SQLModel first if available
        if query_service and db_service:
            # Basic SQL injection protection - only allow SELECT statements
            query_stripped = request.query.strip().upper()
            if not query_stripped.startswith('SELECT'):
                raise HTTPException(status_code=400, detail="Only SELECT queries are allowed")

            # Additional protection against dangerous SQL operations
            dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'CREATE', 'ALTER', 'TRUNCATE', '--', ';']
            for keyword in dangerous_keywords:
                if keyword in query_stripped:
                    raise HTTPException(status_code=400, detail=f"Query contains forbidden keyword: {keyword}")

            # Enforce LIMIT clause for safety
            query = request.query.strip()
            if not query.upper().endswith('LIMIT') and 'LIMIT' not in query.upper():
                # Check if query already ends with a semicolon
                if query.endswith(';'):
                    query = query[:-1] + ' LIMIT 500;'
                else:
                    query = query + ' LIMIT 500'

            # Use SQLModel for type-safe query execution
            try:
                from tower_iq.core.sqlmodel_engine import get_sqlmodel_session
                from tower_iq.models.dashboard_models import QueryService, DashboardPanel, QueryExecutionError

                with get_sqlmodel_session() as session:
                    query_service_instance = QueryService(session)

                    # Create a dummy panel for query execution
                    dummy_panel = DashboardPanel(
                        id="query_endpoint",
                        dashboard_id="query_endpoint",
                        title="API Query",
                        query=query
                    )

                    # Execute with variables if provided
                    variables = request.variables or {}
                    result = await query_service_instance.execute_dashboard_query(dummy_panel, variables)

                    if logger:
                        logger.info("Query executed successfully with SQLModel",
                                   query=query,
                                   row_count=result.row_count,
                                   execution_time_ms=result.execution_time_ms)

                    return QueryResponse(
                        data=result.data,
                        row_count=result.row_count,
                        execution_time_ms=result.execution_time_ms,
                        cache_hit=result.cache_hit
                    )

            except QueryExecutionError as e:
                if logger:
                    logger.error("SQLModel query execution failed, falling back to legacy system",
                               query=query, error=str(e))
                # Check if it's a schema error that should be handled gracefully
                if "no such column" in str(e).lower():
                    if logger:
                        logger.warning("Database schema error detected, returning empty result",
                                     query=query, error=str(e))
                    return QueryResponse(data=[], row_count=0, execution_time_ms=0, cache_hit=False)
                # Fall through to legacy system for other errors

        # Fallback to existing system
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        if not db_service.sqlite_conn:
            raise HTTPException(status_code=503, detail="Database connection not available")

        # Basic SQL injection protection - only allow SELECT statements
        query_stripped = request.query.strip().upper()
        if not query_stripped.startswith('SELECT'):
            raise HTTPException(status_code=400, detail="Only SELECT queries are allowed")

        # Additional protection against dangerous SQL operations
        dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'CREATE', 'ALTER', 'TRUNCATE', '--', ';']
        for keyword in dangerous_keywords:
            if keyword in query_stripped:
                raise HTTPException(status_code=400, detail=f"Query contains forbidden keyword: {keyword}")

        # Enforce LIMIT clause for safety
        query = request.query.strip()
        if not query.upper().endswith('LIMIT') and 'LIMIT' not in query.upper():
            # Check if query already ends with a semicolon
            if query.endswith(';'):
                query = query[:-1] + ' LIMIT 500;'
            else:
                query = query + ' LIMIT 500'

        # Execute the query off the event loop thread (legacy method)
        try:
            data = await asyncio.to_thread(db_service.execute_select_query, query)

            if logger:
                logger.info("Query executed successfully with legacy system",
                           query=query,
                           row_count=len(data))

            return QueryResponse(data=data, row_count=len(data))

        except Exception as legacy_error:
            # Check if it's a schema error
            if "no such column" in str(legacy_error).lower():
                if logger:
                    logger.warning("Database schema error in legacy system, returning empty result",
                                 query=query, error=str(legacy_error))
                return QueryResponse(data=[], row_count=0, execution_time_ms=0, cache_hit=False)
            # Re-raise other errors
            raise

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error executing query", query=request.query, error=str(e))
        raise HTTPException(status_code=500, detail=f"Query execution failed: {str(e)}")


@router.post("/api/v2/query")
async def execute_query_v2(request: QueryRequest):
    """Execute query against specified data source (v2 API)"""
    try:
        # For now, route all queries to the default SQLite data source
        # This will be enhanced with the data source abstraction layer

        # Use the existing query endpoint logic but with v2 enhancements
        return await execute_query(request)

    except Exception as e:
        if logger:
            logger.error("Error executing query v2", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to execute query: {str(e)}")

