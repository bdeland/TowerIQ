"""
Grafana Integration Router

Provides SQL query endpoints for Grafana dashboards to access TowerIQ database.
Supports read-only queries with security measures and configurable limits.
"""

import re
import sqlite3
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..dependencies import get_db_service, get_logger

router = APIRouter()

# Module-level dependencies
logger = None
db_service = None
config = None


def initialize(log, db_svc, cfg):
    """Initialize module-level dependencies."""
    global logger, db_service, config
    logger = log
    db_service = db_svc
    config = cfg


class SQLQueryRequest(BaseModel):
    """Request model for SQL queries."""
    sql: str


class SQLQueryResponse(BaseModel):
    """Response model for SQL query results."""
    columns: List[str]
    rows: List[List[Any]]
    row_count: int
    execution_time_ms: float


class SchemaTable(BaseModel):
    """Schema information for a table."""
    name: str
    columns: List[Dict[str, str]]


class SchemaResponse(BaseModel):
    """Response model for schema information."""
    tables: List[SchemaTable]


class TestResponse(BaseModel):
    """Response model for test endpoint."""
    status: str
    timestamp: str
    message: str


def is_read_only_query(sql: str) -> bool:
    """
    Check if SQL query is read-only (SELECT only).
    
    Args:
        sql: SQL query string
        
    Returns:
        True if query is read-only, False otherwise
    """
    # Normalize SQL - remove comments and extra whitespace
    sql_normalized = re.sub(r'--.*?$', '', sql, flags=re.MULTILINE)  # Remove line comments
    sql_normalized = re.sub(r'/\*.*?\*/', '', sql_normalized, flags=re.DOTALL)  # Remove block comments
    sql_normalized = sql_normalized.strip().upper()
    
    # Check for write operations
    write_keywords = [
        'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'TRUNCATE', 'REPLACE', 'MERGE', 'GRANT', 'REVOKE',
        'PRAGMA', 'ATTACH', 'DETACH'
    ]
    
    for keyword in write_keywords:
        # Use word boundaries to avoid false positives (e.g., "INSERTED_AT" column name)
        if re.search(rf'\b{keyword}\b', sql_normalized):
            return False
    
    # Must start with SELECT (after removing whitespace)
    if not sql_normalized.startswith('SELECT'):
        return False
    
    return True


def get_grafana_settings() -> Dict[str, Any]:
    """
    Get Grafana settings from configuration.
    
    Returns:
        Dictionary of Grafana settings with defaults
    """
    if not config:
        return {
            'enabled': False,
            'bind_address': '127.0.0.1',
            'port': 8000,
            'allow_read_only': True,
            'query_timeout': 30,
            'max_rows': 10000
        }
    
    return {
        'enabled': config.get('grafana.enabled', False),
        'bind_address': config.get('grafana.bind_address', '127.0.0.1'),
        'port': config.get('grafana.port', 8000),
        'allow_read_only': config.get('grafana.allow_read_only', True),
        'query_timeout': config.get('grafana.query_timeout', 30),
        'max_rows': config.get('grafana.max_rows', 10000)
    }


@router.get("/api/grafana/test", response_model=TestResponse)
async def test_connection():
    """
    Test endpoint to verify Grafana integration is working.
    
    Returns:
        TestResponse with status and timestamp
    """
    try:
        settings = get_grafana_settings()
        
        if not settings['enabled']:
            raise HTTPException(
                status_code=503,
                detail="Grafana integration is disabled. Enable it in Database Settings."
            )
        
        return TestResponse(
            status="ok",
            timestamp=datetime.now().isoformat(),
            message="Grafana integration is active and ready"
        )
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error in Grafana test endpoint", error=str(e))
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")


@router.get("/api/grafana/schema", response_model=SchemaResponse)
async def get_schema():
    """
    Get database schema information.
    
    Returns:
        SchemaResponse with all tables and their columns
    """
    try:
        settings = get_grafana_settings()
        
        if not settings['enabled']:
            raise HTTPException(
                status_code=503,
                detail="Grafana integration is disabled"
            )
        
        if not db_service:
            raise HTTPException(status_code=500, detail="Database service not available")
        
        # Get all tables from sqlite_master
        cursor = db_service.sqlite_conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
        """)
        
        tables = []
        for (table_name,) in cursor.fetchall():
            # Get column information for each table
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = []
            for col_info in cursor.fetchall():
                # col_info: (cid, name, type, notnull, dflt_value, pk)
                columns.append({
                    'name': col_info[1],
                    'type': col_info[2],
                    'nullable': not bool(col_info[3]),
                    'primary_key': bool(col_info[5])
                })
            
            tables.append(SchemaTable(name=table_name, columns=columns))
        
        return SchemaResponse(tables=tables)
    
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error getting schema", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get schema: {str(e)}")


@router.post("/api/grafana/query", response_model=SQLQueryResponse)
async def execute_query(query_request: SQLQueryRequest):
    """
    Execute a read-only SQL query and return results.
    
    Args:
        query_request: SQLQueryRequest with SQL query
        
    Returns:
        SQLQueryResponse with query results
    """
    try:
        settings = get_grafana_settings()
        
        # Check if Grafana integration is enabled
        if not settings['enabled']:
            raise HTTPException(
                status_code=503,
                detail="Grafana integration is disabled. Enable it in Database Settings."
            )
        
        if not db_service:
            raise HTTPException(status_code=500, detail="Database service not available")
        
        sql = query_request.sql.strip()
        
        # Validate SQL is read-only
        if not is_read_only_query(sql):
            raise HTTPException(
                status_code=400,
                detail="Only SELECT queries are allowed. Write operations are prohibited."
            )
        
        # Apply row limit if query doesn't already have one
        max_rows = settings['max_rows']
        if not re.search(r'\bLIMIT\b', sql, re.IGNORECASE):
            sql = f"{sql} LIMIT {max_rows}"
        
        if logger:
            logger.info("Executing Grafana query", sql=sql[:200])
        
        # Execute query with timeout
        start_time = time.time()
        cursor = db_service.sqlite_conn.cursor()
        
        # Set query timeout (SQLite uses milliseconds)
        timeout_ms = settings['query_timeout'] * 1000
        cursor.execute(f"PRAGMA query_timeout = {timeout_ms}")
        
        try:
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            # Get column names
            columns = [description[0] for description in cursor.description] if cursor.description else []
            
            # Convert rows to list of lists for JSON serialization
            rows_list = [list(row) for row in rows]
            
            execution_time_ms = (time.time() - start_time) * 1000
            
            if logger:
                logger.info("Query executed successfully", 
                          rows=len(rows_list), 
                          execution_time_ms=round(execution_time_ms, 2))
            
            return SQLQueryResponse(
                columns=columns,
                rows=rows_list,
                row_count=len(rows_list),
                execution_time_ms=round(execution_time_ms, 2)
            )
        
        except sqlite3.OperationalError as e:
            error_msg = str(e)
            if 'timeout' in error_msg.lower():
                raise HTTPException(
                    status_code=408,
                    detail=f"Query timeout after {settings['query_timeout']} seconds"
                )
            raise HTTPException(status_code=400, detail=f"SQL error: {error_msg}")
        
        finally:
            # Reset timeout
            cursor.execute("PRAGMA query_timeout = 0")
    
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error executing query", error=str(e), sql=query_request.sql[:200])
        raise HTTPException(status_code=500, detail=f"Query execution failed: {str(e)}")


