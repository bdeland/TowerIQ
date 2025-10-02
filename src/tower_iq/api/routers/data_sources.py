"""
Data Source Management Router

Handles:
- Data source listing
- Data source creation
- Variable options resolution for dashboard variables
"""

import json
from typing import List
from fastapi import APIRouter, HTTPException

from tower_iq.models.dashboard_config_models import (
    DataSourceConfig, DataSourceCreateRequest,
    VariableOptionsRequest, VariableOption
)
from ..models import QueryRequest

router = APIRouter()

# Module-level dependencies
logger = None
db_service = None


def initialize(log, db_svc):
    """Initialize module-level dependencies."""
    global logger, db_service
    logger = log
    db_service = db_svc


@router.get("/api/v2/data-sources", response_model=List[DataSourceConfig])
async def list_data_sources():
    """List all active data sources"""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        cursor = db_service.sqlite_conn.cursor()
        cursor.execute("""
            SELECT id, name, type, config, credentials, is_active, created_at
            FROM data_sources
            WHERE is_active = 1
            ORDER BY name
        """)

        rows = cursor.fetchall()
        data_sources = []

        for row in rows:
            config = json.loads(row[3])
            credentials = json.loads(row[4]) if row[4] else None

            data_source = DataSourceConfig(
                id=row[0],
                name=row[1],
                type=row[2],
                config=config,
                credentials=credentials,
                is_active=bool(row[5])
            )
            data_sources.append(data_source)

        return data_sources

    except Exception as e:
        if logger:
            logger.error("Error listing data sources", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to list data sources: {str(e)}")


@router.post("/api/v2/data-sources", response_model=DataSourceConfig)
async def create_data_source(request: DataSourceCreateRequest):
    """Create new data source"""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        import uuid
        data_source_id = str(uuid.uuid4())

        cursor = db_service.sqlite_conn.cursor()
        cursor.execute("""
            INSERT INTO data_sources (id, name, type, config, credentials, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data_source_id,
            request.name,
            request.type,
            json.dumps(request.config),
            json.dumps(request.credentials) if request.credentials else None,
            request.is_active
        ))

        db_service.sqlite_conn.commit()

        return DataSourceConfig(
            id=data_source_id,
            name=request.name,
            type=request.type,
            config=request.config,
            credentials=request.credentials,
            is_active=request.is_active
        )

    except Exception as e:
        if logger:
            logger.error("Error creating data source", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to create data source: {str(e)}")


@router.post("/api/v2/variables/{variable_name}/options", response_model=List[VariableOption])
async def get_variable_options(variable_name: str, request: VariableOptionsRequest):
    """Execute variable option query and return formatted options"""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        # Import execute_query from queries router
        from .queries import execute_query

        # Execute the options query
        query_request = QueryRequest(query=request.query, variables=request.dependencies or {})
        query_response = await execute_query(query_request)

        # Transform results into VariableOption format
        options = []
        for row in query_response.data:
            if isinstance(row, dict):
                # Assume first column is value, second is label (if exists)
                keys = list(row.keys())
                value = row[keys[0]]
                label = row[keys[1]] if len(keys) > 1 else str(value)
            else:
                # Handle array format
                value = row[0] if len(row) > 0 else ""
                label = row[1] if len(row) > 1 else str(value)

            options.append(VariableOption(label=str(label), value=value))

        if logger:
            logger.info("Generated variable options", variable_name=variable_name, count=len(options))

        return options

    except Exception as e:
        if logger:
            logger.error("Error getting variable options", variable_name=variable_name, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get variable options: {str(e)}")

