"""
Dashboard Management Router (V2 New API)

Handles new hierarchical dashboard system with:
- Dashboard metadata listing
- Full dashboard configuration
- Create/Update/Delete operations
- Data source integration
"""

import json
from datetime import datetime
from fastapi import APIRouter, HTTPException

# Import V2 dashboard models
from tower_iq.models.dashboard_config_models import (
    DashboardConfig, DashboardMetadata, DashboardListResponse,
    CreateDashboardRequest, UpdateDashboardRequest
)

router = APIRouter()

# Module-level dependencies
logger = None
db_service = None


def initialize(log, db_svc):
    """Initialize module-level dependencies."""
    global logger, db_service
    logger = log
    db_service = db_svc


@router.get("/api/v2/dashboards", response_model=DashboardListResponse)
async def list_dashboards_v2():
    """List all dashboards with metadata only (v2 API)"""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        # Query dashboard_configs table for metadata
        cursor = db_service.sqlite_conn.cursor()
        cursor.execute("""
            SELECT id, name, description, tags, created_at, updated_at, created_by, is_system
            FROM dashboard_configs
            ORDER BY created_at DESC
        """)

        rows = cursor.fetchall()
        dashboards = []

        for row in rows:
            tags = json.loads(row[3]) if row[3] else []
            metadata = DashboardMetadata(
                id=row[0],
                name=row[1],
                description=row[2],
                tags=tags,
                created_at=datetime.fromisoformat(row[4]),
                updated_at=datetime.fromisoformat(row[5]),
                created_by=row[6],
                is_system=bool(row[7])
            )
            dashboards.append(metadata)

        if logger:
            logger.info("Listed dashboards v2", count=len(dashboards))

        return DashboardListResponse(dashboards=dashboards, total=len(dashboards))

    except Exception as e:
        if logger:
            logger.error("Error listing dashboards v2", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to list dashboards: {str(e)}")


@router.get("/api/v2/dashboards/{dashboard_id}", response_model=DashboardConfig)
async def get_dashboard_v2(dashboard_id: str):
    """Get complete dashboard configuration (v2 API)"""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        cursor = db_service.sqlite_conn.cursor()
        cursor.execute("""
            SELECT id, name, description, tags, config, created_at, updated_at, created_by, is_system
            FROM dashboard_configs
            WHERE id = ?
        """, (dashboard_id,))

        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Dashboard not found")

        # Parse the stored JSON config
        config_json = json.loads(row[4])

        if logger:
            logger.info("Retrieved dashboard v2", dashboard_id=dashboard_id)

        return DashboardConfig(**config_json)

    except json.JSONDecodeError as e:
        if logger:
            logger.error("Invalid dashboard config JSON", dashboard_id=dashboard_id, error=str(e))
        raise HTTPException(status_code=500, detail="Dashboard configuration is corrupted")
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error getting dashboard v2", dashboard_id=dashboard_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}")


@router.post("/api/v2/dashboards", response_model=DashboardConfig)
async def create_dashboard_v2(request: CreateDashboardRequest):
    """Create new dashboard from complete configuration (v2 API)"""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        import uuid
        dashboard_id = str(uuid.uuid4())
        now = datetime.now()

        # Store the complete config as JSON
        config_json = request.config.model_dump()

        cursor = db_service.sqlite_conn.cursor()
        cursor.execute("""
            INSERT INTO dashboard_configs
            (id, name, description, tags, config, created_at, updated_at, created_by, is_system)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            dashboard_id,
            request.name,
            request.description,
            json.dumps(request.tags),
            json.dumps(config_json),
            now.isoformat(),
            now.isoformat(),
            request.config.metadata.created_by or "system",
            request.is_system
        ))

        db_service.sqlite_conn.commit()

        if logger:
            logger.info("Created dashboard v2", dashboard_id=dashboard_id, name=request.name)

        return request.config

    except Exception as e:
        if logger:
            logger.error("Error creating dashboard v2", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to create dashboard: {str(e)}")


@router.put("/api/v2/dashboards/{dashboard_id}", response_model=DashboardConfig)
async def update_dashboard_v2(dashboard_id: str, request: UpdateDashboardRequest):
    """Update dashboard configuration (v2 API)"""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        # First check if dashboard exists
        cursor = db_service.sqlite_conn.cursor()
        cursor.execute("SELECT id FROM dashboard_configs WHERE id = ?", (dashboard_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Dashboard not found")

        # Build update query dynamically
        updates = []
        params = []

        if request.name is not None:
            updates.append("name = ?")
            params.append(request.name)

        if request.description is not None:
            updates.append("description = ?")
            params.append(request.description)

        if request.tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(request.tags))

        if request.config is not None:
            updates.append("config = ?")
            params.append(json.dumps(request.config.model_dump()))

        if updates:
            updates.append("updated_at = ?")
            params.append(datetime.now().isoformat())
            params.append(dashboard_id)

            query = f"UPDATE dashboard_configs SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, params)
            db_service.sqlite_conn.commit()

        # Return updated dashboard
        return await get_dashboard_v2(dashboard_id)

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error updating dashboard v2", dashboard_id=dashboard_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to update dashboard: {str(e)}")


@router.delete("/api/v2/dashboards/{dashboard_id}")
async def delete_dashboard_v2(dashboard_id: str):
    """Delete dashboard (v2 API)"""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        cursor = db_service.sqlite_conn.cursor()

        # Check if dashboard exists
        cursor.execute("SELECT id FROM dashboard_configs WHERE id = ?", (dashboard_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Dashboard not found")

        # Delete dashboard
        cursor.execute("DELETE FROM dashboard_configs WHERE id = ?", (dashboard_id,))
        db_service.sqlite_conn.commit()

        if logger:
            logger.info("Deleted dashboard v2", dashboard_id=dashboard_id)

        return {"message": "Dashboard deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error deleting dashboard v2", dashboard_id=dashboard_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to delete dashboard: {str(e)}")

