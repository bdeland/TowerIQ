"""
Dashboard Management Router (V1 Legacy API)

Handles legacy dashboard CRUD operations:
- Get all dashboards
- Get dashboard by ID
- Create dashboard
- Update dashboard
- Delete dashboard
- Set default dashboard
- Get default dashboard
- Ensure dashboards table exists
"""

from typing import List
from fastapi import APIRouter, HTTPException

from ..models import DashboardCreateRequest, DashboardUpdateRequest, DashboardResponse

router = APIRouter()

# Module-level dependencies
logger = None
db_service = None


def initialize(log, db_svc):
    """Initialize module-level dependencies."""
    global logger, db_service
    logger = log
    db_service = db_svc


@router.get("/api/dashboards", response_model=List[DashboardResponse])
async def get_dashboards():
    """Get all dashboards."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        dashboards = db_service.get_all_dashboards()
        return dashboards

    except Exception as e:
        if logger:
            logger.error("Error getting dashboards", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get dashboards: {str(e)}")


@router.get("/api/dashboards/{dashboard_id}", response_model=DashboardResponse)
async def get_dashboard(dashboard_id: str):
    """Get a specific dashboard by ID."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        dashboard = db_service.get_dashboard_by_id(dashboard_id)
        if not dashboard:
            raise HTTPException(status_code=404, detail="Dashboard not found")

        return dashboard

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error getting dashboard", error=str(e), dashboard_id=dashboard_id)
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}")


@router.post("/api/dashboards", response_model=DashboardResponse)
async def create_dashboard(request: DashboardCreateRequest):
    """Create a new dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        import uuid
        dashboard_id = str(uuid.uuid4())
        dashboard_uid = str(uuid.uuid4())

        dashboard_data = {
            'id': dashboard_id,
            'uid': dashboard_uid,
            'title': request.title,
            'description': request.description or '',
            'config': request.config,
            'tags': request.tags or [],
            'created_by': 'system'
        }

        success = db_service.create_dashboard(dashboard_data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to create dashboard")

        # Get the created dashboard
        dashboard = db_service.get_dashboard_by_id(dashboard_id)
        if not dashboard:
            raise HTTPException(status_code=500, detail="Dashboard created but not found")

        return dashboard

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error creating dashboard", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to create dashboard: {str(e)}")


@router.put("/api/dashboards/{dashboard_id}", response_model=DashboardResponse)
async def update_dashboard(dashboard_id: str, request: DashboardUpdateRequest):
    """Update an existing dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        # Check if dashboard exists
        existing = db_service.get_dashboard_by_id(dashboard_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Dashboard not found")

        # Prepare update data
        update_data = {}
        if request.title is not None:
            update_data['title'] = request.title
        if request.description is not None:
            update_data['description'] = request.description
        if request.config is not None:
            update_data['config'] = request.config
        if request.tags is not None:
            update_data['tags'] = request.tags

        success = db_service.update_dashboard(dashboard_id, update_data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update dashboard")

        # Get the updated dashboard
        dashboard = db_service.get_dashboard_by_id(dashboard_id)
        if not dashboard:
            raise HTTPException(status_code=500, detail="Dashboard updated but not found")

        return dashboard

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error updating dashboard", error=str(e), dashboard_id=dashboard_id)
        raise HTTPException(status_code=500, detail=f"Failed to update dashboard: {str(e)}")


@router.delete("/api/dashboards/{dashboard_id}")
async def delete_dashboard(dashboard_id: str):
    """Delete a dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        # Check if dashboard exists
        existing = db_service.get_dashboard_by_id(dashboard_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Dashboard not found")

        success = db_service.delete_dashboard(dashboard_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete dashboard")

        return {"message": "Dashboard deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error deleting dashboard", error=str(e), dashboard_id=dashboard_id)
        raise HTTPException(status_code=500, detail=f"Failed to delete dashboard: {str(e)}")


@router.post("/api/dashboards/{dashboard_id}/set-default")
async def set_default_dashboard(dashboard_id: str):
    """Set a dashboard as the default dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        # Check if dashboard exists
        existing = db_service.get_dashboard_by_id(dashboard_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Dashboard not found")

        success = db_service.set_default_dashboard(dashboard_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to set default dashboard")

        return {"message": "Default dashboard updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error setting default dashboard", error=str(e), dashboard_id=dashboard_id)
        raise HTTPException(status_code=500, detail=f"Failed to set default dashboard: {str(e)}")


@router.get("/api/dashboards/default", response_model=DashboardResponse)
async def get_default_dashboard():
    """Get the default dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        dashboard = db_service.get_default_dashboard()
        if dashboard:
            return dashboard
        else:
            # No default dashboard set, return a placeholder or error
            raise HTTPException(status_code=404, detail="No default dashboard set")

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error getting default dashboard", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get default dashboard: {str(e)}")


@router.post("/api/dashboards/ensure-table")
async def ensure_dashboards_table():
    """Ensure the dashboards table exists in the database."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")

        db_service.ensure_dashboards_table()
        return {"message": "Dashboards table ensured"}

    except Exception as e:
        if logger:
            logger.error("Error ensuring dashboards table", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to ensure dashboards table: {str(e)}")

