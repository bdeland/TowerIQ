"""
SQLModel models for TowerIQ Dashboard functionality.

This module provides type-safe models for dashboard data operations,
replacing raw SQL queries with SQLModel for better type safety and code protection.
"""

from sqlmodel import SQLModel, Field, Relationship, Session, select, text
from sqlalchemy import JSON
from typing import Optional, List, Dict, Any
from datetime import datetime
import time
import json


class Dashboard(SQLModel, table=True):
    """Dashboard model with type safety and relationships."""
    id: Optional[str] = Field(default=None, primary_key=True)
    uid: str = Field(unique=True, index=True)
    title: str
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, sa_type=JSON)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationship to panels
    panels: List["DashboardPanel"] = Relationship(back_populates="dashboard")


class DashboardPanel(SQLModel, table=True):
    """Dashboard panel model with type safety."""
    id: Optional[str] = Field(default=None, primary_key=True)
    dashboard_id: str = Field(foreign_key="dashboard.id")
    title: str
    query: str
    panel_type: str = Field(default="table")
    position: Optional[Dict[str, Any]] = Field(default_factory=dict, sa_type=JSON)
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, sa_type=JSON)
    
    # Relationship to dashboard
    dashboard: Optional[Dashboard] = Relationship(back_populates="panels")


class QueryResult(SQLModel):
    """Query result model for type-safe responses."""
    data: List[Dict[str, Any]]
    row_count: int
    execution_time_ms: Optional[float] = None
    cache_hit: bool = False


class QueryRequest(SQLModel):
    """Request model for query execution."""
    query: str
    variables: Optional[Dict[str, Any]] = Field(default_factory=dict)


class QueryExecutionError(Exception):
    """Custom exception for query execution errors."""
    pass


class QueryService:
    """Type-safe query service using SQLModel."""
    
    def __init__(self, session: Session):
        self.session = session
    
    async def execute_dashboard_query(
        self, 
        panel: DashboardPanel, 
        variables: Dict[str, Any]
    ) -> QueryResult:
        """Execute a dashboard panel query with type safety."""
        start_time = time.time()
        
        try:
            # Compose query with variables (existing logic)
            final_query = self._compose_query(panel.query, variables)
            
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
        """Get panels for a dashboard with type safety."""
        statement = select(DashboardPanel).where(DashboardPanel.dashboard_id == dashboard_id)
        return self.session.exec(statement).all()
    
    def get_dashboard_by_id(self, dashboard_id: str) -> Optional[Dashboard]:
        """Get dashboard by ID with type safety."""
        statement = select(Dashboard).where(Dashboard.id == dashboard_id)
        return self.session.exec(statement).first()
    
    def get_dashboard_by_uid(self, uid: str) -> Optional[Dashboard]:
        """Get dashboard by UID with type safety."""
        statement = select(Dashboard).where(Dashboard.uid == uid)
        return self.session.exec(statement).first()
    
    def _compose_query(self, query: str, variables: Dict[str, Any]) -> str:
        """
        Compose query with variable substitution.
        
        This replaces the existing composeQuery logic from the frontend,
        providing server-side variable substitution for type safety.
        """
        if not variables:
            return query
            
        # Simple variable substitution - replace ${variable} with values
        final_query = query
        for key, value in variables.items():
            placeholder = f"${{{key}}}"
            if placeholder in final_query:
                # Handle different value types
                if isinstance(value, str):
                    final_query = final_query.replace(placeholder, f"'{value}'")
                elif isinstance(value, (int, float)):
                    final_query = final_query.replace(placeholder, str(value))
                elif isinstance(value, bool):
                    final_query = final_query.replace(placeholder, "1" if value else "0")
                else:
                    # Convert to string for other types
                    final_query = final_query.replace(placeholder, f"'{str(value)}'")
        
        return final_query


class DashboardService:
    """Service for dashboard operations with type safety."""
    
    def __init__(self, session: Session):
        self.session = session
        self.query_service = QueryService(session)
    
    def create_dashboard(self, dashboard: Dashboard) -> Dashboard:
        """Create a new dashboard with type safety."""
        self.session.add(dashboard)
        self.session.commit()
        self.session.refresh(dashboard)
        return dashboard
    
    def update_dashboard(self, dashboard_id: str, updates: Dict[str, Any]) -> Optional[Dashboard]:
        """Update dashboard with type safety."""
        dashboard = self.get_dashboard_by_id(dashboard_id)
        if dashboard:
            for key, value in updates.items():
                if hasattr(dashboard, key):
                    setattr(dashboard, key, value)
            dashboard.updated_at = datetime.utcnow()
            self.session.add(dashboard)
            self.session.commit()
            self.session.refresh(dashboard)
        return dashboard
    
    def delete_dashboard(self, dashboard_id: str) -> bool:
        """Delete dashboard with type safety."""
        dashboard = self.get_dashboard_by_id(dashboard_id)
        if dashboard:
            self.session.delete(dashboard)
            self.session.commit()
            return True
        return False
    
    def get_dashboard_by_id(self, dashboard_id: str) -> Optional[Dashboard]:
        """Get dashboard by ID."""
        return self.query_service.get_dashboard_by_id(dashboard_id)
    
    def get_all_dashboards(self) -> List[Dashboard]:
        """Get all dashboards."""
        statement = select(Dashboard)
        return self.session.exec(statement).all()
