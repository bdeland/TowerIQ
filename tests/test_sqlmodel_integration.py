"""
Unit tests for SQLModel integration in TowerIQ.

This module tests the SQLModel integration, including models, query service,
and type safety features.
"""

import pytest
import tempfile
import os
from pathlib import Path
from sqlmodel import Session, create_engine, SQLModel
from typing import Dict, Any

from src.tower_iq.models.dashboard_models import (
    Dashboard, DashboardPanel, QueryService, QueryResult, 
    QueryExecutionError, DashboardService
)
from src.tower_iq.core.sqlmodel_engine import SQLModelEngine


class TestSQLModelModels:
    """Test SQLModel model definitions and relationships."""
    
    def test_dashboard_model_creation(self):
        """Test Dashboard model creation and validation."""
        dashboard = Dashboard(
            id="test-dashboard",
            uid="test-uid",
            title="Test Dashboard",
            description="Test Description"
        )
        
        assert dashboard.id == "test-dashboard"
        assert dashboard.uid == "test-uid"
        assert dashboard.title == "Test Dashboard"
        assert dashboard.description == "Test Description"
        assert dashboard.config == {}
        assert dashboard.created_at is not None
        assert dashboard.updated_at is not None
    
    def test_dashboard_panel_model_creation(self):
        """Test DashboardPanel model creation and validation."""
        panel = DashboardPanel(
            id="test-panel",
            dashboard_id="test-dashboard",
            title="Test Panel",
            query="SELECT * FROM test_table",
            panel_type="table"
        )
        
        assert panel.id == "test-panel"
        assert panel.dashboard_id == "test-dashboard"
        assert panel.title == "Test Panel"
        assert panel.query == "SELECT * FROM test_table"
        assert panel.panel_type == "table"
        assert panel.position == {}
        assert panel.config == {}
    
    def test_dashboard_panel_relationship(self):
        """Test relationship between Dashboard and DashboardPanel."""
        dashboard = Dashboard(
            id="test-dashboard",
            uid="test-uid",
            title="Test Dashboard"
        )
        
        panel = DashboardPanel(
            id="test-panel",
            dashboard_id="test-dashboard",
            title="Test Panel",
            query="SELECT * FROM test_table"
        )
        
        # Test relationship assignment
        panel.dashboard = dashboard
        assert panel.dashboard == dashboard
        assert panel.dashboard.id == "test-dashboard"


class TestSQLModelEngine:
    """Test SQLModel engine functionality."""
    
    @pytest.fixture
    def temp_database(self):
        """Create a temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as tmp:
            temp_path = tmp.name
        
        yield temp_path
        
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    def test_sqlmodel_engine_creation(self, temp_database):
        """Test SQLModel engine creation."""
        engine = SQLModelEngine(temp_database)
        
        assert engine is not None
        assert engine.engine is not None
        assert engine.database_path == temp_database
        
        # Test session creation
        session = engine.get_session()
        assert isinstance(session, Session)
        session.close()
        
        # Cleanup
        engine.close()
    
    def test_sqlmodel_engine_with_password(self, temp_database):
        """Test SQLModel engine creation with password (SQLCipher)."""
        engine = SQLModelEngine(temp_database, password="test_password")
        
        assert engine is not None
        assert engine.engine is not None
        assert engine.password == "test_password"
        
        # Cleanup
        engine.close()
    
    def test_create_tables(self, temp_database):
        """Test table creation with SQLModel."""
        engine = SQLModelEngine(temp_database)
        
        # Create tables
        engine.create_tables()
        
        # Verify tables exist by trying to create a session and insert data
        with engine.get_session() as session:
            dashboard = Dashboard(
                id="test-dashboard",
                uid="test-uid",
                title="Test Dashboard"
            )
            session.add(dashboard)
            session.commit()
            session.refresh(dashboard)
            
            assert dashboard.id == "test-dashboard"
        
        # Cleanup
        engine.close()


class TestQueryService:
    """Test QueryService functionality."""
    
    @pytest.fixture
    def query_service_session(self, temp_database):
        """Create a QueryService with a test session."""
        engine = SQLModelEngine(temp_database)
        engine.create_tables()
        
        session = engine.get_session()
        query_service = QueryService(session)
        
        yield query_service, session, engine
        
        session.close()
        engine.close()
    
    @pytest.fixture
    def temp_database(self):
        """Create a temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as tmp:
            temp_path = tmp.name
        
        yield temp_path
        
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    def test_compose_query_with_variables(self, query_service_session):
        """Test query composition with variables."""
        query_service, session, engine = query_service_session
        
        # Test simple variable substitution
        query = "SELECT * FROM runs WHERE tier = ${tier}"
        variables = {"tier": 5}
        
        composed = query_service._compose_query(query, variables)
        assert composed == "SELECT * FROM runs WHERE tier = 5"
        
        # Test string variable substitution
        query = "SELECT * FROM runs WHERE title = ${title}"
        variables = {"title": "Test Run"}
        
        composed = query_service._compose_query(query, variables)
        assert composed == "SELECT * FROM runs WHERE title = 'Test Run'"
        
        # Test boolean variable substitution
        query = "SELECT * FROM runs WHERE active = ${active}"
        variables = {"active": True}
        
        composed = query_service._compose_query(query, variables)
        assert composed == "SELECT * FROM runs WHERE active = 1"
        
        # Test multiple variables
        query = "SELECT * FROM runs WHERE tier = ${tier} AND title = ${title}"
        variables = {"tier": 3, "title": "Multi Test"}
        
        composed = query_service._compose_query(query, variables)
        assert composed == "SELECT * FROM runs WHERE tier = 3 AND title = 'Multi Test'"
    
    def test_compose_query_without_variables(self, query_service_session):
        """Test query composition without variables."""
        query_service, session, engine = query_service_session
        
        query = "SELECT * FROM runs"
        variables = {}
        
        composed = query_service._compose_query(query, variables)
        assert composed == query
    
    def test_execute_dashboard_query_success(self, query_service_session):
        """Test successful dashboard query execution."""
        query_service, session, engine = query_service_session
        
        # Create test data first
        with session:
            # Create a simple test table and insert data
            session.exec("CREATE TABLE IF NOT EXISTS test_table (id INTEGER, name TEXT)")
            session.exec("INSERT INTO test_table (id, name) VALUES (1, 'Test')")
            session.commit()
        
        # Create a test panel
        panel = DashboardPanel(
            id="test-panel",
            dashboard_id="test-dashboard",
            title="Test Panel",
            query="SELECT * FROM test_table LIMIT 1"
        )
        
        # Execute query
        result = query_service.execute_dashboard_query(panel, {})
        
        assert isinstance(result, QueryResult)
        assert result.row_count == 1
        assert len(result.data) == 1
        assert result.data[0]["id"] == 1
        assert result.data[0]["name"] == "Test"
        assert result.execution_time_ms is not None
        assert result.cache_hit is False
    
    def test_execute_dashboard_query_with_variables(self, query_service_session):
        """Test dashboard query execution with variables."""
        query_service, session, engine = query_service_session
        
        # Create test data first
        with session:
            session.exec("CREATE TABLE IF NOT EXISTS test_table (id INTEGER, name TEXT)")
            session.exec("INSERT INTO test_table (id, name) VALUES (1, 'Test1'), (2, 'Test2')")
            session.commit()
        
        # Create a test panel with variables
        panel = DashboardPanel(
            id="test-panel",
            dashboard_id="test-dashboard",
            title="Test Panel",
            query="SELECT * FROM test_table WHERE id = ${id} LIMIT 1"
        )
        
        # Execute query with variables
        variables = {"id": 2}
        result = query_service.execute_dashboard_query(panel, variables)
        
        assert isinstance(result, QueryResult)
        assert result.row_count == 1
        assert len(result.data) == 1
        assert result.data[0]["id"] == 2
        assert result.data[0]["name"] == "Test2"
    
    def test_execute_dashboard_query_failure(self, query_service_session):
        """Test dashboard query execution failure."""
        query_service, session, engine = query_service_session
        
        # Create a test panel with invalid query
        panel = DashboardPanel(
            id="test-panel",
            dashboard_id="test-dashboard",
            title="Test Panel",
            query="SELECT * FROM non_existent_table"
        )
        
        # Execute query should raise QueryExecutionError
        with pytest.raises(QueryExecutionError):
            query_service.execute_dashboard_query(panel, {})
    
    def test_get_dashboard_panels(self, query_service_session):
        """Test getting dashboard panels."""
        query_service, session, engine = query_service_session
        
        # Create test data
        with session:
            dashboard = Dashboard(
                id="test-dashboard",
                uid="test-uid",
                title="Test Dashboard"
            )
            session.add(dashboard)
            
            panel1 = DashboardPanel(
                id="panel-1",
                dashboard_id="test-dashboard",
                title="Panel 1",
                query="SELECT 1"
            )
            panel2 = DashboardPanel(
                id="panel-2",
                dashboard_id="test-dashboard",
                title="Panel 2",
                query="SELECT 2"
            )
            session.add(panel1)
            session.add(panel2)
            session.commit()
        
        # Get panels
        panels = query_service.get_dashboard_panels("test-dashboard")
        
        assert len(panels) == 2
        assert panels[0].title in ["Panel 1", "Panel 2"]
        assert panels[1].title in ["Panel 1", "Panel 2"]
    
    def test_get_dashboard_by_id(self, query_service_session):
        """Test getting dashboard by ID."""
        query_service, session, engine = query_service_session
        
        # Create test data
        with session:
            dashboard = Dashboard(
                id="test-dashboard",
                uid="test-uid",
                title="Test Dashboard"
            )
            session.add(dashboard)
            session.commit()
        
        # Get dashboard
        found_dashboard = query_service.get_dashboard_by_id("test-dashboard")
        
        assert found_dashboard is not None
        assert found_dashboard.id == "test-dashboard"
        assert found_dashboard.title == "Test Dashboard"
    
    def test_get_dashboard_by_uid(self, query_service_session):
        """Test getting dashboard by UID."""
        query_service, session, engine = query_service_session
        
        # Create test data
        with session:
            dashboard = Dashboard(
                id="test-dashboard",
                uid="test-uid",
                title="Test Dashboard"
            )
            session.add(dashboard)
            session.commit()
        
        # Get dashboard by UID
        found_dashboard = query_service.get_dashboard_by_uid("test-uid")
        
        assert found_dashboard is not None
        assert found_dashboard.uid == "test-uid"
        assert found_dashboard.title == "Test Dashboard"


class TestDashboardService:
    """Test DashboardService functionality."""
    
    @pytest.fixture
    def dashboard_service_session(self, temp_database):
        """Create a DashboardService with a test session."""
        engine = SQLModelEngine(temp_database)
        engine.create_tables()
        
        session = engine.get_session()
        dashboard_service = DashboardService(session)
        
        yield dashboard_service, session, engine
        
        session.close()
        engine.close()
    
    @pytest.fixture
    def temp_database(self):
        """Create a temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as tmp:
            temp_path = tmp.name
        
        yield temp_path
        
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    def test_create_dashboard(self, dashboard_service_session):
        """Test dashboard creation."""
        dashboard_service, session, engine = dashboard_service_session
        
        dashboard = Dashboard(
            id="test-dashboard",
            uid="test-uid",
            title="Test Dashboard",
            description="Test Description"
        )
        
        created_dashboard = dashboard_service.create_dashboard(dashboard)
        
        assert created_dashboard.id == "test-dashboard"
        assert created_dashboard.uid == "test-uid"
        assert created_dashboard.title == "Test Dashboard"
        assert created_dashboard.description == "Test Description"
    
    def test_update_dashboard(self, dashboard_service_session):
        """Test dashboard updates."""
        dashboard_service, session, engine = dashboard_service_session
        
        # Create dashboard first
        dashboard = Dashboard(
            id="test-dashboard",
            uid="test-uid",
            title="Test Dashboard"
        )
        created_dashboard = dashboard_service.create_dashboard(dashboard)
        
        # Update dashboard
        updates = {
            "title": "Updated Dashboard",
            "description": "Updated Description"
        }
        
        updated_dashboard = dashboard_service.update_dashboard("test-dashboard", updates)
        
        assert updated_dashboard is not None
        assert updated_dashboard.title == "Updated Dashboard"
        assert updated_dashboard.description == "Updated Description"
        assert updated_dashboard.updated_at > created_dashboard.updated_at
    
    def test_delete_dashboard(self, dashboard_service_session):
        """Test dashboard deletion."""
        dashboard_service, session, engine = dashboard_service_session
        
        # Create dashboard first
        dashboard = Dashboard(
            id="test-dashboard",
            uid="test-uid",
            title="Test Dashboard"
        )
        dashboard_service.create_dashboard(dashboard)
        
        # Delete dashboard
        result = dashboard_service.delete_dashboard("test-dashboard")
        
        assert result is True
        
        # Verify dashboard is deleted
        found_dashboard = dashboard_service.get_dashboard_by_id("test-dashboard")
        assert found_dashboard is None
    
    def test_get_all_dashboards(self, dashboard_service_session):
        """Test getting all dashboards."""
        dashboard_service, session, engine = dashboard_service_session
        
        # Create multiple dashboards
        dashboard1 = Dashboard(
            id="dashboard-1",
            uid="uid-1",
            title="Dashboard 1"
        )
        dashboard2 = Dashboard(
            id="dashboard-2",
            uid="uid-2",
            title="Dashboard 2"
        )
        
        dashboard_service.create_dashboard(dashboard1)
        dashboard_service.create_dashboard(dashboard2)
        
        # Get all dashboards
        all_dashboards = dashboard_service.get_all_dashboards()
        
        assert len(all_dashboards) == 2
        titles = [d.title for d in all_dashboards]
        assert "Dashboard 1" in titles
        assert "Dashboard 2" in titles


class TestTypeSafety:
    """Test type safety features of SQLModel integration."""
    
    def test_sql_injection_protection(self):
        """Test that SQLModel provides protection against SQL injection."""
        # This test verifies that SQLModel's parameterized queries
        # provide protection against SQL injection
        
        # Note: The actual protection is in the QueryService._compose_query method
        # which should properly escape variables
        
        query_service = QueryService(None)  # We don't need a real session for this test
        
        # Test that variables are properly escaped
        query = "SELECT * FROM runs WHERE name = ${name}"
        variables = {"name": "'; DROP TABLE runs; --"}
        
        composed = query_service._compose_query(query, variables)
        
        # The composed query should escape the malicious input
        assert "DROP TABLE" not in composed
        assert "''; DROP TABLE runs; --'" in composed  # Properly quoted
    
    def test_query_result_type_safety(self):
        """Test QueryResult type safety."""
        result = QueryResult(
            data=[{"id": 1, "name": "Test"}],
            row_count=1,
            execution_time_ms=100.5,
            cache_hit=False
        )
        
        assert isinstance(result.data, list)
        assert isinstance(result.row_count, int)
        assert isinstance(result.execution_time_ms, float)
        assert isinstance(result.cache_hit, bool)
        assert result.row_count == 1
        assert result.execution_time_ms == 100.5
        assert result.cache_hit is False


if __name__ == "__main__":
    pytest.main([__file__])
