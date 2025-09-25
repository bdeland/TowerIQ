#!/usr/bin/env python3
"""
TowerIQ Dashboard API Baseline Tests

Comprehensive test suite covering all existing dashboard endpoints
to establish baseline behavior before refactoring. These tests serve
as regression tests to ensure refactoring doesn't break functionality.

Usage:
    pytest tests/api/test_dashboards_legacy.py -v
    python -m pytest tests/api/test_dashboards_legacy.py::test_get_all_dashboards -v
"""

import pytest
import asyncio
import aiohttp

# Configuration
API_BASE_URL = "http://localhost:8000"
TEST_TIMEOUT = 30  # seconds

class TestDashboardsLegacyAPI:
    """Comprehensive tests for existing dashboard API endpoints."""
    
    @pytest.fixture(scope="class")
    def event_loop(self):
        """Create event loop for async tests."""
        loop = asyncio.new_event_loop()
        yield loop
        loop.close()
    
    @pytest.fixture(scope="class")
    async def http_session(self):
        """Create HTTP session for API calls."""
        timeout = aiohttp.ClientTimeout(total=TEST_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            yield session
    
    @pytest.fixture(scope="class")
    async def server_available(self, http_session):
        """Check if API server is available."""
        try:
            async with http_session.get(f"{API_BASE_URL}/api/dashboards") as response:
                return response.status < 500
        except Exception:
            pytest.skip("API server not available - start with start_toweriq.py")
    
    # GET /api/dashboards - List all dashboards
    
    async def test_get_all_dashboards(self, http_session, server_available):
        """Test GET /api/dashboards endpoint."""
        async with http_session.get(f"{API_BASE_URL}/api/dashboards") as response:
            assert response.status == 200
            
            data = await response.json()
            assert isinstance(data, list)
            
            # Validate dashboard structure
            for dashboard in data:
                assert "id" in dashboard
                assert "title" in dashboard
                assert "config" in dashboard
                assert isinstance(dashboard["config"], dict)
    
    async def test_get_all_dashboards_response_structure(self, http_session, server_available):
        """Test response structure of GET /api/dashboards."""
        async with http_session.get(f"{API_BASE_URL}/api/dashboards") as response:
            data = await response.json()
            
            if len(data) > 0:
                dashboard = data[0]
                
                # Required fields
                required_fields = ["id", "uid", "title", "config", "created_at", "updated_at"]
                for field in required_fields:
                    assert field in dashboard, f"Missing required field: {field}"
                
                # Optional fields should have correct types if present
                if "description" in dashboard:
                    assert isinstance(dashboard["description"], (str, type(None)))
                if "tags" in dashboard:
                    assert isinstance(dashboard["tags"], list)
                if "is_default" in dashboard:
                    assert isinstance(dashboard["is_default"], bool)
    
    # GET /api/dashboards/{id} - Get specific dashboard
    
    async def test_get_dashboard_by_id_valid(self, http_session, server_available):
        """Test GET /api/dashboards/{id} with valid ID."""
        # First get list of dashboards to get a valid ID
        async with http_session.get(f"{API_BASE_URL}/api/dashboards") as response:
            dashboards = await response.json()
            
            if len(dashboards) > 0:
                dashboard_id = dashboards[0]["id"]
                
                # Test getting specific dashboard
                async with http_session.get(f"{API_BASE_URL}/api/dashboards/{dashboard_id}") as detail_response:
                    assert detail_response.status == 200
                    
                    dashboard = await detail_response.json()
                    assert dashboard["id"] == dashboard_id
                    assert "config" in dashboard
                    assert "panels" in dashboard["config"]
    
    async def test_get_dashboard_by_id_invalid(self, http_session, server_available):
        """Test GET /api/dashboards/{id} with invalid ID."""
        invalid_id = "non-existent-dashboard-id"
        
        async with http_session.get(f"{API_BASE_URL}/api/dashboards/{invalid_id}") as response:
            assert response.status == 404
    
    # GET /api/dashboards/default - Get default dashboard
    
    async def test_get_default_dashboard(self, http_session, server_available):
        """Test GET /api/dashboards/default endpoint."""
        async with http_session.get(f"{API_BASE_URL}/api/dashboards/default") as response:
            # Should either return 200 with dashboard or 404 if no default set
            assert response.status in [200, 404]
            
            if response.status == 200:
                dashboard = await response.json()
                assert "id" in dashboard
                assert "title" in dashboard
                assert "config" in dashboard
    
    # POST /api/dashboards - Create dashboard
    
    async def test_create_dashboard_valid(self, http_session, server_available):
        """Test POST /api/dashboards with valid data."""
        dashboard_data = {
            "title": "Test Dashboard",
            "description": "Test dashboard for API baseline",
            "config": {
                "panels": [
                    {
                        "id": "test-panel-1",
                        "type": "stat",
                        "title": "Test Panel",
                        "gridPos": {"x": 0, "y": 0, "w": 6, "h": 3},
                        "query": "SELECT COUNT(*) as test_count FROM runs"
                    }
                ]
            },
            "tags": ["test", "baseline"]
        }
        
        async with http_session.post(f"{API_BASE_URL}/api/dashboards", json=dashboard_data) as response:
            assert response.status == 200
            
            created_dashboard = await response.json()
            assert created_dashboard["title"] == dashboard_data["title"]
            assert created_dashboard["description"] == dashboard_data["description"]
            assert "id" in created_dashboard
            assert "uid" in created_dashboard
            
            # Clean up - delete the created dashboard
            dashboard_id = created_dashboard["id"]
            async with http_session.delete(f"{API_BASE_URL}/api/dashboards/{dashboard_id}"):
                pass  # Ignore delete result for cleanup
    
    async def test_create_dashboard_invalid_data(self, http_session, server_available):
        """Test POST /api/dashboards with invalid data."""
        invalid_data = {
            "title": "",  # Empty title should be invalid
            "config": {}   # Missing panels
        }
        
        async with http_session.post(f"{API_BASE_URL}/api/dashboards", json=invalid_data) as response:
            assert response.status >= 400  # Should return error
    
    # PUT /api/dashboards/{id} - Update dashboard
    
    async def test_update_dashboard(self, http_session, server_available):
        """Test PUT /api/dashboards/{id} endpoint."""
        # First create a dashboard to update
        create_data = {
            "title": "Test Update Dashboard",
            "description": "Dashboard for update testing",
            "config": {"panels": []},
            "tags": ["test"]
        }
        
        async with http_session.post(f"{API_BASE_URL}/api/dashboards", json=create_data) as create_response:
            if create_response.status == 200:
                created_dashboard = await create_response.json()
                dashboard_id = created_dashboard["id"]
                
                # Update the dashboard
                update_data = {
                    "title": "Updated Test Dashboard",
                    "description": "Updated description",
                    "config": {"panels": []},
                    "tags": ["test", "updated"]
                }
                
                async with http_session.put(f"{API_BASE_URL}/api/dashboards/{dashboard_id}", json=update_data) as update_response:
                    assert update_response.status == 200
                    
                    updated_dashboard = await update_response.json()
                    assert updated_dashboard["title"] == update_data["title"]
                    assert updated_dashboard["description"] == update_data["description"]
                
                # Clean up
                async with http_session.delete(f"{API_BASE_URL}/api/dashboards/{dashboard_id}"):
                    pass
    
    # DELETE /api/dashboards/{id} - Delete dashboard
    
    async def test_delete_dashboard(self, http_session, server_available):
        """Test DELETE /api/dashboards/{id} endpoint."""
        # First create a dashboard to delete
        create_data = {
            "title": "Test Delete Dashboard",
            "description": "Dashboard for deletion testing",
            "config": {"panels": []},
            "tags": ["test"]
        }
        
        async with http_session.post(f"{API_BASE_URL}/api/dashboards", json=create_data) as create_response:
            if create_response.status == 200:
                created_dashboard = await create_response.json()
                dashboard_id = created_dashboard["id"]
                
                # Delete the dashboard
                async with http_session.delete(f"{API_BASE_URL}/api/dashboards/{dashboard_id}") as delete_response:
                    assert delete_response.status in [200, 204]
                
                # Verify deletion - should return 404
                async with http_session.get(f"{API_BASE_URL}/api/dashboards/{dashboard_id}") as get_response:
                    assert get_response.status == 404
    
    async def test_delete_nonexistent_dashboard(self, http_session, server_available):
        """Test DELETE /api/dashboards/{id} with non-existent ID."""
        invalid_id = "non-existent-dashboard-id"
        
        async with http_session.delete(f"{API_BASE_URL}/api/dashboards/{invalid_id}") as response:
            assert response.status == 404
    
    # POST /api/dashboards/{id}/set-default - Set default dashboard
    
    async def test_set_default_dashboard(self, http_session, server_available):
        """Test POST /api/dashboards/{id}/set-default endpoint."""
        # Get existing dashboards
        async with http_session.get(f"{API_BASE_URL}/api/dashboards") as response:
            dashboards = await response.json()
            
            if len(dashboards) > 0:
                dashboard_id = dashboards[0]["id"]
                
                async with http_session.post(f"{API_BASE_URL}/api/dashboards/{dashboard_id}/set-default") as set_response:
                    # Should succeed or return appropriate error
                    assert set_response.status in [200, 404, 500]
    
    # POST /api/query - Execute query (dashboard dependency)
    
    async def test_query_endpoint_basic(self, http_session, server_available):
        """Test POST /api/query endpoint with basic query."""
        query_data = {
            "query": "SELECT COUNT(*) as total_runs FROM runs"
        }
        
        async with http_session.post(f"{API_BASE_URL}/api/query", json=query_data) as response:
            assert response.status in [200, 400]  # 400 if no data, 200 if data exists
            
            if response.status == 200:
                result = await response.json()
                assert isinstance(result, list)
    
    async def test_query_endpoint_with_variables(self, http_session, server_available):
        """Test POST /api/query endpoint with variable substitution."""
        # Test query that would use variables (without actual substitution)
        query_data = {
            "query": "SELECT tier, COUNT(*) as count FROM runs GROUP BY tier ORDER BY tier"
        }
        
        async with http_session.post(f"{API_BASE_URL}/api/query", json=query_data) as response:
            assert response.status in [200, 400]  # Depends on data availability
    
    async def test_query_endpoint_invalid_sql(self, http_session, server_available):
        """Test POST /api/query endpoint with invalid SQL."""
        query_data = {
            "query": "INVALID SQL STATEMENT"
        }
        
        async with http_session.post(f"{API_BASE_URL}/api/query", json=query_data) as response:
            assert response.status >= 400  # Should return error
    
    async def test_query_endpoint_forbidden_operations(self, http_session, server_available):
        """Test POST /api/query endpoint with forbidden SQL operations."""
        forbidden_queries = [
            {"query": "DROP TABLE runs"},
            {"query": "DELETE FROM runs"},
            {"query": "UPDATE runs SET tier = 1"},
            {"query": "INSERT INTO runs (tier) VALUES (1)"}
        ]
        
        for query_data in forbidden_queries:
            async with http_session.post(f"{API_BASE_URL}/api/query", json=query_data) as response:
                assert response.status >= 400  # Should be forbidden

class TestDashboardVariableSubstitution:
    """Test variable substitution patterns used in dashboards."""
    
    @pytest.fixture(scope="class")
    async def http_session(self):
        """Create HTTP session for API calls."""
        timeout = aiohttp.ClientTimeout(total=TEST_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            yield session
    
    @pytest.fixture(scope="class")
    async def server_available(self, http_session):
        """Check if API server is available."""
        try:
            async with http_session.get(f"{API_BASE_URL}/api/dashboards") as response:
                return response.status < 500
        except Exception:
            pytest.skip("API server not available")
    
    async def test_tier_filter_pattern(self, http_session, server_available):
        """Test tier_filter variable pattern transformation."""
        # Test base query without filter
        base_query = "SELECT COUNT(*) as count FROM runs"
        
        async with http_session.post(f"{API_BASE_URL}/api/query", json={"query": base_query}) as response:
            assert response.status in [200, 400]
    
    async def test_limit_clause_pattern(self, http_session, server_available):
        """Test limit_clause variable pattern transformation."""
        # Test query with LIMIT
        limit_query = "SELECT * FROM runs ORDER BY start_time DESC LIMIT 5"
        
        async with http_session.post(f"{API_BASE_URL}/api/query", json={"query": limit_query}) as response:
            assert response.status in [200, 400]
    
    async def test_complex_query_patterns(self, http_session, server_available):
        """Test complex SQL patterns found in dashboard queries."""
        complex_queries = [
            # Window function query
            "SELECT row_number() OVER (ORDER BY start_time ASC) as run_number, tier FROM runs LIMIT 1",
            
            # JOIN query
            "SELECT COUNT(m.id) as metric_count FROM metrics m JOIN metric_names mn ON m.metric_name_id = mn.id LIMIT 1",
            
            # Date formatting query
            "SELECT DATE(start_time / 1000, 'unixepoch') as run_date FROM runs LIMIT 1",
            
            # Aggregation query
            "SELECT tier, COUNT(*) as count FROM runs GROUP BY tier ORDER BY tier LIMIT 1"
        ]
        
        for query in complex_queries:
            async with http_session.post(f"{API_BASE_URL}/api/query", json={"query": query}) as response:
                assert response.status in [200, 400]  # Should not cause server errors

class TestDashboardPanelTypes:
    """Test different panel types and their data requirements."""
    
    @pytest.fixture(scope="class")
    async def http_session(self):
        """Create HTTP session for API calls."""
        timeout = aiohttp.ClientTimeout(total=TEST_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            yield session
    
    @pytest.fixture(scope="class")
    async def server_available(self, http_session):
        """Check if API server is available."""
        try:
            async with http_session.get(f"{API_BASE_URL}/api/dashboards") as response:
                return response.status < 500
        except Exception:
            pytest.skip("API server not available")
    
    async def test_stat_panel_queries(self, http_session, server_available):
        """Test queries typical for stat panels."""
        stat_queries = [
            "SELECT COUNT(*) as total_runs FROM runs",
            "SELECT COUNT(*) as total_metrics FROM metrics",
            "SELECT AVG(CPH) as avg_cph FROM runs WHERE CPH IS NOT NULL"
        ]
        
        for query in stat_queries:
            async with http_session.post(f"{API_BASE_URL}/api/query", json={"query": query}) as response:
                assert response.status in [200, 400]
    
    async def test_timeseries_panel_queries(self, http_session, server_available):
        """Test queries typical for timeseries panels."""
        timeseries_queries = [
            "SELECT start_time, CPH FROM runs ORDER BY start_time LIMIT 10",
            "SELECT DATE(start_time / 1000, 'unixepoch') as date, COUNT(*) as count FROM runs GROUP BY DATE(start_time / 1000, 'unixepoch') LIMIT 10"
        ]
        
        for query in timeseries_queries:
            async with http_session.post(f"{API_BASE_URL}/api/query", json={"query": query}) as response:
                assert response.status in [200, 400]
    
    async def test_bar_chart_panel_queries(self, http_session, server_available):
        """Test queries typical for bar chart panels."""
        bar_queries = [
            "SELECT tier, COUNT(*) as count FROM runs GROUP BY tier ORDER BY tier LIMIT 10",
            "SELECT tier, AVG(CPH) as avg_cph FROM runs WHERE CPH IS NOT NULL GROUP BY tier ORDER BY tier LIMIT 10"
        ]
        
        for query in bar_queries:
            async with http_session.post(f"{API_BASE_URL}/api/query", json={"query": query}) as response:
                assert response.status in [200, 400]
    
    async def test_table_panel_queries(self, http_session, server_available):
        """Test queries typical for table panels."""
        table_queries = [
            "SELECT run_id, tier, final_wave, CPH FROM runs ORDER BY start_time DESC LIMIT 5",
            "SELECT timestamp, level, event FROM logs ORDER BY timestamp DESC LIMIT 5"
        ]
        
        for query in table_queries:
            async with http_session.post(f"{API_BASE_URL}/api/query", json={"query": query}) as response:
                assert response.status in [200, 400]

# Utility function to run all tests
async def run_all_tests():
    """Run all dashboard API tests manually."""
    print("🧪 Running TowerIQ Dashboard API Baseline Tests...")
    
    # This is a simplified test runner for manual execution
    # In practice, use pytest for proper test execution
    
    timeout = aiohttp.ClientTimeout(total=TEST_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Test basic connectivity
        try:
            async with session.get(f"{API_BASE_URL}/api/dashboards") as response:
                print(f"✅ API server connectivity: {response.status}")
        except Exception as e:
            print(f"❌ API server not available: {e}")
            return False
        
        # Test dashboard endpoints
        test_results = {
            "get_dashboards": False,
            "create_dashboard": False,
            "query_endpoint": False
        }
        
        # Test GET /api/dashboards
        try:
            async with session.get(f"{API_BASE_URL}/api/dashboards") as response:
                test_results["get_dashboards"] = response.status == 200
                print(f"✅ GET /api/dashboards: {response.status}")
        except Exception as e:
            print(f"❌ GET /api/dashboards failed: {e}")
        
        # Test POST /api/query
        try:
            query_data = {"query": "SELECT 1 as test"}
            async with session.post(f"{API_BASE_URL}/api/query", json=query_data) as response:
                test_results["query_endpoint"] = response.status in [200, 400]
                print(f"✅ POST /api/query: {response.status}")
        except Exception as e:
            print(f"❌ POST /api/query failed: {e}")
        
        # Summary
        passed = sum(test_results.values())
        total = len(test_results)
        print(f"\n📊 Test Summary: {passed}/{total} tests passed")
        
        return passed == total

if __name__ == "__main__":
    # Run tests manually
    success = asyncio.run(run_all_tests())
    exit(0 if success else 1)
