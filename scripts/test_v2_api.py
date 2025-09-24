#!/usr/bin/env python3
"""
TowerIQ v2 API Test Script

This script tests the new v2 API endpoints for the hierarchical dashboard system.
It validates that the endpoints work correctly and the data source abstraction is functional.

Usage:
    python scripts/test_v2_api.py [--base-url http://localhost:8000]
"""

import asyncio
import aiohttp
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
import argparse

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class V2APITester:
    """Tests v2 API endpoints"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session: aiohttp.ClientSession = None
        self.test_results: List[Dict[str, Any]] = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def add_result(self, test_name: str, success: bool, message: str, details: Dict[str, Any] = None):
        """Add a test result"""
        self.test_results.append({
            'test': test_name,
            'success': success,
            'message': message,
            'details': details or {}
        })
        
        status = "✓" if success else "✗"
        print(f"{status} {test_name}: {message}")
        
        if not success and details:
            print(f"  Details: {json.dumps(details, indent=2)}")
    
    async def test_api_health(self) -> bool:
        """Test if the API server is running"""
        try:
            async with self.session.get(f"{self.base_url}/health") as response:
                if response.status == 200:
                    data = await response.json()
                    self.add_result(
                        "API Health Check",
                        True,
                        f"API server is running (status: {data.get('status', 'unknown')})"
                    )
                    return True
                else:
                    self.add_result(
                        "API Health Check",
                        False,
                        f"API server returned status {response.status}",
                        {"status_code": response.status}
                    )
                    return False
                    
        except Exception as e:
            self.add_result(
                "API Health Check",
                False,
                f"Failed to connect to API server: {str(e)}"
            )
            return False
    
    async def test_list_dashboards_v2(self) -> bool:
        """Test listing dashboards via v2 API"""
        try:
            async with self.session.get(f"{self.base_url}/api/v2/dashboards") as response:
                if response.status == 200:
                    data = await response.json()
                    dashboard_count = data.get('total', 0)
                    self.add_result(
                        "List Dashboards v2",
                        True,
                        f"Retrieved {dashboard_count} dashboards",
                        {"dashboard_count": dashboard_count, "dashboards": data.get('dashboards', [])}
                    )
                    return True
                else:
                    error_text = await response.text()
                    self.add_result(
                        "List Dashboards v2",
                        False,
                        f"HTTP {response.status}: {error_text}",
                        {"status_code": response.status, "response": error_text}
                    )
                    return False
                    
        except Exception as e:
            self.add_result(
                "List Dashboards v2",
                False,
                f"Exception: {str(e)}"
            )
            return False
    
    async def test_create_dashboard_v2(self) -> str:
        """Test creating a dashboard via v2 API"""
        try:
            # Create a test dashboard configuration
            test_dashboard = {
                "name": "Test Dashboard v2",
                "description": "Test dashboard created by API test script",
                "tags": ["test", "v2"],
                "is_system": False,
                "config": {
                    "id": "test-dashboard-v2",
                    "metadata": {
                        "id": "test-dashboard-v2",
                        "name": "Test Dashboard v2",
                        "description": "Test dashboard created by API test script",
                        "tags": ["test", "v2"],
                        "created_at": "2024-09-24T12:00:00",
                        "updated_at": "2024-09-24T12:00:00",
                        "created_by": "test-script",
                        "is_system": False
                    },
                    "panels": [
                        {
                            "id": "test-panel-1",
                            "title": "Test Panel",
                            "type": "stat",
                            "grid_pos": {"x": 0, "y": 0, "w": 6, "h": 4},
                            "query": {
                                "raw_query": "SELECT COUNT(*) as total_runs FROM runs",
                                "data_source_id": "default"
                            },
                            "visualization": {
                                "stat_config": {"unit": "none", "format": "number"}
                            }
                        }
                    ],
                    "variables": [],
                    "data_sources": ["default"],
                    "layout": {"type": "grid", "columns": 24},
                    "theme": {"name": "toweriq-dark"}
                }
            }
            
            async with self.session.post(
                f"{self.base_url}/api/v2/dashboards",
                json=test_dashboard
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    dashboard_id = data.get('id')
                    self.add_result(
                        "Create Dashboard v2",
                        True,
                        f"Created dashboard with ID: {dashboard_id}",
                        {"dashboard_id": dashboard_id}
                    )
                    return dashboard_id
                else:
                    error_text = await response.text()
                    self.add_result(
                        "Create Dashboard v2",
                        False,
                        f"HTTP {response.status}: {error_text}",
                        {"status_code": response.status, "response": error_text}
                    )
                    return None
                    
        except Exception as e:
            self.add_result(
                "Create Dashboard v2",
                False,
                f"Exception: {str(e)}"
            )
            return None
    
    async def test_get_dashboard_v2(self, dashboard_id: str) -> bool:
        """Test getting a specific dashboard via v2 API"""
        if not dashboard_id:
            self.add_result(
                "Get Dashboard v2",
                False,
                "No dashboard ID provided"
            )
            return False
            
        try:
            async with self.session.get(f"{self.base_url}/api/v2/dashboards/{dashboard_id}") as response:
                if response.status == 200:
                    data = await response.json()
                    self.add_result(
                        "Get Dashboard v2",
                        True,
                        f"Retrieved dashboard: {data.get('metadata', {}).get('name', 'Unknown')}",
                        {"dashboard_config": data}
                    )
                    return True
                else:
                    error_text = await response.text()
                    self.add_result(
                        "Get Dashboard v2",
                        False,
                        f"HTTP {response.status}: {error_text}",
                        {"status_code": response.status, "response": error_text}
                    )
                    return False
                    
        except Exception as e:
            self.add_result(
                "Get Dashboard v2",
                False,
                f"Exception: {str(e)}"
            )
            return False
    
    async def test_list_data_sources(self) -> bool:
        """Test listing data sources"""
        try:
            async with self.session.get(f"{self.base_url}/api/v2/data-sources") as response:
                if response.status == 200:
                    data = await response.json()
                    data_source_count = len(data)
                    self.add_result(
                        "List Data Sources",
                        True,
                        f"Retrieved {data_source_count} data sources",
                        {"data_source_count": data_source_count, "data_sources": data}
                    )
                    return True
                else:
                    error_text = await response.text()
                    self.add_result(
                        "List Data Sources",
                        False,
                        f"HTTP {response.status}: {error_text}",
                        {"status_code": response.status, "response": error_text}
                    )
                    return False
                    
        except Exception as e:
            self.add_result(
                "List Data Sources",
                False,
                f"Exception: {str(e)}"
            )
            return False
    
    async def test_query_v2(self) -> bool:
        """Test v2 query endpoint"""
        try:
            test_query = {
                "query": "SELECT COUNT(*) as total_runs FROM runs",
                "variables": {}
            }
            
            async with self.session.post(
                f"{self.base_url}/api/v2/query",
                json=test_query
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    row_count = data.get('rowCount', 0)
                    self.add_result(
                        "Query v2",
                        True,
                        f"Query executed successfully, returned {row_count} rows",
                        {"query_result": data}
                    )
                    return True
                else:
                    error_text = await response.text()
                    self.add_result(
                        "Query v2",
                        False,
                        f"HTTP {response.status}: {error_text}",
                        {"status_code": response.status, "response": error_text}
                    )
                    return False
                    
        except Exception as e:
            self.add_result(
                "Query v2",
                False,
                f"Exception: {str(e)}"
            )
            return False
    
    async def test_delete_dashboard_v2(self, dashboard_id: str) -> bool:
        """Test deleting a dashboard via v2 API"""
        if not dashboard_id:
            self.add_result(
                "Delete Dashboard v2",
                False,
                "No dashboard ID provided"
            )
            return False
            
        try:
            async with self.session.delete(f"{self.base_url}/api/v2/dashboards/{dashboard_id}") as response:
                if response.status == 200:
                    data = await response.json()
                    self.add_result(
                        "Delete Dashboard v2",
                        True,
                        f"Dashboard deleted: {data.get('message', 'Success')}",
                        {"response": data}
                    )
                    return True
                else:
                    error_text = await response.text()
                    self.add_result(
                        "Delete Dashboard v2",
                        False,
                        f"HTTP {response.status}: {error_text}",
                        {"status_code": response.status, "response": error_text}
                    )
                    return False
                    
        except Exception as e:
            self.add_result(
                "Delete Dashboard v2",
                False,
                f"Exception: {str(e)}"
            )
            return False
    
    async def run_all_tests(self) -> None:
        """Run all v2 API tests"""
        print("TowerIQ v2 API Test Suite")
        print("=" * 50)
        
        # Test API health
        if not await self.test_api_health():
            print("❌ API server is not available. Please start the server first.")
            return
        
        print()
        
        # Test dashboard endpoints
        await self.test_list_dashboards_v2()
        
        # Create a test dashboard
        test_dashboard_id = await self.test_create_dashboard_v2()
        
        # Get the created dashboard
        if test_dashboard_id:
            await self.test_get_dashboard_v2(test_dashboard_id)
        
        # Test data sources
        await self.test_list_data_sources()
        
        # Test query endpoint
        await self.test_query_v2()
        
        # Clean up - delete test dashboard
        if test_dashboard_id:
            await self.test_delete_dashboard_v2(test_dashboard_id)
        
        # Print summary
        print("\n" + "=" * 50)
        print("Test Summary")
        print("=" * 50)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print(f"Total tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        
        if failed_tests > 0:
            print(f"\nFailed tests:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  - {result['test']}: {result['message']}")
        
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        print(f"\nSuccess rate: {success_rate:.1f}%")
        
        if success_rate == 100:
            print("🎉 All tests passed! The v2 API is working correctly.")
        elif success_rate >= 75:
            print("⚠️  Most tests passed, but some issues were found.")
        else:
            print("❌ Many tests failed. The v2 API needs attention.")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Test TowerIQ v2 API endpoints")
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Base URL for the TowerIQ API server (default: http://localhost:8000)"
    )
    
    args = parser.parse_args()
    
    async with V2APITester(args.base_url) as tester:
        await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
