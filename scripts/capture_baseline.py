#!/usr/bin/env python3
"""
TowerIQ Dashboard Baseline Capture Script

This script captures the current state of all dashboard configurations 
to establish a baseline for the refactoring process. It exports both 
hardcoded TypeScript dashboards and database-stored dashboards.

Usage:
    python scripts/capture_baseline.py

Output:
    - memory/pre_refactor_dashboards.json: Complete baseline snapshot
    - memory/variable_patterns_baseline.json: Variable substitution patterns
"""

import json
import os
import sys
import re
import asyncio
import aiohttp
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configuration
API_BASE_URL = "http://localhost:8000"
MEMORY_DIR = project_root / "memory"
FRONTEND_CONFIG_DIR = project_root / "src" / "gui" / "TowerIQ" / "src" / "config"

# Ensure memory directory exists
MEMORY_DIR.mkdir(exist_ok=True)

class DashboardBaseline:
    """Captures baseline dashboard configurations for refactoring safety."""
    
    def __init__(self):
        self.baseline_data = {
            "capture_timestamp": datetime.utcnow().isoformat(),
            "system_dashboards": {},
            "database_dashboards": [],
            "api_endpoints": [],
            "variable_patterns": {},
            "summary": {}
        }
    
    async def capture_all(self) -> Dict[str, Any]:
        """Capture complete baseline of all dashboard configurations."""
        print("🔍 Starting TowerIQ Dashboard Baseline Capture...")
        
        # Capture hardcoded TypeScript dashboards
        await self.capture_typescript_dashboards()
        
        # Capture database-stored dashboards
        await self.capture_database_dashboards()
        
        # Document variable substitution patterns
        self.document_variable_patterns()
        
        # Test API endpoints
        await self.test_api_endpoints()
        
        # Generate summary
        self.generate_summary()
        
        return self.baseline_data
    
    async def capture_typescript_dashboards(self):
        """Capture hardcoded TypeScript dashboard configurations."""
        print("📄 Capturing TypeScript dashboard configurations...")
        
        dashboard_files = [
            "defaultDashboard.ts",
            "databaseHealthDashboard.ts", 
            "liveRunTrackingDashboard.ts"
        ]
        
        for file_name in dashboard_files:
            file_path = FRONTEND_CONFIG_DIR / file_name
            if file_path.exists():
                try:
                    # Read the TypeScript file
                    content = file_path.read_text(encoding='utf-8')
                    
                    # Extract dashboard configuration (simplified parsing)
                    dashboard_info = self.parse_typescript_dashboard(content, file_name)
                    
                    if dashboard_info:
                        self.baseline_data["system_dashboards"][file_name] = dashboard_info
                        print(f"  ✅ Captured {file_name}")
                    else:
                        print(f"  ⚠️  Failed to parse {file_name}")
                        
                except Exception as e:
                    print(f"  ❌ Error reading {file_name}: {e}")
            else:
                print(f"  ❌ File not found: {file_name}")
    
    def parse_typescript_dashboard(self, content: str, file_name: str) -> Optional[Dict[str, Any]]:
        """Parse TypeScript dashboard configuration (simplified extraction)."""
        try:
            # Extract basic metadata using regex
            dashboard_info = {
                "file_name": file_name,
                "file_size": len(content),
                "line_count": len(content.split('\n')),
                "panels": [],
                "variables": [],
                "queries": []
            }
            
            # Extract dashboard ID
            id_match = re.search(r"id:\s*['\"]([^'\"]+)['\"]", content)
            if id_match:
                dashboard_info["id"] = id_match.group(1)
            
            # Extract title
            title_match = re.search(r"title:\s*['\"]([^'\"]+)['\"]", content)
            if title_match:
                dashboard_info["title"] = title_match.group(1)
            
            # Extract description
            desc_match = re.search(r"description:\s*['\"]([^'\"]+)['\"]", content)
            if desc_match:
                dashboard_info["description"] = desc_match.group(1)
            
            # Count panels
            panel_matches = re.findall(r"{\s*id:\s*['\"][^'\"]+['\"]", content)
            dashboard_info["panel_count"] = len(panel_matches)
            
            # Extract all queries
            query_matches = re.findall(r"query:\s*['\"]([^'\"]+)['\"]", content, re.MULTILINE | re.DOTALL)
            dashboard_info["queries"] = query_matches
            dashboard_info["query_count"] = len(query_matches)
            
            # Extract variable patterns
            variable_patterns = re.findall(r"\$\{([^}]+)\}", content)
            dashboard_info["variable_patterns"] = list(set(variable_patterns))
            
            return dashboard_info
            
        except Exception as e:
            print(f"Error parsing {file_name}: {e}")
            return None
    
    async def capture_database_dashboards(self):
        """Capture database-stored dashboard configurations via API."""
        print("🗄️  Capturing database dashboard configurations...")
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get all dashboards
                async with session.get(f"{API_BASE_URL}/api/dashboards") as response:
                    if response.status == 200:
                        dashboards = await response.json()
                        self.baseline_data["database_dashboards"] = dashboards
                        print(f"  ✅ Captured {len(dashboards)} database dashboards")
                        
                        # Capture individual dashboard details
                        for dashboard in dashboards:
                            dashboard_id = dashboard.get("id")
                            if dashboard_id:
                                async with session.get(f"{API_BASE_URL}/api/dashboards/{dashboard_id}") as detail_response:
                                    if detail_response.status == 200:
                                        detail = await detail_response.json()
                                        dashboard["_detailed_config"] = detail
                                        
                    else:
                        print(f"  ❌ API error: {response.status}")
                        self.baseline_data["database_dashboards"] = []
                        
        except aiohttp.ClientError as e:
            print(f"  ⚠️  API connection failed: {e}")
            self.baseline_data["database_dashboards"] = []
        except Exception as e:
            print(f"  ❌ Unexpected error: {e}")
            self.baseline_data["database_dashboards"] = []
    
    def document_variable_patterns(self):
        """Document all variable substitution patterns found."""
        print("🔍 Documenting variable substitution patterns...")
        
        patterns = {}
        
        # Extract patterns from TypeScript dashboards
        for file_name, dashboard in self.baseline_data["system_dashboards"].items():
            for pattern in dashboard.get("variable_patterns", []):
                if pattern not in patterns:
                    patterns[pattern] = {
                        "pattern": f"${{{pattern}}}",
                        "found_in": [],
                        "example_queries": [],
                        "transformation_rules": self.get_transformation_rules(pattern)
                    }
                patterns[pattern]["found_in"].append(file_name)
                
                # Add example queries containing this pattern
                for query in dashboard.get("queries", []):
                    if f"${{{pattern}}}" in query:
                        patterns[pattern]["example_queries"].append(query)
        
        self.baseline_data["variable_patterns"] = patterns
        print(f"  ✅ Documented {len(patterns)} variable patterns")
    
    def get_transformation_rules(self, pattern: str) -> Dict[str, str]:
        """Get transformation rules for variable patterns."""
        rules = {
            "tier_filter": "Transforms tier array to SQL WHERE/AND clause: [1,2] → 'AND tier IN (1,2)'",
            "limit_clause": "Transforms num_runs to SQL LIMIT clause: 10 → 'LIMIT 10'"
        }
        return {"description": rules.get(pattern, "Unknown transformation pattern")}
    
    async def test_api_endpoints(self):
        """Test current API endpoints to document baseline behavior."""
        print("🔌 Testing API endpoints...")
        
        endpoints = [
            {"method": "GET", "path": "/api/dashboards", "description": "List all dashboards"},
            {"method": "GET", "path": "/api/dashboards/default", "description": "Get default dashboard"},
            {"method": "POST", "path": "/api/query", "description": "Execute query"},
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for endpoint in endpoints:
                    try:
                        method = endpoint["method"].lower()
                        url = f"{API_BASE_URL}{endpoint['path']}"
                        
                        if method == "get":
                            async with session.get(url) as response:
                                endpoint["status"] = response.status
                                endpoint["available"] = response.status < 400
                        elif method == "post":
                            # Test with minimal payload
                            test_payload = {"query": "SELECT 1 as test"}
                            async with session.post(url, json=test_payload) as response:
                                endpoint["status"] = response.status
                                endpoint["available"] = response.status < 400
                                
                    except Exception as e:
                        endpoint["status"] = "error"
                        endpoint["available"] = False
                        endpoint["error"] = str(e)
                        
        except Exception as e:
            print(f"  ❌ API testing failed: {e}")
        
        self.baseline_data["api_endpoints"] = endpoints
        available_count = sum(1 for ep in endpoints if ep.get("available", False))
        print(f"  ✅ Tested {len(endpoints)} endpoints, {available_count} available")
    
    def generate_summary(self):
        """Generate summary of captured baseline data."""
        summary = {
            "typescript_dashboards": len(self.baseline_data["system_dashboards"]),
            "database_dashboards": len(self.baseline_data["database_dashboards"]),
            "total_dashboards": len(self.baseline_data["system_dashboards"]) + len(self.baseline_data["database_dashboards"]),
            "variable_patterns": len(self.baseline_data["variable_patterns"]),
            "api_endpoints_tested": len(self.baseline_data["api_endpoints"]),
            "api_endpoints_available": sum(1 for ep in self.baseline_data["api_endpoints"] if ep.get("available", False))
        }
        
        # Count total queries
        total_queries = 0
        for dashboard in self.baseline_data["system_dashboards"].values():
            total_queries += dashboard.get("query_count", 0)
        
        summary["total_queries"] = total_queries
        self.baseline_data["summary"] = summary
        
        print("\n📊 Baseline Capture Summary:")
        print(f"  • TypeScript Dashboards: {summary['typescript_dashboards']}")
        print(f"  • Database Dashboards: {summary['database_dashboards']}")
        print(f"  • Total Queries: {summary['total_queries']}")
        print(f"  • Variable Patterns: {summary['variable_patterns']}")
        print(f"  • API Endpoints Available: {summary['api_endpoints_available']}/{summary['api_endpoints_tested']}")

async def main():
    """Main entry point for baseline capture."""
    try:
        baseline = DashboardBaseline()
        data = await baseline.capture_all()
        
        # Save to JSON file
        output_file = MEMORY_DIR / "pre_refactor_dashboards.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Baseline data saved to: {output_file}")
        
        # Save variable patterns separately
        patterns_file = MEMORY_DIR / "variable_patterns_baseline.json"
        with open(patterns_file, 'w', encoding='utf-8') as f:
            json.dump(data["variable_patterns"], f, indent=2, ensure_ascii=False)
        
        print(f"💾 Variable patterns saved to: {patterns_file}")
        print("\n✅ Baseline capture completed successfully!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Baseline capture failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
