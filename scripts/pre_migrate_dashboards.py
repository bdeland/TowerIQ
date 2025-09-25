#!/usr/bin/env python3
"""
TowerIQ Dashboard Migration Analysis Script

This script analyzes existing dashboard configurations and identifies 
migration requirements for the hierarchical refactoring. It creates
a comprehensive migration plan and mapping between old and new formats.

Usage:
    python scripts/pre_migrate_dashboards.py

Output:
    - memory/dashboard_migration_mapping.json: Migration plan and mapping
    - memory/migration_analysis_report.json: Detailed analysis report
"""

import json
import sys
import re
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional
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

class DashboardMigrationAnalyzer:
    """Analyzes existing dashboards and creates migration plan."""
    
    def __init__(self):
        self.analysis_data = {
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "hardcoded_dashboards": {},
            "database_dashboards": [],
            "migration_complexity": {},
            "variable_patterns": {},
            "panel_types": {},
            "migration_mapping": {},
            "recommendations": [],
            "summary": {}
        }
        
        # Load baseline data if available
        self.baseline_data = self.load_baseline_data()
    
    def load_baseline_data(self) -> Optional[Dict[str, Any]]:
        """Load previously captured baseline data."""
        baseline_file = MEMORY_DIR / "pre_refactor_dashboards.json"
        if baseline_file.exists():
            try:
                with open(baseline_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  Could not load baseline data: {e}")
        return None
    
    async def analyze_existing_dashboards(self) -> Dict[str, Any]:
        """Analyze current dashboard configurations and identify migration requirements."""
        print("🔍 Starting TowerIQ Dashboard Migration Analysis...")
        
        # Analyze hardcoded TypeScript dashboards
        await self.analyze_hardcoded_dashboards()
        
        # Analyze database-stored dashboards
        await self.analyze_database_dashboards()
        
        # Analyze variable patterns
        self.analyze_variable_patterns()
        
        # Analyze panel types and complexity
        self.analyze_panel_types()
        
        # Assess migration complexity
        self.assess_migration_complexity()
        
        # Create migration mapping
        self.create_migration_mapping()
        
        # Generate recommendations
        self.generate_recommendations()
        
        # Generate summary
        self.generate_summary()
        
        return self.analysis_data
    
    async def analyze_hardcoded_dashboards(self):
        """Analyze hardcoded TypeScript dashboard configurations."""
        print("📄 Analyzing TypeScript dashboard configurations...")
        
        dashboard_files = [
            "defaultDashboard.ts",
            "databaseHealthDashboard.ts", 
            "liveRunTrackingDashboard.ts"
        ]
        
        for file_name in dashboard_files:
            file_path = FRONTEND_CONFIG_DIR / file_name
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8')
                    analysis = self.analyze_typescript_dashboard(content, file_name)
                    self.analysis_data["hardcoded_dashboards"][file_name] = analysis
                    print(f"  ✅ Analyzed {file_name}: {analysis['complexity_score']}/10 complexity")
                    
                except Exception as e:
                    print(f"  ❌ Error analyzing {file_name}: {e}")
    
    def analyze_typescript_dashboard(self, content: str, file_name: str) -> Dict[str, Any]:
        """Analyze a TypeScript dashboard for migration complexity."""
        analysis = {
            "file_name": file_name,
            "file_size": len(content),
            "line_count": len(content.split('\n')),
            "complexity_score": 0,  # 1-10 scale
            "migration_challenges": [],
            "panels": [],
            "variables": [],
            "queries": [],
            "echarts_customizations": 0,
            "external_dependencies": []
        }
        
        # Extract dashboard metadata
        id_match = re.search(r"id:\s*['\"]([^'\"]+)['\"]", content)
        if id_match:
            analysis["dashboard_id"] = id_match.group(1)
        
        title_match = re.search(r"title:\s*['\"]([^'\"]+)['\"]", content)
        if title_match:
            analysis["dashboard_title"] = title_match.group(1)
        
        # Count panels and analyze types
        panel_matches = re.findall(r"type:\s*['\"]([^'\"]+)['\"]", content)
        analysis["panel_types"] = list(set(panel_matches))
        analysis["panel_count"] = len(panel_matches)
        
        # Analyze queries
        query_matches = re.findall(r"query:\s*[\"'`]([^\"'`]+)[\"'`]", content, re.MULTILINE | re.DOTALL)
        analysis["queries"] = query_matches
        analysis["query_count"] = len(query_matches)
        
        # Count complex SQL features
        complex_sql_features = 0
        for query in query_matches:
            if "JOIN" in query.upper():
                complex_sql_features += 1
            if "CTE" in query.upper() or "WITH " in query.upper():
                complex_sql_features += 2
            if "WINDOW" in query.upper() or "OVER" in query.upper():
                complex_sql_features += 1
            if "CASE WHEN" in query.upper():
                complex_sql_features += 1
        
        analysis["complex_sql_features"] = complex_sql_features
        
        # Analyze variable patterns
        variable_patterns = re.findall(r"\$\{([^}]+)\}", content)
        analysis["variable_patterns"] = list(set(variable_patterns))
        analysis["variable_count"] = len(set(variable_patterns))
        
        # Count ECharts customizations
        echarts_customizations = 0
        echarts_customizations += len(re.findall(r"echartsOption:", content))
        echarts_customizations += len(re.findall(r"applyChartTheme", content))
        echarts_customizations += len(re.findall(r"formatter:", content))
        echarts_customizations += len(re.findall(r"tooltip:", content))
        analysis["echarts_customizations"] = echarts_customizations
        
        # Identify external dependencies
        dependencies = []
        if "generateUUID" in content:
            dependencies.append("UUID generation")
        if "formatCurrency" in content:
            dependencies.append("Currency formatting")
        if "formatDataSize" in content:
            dependencies.append("Data size formatting")
        if "CHART_COLORS" in content:
            dependencies.append("Color palette")
        if "applyChartTheme" in content:
            dependencies.append("Chart theming")
        
        analysis["external_dependencies"] = dependencies
        
        # Calculate complexity score (1-10)
        complexity = 0
        complexity += min(analysis["panel_count"] * 0.5, 3)  # Panel count
        complexity += min(analysis["query_count"] * 0.3, 2)  # Query count
        complexity += min(complex_sql_features * 0.5, 2)     # SQL complexity
        complexity += min(analysis["variable_count"] * 0.3, 1)  # Variables
        complexity += min(echarts_customizations * 0.1, 1)   # ECharts customization
        complexity += min(len(dependencies) * 0.2, 1)        # Dependencies
        
        analysis["complexity_score"] = round(complexity, 1)
        
        # Identify migration challenges
        challenges = []
        if analysis["panel_count"] > 10:
            challenges.append("High panel count requires careful migration")
        if complex_sql_features > 5:
            challenges.append("Complex SQL queries need validation")
        if analysis["variable_count"] > 3:
            challenges.append("Multiple variables require new variable system")
        if echarts_customizations > 10:
            challenges.append("Heavy ECharts customization needs preservation")
        if "drilldown" in content.lower():
            challenges.append("Drilldown functionality requires special handling")
        if "calendar" in content.lower():
            challenges.append("Calendar heatmap requires specialized migration")
        
        analysis["migration_challenges"] = challenges
        
        return analysis
    
    async def analyze_database_dashboards(self):
        """Analyze database-stored dashboard configurations."""
        print("🗄️  Analyzing database dashboard configurations...")
        
        if self.baseline_data and self.baseline_data.get("database_dashboards"):
            dashboards = self.baseline_data["database_dashboards"]
            self.analysis_data["database_dashboards"] = []
            
            for dashboard in dashboards:
                analysis = self.analyze_database_dashboard(dashboard)
                self.analysis_data["database_dashboards"].append(analysis)
                print(f"  ✅ Analyzed database dashboard: {dashboard.get('title', 'Unknown')}")
        else:
            print("  ⚠️  No database dashboards found in baseline data")
    
    def analyze_database_dashboard(self, dashboard: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a database-stored dashboard for migration complexity."""
        analysis = {
            "dashboard_id": dashboard.get("id"),
            "title": dashboard.get("title"),
            "panel_count": 0,
            "complexity_score": 1,  # Database dashboards are typically simpler
            "migration_challenges": ["Requires database schema migration"],
            "requires_data_migration": True
        }
        
        # Analyze panels if available
        config = dashboard.get("config", {})
        panels = config.get("panels", [])
        analysis["panel_count"] = len(panels)
        analysis["panel_types"] = [panel.get("type") for panel in panels if panel.get("type")]
        
        # Simple complexity calculation for database dashboards
        analysis["complexity_score"] = min(1 + len(panels) * 0.3, 5)
        
        return analysis
    
    def analyze_variable_patterns(self):
        """Analyze variable patterns for migration requirements."""
        print("🔍 Analyzing variable patterns...")
        
        if self.baseline_data and self.baseline_data.get("variable_patterns"):
            patterns = self.baseline_data["variable_patterns"]
            
            for pattern_name, pattern_data in patterns.items():
                # Only analyze actual SQL variable patterns
                if pattern_name in ["tier_filter", "limit_clause"]:
                    analysis = {
                        "pattern": pattern_name,
                        "complexity": "medium" if len(pattern_data.get("example_queries", [])) > 2 else "low",
                        "migration_strategy": self.get_variable_migration_strategy(pattern_name),
                        "requires_new_system": True,
                        "example_count": len(pattern_data.get("example_queries", []))
                    }
                    self.analysis_data["variable_patterns"][pattern_name] = analysis
        
        print(f"  ✅ Analyzed {len(self.analysis_data['variable_patterns'])} variable patterns")
    
    def get_variable_migration_strategy(self, pattern: str) -> str:
        """Get migration strategy for specific variable pattern."""
        strategies = {
            "tier_filter": "Migrate to new DashboardVariables class with Zod validation and multi-select support",
            "limit_clause": "Migrate to new DashboardVariables class with range validation and dropdown options"
        }
        return strategies.get(pattern, "Create new variable definition with appropriate validation")
    
    def analyze_panel_types(self):
        """Analyze panel types across all dashboards."""
        print("📊 Analyzing panel types...")
        
        panel_types = {}
        
        # Analyze hardcoded dashboards
        for file_name, dashboard in self.analysis_data["hardcoded_dashboards"].items():
            for panel_type in dashboard.get("panel_types", []):
                if panel_type not in panel_types:
                    panel_types[panel_type] = {
                        "count": 0,
                        "dashboards": [],
                        "migration_complexity": "low"
                    }
                panel_types[panel_type]["count"] += 1
                panel_types[panel_type]["dashboards"].append(file_name)
        
        # Analyze database dashboards
        for dashboard in self.analysis_data["database_dashboards"]:
            for panel_type in dashboard.get("panel_types", []):
                if panel_type and panel_type not in panel_types:
                    panel_types[panel_type] = {
                        "count": 0,
                        "dashboards": [],
                        "migration_complexity": "low"
                    }
                if panel_type:
                    panel_types[panel_type]["count"] += 1
                    panel_types[panel_type]["dashboards"].append(dashboard.get("title", "Unknown"))
        
        # Set migration complexity based on panel type
        complexity_map = {
            "stat": "low",
            "bar": "medium",
            "timeseries": "medium",
            "pie": "medium",
            "table": "low",
            "calendar": "high",
            "treemap": "high"
        }
        
        for panel_type in panel_types:
            panel_types[panel_type]["migration_complexity"] = complexity_map.get(panel_type, "medium")
        
        self.analysis_data["panel_types"] = panel_types
        print(f"  ✅ Found {len(panel_types)} panel types")
    
    def assess_migration_complexity(self):
        """Assess overall migration complexity."""
        print("⚖️  Assessing migration complexity...")
        
        complexity = {
            "overall_score": 0,
            "risk_factors": [],
            "estimated_effort": "medium",
            "critical_dependencies": [],
            "breaking_changes": []
        }
        
        # Calculate overall complexity
        total_complexity = 0
        dashboard_count = 0
        
        for dashboard in self.analysis_data["hardcoded_dashboards"].values():
            total_complexity += dashboard.get("complexity_score", 0)
            dashboard_count += 1
        
        for dashboard in self.analysis_data["database_dashboards"]:
            total_complexity += dashboard.get("complexity_score", 0)
            dashboard_count += 1
        
        if dashboard_count > 0:
            complexity["overall_score"] = round(total_complexity / dashboard_count, 1)
        
        # Identify risk factors
        risk_factors = []
        
        # High panel count
        total_panels = sum(d.get("panel_count", 0) for d in self.analysis_data["hardcoded_dashboards"].values())
        if total_panels > 20:
            risk_factors.append("High total panel count requires careful migration")
        
        # Complex variable system
        if len(self.analysis_data["variable_patterns"]) > 2:
            risk_factors.append("Complex variable system needs comprehensive testing")
        
        # Calendar/treemap panels
        for panel_type, data in self.analysis_data["panel_types"].items():
            if data["migration_complexity"] == "high":
                risk_factors.append(f"{panel_type.title()} panels require specialized migration")
        
        complexity["risk_factors"] = risk_factors
        
        # Estimate effort
        if complexity["overall_score"] < 3:
            complexity["estimated_effort"] = "low"
        elif complexity["overall_score"] < 6:
            complexity["estimated_effort"] = "medium"
        else:
            complexity["estimated_effort"] = "high"
        
        # Critical dependencies
        dependencies = set()
        for dashboard in self.analysis_data["hardcoded_dashboards"].values():
            dependencies.update(dashboard.get("external_dependencies", []))
        
        complexity["critical_dependencies"] = list(dependencies)
        
        # Breaking changes
        breaking_changes = [
            "Dashboard context structure will change",
            "Panel data fetching API will be unified",
            "Variable system will be completely rewritten",
            "ECharts options may need adjustment"
        ]
        complexity["breaking_changes"] = breaking_changes
        
        self.analysis_data["migration_complexity"] = complexity
        print(f"  ✅ Overall complexity: {complexity['overall_score']}/10 ({complexity['estimated_effort']} effort)")
    
    def create_migration_mapping(self):
        """Create mapping between old and new dashboard formats."""
        print("🗺️  Creating migration mapping...")
        
        mapping = {
            "typescript_to_database": {},
            "old_to_new_format": {},
            "variable_mapping": {},
            "panel_mapping": {}
        }
        
        # Map TypeScript dashboards to new database format
        for file_name, dashboard in self.analysis_data["hardcoded_dashboards"].items():
            dashboard_id = dashboard.get("dashboard_id", file_name.replace(".ts", ""))
            
            mapping["typescript_to_database"][file_name] = {
                "old_location": f"src/gui/TowerIQ/src/config/{file_name}",
                "new_table": "dashboard_configs",
                "dashboard_id": dashboard_id,
                "is_system": True,
                "migration_steps": [
                    "Parse TypeScript configuration",
                    "Transform to DashboardConfig JSON",
                    "Insert into dashboard_configs table",
                    "Mark as system dashboard"
                ]
            }
        
        # Map old format to new hierarchical format
        mapping["old_to_new_format"] = {
            "Dashboard": "Dashboard class instance",
            "DashboardPanel": "Panel class instance",
            "DashboardContext": "DashboardManager singleton",
            "DashboardVariableContext": "DashboardVariables class",
            "useDashboardData": "Dashboard.loadData() method",
            "DashboardDataService": "Integrated into Dashboard class"
        }
        
        # Map variable patterns
        for pattern_name in self.analysis_data["variable_patterns"]:
            mapping["variable_mapping"][pattern_name] = {
                "old_pattern": f"${{{pattern_name}}}",
                "new_system": "DashboardVariables.getComposedQuery()",
                "validation": "Zod schema validation",
                "options_loading": "Query-backed variable options"
            }
        
        # Map panel types
        for panel_type in self.analysis_data["panel_types"]:
            mapping["panel_mapping"][panel_type] = {
                "old_system": "React component with mixed concerns",
                "new_system": "Panel class with encapsulated logic",
                "data_fetching": "Panel.fetchData() method",
                "visualization": "Panel.getEChartsOptions() method"
            }
        
        self.analysis_data["migration_mapping"] = mapping
        print(f"  ✅ Created migration mapping for {len(mapping['typescript_to_database'])} dashboards")
    
    def generate_recommendations(self):
        """Generate migration recommendations."""
        print("💡 Generating recommendations...")
        
        recommendations = []
        
        # Phase-based recommendations
        recommendations.append({
            "priority": "high",
            "phase": "0",
            "title": "Complete baseline validation",
            "description": "Ensure all dashboard functionality is captured and tested before migration",
            "action_items": [
                "Run comprehensive API tests",
                "Validate variable substitution patterns",
                "Test all panel types with sample data"
            ]
        })
        
        recommendations.append({
            "priority": "high", 
            "phase": "1",
            "title": "Start with lowest complexity dashboards",
            "description": "Begin migration with simplest dashboards to validate approach",
            "action_items": [
                "Start with stat panels (lowest complexity)",
                "Migrate live-run-tracking-dashboard first (simple structure)",
                "Save calendar/treemap panels for last (highest complexity)"
            ]
        })
        
        # Variable system recommendations
        if len(self.analysis_data["variable_patterns"]) > 0:
            recommendations.append({
                "priority": "medium",
                "phase": "1",
                "title": "Design robust variable system",
                "description": "New variable system must handle all current patterns",
                "action_items": [
                    "Create Zod schemas for tier_filter validation",
                    "Implement query-backed variable options",
                    "Add comprehensive variable testing"
                ]
            })
        
        # Panel type recommendations
        high_complexity_panels = [pt for pt, data in self.analysis_data["panel_types"].items() 
                                 if data["migration_complexity"] == "high"]
        if high_complexity_panels:
            recommendations.append({
                "priority": "medium",
                "phase": "2",
                "title": "Special handling for complex panels",
                "description": f"Panels requiring special attention: {', '.join(high_complexity_panels)}",
                "action_items": [
                    "Create specialized Panel subclasses",
                    "Preserve all ECharts customizations",
                    "Test drilldown functionality thoroughly"
                ]
            })
        
        # Database migration recommendations
        if len(self.analysis_data["database_dashboards"]) > 0:
            recommendations.append({
                "priority": "low",
                "phase": "1B",
                "title": "Database schema migration",
                "description": "Existing database dashboards need schema updates",
                "action_items": [
                    "Create migration script for existing data",
                    "Validate data integrity after migration",
                    "Maintain backward compatibility during transition"
                ]
            })
        
        self.analysis_data["recommendations"] = recommendations
        print(f"  ✅ Generated {len(recommendations)} recommendations")
    
    def generate_summary(self):
        """Generate analysis summary."""
        summary = {
            "total_dashboards": len(self.analysis_data["hardcoded_dashboards"]) + len(self.analysis_data["database_dashboards"]),
            "hardcoded_dashboards": len(self.analysis_data["hardcoded_dashboards"]),
            "database_dashboards": len(self.analysis_data["database_dashboards"]),
            "total_panels": 0,
            "panel_types": len(self.analysis_data["panel_types"]),
            "variable_patterns": len(self.analysis_data["variable_patterns"]),
            "overall_complexity": self.analysis_data["migration_complexity"]["overall_score"],
            "estimated_effort": self.analysis_data["migration_complexity"]["estimated_effort"],
            "high_risk_factors": len(self.analysis_data["migration_complexity"]["risk_factors"]),
            "recommendations": len(self.analysis_data["recommendations"])
        }
        
        # Count total panels
        for dashboard in self.analysis_data["hardcoded_dashboards"].values():
            summary["total_panels"] += dashboard.get("panel_count", 0)
        
        for dashboard in self.analysis_data["database_dashboards"]:
            summary["total_panels"] += dashboard.get("panel_count", 0)
        
        self.analysis_data["summary"] = summary
        
        print("\n📊 Migration Analysis Summary:")
        print(f"  • Total Dashboards: {summary['total_dashboards']}")
        print(f"  • Total Panels: {summary['total_panels']}")
        print(f"  • Panel Types: {summary['panel_types']}")
        print(f"  • Variable Patterns: {summary['variable_patterns']}")
        print(f"  • Overall Complexity: {summary['overall_complexity']}/10")
        print(f"  • Estimated Effort: {summary['estimated_effort']}")
        print(f"  • Recommendations: {summary['recommendations']}")

async def main():
    """Main entry point for migration analysis."""
    try:
        analyzer = DashboardMigrationAnalyzer()
        data = await analyzer.analyze_existing_dashboards()
        
        # Save analysis report
        analysis_file = MEMORY_DIR / "migration_analysis_report.json"
        with open(analysis_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Analysis report saved to: {analysis_file}")
        
        # Save migration mapping separately
        mapping_file = MEMORY_DIR / "dashboard_migration_mapping.json"
        with open(mapping_file, 'w', encoding='utf-8') as f:
            json.dump(data["migration_mapping"], f, indent=2, ensure_ascii=False)
        
        print(f"💾 Migration mapping saved to: {mapping_file}")
        print("\n✅ Migration analysis completed successfully!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Migration analysis failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
