#!/usr/bin/env python3
"""
TowerIQ Dashboard Migration Script

This script migrates hardcoded TypeScript dashboards to the new unified
dashboard_configs table format for the hierarchical dashboard system.

Usage:
    python scripts/migrate_dashboards_to_v2.py [--dry-run] [--force]
"""

import asyncio
import json
import sys
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.tower_iq.models.dashboard_config_models import (  # noqa: E402
    DashboardConfig, DashboardMetadata, PanelConfig, PanelType, 
    GridPosition, QueryDefinition, VisualizationConfig
)


class DashboardMigrator:
    """Migrates hardcoded dashboards to database storage"""
    
    def __init__(self, database_path: str, dry_run: bool = False):
        self.database_path = database_path
        self.dry_run = dry_run
        self.migrated_count = 0
        self.failed_migrations: List[str] = []
        
    def connect_database(self) -> sqlite3.Connection:
        """Connect to the SQLite database"""
        if not os.path.exists(self.database_path):
            raise FileNotFoundError(f"Database not found: {self.database_path}")
        
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def ensure_tables_exist(self, conn: sqlite3.Connection) -> None:
        """Ensure required tables exist"""
        cursor = conn.cursor()
        
        # Check if dashboard_configs table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='dashboard_configs'
        """)
        
        if not cursor.fetchone():
            print("Creating dashboard_configs table...")
            cursor.execute("""
                CREATE TABLE dashboard_configs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    tags TEXT DEFAULT '[]',
                    config TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now', 'localtime')),
                    updated_at TEXT DEFAULT (datetime('now', 'localtime')),
                    created_by TEXT,
                    is_system BOOLEAN DEFAULT 0
                )
            """)
            
            cursor.execute("""
                CREATE INDEX idx_dashboard_configs_name 
                ON dashboard_configs(name)
            """)
            
            cursor.execute("""
                CREATE INDEX idx_dashboard_configs_system 
                ON dashboard_configs(is_system)
            """)
            
            conn.commit()
            print("dashboard_configs table created successfully")
    
    def parse_typescript_dashboard(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse TypeScript dashboard file and extract configuration"""
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # This is a simplified parser - in production, you'd want a proper TS parser
            # For now, we'll extract key information using string parsing
            
            # Extract dashboard object
            if 'defaultDashboard:' in content:
                dashboard_name = "TowerIQ Overview"
                dashboard_id = "default-dashboard"
                description = "Default pre-written dashboard, loaded from the frontend."
            elif 'databaseHealthDashboard:' in content:
                dashboard_name = "Database Health"
                dashboard_id = "database-health-dashboard"  
                description = "Database health and usage monitoring dashboard."
            elif 'liveRunTrackingDashboard:' in content:
                dashboard_name = "Live Run Tracking"
                dashboard_id = "live-run-tracking-dashboard"
                description = "Real-time run tracking dashboard."
            else:
                return None
            
            # Extract basic metadata
            dashboard_data = {
                'id': dashboard_id,
                'name': dashboard_name,
                'description': description,
                'tags': ['system', 'default'],
                'is_system': True,
                'created_by': 'system',
                'file_path': str(file_path)
            }
            
            return dashboard_data
            
        except Exception as e:
            print(f"Error parsing {file_path}: {str(e)}")
            return None
    
    def transform_to_dashboard_config(self, legacy_data: Dict[str, Any]) -> DashboardConfig:
        """Transform legacy dashboard data to new DashboardConfig format"""
        now = datetime.now()
        
        # Create metadata
        metadata = DashboardMetadata(
            id=legacy_data['id'],
            name=legacy_data['name'],
            description=legacy_data['description'],
            tags=legacy_data.get('tags', []),
            created_at=now,
            updated_at=now,
            created_by=legacy_data.get('created_by', 'system'),
            is_system=legacy_data.get('is_system', True)
        )
        
        # For now, create a placeholder panel structure
        # In a full migration, you'd parse the actual panel configurations
        panels = self.create_placeholder_panels(legacy_data['id'])
        
        # Create dashboard config
        dashboard_config = DashboardConfig(
            id=legacy_data['id'],
            metadata=metadata,
            panels=panels,
            variables=[],  # Variables would be extracted from actual TS files
            data_sources=["default"],
            layout={"type": "grid", "columns": 24},
            theme={"name": "toweriq-dark"}
        )
        
        return dashboard_config
    
    def create_placeholder_panels(self, dashboard_id: str) -> List[PanelConfig]:
        """Create placeholder panels for the dashboard"""
        panels = []
        
        if dashboard_id == "default-dashboard":
            panels = [
                PanelConfig(
                    id="coins-vs-run-panel",
                    title="Coins vs. Run (Chronological)",
                    type=PanelType.CHART,
                    grid_pos=GridPosition(x=0, y=0, w=12, h=6),
                    query=QueryDefinition(
                        raw_query="SELECT row_number() OVER (ORDER BY start_time ASC) as run_number, round_coins, CPH, tier FROM runs ORDER BY start_time ASC LIMIT 50",
                        data_source_id="default"
                    ),
                    visualization=VisualizationConfig(
                        chart_type="bar",
                        echarts_option={"xAxis": {"type": "category"}, "yAxis": {"type": "value"}}
                    )
                ),
                PanelConfig(
                    id="recent-runs-panel",
                    title="Recent Runs",
                    type=PanelType.TABLE,
                    grid_pos=GridPosition(x=12, y=0, w=12, h=6),
                    query=QueryDefinition(
                        raw_query="SELECT hex(run_id) as run_id, tier, final_wave, CPH, duration_gametime FROM runs ORDER BY start_time DESC LIMIT 10",
                        data_source_id="default"
                    ),
                    visualization=VisualizationConfig(
                        table_config={"pagination": True, "pageSize": 10}
                    )
                )
            ]
        elif dashboard_id == "database-health-dashboard":
            panels = [
                PanelConfig(
                    id="db-size-panel",
                    title="Database Size",
                    type=PanelType.STAT,
                    grid_pos=GridPosition(x=0, y=0, w=6, h=4),
                    query=QueryDefinition(
                        raw_query="SELECT page_count * page_size as database_size FROM pragma_page_count(), pragma_page_size()",
                        data_source_id="default"
                    ),
                    visualization=VisualizationConfig(
                        stat_config={"unit": "bytes", "format": "data"}
                    )
                )
            ]
        elif dashboard_id == "live-run-tracking-dashboard":
            panels = [
                PanelConfig(
                    id="current-run-panel",
                    title="Current Run",
                    type=PanelType.STAT,
                    grid_pos=GridPosition(x=0, y=0, w=12, h=4),
                    query=QueryDefinition(
                        raw_query="SELECT hex(run_id) as run_id FROM runs WHERE end_time IS NULL ORDER BY start_time DESC LIMIT 1",
                        data_source_id="default"
                    ),
                    visualization=VisualizationConfig(
                        stat_config={"unit": "none", "format": "string"}
                    )
                )
            ]
        
        return panels
    
    async def migrate_dashboard(self, conn: sqlite3.Connection, dashboard_data: Dict[str, Any]) -> bool:
        """Migrate a single dashboard to the database"""
        try:
            # Check if dashboard already exists
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM dashboard_configs WHERE id = ?", 
                (dashboard_data['id'],)
            )
            
            if cursor.fetchone():
                print(f"Dashboard {dashboard_data['id']} already exists, skipping...")
                return True
            
            # Transform to new format
            dashboard_config = self.transform_to_dashboard_config(dashboard_data)
            
            if self.dry_run:
                print(f"[DRY RUN] Would migrate dashboard: {dashboard_config.metadata.name}")
                return True
            
            # Insert into database
            cursor.execute("""
                INSERT INTO dashboard_configs 
                (id, name, description, tags, config, created_at, updated_at, created_by, is_system)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                dashboard_config.id,
                dashboard_config.metadata.name,
                dashboard_config.metadata.description,
                json.dumps(dashboard_config.metadata.tags),
                json.dumps(dashboard_config.model_dump(), default=str),
                dashboard_config.metadata.created_at.isoformat(),
                dashboard_config.metadata.updated_at.isoformat(),
                dashboard_config.metadata.created_by,
                dashboard_config.metadata.is_system
            ))
            
            conn.commit()
            
            print(f"✓ Migrated dashboard: {dashboard_config.metadata.name}")
            self.migrated_count += 1
            return True
            
        except Exception as e:
            print(f"✗ Failed to migrate dashboard {dashboard_data.get('id', 'unknown')}: {str(e)}")
            self.failed_migrations.append(dashboard_data.get('id', 'unknown'))
            return False
    
    async def discover_typescript_dashboards(self) -> List[Path]:
        """Discover TypeScript dashboard files"""
        dashboard_files = []
        
        # Look for dashboard files in the frontend config directory
        config_dir = project_root / "src" / "gui" / "TowerIQ" / "src" / "config"
        
        if config_dir.exists():
            for file_path in config_dir.glob("*Dashboard.ts"):
                dashboard_files.append(file_path)
        
        return dashboard_files
    
    async def run_migration(self) -> None:
        """Run the complete migration process"""
        print("TowerIQ Dashboard Migration to v2")
        print("=" * 50)
        
        if self.dry_run:
            print("🔍 DRY RUN MODE - No changes will be made")
            print()
        
        # Connect to database
        try:
            conn = self.connect_database()
            print(f"✓ Connected to database: {self.database_path}")
        except Exception as e:
            print(f"✗ Failed to connect to database: {str(e)}")
            return
        
        # Ensure tables exist
        try:
            self.ensure_tables_exist(conn)
        except Exception as e:
            print(f"✗ Failed to ensure tables exist: {str(e)}")
            return
        
        # Discover TypeScript dashboards
        print("\n📁 Discovering TypeScript dashboards...")
        dashboard_files = await self.discover_typescript_dashboards()
        print(f"Found {len(dashboard_files)} dashboard files")
        
        # Parse and migrate each dashboard
        print("\n🔄 Migrating dashboards...")
        
        for file_path in dashboard_files:
            print(f"\nProcessing: {file_path.name}")
            
            # Parse TypeScript file
            dashboard_data = self.parse_typescript_dashboard(file_path)
            if not dashboard_data:
                print("  ⚠️  Could not parse dashboard file")
                continue
            
            # Migrate to database
            await self.migrate_dashboard(conn, dashboard_data)
        
        # Close database connection
        conn.close()
        
        # Print summary
        print("\n" + "=" * 50)
        print("Migration Summary")
        print("=" * 50)
        print(f"Total dashboards processed: {len(dashboard_files)}")
        print(f"Successfully migrated: {self.migrated_count}")
        print(f"Failed migrations: {len(self.failed_migrations)}")
        
        if self.failed_migrations:
            print(f"Failed dashboard IDs: {', '.join(self.failed_migrations)}")
        
        if not self.dry_run and self.migrated_count > 0:
            print("\n✓ Migration completed successfully!")
            print("New dashboards are now available via the v2 API endpoints.")
        elif self.dry_run:
            print("\n🔍 Dry run completed. Use --force to apply changes.")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Migrate TowerIQ dashboards to v2 format")
    parser.add_argument(
        "--database", 
        default="data/toweriq.sqlite",
        help="Path to TowerIQ database (default: data/toweriq.sqlite)"
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true",
        help="Run in dry-run mode (no changes made)"
    )
    parser.add_argument(
        "--force", 
        action="store_true",
        help="Force migration (opposite of dry-run)"
    )
    
    args = parser.parse_args()
    
    # Determine if this is a dry run
    dry_run = args.dry_run and not args.force
    
    # Resolve database path
    database_path = Path(args.database)
    if not database_path.is_absolute():
        database_path = project_root / database_path
    
    # Create migrator and run
    migrator = DashboardMigrator(str(database_path), dry_run=dry_run)
    await migrator.run_migration()


if __name__ == "__main__":
    asyncio.run(main())
