"""
TowerIQ Database Management Service

This module provides the DatabaseService class for managing both InfluxDB
and SQLite databases used by the application.
"""

import asyncio
import shutil
from typing import Any, Optional, Dict, List
from pathlib import Path
from datetime import datetime

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import sqlcipher3 as sqlcipher

from ..core.config import ConfigurationManager


class DatabaseService:
    """
    Service for managing all database operations including InfluxDB and SQLite.
    Handles connections, writes, reads, migrations, and backups.
    """
    
    def __init__(self, config: ConfigurationManager, logger: Any) -> None:
        """
        Initialize the database service.
        
        Args:
            config: Configuration manager instance
            logger: Logger instance for this service
        """
        self.logger = logger.bind(source="DatabaseService")
        
        # InfluxDB configuration
        self.influx_host = config.get('database.influxdb.host')
        self.influx_port = config.get('database.influxdb.port')
        self.influx_org = config.get('database.influxdb.org')
        self.influx_bucket = config.get('database.influxdb.bucket')
        self.influx_token = config.get('database.influxdb.token')
        self.influx_timeout = config.get('database.influxdb.timeout', 30)
        self.influx_url = f"http://{self.influx_host}:{self.influx_port}"
        
        # SQLite configuration
        self.sqlite_db_path = config.get('database.sqlite.db_path')
        self.sqlite_encryption_key = config.get('database.sqlite.encryption_key', 'default_key')
        self.sqlite_backup_path = config.get('database.sqlite.backup_path', 'data/backups/')
        self.backup_retention_days = config.get('database.sqlite.backup_retention_days', 30)
        
        # Database clients
        self.influx_client: Optional[InfluxDBClient] = None
        self.sqlite_conn: Optional[sqlcipher.Connection] = None
    
    async def connect(self) -> None:
        """
        Establish connections to both InfluxDB and SQLite databases.
        Called once at startup.
        """
        await self._connect_influxdb()
        await self._connect_sqlite()
    
    async def close(self) -> None:
        """Gracefully close both database connections."""
        await self._close_influxdb()
        await self._close_sqlite()
    
    async def _connect_influxdb(self) -> None:
        """Connect to InfluxDB."""
        try:
            self.logger.info("Connecting to InfluxDB", url=self.influx_url, org=self.influx_org)
            
            self.influx_client = InfluxDBClient(
                url=self.influx_url,
                token=self.influx_token,
                org=self.influx_org,
                timeout=self.influx_timeout * 1000  # Convert to milliseconds
            )
            
            # Test connection
            health = await asyncio.to_thread(self.influx_client.health)
            if health.status == "pass":
                self.logger.info("InfluxDB connection established successfully")
            else:
                self.logger.error("InfluxDB health check failed", status=health.status)
                
        except Exception as e:
            self.logger.error("Failed to connect to InfluxDB", error=str(e))
            self.influx_client = None
    
    async def _connect_sqlite(self) -> None:
        """Connect to encrypted SQLite database."""
        try:
            # Ensure database directory exists
            db_path = Path(self.sqlite_db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            self.logger.info("Connecting to SQLite database", path=self.sqlite_db_path)
            
            # Connect with encryption
            self.sqlite_conn = await asyncio.to_thread(
                sqlcipher.connect, 
                self.sqlite_db_path
            )
            
            # Set encryption key (required for SQLCipher)
            await asyncio.to_thread(
                self.sqlite_conn.execute,
                f"PRAGMA key = '{self.sqlite_encryption_key}'"
            )
            
            # Enable WAL mode for better concurrency
            await asyncio.to_thread(
                self.sqlite_conn.execute,
                "PRAGMA journal_mode = WAL"
            )
            
            # Test connection
            await asyncio.to_thread(
                self.sqlite_conn.execute,
                "SELECT 1"
            )
            
            self.logger.info("SQLite connection established successfully")
            
            # Run migrations
            await self.run_migrations()
            
        except Exception as e:
            self.logger.error("Failed to connect to SQLite database", error=str(e))
            self.sqlite_conn = None
    
    async def _close_influxdb(self) -> None:
        """Close InfluxDB connection."""
        if self.influx_client:
            try:
                await asyncio.to_thread(self.influx_client.close)
                self.logger.info("InfluxDB connection closed")
            except Exception as e:
                self.logger.error("Error closing InfluxDB connection", error=str(e))
            finally:
                self.influx_client = None
    
    async def _close_sqlite(self) -> None:
        """Close SQLite connection."""
        if self.sqlite_conn:
            try:
                await asyncio.to_thread(self.sqlite_conn.close)
                self.logger.info("SQLite connection closed")
            except Exception as e:
                self.logger.error("Error closing SQLite connection", error=str(e))
            finally:
                self.sqlite_conn = None
    
    # InfluxDB Methods
    async def write_metric(self, measurement: str, fields: Dict[str, Any], tags: Dict[str, str] = None) -> None:
        """
        Write a metric to InfluxDB.
        
        Args:
            measurement: Measurement name
            fields: Field values
            tags: Tag values (optional)
        """
        if not self.influx_client:
            self.logger.error("InfluxDB client not available")
            return
        
        try:
            write_api = self.influx_client.write_api(write_options=SYNCHRONOUS)
            
            point = Point(measurement)
            
            # Add tags
            if tags:
                for key, value in tags.items():
                    point = point.tag(key, value)
            
            # Add fields
            for key, value in fields.items():
                point = point.field(key, value)
            
            # Set timestamp
            point = point.time(datetime.utcnow())
            
            await asyncio.to_thread(
                write_api.write,
                bucket=self.influx_bucket,
                org=self.influx_org,
                record=point
            )
            
            self.logger.debug("Metric written to InfluxDB", measurement=measurement)
            
        except Exception as e:
            self.logger.error("Failed to write metric to InfluxDB", error=str(e), measurement=measurement)
    
    async def write_event(self, measurement: str, fields: Dict[str, Any], tags: Dict[str, str] = None) -> None:
        """
        Write an event to InfluxDB.
        
        Args:
            measurement: Measurement name
            fields: Field values
            tags: Tag values (optional)
        """
        # Events are just metrics with additional context
        if tags is None:
            tags = {}
        tags['type'] = 'event'
        
        await self.write_metric(measurement, fields, tags)
    
    async def query_metrics(self, query: str) -> List[Dict[str, Any]]:
        """
        Query metrics from InfluxDB.
        
        Args:
            query: Flux query string
            
        Returns:
            List of query results
        """
        if not self.influx_client:
            self.logger.error("InfluxDB client not available")
            return []
        
        try:
            query_api = self.influx_client.query_api()
            
            tables = await asyncio.to_thread(
                query_api.query,
                query=query,
                org=self.influx_org
            )
            
            results = []
            for table in tables:
                for record in table.records:
                    results.append(record.values)
            
            return results
            
        except Exception as e:
            self.logger.error("Failed to query InfluxDB", error=str(e))
            return []
    
    # SQLite Methods
    async def run_migrations(self) -> None:
        """
        Check schema version and apply necessary migration scripts.
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return
        
        try:
            # Create schema_version table if it doesn't exist
            await asyncio.to_thread(
                self.sqlite_conn.execute,
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            
            # Check current schema version
            cursor = await asyncio.to_thread(
                self.sqlite_conn.execute,
                "SELECT MAX(version) FROM schema_version"
            )
            result = await asyncio.to_thread(cursor.fetchone)
            current_version = result[0] if result[0] is not None else 0
            
            # Apply migrations
            await self._apply_migrations(current_version)
            
            await asyncio.to_thread(self.sqlite_conn.commit)
            
        except Exception as e:
            self.logger.error("Failed to run database migrations", error=str(e))
            if self.sqlite_conn:
                await asyncio.to_thread(self.sqlite_conn.rollback)
    
    async def _apply_migrations(self, current_version: int) -> None:
        """Apply database migrations from current version."""
        migrations = [
            # Migration 1: Create settings table
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            # Migration 2: Create run_sessions table
            """
            CREATE TABLE IF NOT EXISTS run_sessions (
                id TEXT PRIMARY KEY,
                game_version TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                status TEXT DEFAULT 'active'
            );
            """,
            # Migration 3: Create hook_activity table
            """
            CREATE TABLE IF NOT EXISTS hook_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                hook_name TEXT,
                event_type TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data TEXT,
                FOREIGN KEY (run_id) REFERENCES run_sessions(id)
            );
            """
        ]
        
        for i, migration_sql in enumerate(migrations, 1):
            if i > current_version:
                try:
                    await asyncio.to_thread(self.sqlite_conn.execute, migration_sql)
                    await asyncio.to_thread(
                        self.sqlite_conn.execute,
                        "INSERT INTO schema_version (version) VALUES (?)",
                        (i,)
                    )
                    self.logger.info("Applied database migration", version=i)
                except Exception as e:
                    self.logger.error("Failed to apply migration", version=i, error=str(e))
                    raise
    
    async def get_setting(self, key: str) -> Optional[str]:
        """
        Get a setting value from the database.
        
        Args:
            key: Setting key
            
        Returns:
            Setting value or None if not found
        """
        if not self.sqlite_conn:
            return None
        
        try:
            cursor = await asyncio.to_thread(
                self.sqlite_conn.execute,
                "SELECT value FROM settings WHERE key = ?",
                (key,)
            )
            result = await asyncio.to_thread(cursor.fetchone)
            return result[0] if result else None
            
        except Exception as e:
            self.logger.error("Failed to get setting", key=key, error=str(e))
            return None
    
    async def set_setting(self, key: str, value: str) -> None:
        """
        Set a setting value in the database.
        
        Args:
            key: Setting key
            value: Setting value
        """
        if not self.sqlite_conn:
            return
        
        try:
            await asyncio.to_thread(
                self.sqlite_conn.execute,
                """
                INSERT OR REPLACE INTO settings (key, value, updated_at) 
                VALUES (?, ?, CURRENT_TIMESTAMP)
                """,
                (key, value)
            )
            await asyncio.to_thread(self.sqlite_conn.commit)
            
        except Exception as e:
            self.logger.error("Failed to set setting", key=key, error=str(e))
    
    async def backup_database(self, backup_path: Optional[str] = None) -> bool:
        """
        Perform a safe online backup of the SQLite database.
        
        Args:
            backup_path: Custom backup path (optional)
            
        Returns:
            True if backup successful, False otherwise
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available for backup")
            return False
        
        try:
            if backup_path is None:
                backup_dir = Path(self.sqlite_backup_path)
                backup_dir.mkdir(parents=True, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = backup_dir / f"tower_iq_backup_{timestamp}.db"
            
            self.logger.info("Starting database backup", backup_path=str(backup_path))
            
            # Perform backup using SQLite's backup API
            backup_conn = await asyncio.to_thread(sqlcipher.connect, str(backup_path))
            
            # Set encryption key for backup (only if encryption is available)
            if ENCRYPTION_AVAILABLE:
                await asyncio.to_thread(
                    backup_conn.execute,
                    f"PRAGMA key = '{self.sqlite_encryption_key}'"
                )
            
            # Use SQLite backup API
            await asyncio.to_thread(
                self.sqlite_conn.backup,
                backup_conn
            )
            
            await asyncio.to_thread(backup_conn.close)
            
            self.logger.info("Database backup completed successfully", backup_path=str(backup_path))
            
            # Clean up old backups
            await self._cleanup_old_backups()
            
            return True
            
        except Exception as e:
            self.logger.error("Database backup failed", error=str(e))
            return False
    
    async def _cleanup_old_backups(self) -> None:
        """Remove backup files older than retention period."""
        try:
            backup_dir = Path(self.sqlite_backup_path)
            if not backup_dir.exists():
                return
            
            cutoff_time = datetime.now().timestamp() - (self.backup_retention_days * 24 * 3600)
            
            for backup_file in backup_dir.glob("tower_iq_backup_*.db"):
                if backup_file.stat().st_mtime < cutoff_time:
                    backup_file.unlink()
                    self.logger.info("Removed old backup", file=str(backup_file))
            
        except Exception as e:
            self.logger.error("Failed to cleanup old backups", error=str(e)) 