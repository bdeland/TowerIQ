"""
TowerIQ Database Management Service

This module provides the DatabaseService class for managing the SQLite database
used by the embedded application architecture.
"""

import json
import sqlite3
import os
import shutil
from typing import Any, Optional, Dict, List, cast
from pathlib import Path
from datetime import datetime
import pandas as pd
import functools
import tempfile
import zipfile

from ..core.config import ConfigurationManager

# Decorator to handle DB connection checks and errors
def db_operation(default_return_value: Any = None):
    """
    Decorator to wrap database operations, handling connection checks and exceptions.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self: 'DatabaseService', *args, **kwargs):
            if not self.sqlite_conn:
                self.logger.error(
                    "Database operation skipped: connection not available",
                    operation=func.__name__
                )
                return default_return_value
            try:
                return func(self, *args, **kwargs)
            except Exception as e:
                self.logger.error(
                    "Database operation failed",
                    operation=func.__name__,
                    error=str(e),
                    args=args,
                    kwargs=kwargs
                )
                return default_return_value
        return wrapper
    return decorator

class DatabaseService:
    """
    Service for managing SQLite database operations.
    Handles connections, writes, reads, migrations, and backups.
    """
    
    DB_VERSION = "6" # Normalized db_metrics table with lookup tables for better performance
    
    def __init__(self, config: ConfigurationManager, logger: Any, db_path: str = '') -> None:
        """
        Initialize the database service.
        Args:
            config: ConfigurationManager instance
            logger: Logger instance for this service
            db_path: Optional override for the database file path
        """
        self.config = config  # Store reference to config manager
        self.logger = logger.bind(source="DatabaseService")
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = config.get('database.sqlite_path', 'data/toweriq.sqlite')
        self.logger.debug("Database path resolved", db_path=self.db_path, db_path_type=str(type(self.db_path)))
        self.sqlite_conn: Optional[sqlite3.Connection] = None
    
    def connect(self) -> None:
        """
        Establish connection to the SQLite database.
        Called once at startup.
        """
        try:
            # Ensure database directory exists
            db_path = Path(self.db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            self.logger.info("Connecting to SQLite database", path=self.db_path)
            
            # Connect to standard SQLite database
            self.sqlite_conn = sqlite3.connect(self.db_path, check_same_thread=False)
            
            # Set reasonable busy timeout
            self.sqlite_conn.execute("PRAGMA busy_timeout=3000;")

            # Enable WAL mode for better concurrency
            self.sqlite_conn.execute("PRAGMA journal_mode=WAL;")

            # If prior run left WAL/SHM, checkpoint them safely at startup
            try:
                wal_exists = os.path.exists(f"{self.db_path}-wal")
                shm_exists = os.path.exists(f"{self.db_path}-shm")
                if wal_exists or shm_exists:
                    self.logger.info("Existing SQLite journal files detected at startup; checkpointing",
                                     wal_exists=wal_exists, shm_exists=shm_exists)
                    # Merge WAL contents and truncate
                    self.sqlite_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            except Exception as checkpoint_err:
                # Non-fatal; continue with connection and migrations
                self.logger.warning("Startup WAL checkpoint failed", error=str(checkpoint_err))
            
            # Test connection
            self.sqlite_conn.execute("SELECT 1")
            
            self.logger.info("SQLite connection established successfully")
            
            # Run migrations
            self.run_migrations()
            
        except Exception as e:
            self.logger.error("Failed to connect to SQLite database", error=str(e))
            self.sqlite_conn = None
            raise
    
    def close(self) -> None:
        """Gracefully close the database connection and clean up WAL files."""
        if self.sqlite_conn:
            try:
                # Checkpoint the WAL file to merge changes back to main database
                self.logger.debug("Checkpointing WAL file before closing")
                self.sqlite_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                
                # Switch back to DELETE mode to clean up WAL and SHM files
                self.logger.debug("Switching to DELETE journal mode for cleanup")
                self.sqlite_conn.execute("PRAGMA journal_mode=DELETE;")
                
                # Commit any pending transactions
                self.sqlite_conn.commit()
                
                # Close the connection
                self.sqlite_conn.close()
                
                # Best-effort removal of any remaining -wal/-shm files
                try:
                    wal_path = f"{self.db_path}-wal"
                    shm_path = f"{self.db_path}-shm"
                    for fpath in (wal_path, shm_path):
                        if os.path.exists(fpath):
                            os.remove(fpath)
                            self.logger.debug("Removed SQLite journal file", file=fpath)
                except Exception as cleanup_err:
                    # Non-fatal: log at debug to avoid noise
                    self.logger.debug("Could not remove SQLite journal file(s)", error=str(cleanup_err))
                self.logger.info("SQLite connection closed and WAL files cleaned up")
            except Exception as e:
                self.logger.error("Error closing SQLite connection", error=str(e))
                # Still try to close the connection even if cleanup failed
                try:
                    self.sqlite_conn.close()
                except:
                    pass
            finally:
                self.sqlite_conn = None
    
    def run_migrations(self) -> None:
        """
        Manages database schema migrations based on a version stored in the DB.
        """
        self.logger.info("Checking database schema version.")
        if self.sqlite_conn is None:
            raise RuntimeError("Database connection is not established")
        conn = cast(sqlite3.Connection, self.sqlite_conn)
        
        # Check if settings table exists and what schema it has
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
        settings_exists = cursor.fetchone() is not None
        
        if settings_exists:
            # Settings table exists, check its schema
            cursor = conn.execute("PRAGMA table_info(settings)")
            columns = [row[1] for row in cursor.fetchall()]
            has_enhanced_schema = 'value_type' in columns
            
            if has_enhanced_schema:
                # Enhanced schema exists, check version
                current_version = self.get_setting("db_version")
                if current_version == self.DB_VERSION:
                    self.logger.info("Database schema is up to date.", version=self.DB_VERSION)
                    return
            else:
                # Basic schema exists, migrate to enhanced
                self.logger.info("Migrating settings table from basic to enhanced schema")
                self._migrate_settings_table_if_needed()
                current_version = self.get_setting("db_version")
                if current_version == self.DB_VERSION:
                    self.logger.info("Database schema is up to date after migration.", version=self.DB_VERSION)
                    return
        else:
            # No settings table exists, this is a fresh database
            current_version = None

        self.logger.warning(
            "Database schema is outdated or new. Running migrations.",
            current_version=current_version,
            target_version=self.DB_VERSION
        )
        
        # For this major change, we will create the new optimized schema.
        # A more advanced system would have sequential migration scripts (e.g., migrate_v1_to_v2).
        self._create_schema_v6()

        self.set_setting("db_version", self.DB_VERSION)
        self.logger.info("Database migration to version %s completed.", self.DB_VERSION)
        
        # Create default dashboards after schema is ready
        # self.create_default_dashboards() # <--- THIS LINE IS NOW COMMENTED OUT

    def _migrate_settings_table_if_needed(self):
        """Migrate the settings table to include metadata if needed."""
        if self.sqlite_conn is None:
            return
            
        try:
            # Check if the enhanced schema already exists
            cursor = self.sqlite_conn.execute("PRAGMA table_info(settings)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'value_type' not in columns:
                self.logger.info("Migrating settings table to enhanced schema")
                
                # Create new table with enhanced schema
                self.sqlite_conn.execute("""
                    CREATE TABLE settings_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT NOT NULL UNIQUE,
                        value TEXT NOT NULL,
                        value_type TEXT NOT NULL DEFAULT 'string',
                        description TEXT,
                        category TEXT DEFAULT 'general',
                        is_sensitive BOOLEAN DEFAULT 0,
                        created_at TEXT DEFAULT (datetime('now', 'localtime')),
                        updated_at TEXT DEFAULT (datetime('now', 'localtime')),
                        created_by TEXT DEFAULT 'system',
                        version INTEGER DEFAULT 1
                    )
                """)
                
                # Copy existing data
                cursor = self.sqlite_conn.execute("SELECT key, value FROM settings")
                for row in cursor.fetchall():
                    key, value = row
                    # Try to determine the type
                    value_type = 'string'
                    
                    # First check for boolean values
                    if isinstance(value, str) and value.lower() in ('true', 'false', '1', '0'):
                        value_type = 'bool'
                    else:
                        try:
                            # Try to parse as JSON
                            json.loads(value)
                            value_type = 'json'
                        except (ValueError, json.JSONDecodeError):
                            try:
                                # Try to parse as int
                                int(value)
                                value_type = 'int'
                            except ValueError:
                                try:
                                    # Try to parse as float
                                    float(value)
                                    value_type = 'float'
                                except ValueError:
                                    # Default to string
                                    value_type = 'string'
                    
                    # Determine category
                    category = 'general'
                    if key.startswith('logging.'):
                        category = 'logging'
                    elif key.startswith('database.'):
                        category = 'database'
                    elif key.startswith('frida.'):
                        category = 'frida'
                    elif key.startswith('gui.'):
                        category = 'gui'
                    elif key.startswith('emulator.'):
                        category = 'emulator'
                    
                    self.sqlite_conn.execute("""
                        INSERT INTO settings_new 
                        (key, value, value_type, category, created_at, updated_at) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (key, value, value_type, category, 
                          datetime.now().isoformat(), datetime.now().isoformat()))
                
                # Drop old table and rename new one
                self.sqlite_conn.execute("DROP TABLE settings")
                self.sqlite_conn.execute("ALTER TABLE settings_new RENAME TO settings")
                
                # Create indexes
                self.sqlite_conn.execute("CREATE INDEX idx_settings_key ON settings(key)")
                self.sqlite_conn.execute("CREATE INDEX idx_settings_category ON settings(category)")
                
                self.sqlite_conn.commit()
                self.logger.info("Settings table migration completed successfully")
                
        except Exception as e:
            self.logger.error("Failed to migrate settings table", error=str(e))
            # Don't raise the exception - the application can still work with the basic schema

    def _create_schema_v2(self):
        """Creates the version 2 schema with a 'long' metrics table."""
        if self.sqlite_conn is None:
            raise RuntimeError("Database connection is not established")
        conn = cast(sqlite3.Connection, self.sqlite_conn)
        try:
            # Check which tables already exist
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing_tables = {row[0] for row in cursor.fetchall()}
            
            self.logger.info("Checking existing tables", existing_tables=list(existing_tables))
            
            # Only create tables that don't exist
            if 'runs' not in existing_tables:
                self.logger.info("Creating runs table")
                conn.execute("""
                    CREATE TABLE runs (
                        run_id TEXT PRIMARY KEY,
                        start_time INTEGER NOT NULL,
                        end_time INTEGER,
                        duration_realtime INTEGER,
                        duration_gametime REAL,
                        final_wave INTEGER,
                        coins_earned REAL,
                        CPH REAL,
                        round_cells REAL,
                        round_gems REAL,
                        round_cash REAL,
                        game_version TEXT,
                        tier INTEGER
                    )
                """)

            if 'metrics' not in existing_tables:
                self.logger.info("Creating metrics table")
                # NEW "Long" format for metrics table - highly extensible
                conn.execute("""
                    CREATE TABLE metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_id TEXT NOT NULL,
                        real_timestamp INTEGER NOT NULL,
                        game_timestamp REAL NOT NULL,
                        current_wave INTEGER NOT NULL,
                        metric_name TEXT NOT NULL,
                        metric_value REAL NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE INDEX idx_metrics_run_name_time 
                    ON metrics(run_id, metric_name, real_timestamp)
                """)

            if 'events' not in existing_tables:
                self.logger.info("Creating events table")
                conn.execute("""
                    CREATE TABLE events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_id TEXT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        event_name TEXT NOT NULL,
                        data TEXT
                    )
                """)
                
            if 'logs' not in existing_tables:
                self.logger.info("Creating logs table")
                conn.execute("""
                    CREATE TABLE logs (
                        timestamp INTEGER, level TEXT, source TEXT, event TEXT, data TEXT
                    )
                """)
            
            # Create dashboards table
            if 'dashboards' not in existing_tables:
                self.logger.info("Creating dashboards table")
                conn.execute("""
                    CREATE TABLE dashboards (
                        id TEXT PRIMARY KEY,
                        uid TEXT UNIQUE NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        config TEXT NOT NULL,
                        tags TEXT,
                        created_at TEXT DEFAULT (datetime('now', 'localtime')),
                        updated_at TEXT DEFAULT (datetime('now', 'localtime')),
                        created_by TEXT DEFAULT 'system',
                        is_default BOOLEAN DEFAULT 0,
                        schema_version INTEGER DEFAULT 1
                    )
                """)
                conn.execute("CREATE INDEX idx_dashboards_uid ON dashboards(uid)")
                conn.execute("CREATE INDEX idx_dashboards_title ON dashboards(title)")
                conn.execute("CREATE INDEX idx_dashboards_created_at ON dashboards(created_at)")
            else:
                self.logger.info("Dashboards table already exists")
            
            # Always ensure settings table exists (it was deleted)
            if 'settings' not in existing_tables:
                self.logger.info("Creating settings table")
                conn.execute("""
                    CREATE TABLE settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT NOT NULL UNIQUE,
                        value TEXT NOT NULL,
                        value_type TEXT NOT NULL DEFAULT 'string',
                        description TEXT,
                        category TEXT DEFAULT 'general',
                        is_sensitive BOOLEAN DEFAULT 0,
                        created_at TEXT DEFAULT (datetime('now', 'localtime')),
                        updated_at TEXT DEFAULT (datetime('now', 'localtime')),
                        created_by TEXT DEFAULT 'system',
                        version INTEGER DEFAULT 1
                    )
                """)
                conn.execute("CREATE INDEX idx_settings_key ON settings(key)")
                conn.execute("CREATE INDEX idx_settings_category ON settings(category)")
            else:
                self.logger.info("Settings table already exists")
            
            
            conn.commit()
            self.logger.info("Successfully created V2 database schema.")
        except Exception as e:
            self.logger.error("Failed during V2 schema creation", error=str(e))
            try:
                conn.rollback()
            except Exception:
                pass
            raise

    def _create_schema_v4(self):
        """Creates the version 4 optimized schema with integer primary keys and lookup tables."""
        if self.sqlite_conn is None:
            raise RuntimeError("Database connection is not established")
        conn = cast(sqlite3.Connection, self.sqlite_conn)
        try:
            # Check which tables already exist
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing_tables = {row[0] for row in cursor.fetchall()}
            
            self.logger.info("Checking existing tables for V4 schema", existing_tables=list(existing_tables))
            
            # Create lookup tables first
            if 'metric_names' not in existing_tables:
                self.logger.info("Creating metric_names lookup table")
                conn.execute("""
                    CREATE TABLE metric_names (
                        metric_name_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT NOT NULL UNIQUE
                    )
                """)
                conn.execute("CREATE INDEX idx_metric_names_name ON metric_names(metric_name)")

            if 'event_names' not in existing_tables:
                self.logger.info("Creating event_names lookup table")
                conn.execute("""
                    CREATE TABLE event_names (
                        event_name_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_name TEXT NOT NULL UNIQUE
                    )
                """)
                conn.execute("CREATE INDEX idx_event_names_name ON event_names(event_name)")

            # Create optimized runs table with integer primary key
            if 'runs' not in existing_tables:
                self.logger.info("Creating optimized runs table")
                conn.execute("""
                    CREATE TABLE runs (
                        run_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_id TEXT NOT NULL UNIQUE,
                        start_time INTEGER NOT NULL,
                        end_time INTEGER,
                        duration_realtime INTEGER,
                        duration_gametime INTEGER,
                        final_wave INTEGER,
                        coins_earned INTEGER,
                        CPH INTEGER,
                        round_cells INTEGER,
                        round_gems INTEGER,
                        round_cash INTEGER,
                        game_version TEXT,
                        tier INTEGER
                    )
                """)
                conn.execute("CREATE INDEX idx_runs_run_id ON runs(run_id)")
                conn.execute("CREATE INDEX idx_runs_start_time ON runs(start_time)")

            # Create optimized metrics table with foreign keys
            if 'metrics' not in existing_tables:
                self.logger.info("Creating optimized metrics table")
                conn.execute("""
                    CREATE TABLE metrics (
                        metric_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_fk INTEGER NOT NULL,
                        metric_name_fk INTEGER NOT NULL,
                        real_timestamp INTEGER NOT NULL,
                        game_timestamp INTEGER NOT NULL,
                        current_wave INTEGER NOT NULL,
                        metric_value INTEGER NOT NULL,
                        FOREIGN KEY (run_fk) REFERENCES runs(run_pk),
                        FOREIGN KEY (metric_name_fk) REFERENCES metric_names(metric_name_pk)
                    )
                """)
                conn.execute("""
                    CREATE INDEX idx_metrics_run_fk_time 
                    ON metrics(run_fk, real_timestamp)
                """)
                conn.execute("""
                    CREATE INDEX idx_metrics_name_fk_time 
                    ON metrics(metric_name_fk, real_timestamp)
                """)

            # Create optimized events table with foreign keys
            if 'events' not in existing_tables:
                self.logger.info("Creating optimized events table")
                conn.execute("""
                    CREATE TABLE events (
                        event_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_fk INTEGER NOT NULL,
                        event_name_fk INTEGER NOT NULL,
                        timestamp INTEGER NOT NULL,
                        data TEXT,
                        FOREIGN KEY (run_fk) REFERENCES runs(run_pk),
                        FOREIGN KEY (event_name_fk) REFERENCES event_names(event_name_pk)
                    )
                """)
                conn.execute("CREATE INDEX idx_events_run_fk ON events(run_fk)")
                conn.execute("CREATE INDEX idx_events_timestamp ON events(timestamp)")

            # Create logs table (unchanged)
            if 'logs' not in existing_tables:
                self.logger.info("Creating logs table")
                conn.execute("""
                    CREATE TABLE logs (
                        timestamp INTEGER, level TEXT, source TEXT, event TEXT, data TEXT
                    )
                """)
            
            # Create dashboards table (unchanged)
            if 'dashboards' not in existing_tables:
                self.logger.info("Creating dashboards table")
                conn.execute("""
                    CREATE TABLE dashboards (
                        id TEXT PRIMARY KEY,
                        uid TEXT UNIQUE NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        config TEXT NOT NULL,
                        tags TEXT,
                        created_at TEXT DEFAULT (datetime('now', 'localtime')),
                        updated_at TEXT DEFAULT (datetime('now', 'localtime')),
                        created_by TEXT DEFAULT 'system',
                        is_default BOOLEAN DEFAULT 0,
                        schema_version INTEGER DEFAULT 1
                    )
                """)
                conn.execute("CREATE INDEX idx_dashboards_uid ON dashboards(uid)")
                conn.execute("CREATE INDEX idx_dashboards_title ON dashboards(title)")
                conn.execute("CREATE INDEX idx_dashboards_created_at ON dashboards(created_at)")
            
            # Create optimized settings table
            if 'settings' not in existing_tables:
                self.logger.info("Creating optimized settings table")
                conn.execute("""
                    CREATE TABLE settings (
                        setting_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT NOT NULL UNIQUE,
                        value TEXT NOT NULL,
                        is_sensitive INTEGER DEFAULT 0,
                        created_at INTEGER DEFAULT (strftime('%s', 'now')),
                        updated_at INTEGER DEFAULT (strftime('%s', 'now'))
                    )
                """)
                conn.execute("CREATE INDEX idx_settings_key ON settings(key)")
            
            
            conn.commit()
            self.logger.info("Successfully created V4 optimized database schema.")
        except Exception as e:
            self.logger.error("Failed during V4 schema creation", error=str(e))
            try:
                conn.rollback()
            except Exception:
                pass
            raise

    def _create_schema_v5(self):
        """Creates the version 5 schema with db_metrics table for database health monitoring."""
        # First create all V4 tables
        self._create_schema_v4()
        
        if self.sqlite_conn is None:
            raise RuntimeError("Database connection is not established")
        conn = cast(sqlite3.Connection, self.sqlite_conn)
        try:
            # Check which tables already exist
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing_tables = {row[0] for row in cursor.fetchall()}
            
            self.logger.info("Checking existing tables for V5 schema", existing_tables=list(existing_tables))
            
            # Create db_metrics table for database health monitoring
            if 'db_metrics' not in existing_tables:
                self.logger.info("Creating db_metrics table")
                conn.execute("""
                    CREATE TABLE db_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp INTEGER NOT NULL,
                        metric_name TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        table_name TEXT,  -- For table-specific metrics
                        index_name TEXT   -- For index-specific metrics
                    )
                """)
                conn.execute("CREATE INDEX idx_db_metrics_timestamp ON db_metrics(timestamp)")
                conn.execute("CREATE INDEX idx_db_metrics_metric_name ON db_metrics(metric_name)")
            
            conn.commit()
            self.logger.info("Successfully created V5 database schema with db_metrics table.")
        except Exception as e:
            self.logger.error("Failed during V5 schema creation", error=str(e))
            try:
                conn.rollback()
            except Exception:
                pass
            raise

    def _create_schema_v6(self):
        """Creates the version 6 schema with normalized db_metrics table using lookup tables."""
        # First create all V5 tables
        self._create_schema_v5()
        
        if self.sqlite_conn is None:
            raise RuntimeError("Database connection is not established")
        conn = cast(sqlite3.Connection, self.sqlite_conn)
        try:
            # Check which tables already exist
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing_tables = {row[0] for row in cursor.fetchall()}
            
            self.logger.info("Checking existing tables for V6 schema", existing_tables=list(existing_tables))
            
            # Create db_metric_names lookup table
            if 'db_metric_names' not in existing_tables:
                self.logger.info("Creating db_metric_names lookup table")
                conn.execute("""
                    CREATE TABLE db_metric_names (
                        metric_name_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT NOT NULL UNIQUE,
                        metric_description TEXT
                    )
                """)
                conn.execute("CREATE UNIQUE INDEX idx_db_metric_names_name ON db_metric_names(metric_name)")
            
            # Create db_monitored_objects lookup table
            if 'db_monitored_objects' not in existing_tables:
                self.logger.info("Creating db_monitored_objects lookup table")
                conn.execute("""
                    CREATE TABLE db_monitored_objects (
                        object_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        object_name TEXT NOT NULL,
                        object_type TEXT NOT NULL CHECK(object_type IN ('TABLE', 'INDEX'))
                    )
                """)
                conn.execute("CREATE UNIQUE INDEX idx_db_monitored_objects_name_type ON db_monitored_objects(object_name, object_type)")
            
            # Check if we need to migrate existing db_metrics table
            if 'db_metrics' in existing_tables:
                # Check if the table is already normalized (has metric_name_id column)
                cursor.execute("PRAGMA table_info(db_metrics)")
                columns = [row[1] for row in cursor.fetchall()]
                
                if 'metric_name_id' not in columns:
                    self.logger.info("Migrating existing db_metrics table to normalized schema")
                    self._migrate_db_metrics_to_v6()
                else:
                    self.logger.info("db_metrics table already normalized")
            else:
                # Create new normalized db_metrics table
                self.logger.info("Creating new normalized db_metrics table")
                conn.execute("""
                    CREATE TABLE db_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp INTEGER NOT NULL,
                        metric_name_id INTEGER NOT NULL,
                        metric_value REAL NOT NULL,
                        object_id INTEGER,
                        FOREIGN KEY (metric_name_id) REFERENCES db_metric_names(metric_name_id),
                        FOREIGN KEY (object_id) REFERENCES db_monitored_objects(object_id)
                    )
                """)
                conn.execute("CREATE INDEX idx_db_metrics_timestamp ON db_metrics(timestamp)")
                conn.execute("CREATE INDEX idx_db_metrics_metric_name_id ON db_metrics(metric_name_id)")
                conn.execute("CREATE INDEX idx_db_metrics_object_id ON db_metrics(object_id)")
            
            conn.commit()
            self.logger.info("Successfully created V6 normalized database schema.")
        except Exception as e:
            self.logger.error("Failed during V6 schema creation", error=str(e))
            try:
                conn.rollback()
            except Exception:
                pass
            raise

    def _migrate_db_metrics_to_v6(self):
        """Migrates existing db_metrics table from V5 to V6 normalized schema."""
        if self.sqlite_conn is None:
            raise RuntimeError("Database connection is not established")
        
        conn = cast(sqlite3.Connection, self.sqlite_conn)
        cursor = conn.cursor()
        
        try:
            self.logger.info("Starting migration of db_metrics table to V6")
            
            # Step 1: Populate db_metric_names lookup table with existing metric names
            self.logger.info("Populating db_metric_names lookup table")
            cursor.execute("""
                INSERT OR IGNORE INTO db_metric_names (metric_name)
                SELECT DISTINCT metric_name FROM db_metrics
                WHERE metric_name IS NOT NULL
            """)
            
            # Step 2: Populate db_monitored_objects lookup table with existing table/index names
            self.logger.info("Populating db_monitored_objects lookup table")
            
            # Add tables
            cursor.execute("""
                INSERT OR IGNORE INTO db_monitored_objects (object_name, object_type)
                SELECT DISTINCT table_name, 'TABLE' FROM db_metrics
                WHERE table_name IS NOT NULL
            """)
            
            # Add indexes
            cursor.execute("""
                INSERT OR IGNORE INTO db_monitored_objects (object_name, object_type)
                SELECT DISTINCT index_name, 'INDEX' FROM db_metrics
                WHERE index_name IS NOT NULL
            """)
            
            # Step 3: Create new normalized db_metrics table
            self.logger.info("Creating new normalized db_metrics table")
            cursor.execute("ALTER TABLE db_metrics RENAME TO db_metrics_old")
            
            cursor.execute("""
                CREATE TABLE db_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    metric_name_id INTEGER NOT NULL,
                    metric_value REAL NOT NULL,
                    object_id INTEGER,
                    FOREIGN KEY (metric_name_id) REFERENCES db_metric_names(metric_name_id),
                    FOREIGN KEY (object_id) REFERENCES db_monitored_objects(object_id)
                )
            """)
            
            # Step 4: Migrate data from old table to new normalized structure
            self.logger.info("Migrating data to normalized structure")
            cursor.execute("""
                INSERT INTO db_metrics (id, timestamp, metric_name_id, metric_value, object_id)
                SELECT 
                    dm_old.id,
                    dm_old.timestamp,
                    dmn.metric_name_id,
                    dm_old.metric_value,
                    CASE 
                        WHEN dm_old.table_name IS NOT NULL THEN 
                            (SELECT object_id FROM db_monitored_objects 
                             WHERE object_name = dm_old.table_name AND object_type = 'TABLE')
                        WHEN dm_old.index_name IS NOT NULL THEN 
                            (SELECT object_id FROM db_monitored_objects 
                             WHERE object_name = dm_old.index_name AND object_type = 'INDEX')
                        ELSE NULL
                    END
                FROM db_metrics_old dm_old
                JOIN db_metric_names dmn ON dm_old.metric_name = dmn.metric_name
            """)
            
            # Step 5: Create indexes on new table (drop existing ones first if they exist)
            try:
                cursor.execute("DROP INDEX IF EXISTS idx_db_metrics_timestamp")
                cursor.execute("DROP INDEX IF EXISTS idx_db_metrics_metric_name")
                cursor.execute("DROP INDEX IF EXISTS idx_db_metrics_metric_name_id")
                cursor.execute("DROP INDEX IF EXISTS idx_db_metrics_object_id")
            except Exception:
                pass  # Indexes may not exist, continue
            
            cursor.execute("CREATE INDEX idx_db_metrics_timestamp ON db_metrics(timestamp)")
            cursor.execute("CREATE INDEX idx_db_metrics_metric_name_id ON db_metrics(metric_name_id)")
            cursor.execute("CREATE INDEX idx_db_metrics_object_id ON db_metrics(object_id)")
            
            # Step 6: Drop old table
            cursor.execute("DROP TABLE db_metrics_old")
            
            conn.commit()
            self.logger.info("Successfully migrated db_metrics table to V6 normalized schema")
            
        except Exception as e:
            self.logger.error("Failed to migrate db_metrics table to V6", error=str(e))
            conn.rollback()
            raise

    @db_operation()
    def _get_or_create_metric_name_id(self, metric_name: str, description: str = None) -> int:
        """Get or create a metric name ID in the db_metric_names lookup table."""
        if not self.sqlite_conn:
            return 0
        
        # Try to get existing ID
        cursor = self.sqlite_conn.execute(
            "SELECT metric_name_id FROM db_metric_names WHERE metric_name = ?", 
            (metric_name,)
        )
        result = cursor.fetchone()
        
        if result:
            return result[0]
        
        # Create new entry
        if description:
            cursor = self.sqlite_conn.execute(
                "INSERT INTO db_metric_names (metric_name, metric_description) VALUES (?, ?)", 
                (metric_name, description)
            )
        else:
            cursor = self.sqlite_conn.execute(
                "INSERT INTO db_metric_names (metric_name) VALUES (?)", 
                (metric_name,)
            )
        return cursor.lastrowid or 0

    @db_operation()
    def _get_or_create_monitored_object_id(self, object_name: str, object_type: str) -> int:
        """Get or create a monitored object ID in the db_monitored_objects lookup table."""
        if not self.sqlite_conn:
            return 0
        
        # Validate object_type
        if object_type not in ('TABLE', 'INDEX'):
            raise ValueError(f"Invalid object_type: {object_type}. Must be 'TABLE' or 'INDEX'")
        
        # Try to get existing ID
        cursor = self.sqlite_conn.execute(
            "SELECT object_id FROM db_monitored_objects WHERE object_name = ? AND object_type = ?", 
            (object_name, object_type)
        )
        result = cursor.fetchone()
        
        if result:
            return result[0]
        
        # Create new entry
        cursor = self.sqlite_conn.execute(
            "INSERT INTO db_monitored_objects (object_name, object_type) VALUES (?, ?)", 
            (object_name, object_type)
        )
        return cursor.lastrowid or 0

    @db_operation()
    def _get_or_create_event_name_id(self, event_name: str) -> int:
        """Get or create an event name ID in the lookup table."""
        if not self.sqlite_conn:
            return 0
        
        # Try to get existing ID
        cursor = self.sqlite_conn.execute(
            "SELECT event_name_pk FROM event_names WHERE event_name = ?", 
            (event_name,)
        )
        result = cursor.fetchone()
        
        if result:
            return result[0]
        
        # Create new entry
        cursor = self.sqlite_conn.execute(
            "INSERT INTO event_names (event_name) VALUES (?)", 
            (event_name,)
        )
        return cursor.lastrowid or 0

    @db_operation()
    def _get_run_pk_by_run_id(self, run_id: str) -> Optional[int]:
        """Get the run_pk for a given run_id."""
        if not self.sqlite_conn:
            return None
        
        cursor = self.sqlite_conn.execute(
            "SELECT run_pk FROM runs WHERE run_id = ?", 
            (run_id,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    @db_operation()
    def write_metric(self, run_id: str, real_timestamp: int, game_timestamp: float, current_wave: int, metrics: Dict[str, float]) -> None:
        """
        Insert new metric rows in optimized format using lookup tables and integer values.
        This method is now fully dynamic and requires no changes to add new metrics.
        """
        if not self.sqlite_conn:
            return
        
        # Get run_pk for the given run_id
        run_pk = self._get_run_pk_by_run_id(run_id)
        if run_pk is None:
            self.logger.error("Run not found for metric insertion", run_id=run_id)
            return
        
        metric_data = []
        for name, value in metrics.items():
            if value is not None:
                # Get or create metric name ID
                metric_name_id = self._get_or_create_metric_name_id(name)
                
                # Convert float values to integers (multiply by 1000 to preserve 3 decimal places)
                # This is a scaling factor - adjust as needed for your data precision requirements
                scaled_value = int(value * 1000) if isinstance(value, (int, float)) else int(value)
                
                metric_data.append((
                    run_pk,
                    metric_name_id,
                    int(real_timestamp),
                    int(game_timestamp * 1000),  # Convert to milliseconds
                    int(current_wave),
                    scaled_value
                ))

        if not metric_data:
            return

        sql = """
            INSERT INTO metrics 
            (run_fk, metric_name_fk, real_timestamp, game_timestamp, current_wave, metric_value) 
            VALUES (?, ?, ?, ?, ?, ?)
        """
        self.sqlite_conn.executemany(sql, metric_data)
        self.sqlite_conn.commit()
        self.logger.debug("Metrics inserted", run_id=run_id, count=len(metric_data))

    @db_operation(default_return_value=pd.DataFrame())
    def get_run_metrics(self, run_id: str, metric_name: str) -> pd.DataFrame:
        """
        Get all data points for a specific metric in a given run.
        This is now dynamic; any `metric_name` can be requested.
        """
        if not self.sqlite_conn:
            return pd.DataFrame()
        
        # Get the metric name ID
        metric_name_id = self._get_or_create_metric_name_id(metric_name)
        if metric_name_id == 0:
            return pd.DataFrame()
        
        query = """
            SELECT m.real_timestamp, m.metric_value 
            FROM metrics m
            JOIN runs r ON m.run_fk = r.run_pk
            WHERE r.run_id = ? AND m.metric_name_fk = ? 
            ORDER BY m.real_timestamp
        """
        df = pd.read_sql_query(query, self.sqlite_conn, params=[run_id, metric_name_id])
        
        # Convert scaled integer values back to floats
        if not df.empty:
            df['metric_value'] = df['metric_value'] / 1000.0
            df.rename(columns={'metric_value': metric_name}, inplace=True)
        
        return df

    @db_operation()
    def write_event(self, run_id: str, timestamp: int, event_name: str, data: Optional[dict] = None) -> None:
        """Insert a new event row using optimized schema."""
        if not self.sqlite_conn:
            return
        
        # Get run_pk for the given run_id
        run_pk = self._get_run_pk_by_run_id(run_id)
        if run_pk is None:
            self.logger.error("Run not found for event insertion", run_id=run_id)
            return
        
        # Get or create event name ID
        event_name_id = self._get_or_create_event_name_id(event_name)
        
        data_json = json.dumps(data if data is not None else {})
        self.sqlite_conn.execute(
            "INSERT INTO events (run_fk, event_name_fk, timestamp, data) VALUES (?, ?, ?, ?)",
            (run_pk, event_name_id, int(timestamp), data_json)
        )
        self.sqlite_conn.commit()
        self.logger.debug("Event inserted", run_id=run_id, event_name=event_name)

    @db_operation()
    def write_log_entry(self, log_entry: dict) -> None:
        """
        Write a log entry to the database.
        This is the target for the SQLiteLogHandler.
        Args:
            log_entry: Processed structlog dictionary
        """
        if not self.sqlite_conn:
            return
        timestamp = int(log_entry.get('timestamp', datetime.now().timestamp()))
        level = log_entry.get('level', 'INFO')
        source = log_entry.get('source', 'unknown')
        event = log_entry.get('event', 'unknown')
        data_dict = {k: v for k, v in log_entry.items() if k not in ['timestamp', 'level', 'source', 'event']}
        data_json = json.dumps(data_dict)
        self.sqlite_conn.execute(
            "INSERT INTO logs (timestamp, level, source, event, data) VALUES (?, ?, ?, ?, ?)",
            (timestamp, level, source, event, data_json)
        )
        self.sqlite_conn.commit()

    @db_operation(default_return_value=None)
    def get_setting(self, key: str) -> Optional[str]:
        """
        Get a setting value from the database.
        Args:
            key: Setting key
        Returns:
            Setting value or None if not found
        """
        if not self.sqlite_conn:
            return None
        cursor = self.sqlite_conn.execute(
            "SELECT value FROM settings WHERE key = ?",
            (key,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    @db_operation()
    def set_setting(self, key: str, value: str) -> None:
        """
        Set a setting value in the database.
        Args:
            key: Setting key
            value: Setting value
        """
        if not self.sqlite_conn:
            return
        
        # Check if setting exists
        cursor = self.sqlite_conn.execute("SELECT id FROM settings WHERE key = ?", (key,))
        existing_row = cursor.fetchone()
        
        if existing_row:
            # Update existing setting
            self.sqlite_conn.execute(
                "UPDATE settings SET value = ? WHERE key = ?",
                (value, key)
            )
        else:
            # Insert new setting
            self.sqlite_conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                (key, value)
            )
        
        self.sqlite_conn.commit()

    @db_operation()
    def set_setting_with_metadata(self, key: str, value: str, value_type: str = 'string', 
                                 description: Optional[str] = None, category: str = 'general', 
                                 is_sensitive: bool = False) -> None:
        """
        Set a setting value in the database with metadata.
        Args:
            key: Setting key
            value: Setting value
            value_type: Type of the value ('string', 'int', 'float', 'bool', 'json', 'yaml')
            description: Optional description of the setting
            category: Setting category
            is_sensitive: Whether this setting contains sensitive data
        """
        if not self.sqlite_conn:
            return
        
        # Check if we have the enhanced schema
        try:
            # Try to use the enhanced schema first
            # First check if the setting exists
            cursor = self.sqlite_conn.execute("SELECT id FROM settings WHERE key = ?", (key,))
            existing_row = cursor.fetchone()
            
            if existing_row:
                # Update existing setting
                self.sqlite_conn.execute(
                    """
                    UPDATE settings 
                    SET value = ?, value_type = ?, description = ?, category = ?, 
                        is_sensitive = ?, updated_at = (datetime('now', 'localtime'))
                    WHERE key = ?
                    """,
                    (value, value_type, description, category, is_sensitive, key)
                )
            else:
                # Insert new setting
                self.sqlite_conn.execute(
                    """
                    INSERT INTO settings 
                    (key, value, value_type, description, category, is_sensitive) 
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (key, value, value_type, description, category, is_sensitive)
                )
        except Exception:
            # Fallback to basic schema
            cursor = self.sqlite_conn.execute("SELECT id FROM settings WHERE key = ?", (key,))
            existing_row = cursor.fetchone()
            
            if existing_row:
                # Update existing setting
                self.sqlite_conn.execute(
                    "UPDATE settings SET value = ? WHERE key = ?",
                    (value, key)
                )
            else:
                # Insert new setting
                self.sqlite_conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)",
                    (key, value)
                )
        
        self.sqlite_conn.commit()
        self.logger.debug("Setting committed to database", key=key, value=value, db_path=self.db_path)

    @db_operation()
    def delete_setting(self, key: str) -> None:
        """
        Delete a setting from the database.
        Args:
            key: Setting key to delete
        """
        if not self.sqlite_conn:
            return
        self.sqlite_conn.execute("DELETE FROM settings WHERE key = ?", (key,))
        self.sqlite_conn.commit()

    @db_operation()
    def insert_run_start(self, run_id: str, start_time: int, game_version: Optional[str] = None, tier: Optional[int] = None) -> None:
        """
        Insert a new run record at the start of a round using optimized schema.
        New fields (CPH, round_cells, round_gems, round_cash) are initialized as NULL.
        """
        if not self.sqlite_conn:
            return
        self.sqlite_conn.execute(
            "INSERT OR IGNORE INTO runs (run_id, start_time, game_version, tier, CPH, round_cells, round_gems, round_cash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(run_id), int(start_time), str(game_version) if game_version is not None else None, int(tier) if tier is not None else None, None, None, None, None)
        )
        self.sqlite_conn.commit()
        self.logger.debug("Run start inserted", run_id=run_id, start_time=start_time)

    @db_operation()
    def update_run_end(self, run_id: str, end_time: int, final_wave: Optional[int] = None, coins_earned: Optional[float] = None, duration_realtime: Optional[int] = None, duration_gametime: Optional[float] = None, round_cells: Optional[float] = None, round_gems: Optional[float] = None, round_cash: Optional[float] = None) -> None:
        """
        Update an existing run record at the end of a round.
        duration_realtime is now stored in seconds (auto-converted if needed).
        CPH (coins per hour) is calculated as coins_earned / (duration_realtime in hours).
        round_cells, round_gems, and round_cash are stored as the final aggregate values for the round.
        Argument order: run_id, end_time, final_wave, coins_earned, duration_realtime, duration_gametime, round_cells, round_gems, round_cash
        """
        if not self.sqlite_conn:
            return
        # If duration_realtime is not provided, calculate from start_time
        if duration_realtime is None:
            cursor = self.sqlite_conn.execute(
                "SELECT start_time FROM runs WHERE run_id = ?",
                (str(run_id),)
            )
            row = cursor.fetchone()
            if not row:
                self.logger.error("No run found to update for gameOver", run_id=run_id)
                return
            start_time = row[0]
            duration_realtime = int(end_time) - int(start_time) if end_time is not None and start_time is not None else None
        # Convert duration_realtime from ms to seconds if it's > 10,000 (assume ms if so)
        if duration_realtime is not None and duration_realtime > 10000:
            duration_realtime = int(duration_realtime // 1000)
        # Calculate CPH (coins per hour) and convert to integer
        CPH = None
        if coins_earned is not None and duration_realtime and duration_realtime > 0:
            hours = duration_realtime / 3600.0
            if hours > 0:
                CPH = int((float(coins_earned) / hours) * 1000)  # Scale to preserve 3 decimal places
        
        self.sqlite_conn.execute(
            """
            UPDATE runs SET end_time = ?, final_wave = ?, coins_earned = ?, duration_realtime = ?, duration_gametime = ?, CPH = ?, round_cells = ?, round_gems = ?, round_cash = ?
            WHERE run_id = ?
            """,
            (
                int(end_time) if end_time is not None else None,
                int(final_wave) if final_wave is not None else None,
                int(coins_earned * 1000) if coins_earned is not None else None,  # Scale to preserve 3 decimal places
                int(duration_realtime) if duration_realtime is not None else None,
                int(duration_gametime * 1000) if duration_gametime is not None else None,  # Scale to preserve 3 decimal places
                CPH,  # Already converted to integer
                int(round_cells * 1000) if round_cells is not None else None,  # Scale to preserve 3 decimal places
                int(round_gems * 1000) if round_gems is not None else None,  # Scale to preserve 3 decimal places
                int(round_cash * 1000) if round_cash is not None else None,  # Scale to preserve 3 decimal places
                str(run_id)
            )
        )
        self.sqlite_conn.commit()
        self.logger.debug("Run end updated", run_id=run_id, end_time=end_time)

    @db_operation(default_return_value=pd.DataFrame())
    def get_recent_runs_for_histogram(self, limit: Optional[int] = None) -> pd.DataFrame:
        """
        Return a DataFrame with columns: tier, CPH, for the most recent N runs (by end_time DESC).
        If limit is None, return all runs.
        """
        if not self.sqlite_conn:
            return pd.DataFrame()
        query = "SELECT tier, CPH FROM runs WHERE CPH IS NOT NULL AND tier IS NOT NULL ORDER BY end_time DESC"
        if limit is not None:
            query += f" LIMIT {int(limit)}"
        df = pd.read_sql_query(query, self.sqlite_conn)
        return df

    @db_operation(default_return_value=pd.DataFrame())
    def get_all_runs(self, limit: Optional[int] = None) -> pd.DataFrame:
        """
        Return a DataFrame with all columns from the runs table, for the most recent N runs (by end_time DESC).
        If limit is None, return all runs.
        """
        if not self.sqlite_conn:
            return pd.DataFrame()
        query = "SELECT * FROM runs ORDER BY end_time DESC"
        if limit is not None:
            query += f" LIMIT {int(limit)}"
        df = pd.read_sql_query(query, self.sqlite_conn)
        return df

    @db_operation(default_return_value=None)
    def get_run_by_id(self, run_id: str) -> Optional[dict]:
        """
        Fetch a single run from the runs table by run_id.
        Returns a dict of the row if found, else None.
        """
        if not self.sqlite_conn:
            return None
        cursor = self.sqlite_conn.execute(
            "SELECT * FROM runs WHERE run_id = ?",
            (str(run_id),)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        # Get column names
        col_names = [desc[0] for desc in cursor.description]
        return dict(zip(col_names, row))

    @db_operation(default_return_value=pd.DataFrame())
    def get_wave_coins_per_wave(self, run_id: str) -> pd.DataFrame:
        if not self.sqlite_conn:
            return pd.DataFrame()
        query = '''
            SELECT current_wave, metric_value
            FROM metrics
            WHERE run_id = ? AND metric_name = 'wave_coins'
            ORDER BY current_wave
        '''
        return pd.read_sql_query(query, self.sqlite_conn, params=[run_id])

    @db_operation(default_return_value=pd.DataFrame())
    def get_total_gems_over_time(self, run_id: str) -> pd.DataFrame:
        """
        Returns a DataFrame with columns: real_timestamp, total_gems
        where total_gems is the sum of round_gems_from_blocks_value and round_gems_from_ads_value
        at each timestamp for the given run_id.
        """
        if not self.sqlite_conn:
            return pd.DataFrame()
        # Get all timestamps and values for both metrics
        query = '''
            SELECT real_timestamp, metric_name, metric_value
            FROM metrics
            WHERE run_id = ? AND (metric_name = 'round_gems_from_blocks_value' OR metric_name = 'round_gems_from_ads_value')
            ORDER BY real_timestamp
        '''
        df = pd.read_sql_query(query, self.sqlite_conn, params=[run_id])
        if df.empty:
            return pd.DataFrame({"real_timestamp": [], "total_gems": []})
        # Pivot to wide format: columns for each metric, fill missing with 0
        df_wide = df.pivot_table(index="real_timestamp", columns="metric_name", values="metric_value", fill_value=0)
        # Ensure both columns exist
        for col in ["round_gems_from_blocks_value", "round_gems_from_ads_value"]:
            if col not in df_wide:
                df_wide[col] = 0
        # Compute the sum at each timestamp (no cumsum)
        df_wide["total_gems"] = df_wide["round_gems_from_blocks_value"] + df_wide["round_gems_from_ads_value"]
        # Reset index to get real_timestamp as a column
        result = df_wide.reset_index()[["real_timestamp", "total_gems"]]
        return pd.DataFrame(result)

    @db_operation(default_return_value={})
    def get_final_round_totals(self, run_id: str) -> Dict[str, Optional[float]]:
        """
        Compute final aggregate values for a run from the metrics table.
        Returns a dict with keys: round_cells, round_gems, round_cash.
        """
        if not self.sqlite_conn:
            return {}

        try:
            # Get the last value for each metric of interest
            metrics_of_interest = [
                'round_cells',
                'round_cash',
                'round_gems_from_blocks_value',
                'round_gems_from_ads_value',
            ]
            placeholders = ','.join(['?'] * len(metrics_of_interest))
            query = f"""
                SELECT metric_name, metric_value
                FROM (
                    SELECT metric_name, metric_value, real_timestamp,
                           ROW_NUMBER() OVER (PARTITION BY metric_name ORDER BY real_timestamp DESC) as rn
                    FROM metrics
                    WHERE run_id = ? AND metric_name IN ({placeholders})
                )
                WHERE rn = 1
            """
            params = [str(run_id)] + metrics_of_interest
            cursor = self.sqlite_conn.execute(query, params)
            latest_values: Dict[str, float] = {}
            for name, value in cursor.fetchall():
                latest_values[name] = float(value)

            round_cells = latest_values.get('round_cells')
            round_cash = latest_values.get('round_cash')
            # Sum value-based gem metrics to get a total gem value for the round
            round_gems_blocks = latest_values.get('round_gems_from_blocks_value')
            round_gems_ads = latest_values.get('round_gems_from_ads_value')
            round_gems = None
            if round_gems_blocks is not None or round_gems_ads is not None:
                round_gems = (round_gems_blocks or 0.0) + (round_gems_ads or 0.0)

            return {
                'round_cells': float(round_cells) if round_cells is not None else None,
                'round_gems': float(round_gems) if round_gems is not None else None,
                'round_cash': float(round_cash) if round_cash is not None else None,
            }
        except Exception as e:
            self.logger.error("Failed computing final round totals", run_id=run_id, error=str(e))
            return {}

    @db_operation(default_return_value=[])
    def get_all_run_ids(self):
        """Return a list of all run_ids in the runs table, ordered by start_time."""
        if self.sqlite_conn is None:
            return []
        conn = self.sqlite_conn
        cursor = conn.cursor()
        cursor.execute("SELECT run_id FROM runs ORDER BY start_time ASC")
        rows = cursor.fetchall()
        return [row[0] for row in rows]

    @db_operation(default_return_value=None)
    def get_all_metrics_for_run(self, run_id):
        """Return a DataFrame of all metrics for a run, ordered by game_timestamp or real_timestamp."""
        if self.sqlite_conn is None:
            import pandas as pd
            return pd.DataFrame()
        conn = self.sqlite_conn
        query = "SELECT * FROM metrics WHERE run_id = ? ORDER BY game_timestamp ASC, real_timestamp ASC"
        import pandas as pd
        df = pd.read_sql_query(query, conn, params=[run_id])
        return df

    @db_operation(default_return_value=[])
    def get_all_settings(self) -> list[dict[str, Any]]:
        """Gets all key-value pairs from the settings table."""
        if not self.sqlite_conn:
            return []
        
        try:
            # Try to use enhanced schema first
            cursor = self.sqlite_conn.execute("""
                SELECT key, value, value_type, description, category, is_sensitive, 
                       created_at, updated_at, created_by, version 
                FROM settings
            """)
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
            return [dict(zip(columns, row)) for row in rows]
        except Exception:
            # Fallback to basic schema
            cursor = self.sqlite_conn.execute("SELECT key, value FROM settings")
            rows = cursor.fetchall()
            return [{'key': row[0], 'value': row[1]} for row in rows]

    # ============================================================================
    # BULK INSERT METHODS FOR PERFORMANCE OPTIMIZATION
    # ============================================================================
    
    @db_operation()
    def bulk_insert_runs(self, runs_data: List[Dict[str, Any]]) -> None:
        """
        Bulk insert run records for better performance.
        Each run_data dict should contain: run_id, start_time, game_version, tier
        """
        if not self.sqlite_conn or not runs_data:
            return
        
        # Prepare data for bulk insert
        run_records = []
        for run_data in runs_data:
            run_records.append((
                str(run_data['run_id']),
                int(run_data['start_time']),
                str(run_data.get('game_version', '')),
                int(run_data.get('tier', 0)) if run_data.get('tier') is not None else None,
                None,  # CPH
                None,  # round_cells
                None,  # round_gems
                None   # round_cash
            ))
        
        sql = """
            INSERT OR IGNORE INTO runs 
            (run_id, start_time, game_version, tier, CPH, round_cells, round_gems, round_cash) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.sqlite_conn.executemany(sql, run_records)
        self.logger.debug("Bulk inserted runs", count=len(run_records))
    
    @db_operation()
    def bulk_insert_events(self, events_data: List[Dict[str, Any]]) -> None:
        """
        Bulk insert event records for better performance using optimized schema.
        Each event_data dict should contain: run_id, timestamp, event_name, data
        """
        if not self.sqlite_conn or not events_data:
            return
        
        # Prepare data for bulk insert using optimized schema
        event_records = []
        for event_data in events_data:
            # Get run_pk for foreign key reference
            run_pk = self._get_run_pk_by_run_id(event_data['run_id'])
            if run_pk is None:
                self.logger.error("Run not found for event insertion", run_id=event_data['run_id'])
                continue
            
            # Get or create event name ID
            event_name_id = self._get_or_create_event_name_id(event_data['event_name'])
            
            data_json = json.dumps(event_data.get('data', {}))
            event_records.append((
                run_pk,
                event_name_id,
                int(event_data['timestamp']),
                data_json
            ))
        
        if event_records:
            sql = """
                INSERT INTO events (run_fk, event_name_fk, timestamp, data) 
                VALUES (?, ?, ?, ?)
            """
            self.sqlite_conn.executemany(sql, event_records)
            self.logger.debug("Bulk inserted events", count=len(event_records))
    
    @db_operation()
    def bulk_insert_metrics(self, metrics_data: List[Dict[str, Any]]) -> None:
        """
        Bulk insert metric records for better performance using optimized schema.
        Each metric_data dict should contain: run_id, real_timestamp, game_timestamp, current_wave, metrics
        """
        if not self.sqlite_conn or not metrics_data:
            return
        
        # Prepare data for bulk insert - flatten metrics into individual rows using optimized schema
        metric_records = []
        for metric_data in metrics_data:
            # Get run_pk for foreign key reference
            run_pk = self._get_run_pk_by_run_id(metric_data['run_id'])
            if run_pk is None:
                self.logger.error("Run not found for metric insertion", run_id=metric_data['run_id'])
                continue
            
            real_timestamp = int(metric_data['real_timestamp'])
            game_timestamp = int(metric_data['game_timestamp'] * 1000)  # Convert to milliseconds
            current_wave = int(metric_data['current_wave'])
            metrics = metric_data['metrics']
            
            for name, value in metrics.items():
                if value is not None:
                    # Get or create metric name ID
                    metric_name_id = self._get_or_create_metric_name_id(name)
                    
                    # Convert float values to integers (scale by 1000 to preserve 3 decimal places)
                    scaled_value = int(value * 1000) if isinstance(value, (int, float)) else int(value)
                    
                    metric_records.append((
                        run_pk,
                        metric_name_id,
                        real_timestamp,
                        game_timestamp,
                        current_wave,
                        scaled_value
                    ))
        
        if not metric_records:
            return
        
        sql = """
            INSERT INTO metrics 
            (run_fk, metric_name_fk, real_timestamp, game_timestamp, current_wave, metric_value) 
            VALUES (?, ?, ?, ?, ?, ?)
        """
        self.sqlite_conn.executemany(sql, metric_records)
        self.logger.debug("Bulk inserted metrics", count=len(metric_records))
    
    @db_operation()
    def bulk_update_runs_end(self, runs_end_data: List[Dict[str, Any]]) -> None:
        """
        Bulk update run records with end data for better performance.
        Each run_end_data dict should contain: run_id, end_time, final_wave, coins_earned, 
        duration_realtime, duration_gametime, round_cells, round_gems, round_cash
        """
        if not self.sqlite_conn or not runs_end_data:
            return
        
        # Prepare data for bulk update
        run_updates = []
        for run_data in runs_end_data:
            # Calculate CPH if we have coins_earned and duration_realtime
            CPH = None
            coins_earned = run_data.get('coins_earned')
            duration_realtime = run_data.get('duration_realtime')
            
            if coins_earned is not None and duration_realtime and duration_realtime > 0:
                # Convert duration_realtime from ms to seconds if needed
                if duration_realtime > 10000:
                    duration_realtime = duration_realtime // 1000
                hours = duration_realtime / 3600.0
                if hours > 0:
                    CPH = int((float(coins_earned) / hours) * 1000)  # Scale to preserve 3 decimal places
            
            run_updates.append((
                int(run_data.get('end_time', 0)) if run_data.get('end_time') is not None else None,
                int(run_data.get('final_wave', 0)) if run_data.get('final_wave') is not None else None,
                int(coins_earned * 1000) if coins_earned is not None else None,  # Scale to preserve 3 decimal places
                int(duration_realtime) if duration_realtime is not None else None,
                int(run_data.get('duration_gametime', 0) * 1000) if run_data.get('duration_gametime') is not None else None,  # Scale to preserve 3 decimal places
                CPH,  # Already converted to integer
                int(run_data.get('round_cells', 0) * 1000) if run_data.get('round_cells') is not None else None,  # Scale to preserve 3 decimal places
                int(run_data.get('round_gems', 0) * 1000) if run_data.get('round_gems') is not None else None,  # Scale to preserve 3 decimal places
                int(run_data.get('round_cash', 0) * 1000) if run_data.get('round_cash') is not None else None,  # Scale to preserve 3 decimal places
                str(run_data['run_id'])
            ))
        
        sql = """
            UPDATE runs SET 
                end_time = ?, final_wave = ?, coins_earned = ?, duration_realtime = ?, 
                duration_gametime = ?, CPH = ?, round_cells = ?, round_gems = ?, round_cash = ?
            WHERE run_id = ?
        """
        self.sqlite_conn.executemany(sql, run_updates)
        self.logger.debug("Bulk updated runs end", count=len(run_updates))
    
    @db_operation()
    def bulk_write_run_data(self, run_data: Dict[str, Any]) -> None:
        """
        Write a complete run's data (start, events, metrics, end) in a single transaction using optimized schema.
        This is the most efficient way to write a single run's data.
        """
        if not self.sqlite_conn:
            return
        
        try:
            # Start transaction
            self.sqlite_conn.execute("BEGIN TRANSACTION")
            
            # Insert run start
            self.sqlite_conn.execute(
                "INSERT OR IGNORE INTO runs (run_id, start_time, game_version, tier, CPH, round_cells, round_gems, round_cash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(run_data['run_id']),
                    int(run_data['start_time']),
                    str(run_data.get('game_version', '')),
                    int(run_data.get('tier', 0)) if run_data.get('tier') is not None else None,
                    None, None, None, None
                )
            )
            
            # Get run_pk for foreign key references
            run_pk = self._get_run_pk_by_run_id(run_data['run_id'])
            if run_pk is None:
                raise Exception(f"Failed to get run_pk for run_id: {run_data['run_id']}")
            
            # Insert events using optimized schema
            if run_data.get('events'):
                event_records = []
                for event in run_data['events']:
                    data_json = json.dumps(event.get('data', {}))
                    event_name_id = self._get_or_create_event_name_id(event['event_name'])
                    event_records.append((
                        run_pk,
                        event_name_id,
                        int(event['timestamp']),
                        data_json
                    ))
                
                if event_records:
                    self.sqlite_conn.executemany(
                        "INSERT INTO events (run_fk, event_name_fk, timestamp, data) VALUES (?, ?, ?, ?)",
                        event_records
                    )
            
            # Insert metrics using optimized schema
            if run_data.get('metrics'):
                metric_records = []
                for metric in run_data['metrics']:
                    real_timestamp = int(metric['real_timestamp'])
                    game_timestamp = int(metric['game_timestamp'] * 1000)  # Convert to milliseconds
                    current_wave = int(metric['current_wave'])
                    metrics_dict = metric['metrics']
                    
                    for name, value in metrics_dict.items():
                        if value is not None:
                            metric_name_id = self._get_or_create_metric_name_id(name)
                            scaled_value = int(value * 1000) if isinstance(value, (int, float)) else int(value)
                            metric_records.append((
                                run_pk, metric_name_id, real_timestamp, game_timestamp, current_wave, scaled_value
                            ))
                
                if metric_records:
                    self.sqlite_conn.executemany(
                        "INSERT INTO metrics (run_fk, metric_name_fk, real_timestamp, game_timestamp, current_wave, metric_value) VALUES (?, ?, ?, ?, ?, ?)",
                        metric_records
                    )
            
            # Update run end with integer values
            CPH = None
            coins_earned = run_data.get('coins_earned')
            duration_realtime = run_data.get('duration_realtime')
            
            if coins_earned is not None and duration_realtime and duration_realtime > 0:
                if duration_realtime > 10000:
                    duration_realtime = duration_realtime // 1000
                hours = duration_realtime / 3600.0
                if hours > 0:
                    CPH = int((float(coins_earned) / hours) * 1000)  # Scale to preserve 3 decimal places
            
            self.sqlite_conn.execute(
                """
                UPDATE runs SET 
                    end_time = ?, final_wave = ?, coins_earned = ?, duration_realtime = ?, 
                    duration_gametime = ?, CPH = ?, round_cells = ?, round_gems = ?, round_cash = ?
                WHERE run_id = ?
                """,
                (
                    int(run_data.get('end_time', 0)) if run_data.get('end_time') is not None else None,
                    int(run_data.get('final_wave', 0)) if run_data.get('final_wave') is not None else None,
                    int(coins_earned * 1000) if coins_earned is not None else None,  # Scale to preserve 3 decimal places
                    int(duration_realtime) if duration_realtime is not None else None,
                    int(run_data.get('duration_gametime', 0) * 1000) if run_data.get('duration_gametime') is not None else None,  # Scale to preserve 3 decimal places
                    CPH,  # Already converted to integer
                    int(run_data.get('round_cells', 0) * 1000) if run_data.get('round_cells') is not None else None,  # Scale to preserve 3 decimal places
                    int(run_data.get('round_gems', 0) * 1000) if run_data.get('round_gems') is not None else None,  # Scale to preserve 3 decimal places
                    int(run_data.get('round_cash', 0) * 1000) if run_data.get('round_cash') is not None else None,  # Scale to preserve 3 decimal places
                    str(run_data['run_id'])
                )
            )
            
            # Commit transaction
            self.sqlite_conn.commit()
            self.logger.debug("Bulk wrote run data", run_id=run_data['run_id'])
            
        except Exception as e:
            # Rollback on error
            self.sqlite_conn.rollback()
            self.logger.error("Failed to bulk write run data", run_id=run_data.get('run_id'), error=str(e))
            raise

    @db_operation(default_return_value={})
    def get_database_statistics(self) -> dict:
        """
        Collects comprehensive database statistics including file metrics and table row counts.
        Returns a dictionary with database and file information.
        """
        stats = {
            'file_path': self.db_path,
            'file_size': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0,
            'wal_file_size': os.path.getsize(f"{self.db_path}-wal") if os.path.exists(f"{self.db_path}-wal") else 0,
            'created_date': datetime.fromtimestamp(os.path.getctime(self.db_path)).isoformat() if os.path.exists(self.db_path) else None,
            'modified_date': datetime.fromtimestamp(os.path.getmtime(self.db_path)).isoformat() if os.path.exists(self.db_path) else None,
            'sqlite_version': sqlite3.sqlite_version,
            'schema_version': self.get_setting('db_version'),
            'last_backup_date': self.get_setting('last_backup_timestamp'),
            'connection_status': 'Connected' if self.sqlite_conn else 'Disconnected',
            'total_rows': 0,  # To be calculated below
            'table_rows': {
                'runs': 0,
                'metrics': 0,
                'events': 0,
                'logs': 0,
            }
        }

        # Query row counts for each table
        if self.sqlite_conn:
            cursor = self.sqlite_conn.cursor()
            total_rows = 0
            for table in stats['table_rows']:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    stats['table_rows'][table] = count
                    total_rows += count
                except sqlite3.OperationalError:
                    # Table might not exist, which is fine
                    stats['table_rows'][table] = 'N/A'

            stats['total_rows'] = total_rows
        
        return stats

    @db_operation()
    def collect_and_store_db_metrics(self) -> bool:
        """
        Collects comprehensive database metrics and stores them in the normalized db_metrics table.
        This includes database-level metrics (size, pages, fragmentation) and 
        table-level metrics (record counts).
        
        Returns:
            bool: True if metrics collection was successful, False otherwise
        """
        if not self.sqlite_conn:
            self.logger.error("Cannot collect metrics: database connection not available")
            return False
        
        try:
            cursor = self.sqlite_conn.cursor()
            current_timestamp = int(datetime.now().timestamp())
            
            # List to store all metrics for bulk insert (timestamp, metric_name_id, metric_value, object_id)
            metrics_to_insert = []
            
            # Collect database-level metrics using PRAGMA statements
            self.logger.info("Collecting database-level metrics")
            
            # Get page count and page size
            page_count = cursor.execute("PRAGMA page_count").fetchone()[0]
            page_size = cursor.execute("PRAGMA page_size").fetchone()[0]
            freelist_count = cursor.execute("PRAGMA freelist_count").fetchone()[0]
            
            # Calculate database size
            database_size = page_count * page_size
            
            # Get or create metric name IDs for database-level metrics
            total_pages_id = self._get_or_create_metric_name_id('total_pages', 'Total number of pages in the database')
            page_size_id = self._get_or_create_metric_name_id('page_size', 'Database page size in bytes')
            database_size_id = self._get_or_create_metric_name_id('database_size', 'Total database size in bytes')
            free_pages_id = self._get_or_create_metric_name_id('free_pages', 'Number of free pages in the database')
            
            # Add database-level metrics (no object_id for database-level metrics)
            metrics_to_insert.extend([
                (current_timestamp, total_pages_id, page_count, None),
                (current_timestamp, page_size_id, page_size, None),
                (current_timestamp, database_size_id, database_size, None),
                (current_timestamp, free_pages_id, freelist_count, None)
            ])
            
            self.logger.info("Collected database metrics", 
                           total_pages=page_count, 
                           page_size=page_size, 
                           database_size=database_size, 
                           free_pages=freelist_count)
            
            # Collect table-level metrics (record counts and sizes)
            self.logger.info("Collecting table-level metrics")
            
            # Get or create metric name IDs for table-level metrics
            record_count_id = self._get_or_create_metric_name_id('record_count', 'Number of records in the table')
            table_size_bytes_id = self._get_or_create_metric_name_id('table_size_bytes', 'Table size in bytes')
            
            # Get list of all user tables (excluding SQLite system tables)
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                try:
                    # Get or create object ID for this table
                    table_object_id = self._get_or_create_monitored_object_id(table, 'TABLE')
                    
                    # Get record count
                    record_count = cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    metrics_to_insert.append(
                        (current_timestamp, record_count_id, record_count, table_object_id)
                    )
                    
                    # Get table size in bytes using multiple methods
                    try:
                        table_size_bytes = None
                        
                        # Method 1: Try dbstat virtual table (most accurate)
                        try:
                            table_size_result = cursor.execute(
                                "SELECT SUM(pgsize) FROM dbstat WHERE name = ?", (table,)
                            ).fetchone()
                            
                            if table_size_result and table_size_result[0] is not None:
                                table_size_bytes = table_size_result[0]
                                self.logger.debug("Got table size from dbstat", 
                                                table=table, size_bytes=table_size_bytes)
                        except Exception:
                            # dbstat not available, continue to other methods
                            pass
                        
                        # Method 2: Use ANALYZE and sqlite_stat1 if available
                        if table_size_bytes is None:
                            try:
                                # Run ANALYZE on the table to populate statistics
                                cursor.execute(f"ANALYZE {table}")
                                
                                # Try to get page count from sqlite_stat1
                                stat_result = cursor.execute(
                                    "SELECT stat FROM sqlite_stat1 WHERE tbl = ?", (table,)
                                ).fetchone()
                                
                                if stat_result:
                                    # Parse the stat string (format: "nrow ncol ...")
                                    stat_parts = stat_result[0].split()
                                    if len(stat_parts) >= 2:
                                        nrow = int(stat_parts[0])
                                        # Estimate bytes per row based on table structure
                                        table_info = cursor.execute(f"PRAGMA table_info({table})").fetchall()
                                        estimated_bytes_per_row = len(table_info) * 20  # Rough estimate
                                        table_size_bytes = nrow * estimated_bytes_per_row
                                        self.logger.debug("Got table size from sqlite_stat1", 
                                                        table=table, size_bytes=table_size_bytes)
                            except Exception:
                                pass
                        
                        # Method 3: Fallback estimation based on record count and table structure
                        if table_size_bytes is None:
                            # Get table structure to make a better estimation
                            try:
                                table_info = cursor.execute(f"PRAGMA table_info({table})").fetchall()
                                column_count = len(table_info)
                                
                                # Estimate bytes per row based on column types and count
                                estimated_bytes_per_row = 50  # Base overhead
                                for col_info in table_info:
                                    col_type = col_info[2].upper() if col_info[2] else 'TEXT'
                                    if 'INT' in col_type:
                                        estimated_bytes_per_row += 8
                                    elif 'REAL' in col_type or 'FLOAT' in col_type:
                                        estimated_bytes_per_row += 8
                                    elif 'TEXT' in col_type:
                                        estimated_bytes_per_row += 50  # Average text size
                                    elif 'BLOB' in col_type:
                                        estimated_bytes_per_row += 100  # Average blob size
                                    else:
                                        estimated_bytes_per_row += 20  # Default
                                
                                table_size_bytes = record_count * estimated_bytes_per_row
                                self.logger.debug("Using structure-based table size estimation", 
                                                table=table, 
                                                columns=column_count,
                                                bytes_per_row=estimated_bytes_per_row,
                                                size_bytes=table_size_bytes)
                            except Exception:
                                # Final fallback: simple estimation
                                table_size_bytes = record_count * 100
                                self.logger.debug("Using simple table size estimation", 
                                                table=table, size_bytes=table_size_bytes)
                        
                        metrics_to_insert.append(
                            (current_timestamp, table_size_bytes_id, table_size_bytes, table_object_id)
                        )
                        
                        self.logger.debug("Collected table metrics", 
                                        table=table, 
                                        record_count=record_count,
                                        size_bytes=table_size_bytes)
                        
                    except Exception as size_e:
                        # If we can't get size, use simple estimation
                        self.logger.warning("Failed to get table size, using simple estimation", 
                                          table=table, error=str(size_e))
                        estimated_size = record_count * 100
                        metrics_to_insert.append(
                            (current_timestamp, table_size_bytes_id, estimated_size, table_object_id)
                        )
                        
                except Exception as e:
                    self.logger.warning("Failed to get table metrics", 
                                      table=table, error=str(e))
                    continue
            
            # Collect index-level metrics (index count)
            self.logger.info("Collecting index-level metrics")
            cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
            index_count = cursor.fetchone()[0]
            
            # Get or create metric name ID for index count
            index_count_id = self._get_or_create_metric_name_id('index_count', 'Total number of user indexes')
            metrics_to_insert.append(
                (current_timestamp, index_count_id, index_count, None)
            )
            
            # Bulk insert all metrics using normalized schema
            self.logger.info("Storing metrics to database", metric_count=len(metrics_to_insert))
            cursor.executemany("""
                INSERT INTO db_metrics (timestamp, metric_name_id, metric_value, object_id)
                VALUES (?, ?, ?, ?)
            """, metrics_to_insert)
            
            self.sqlite_conn.commit()
            self.logger.info("Successfully collected and stored database metrics", 
                           metrics_collected=len(metrics_to_insert))
            return True
            
        except Exception as e:
            self.logger.error("Failed to collect database metrics", error=str(e))
            try:
                self.sqlite_conn.rollback()
            except Exception:
                pass
            return False

    @db_operation(default_return_value=[])
    def validate_database(self, perform_fixes: bool = False) -> List[Dict[str, Any]]:
        """
        Validates the database integrity and optionally performs fixes.
        
        Args:
            perform_fixes: If True, attempts to fix issues found
            
        Returns:
            List of validation results with status and description
        """
        results = []
        
        if not self.sqlite_conn:
            results.append({
                'status': 'error',
                'message': 'Database connection not available'
            })
            return results
        
        try:
            # Check database integrity
            cursor = self.sqlite_conn.cursor()
            cursor.execute("PRAGMA integrity_check;")
            integrity_result = cursor.fetchone()[0]
            
            if integrity_result == "ok":
                results.append({
                    'status': 'success',
                    'message': 'Database integrity check passed'
                })
            else:
                results.append({
                    'status': 'error',
                    'message': f'Database integrity check failed: {integrity_result}'
                })
                
                if perform_fixes:
                    # Try to recover from integrity issues
                    try:
                        cursor.execute("VACUUM;")
                        results.append({
                            'status': 'info',
                            'message': 'Attempted database recovery with VACUUM'
                        })
                    except Exception as e:
                        results.append({
                            'status': 'error',
                            'message': f'Failed to recover database: {str(e)}'
                        })
            
            # Check for orphaned records
            orphaned_metrics = cursor.execute(
                "SELECT COUNT(*) FROM metrics WHERE run_id NOT IN (SELECT run_id FROM runs)"
            ).fetchone()[0]
            
            if orphaned_metrics > 0:
                results.append({
                    'status': 'warning',
                    'message': f'Found {orphaned_metrics} orphaned metric records'
                })
                
                if perform_fixes:
                    try:
                        cursor.execute("DELETE FROM metrics WHERE run_id NOT IN (SELECT run_id FROM runs)")
                        results.append({
                            'status': 'info',
                            'message': f'Removed {orphaned_metrics} orphaned metric records'
                        })
                    except Exception as e:
                        results.append({
                            'status': 'error',
                            'message': f'Failed to remove orphaned records: {str(e)}'
                        })
            
            # Check WAL file size
            wal_path = f"{self.db_path}-wal"
            if os.path.exists(wal_path):
                wal_size = os.path.getsize(wal_path)
                if wal_size > 10 * 1024 * 1024:  # 10MB
                    results.append({
                        'status': 'warning',
                        'message': f'WAL file is large ({wal_size / 1024 / 1024:.1f}MB)'
                    })
                    
                    if perform_fixes:
                        try:
                            cursor.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                            results.append({
                                'status': 'info',
                                'message': 'Truncated WAL file'
                            })
                        except Exception as e:
                            results.append({
                                'status': 'error',
                                'message': f'Failed to truncate WAL: {str(e)}'
                            })
            
            # Check for missing indexes
            cursor.execute("PRAGMA index_list(metrics);")
            indexes = [row[1] for row in cursor.fetchall()]
            
            if 'idx_metrics_run_id' not in indexes:
                results.append({
                    'status': 'warning',
                    'message': 'Missing index on metrics.run_id'
                })
                
                if perform_fixes:
                    try:
                        cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_run_id ON metrics(run_id);")
                        results.append({
                            'status': 'info',
                            'message': 'Created missing index on metrics.run_id'
                        })
                    except Exception as e:
                        results.append({
                            'status': 'error',
                            'message': f'Failed to create index: {str(e)}'
                        })
            
            # Check for settings with incorrect value types
            # Use ConfigurationManager's detection if available
            if hasattr(self, 'config') and self.config:
                value_type_issues = self.config.get_value_type_issues()
                if value_type_issues:
                    results.append({
                        'status': 'warning',
                        'message': f'Found {len(value_type_issues)} settings with incorrect value types'
                    })
                    
                    if perform_fixes:
                        self.config.fix_incorrect_value_types()
                        results.append({
                            'status': 'info',
                            'message': f'Fixed {len(value_type_issues)} settings with incorrect value types'
                        })
            else:
                # Fallback to direct database check if no config manager
                settings_with_incorrect_types = self._check_settings_value_types()
                if settings_with_incorrect_types:
                    results.append({
                        'status': 'warning',
                        'message': f'Found {len(settings_with_incorrect_types)} settings with incorrect value types'
                    })
                    
                    if perform_fixes:
                        fixed_count = self._fix_settings_value_types(settings_with_incorrect_types)
                        results.append({
                            'status': 'info',
                            'message': f'Fixed {fixed_count} settings with incorrect value types'
                        })
            
        except Exception as e:
            results.append({
                'status': 'error',
                'message': f'Database validation failed: {str(e)}'
            })
        
        return results

    @db_operation(default_return_value=False)
    def backup_database(self, backup_path: Optional[str] = None) -> bool:
        """
        Creates a backup of the database.
        
        Args:
            backup_path: Optional path for the backup file. If None, uses default location.
            
        Returns:
            True if backup was successful, False otherwise
        """
        if not self.sqlite_conn:
            return False
        
        try:
            # Determine backup directory and filename
            if backup_path is None:
                configured_dir = self.config.get('database.backup.backup_dir', None) if hasattr(self, 'config') else None
                backup_dir = Path(configured_dir) if configured_dir else (Path(self.db_path).parent / "backups")
                backup_dir.mkdir(parents=True, exist_ok=True)
                prefix = self.config.get('database.backup.filename_prefix', 'toweriq_backup_') if hasattr(self, 'config') else 'toweriq_backup_'
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = str(backup_dir / f"{prefix}{timestamp}.sqlite")
            
            # Create backup using SQLite backup API
            backup_conn = sqlite3.connect(backup_path)
            self.sqlite_conn.backup(backup_conn)
            backup_conn.close()
            
            # Optional compression
            compress_zip = self.config.get('database.backup.compress_zip', True) if hasattr(self, 'config') else True
            zip_path = None
            if compress_zip:
                try:
                    import zipfile
                    zip_path = f"{backup_path}.zip"
                    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                        zf.write(backup_path, arcname=Path(backup_path).name)
                    # Keep both by default; we could delete the .sqlite if desired
                except Exception as zip_err:
                    self.logger.warning("Backup compression failed", error=str(zip_err))

            # Rotate backups according to retention
            try:
                retention = int(self.config.get('database.backup.retention_count', 7)) if hasattr(self, 'config') else 7
                backup_dir_final = Path(backup_path).parent
                prefix = self.config.get('database.backup.filename_prefix', 'toweriq_backup_') if hasattr(self, 'config') else 'toweriq_backup_'
                # Collect .sqlite and .sqlite.zip that match prefix
                candidates = sorted(
                    [p for p in backup_dir_final.glob(f"{prefix}*.sqlite*")],
                    key=lambda p: p.stat().st_mtime,
                    reverse=True
                )
                for old in candidates[retention:]:
                    try:
                        old.unlink()
                        self.logger.debug("Removed old backup", file=str(old))
                    except Exception as rm_err:
                        self.logger.warning("Failed to remove old backup", file=str(old), error=str(rm_err))
            except Exception as rot_err:
                self.logger.warning("Backup rotation failed", error=str(rot_err))

            # Update last backup timestamp
            self.set_setting('last_backup_timestamp', datetime.now().isoformat())
            
            self.logger.info("Database backup created successfully", backup_path=str(backup_path))
            return True
            
        except Exception as e:
            self.logger.error("Database backup failed", error=str(e))
            return False

    def restore_database(self, backup_path: str) -> bool:
        """
        Restore the main SQLite database from a backup file.
        Supports raw .sqlite files and .zip archives created by backup_database.

        Returns True on success.
        """
        try:
            if not backup_path or not os.path.exists(backup_path):
                self.logger.error("Backup file not found", backup_path=str(backup_path))
                return False

            # Close current connection to release file handles
            try:
                self.close()
            except Exception:
                pass

            target_path = Path(self.db_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Determine source db file
            source_db_path: Optional[Path] = None
            temp_file: Optional[Path] = None
            try:
                if backup_path.lower().endswith('.zip'):
                    with zipfile.ZipFile(backup_path, 'r') as zf:
                        # Pick first .sqlite entry
                        entry = next((i for i in zf.infolist() if i.filename.lower().endswith('.sqlite')), None)
                        if not entry:
                            self.logger.error("No .sqlite file found in zip", backup_path=backup_path)
                            return False
                        tmp_dir = Path(tempfile.mkdtemp(prefix='toweriq_restore_'))
                        zf.extract(entry, path=tmp_dir)
                        temp_file = tmp_dir / entry.filename
                        source_db_path = temp_file
                else:
                    source_db_path = Path(backup_path)

                if not source_db_path or not source_db_path.exists():
                    self.logger.error("Resolved backup source not found", source=str(source_db_path))
                    return False

                # Backup existing db if present
                if target_path.exists():
                    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                    bak_path = target_path.with_suffix(f'.pre_restore_{ts}.sqlite.bak')
                    try:
                        shutil.copy2(str(target_path), str(bak_path))
                        self.logger.info("Backed up existing database before restore", backup=str(bak_path))
                    except Exception as copy_err:
                        self.logger.warning("Failed to backup existing database before restore", error=str(copy_err))

                # Copy source over target
                shutil.copy2(str(source_db_path), str(target_path))

            finally:
                # Cleanup temp extracted file/folder
                try:
                    if temp_file is not None and temp_file.exists():
                        try:
                            os.remove(str(temp_file))
                        except Exception:
                            pass
                        # remove parent temp dir
                        try:
                            parent_dir = temp_file.parent
                            # attempt to remove entire temp dir tree
                            shutil.rmtree(parent_dir, ignore_errors=True)
                        except Exception:
                            pass
                except Exception:
                    pass

            # Reconnect
            self.connect()
            self.set_setting('last_restore_timestamp', datetime.now().isoformat())
            self.logger.info("Database restored successfully", from_backup=backup_path, target=str(target_path))
            return True
        except Exception as e:
            self.logger.error("Database restore failed", error=str(e), backup_path=str(backup_path))
            return False

    def _check_settings_value_types(self) -> List[Dict[str, Any]]:
        """
        Check for settings that have incorrect value types in the database.
        
        Returns:
            List of settings with incorrect value types
        """
        incorrect_settings = []
        
        if not self.sqlite_conn:
            return incorrect_settings
        
        try:
            # Get all settings from database
            settings_list = self.get_all_settings()
            if not settings_list:
                return incorrect_settings
            
            for setting in settings_list:
                key = setting['key']
                value = setting['value']
                value_type = setting.get('value_type', 'string')
                
                # Check if this is a boolean value stored with wrong type
                if isinstance(value, str) and value.lower() in ('true', 'false', '1', '0'):
                    if value_type != 'bool':
                        incorrect_settings.append({
                            'key': key,
                            'value': value,
                            'current_type': value_type,
                            'correct_type': 'bool'
                        })
                
                # Check for other type mismatches
                elif value_type == 'int':
                    try:
                        int(value)
                    except (ValueError, TypeError):
                        incorrect_settings.append({
                            'key': key,
                            'value': value,
                            'current_type': value_type,
                            'correct_type': 'string'
                        })
                
                elif value_type == 'float':
                    try:
                        float(value)
                    except (ValueError, TypeError):
                        incorrect_settings.append({
                            'key': key,
                            'value': value,
                            'current_type': value_type,
                            'correct_type': 'string'
                        })
                
                elif value_type == 'json':
                    try:
                        json.loads(value)
                    except (ValueError, json.JSONDecodeError):
                        incorrect_settings.append({
                            'key': key,
                            'value': value,
                            'current_type': value_type,
                            'correct_type': 'string'
                        })
        
        except Exception as e:
            self.logger.error("Error checking settings value types", error=str(e))
        
        return incorrect_settings

    def _fix_settings_value_types(self, incorrect_settings: List[Dict[str, Any]]) -> int:
        """
        Fix settings that have incorrect value types in the database.
        
        Args:
            incorrect_settings: List of settings with incorrect value types
            
        Returns:
            Number of settings that were fixed
        """
        fixed_count = 0
        
        if not self.sqlite_conn:
            return fixed_count
        
        try:
            for setting in incorrect_settings:
                key = setting['key']
                value = setting['value']
                correct_type = setting['correct_type']
                
                # Convert value to correct type
                if correct_type == 'bool':
                    corrected_value = value.lower() in ('true', '1')
                elif correct_type == 'int':
                    corrected_value = int(value)
                elif correct_type == 'float':
                    corrected_value = float(value)
                elif correct_type == 'string':
                    corrected_value = str(value)
                else:
                    corrected_value = value
                
                # Update the setting with correct type
                self.set_setting_with_metadata(
                    key=key,
                    value=str(corrected_value),
                    value_type=correct_type,
                    description=setting.get('description', f"Fixed value type for {key}")
                )
                
                self.logger.info("Fixed setting value type", 
                               key=key, 
                               old_type=setting['current_type'], 
                               new_type=correct_type)
                fixed_count += 1
        
        except Exception as e:
            self.logger.error("Error fixing settings value types", error=str(e))
        
        return fixed_count

    # Dashboard Operations
    @db_operation([])
    def get_all_dashboards(self) -> List[Dict[str, Any]]:
        """Get all dashboards from the database."""
        if not self.sqlite_conn:
            return []
        
        try:
            cursor = self.sqlite_conn.execute("""
                SELECT id, uid, title, description, config, tags, created_at, updated_at, created_by, is_default, schema_version
                FROM dashboards
                ORDER BY created_at DESC
            """)
            
            dashboards = []
            for row in cursor.fetchall():
                dashboard = {
                    'id': row[0],
                    'uid': row[1],
                    'title': row[2],
                    'description': row[3],
                    'config': json.loads(row[4]) if row[4] else {},
                    'tags': json.loads(row[5]) if row[5] else [],
                    'created_at': row[6],
                    'updated_at': row[7],
                    'created_by': row[8],
                    'is_default': bool(row[9]),
                    'schema_version': row[10]
                }
                dashboards.append(dashboard)
            
            return dashboards
        except Exception as e:
            self.logger.error("Error getting all dashboards", error=str(e))
            return []

    @db_operation(None)
    def get_dashboard_by_id(self, dashboard_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific dashboard by ID."""
        if not self.sqlite_conn:
            return None
        
        try:
            cursor = self.sqlite_conn.execute("""
                SELECT id, uid, title, description, config, tags, created_at, updated_at, created_by, is_default, schema_version
                FROM dashboards
                WHERE id = ?
            """, (dashboard_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'uid': row[1],
                    'title': row[2],
                    'description': row[3],
                    'config': json.loads(row[4]) if row[4] else {},
                    'tags': json.loads(row[5]) if row[5] else [],
                    'created_at': row[6],
                    'updated_at': row[7],
                    'created_by': row[8],
                    'is_default': bool(row[9]),
                    'schema_version': row[10]
                }
            return None
        except Exception as e:
            self.logger.error("Error getting dashboard by ID", error=str(e), dashboard_id=dashboard_id)
            return None

    @db_operation(None)
    def get_dashboard_by_uid(self, uid: str) -> Optional[Dict[str, Any]]:
        """Get a specific dashboard by UID."""
        if not self.sqlite_conn:
            return None
        
        try:
            cursor = self.sqlite_conn.execute("""
                SELECT id, uid, title, description, config, tags, created_at, updated_at, created_by, is_default, schema_version
                FROM dashboards
                WHERE uid = ?
            """, (uid,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'uid': row[1],
                    'title': row[2],
                    'description': row[3],
                    'config': json.loads(row[4]) if row[4] else {},
                    'tags': json.loads(row[5]) if row[5] else [],
                    'created_at': row[6],
                    'updated_at': row[7],
                    'created_by': row[8],
                    'is_default': bool(row[9]),
                    'schema_version': row[10]
                }
            return None
        except Exception as e:
            self.logger.error("Error getting dashboard by UID", error=str(e), uid=uid)
            return None

    @db_operation(False)
    def create_dashboard(self, dashboard_data: Dict[str, Any]) -> bool:
        """Create a new dashboard."""
        if not self.sqlite_conn:
            return False
        
        try:
            # Ensure required fields
            required_fields = ['id', 'uid', 'title', 'config']
            for field in required_fields:
                if field not in dashboard_data:
                    self.logger.error("Missing required field for dashboard creation", field=field)
                    return False
            
            self.sqlite_conn.execute("""
                INSERT INTO dashboards 
                (id, uid, title, description, config, tags, created_at, updated_at, created_by, is_default, schema_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                dashboard_data['id'],
                dashboard_data['uid'],
                dashboard_data['title'],
                dashboard_data.get('description', ''),
                json.dumps(dashboard_data['config']),
                json.dumps(dashboard_data.get('tags', [])),
                dashboard_data.get('created_at', datetime.now().isoformat()),
                dashboard_data.get('updated_at', datetime.now().isoformat()),
                dashboard_data.get('created_by', 'system'),
                dashboard_data.get('is_default', False),
                dashboard_data.get('schema_version', 1)
            ))
            
            self.sqlite_conn.commit()
            self.logger.info("Dashboard created successfully", dashboard_id=dashboard_data['id'])
            return True
        except Exception as e:
            self.logger.error("Error creating dashboard", error=str(e), dashboard_data=dashboard_data)
            return False

    @db_operation(False)
    def update_dashboard(self, dashboard_id: str, dashboard_data: Dict[str, Any]) -> bool:
        """Update an existing dashboard."""
        if not self.sqlite_conn:
            return False
        
        try:
            # Check if dashboard exists
            existing = self.get_dashboard_by_id(dashboard_id)
            if not existing:
                self.logger.error("Dashboard not found for update", dashboard_id=dashboard_id)
                return False
            
            # Update fields
            update_fields = []
            params = []
            
            if 'title' in dashboard_data:
                update_fields.append("title = ?")
                params.append(dashboard_data['title'])
            
            if 'description' in dashboard_data:
                update_fields.append("description = ?")
                params.append(dashboard_data['description'])
            
            if 'config' in dashboard_data:
                update_fields.append("config = ?")
                params.append(json.dumps(dashboard_data['config']))
            
            if 'tags' in dashboard_data:
                update_fields.append("tags = ?")
                params.append(json.dumps(dashboard_data['tags']))
            
            if 'is_default' in dashboard_data:
                update_fields.append("is_default = ?")
                params.append(dashboard_data['is_default'])
            
            # Always update the updated_at timestamp
            update_fields.append("updated_at = ?")
            params.append(datetime.now().isoformat())
            
            if update_fields:
                params.append(dashboard_id)
                query = f"UPDATE dashboards SET {', '.join(update_fields)} WHERE id = ?"
                self.sqlite_conn.execute(query, params)
                self.sqlite_conn.commit()
                
                self.logger.info("Dashboard updated successfully", dashboard_id=dashboard_id)
                return True
            
            return False
        except Exception as e:
            self.logger.error("Error updating dashboard", error=str(e), dashboard_id=dashboard_id)
            return False

    @db_operation(False)
    def delete_dashboard(self, dashboard_id: str) -> bool:
        """Delete a dashboard."""
        if not self.sqlite_conn:
            return False
        
        try:
            # Check if dashboard exists
            existing = self.get_dashboard_by_id(dashboard_id)
            if not existing:
                self.logger.error("Dashboard not found for deletion", dashboard_id=dashboard_id)
                return False
            
            self.sqlite_conn.execute("DELETE FROM dashboards WHERE id = ?", (dashboard_id,))
            self.sqlite_conn.commit()
            
            self.logger.info("Dashboard deleted successfully", dashboard_id=dashboard_id)
            return True
        except Exception as e:
            self.logger.error("Error deleting dashboard", error=str(e), dashboard_id=dashboard_id)
            return False

    @db_operation(False)
    def set_default_dashboard(self, dashboard_id: str) -> bool:
        """Set a dashboard as the default dashboard."""
        if not self.sqlite_conn:
            return False
        
        try:
            # First, unset all other dashboards as default
            self.sqlite_conn.execute("UPDATE dashboards SET is_default = 0")
            
            # Set the specified dashboard as default
            self.sqlite_conn.execute("UPDATE dashboards SET is_default = 1 WHERE id = ?", (dashboard_id,))
            self.sqlite_conn.commit()
            
            self.logger.info("Default dashboard set successfully", dashboard_id=dashboard_id)
            return True
        except Exception as e:
            self.logger.error("Error setting default dashboard", error=str(e), dashboard_id=dashboard_id)
            return False

    @db_operation(None)
    def get_default_dashboard(self) -> Optional[Dict[str, Any]]:
        """Get the default dashboard."""
        if not self.sqlite_conn:
            return None
        
        try:
            cursor = self.sqlite_conn.execute("""
                SELECT id, uid, title, description, config, tags, created_at, updated_at, created_by, is_default, schema_version
                FROM dashboards
                WHERE is_default = 1
                LIMIT 1
            """)
            
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'uid': row[1],
                    'title': row[2],
                    'description': row[3],
                    'config': json.loads(row[4]) if row[4] else {},
                    'tags': json.loads(row[5]) if row[5] else [],
                    'created_at': row[6],
                    'updated_at': row[7],
                    'created_by': row[8],
                    'is_default': bool(row[9]),
                    'schema_version': row[10]
                }
            return None
        except Exception as e:
            self.logger.error("Error getting default dashboard", error=str(e))
            return None

    def create_default_dashboards(self) -> None:
        """Create default dashboards if none exist."""
        if not self.sqlite_conn:
            return
        
        try:
            # Check if any dashboards exist
            cursor = self.sqlite_conn.execute("SELECT COUNT(*) FROM dashboards")
            count = cursor.fetchone()[0]
            
            if count > 0:
                self.logger.info("Dashboards already exist, skipping default creation")
                return
            
            self.logger.info("Creating default dashboards")
            
            # Default System Overview Dashboard
            system_overview_config = {
                "panels": [
                    {
                        "id": "panel-1",
                        "type": "stat",
                        "title": "System Health",
                        "gridPos": {"x": 0, "y": 0, "w": 4, "h": 2},
                        "query": "SELECT COUNT(*) AS value FROM metrics WHERE metric_name = 'system_health'",
                        "echartsOption": {
                            "tooltip": {"show": False},
                            "graphic": [{
                                "type": "text",
                                "left": "center",
                                "top": "center",
                                "style": {
                                    "text": "",
                                    "fontSize": 24,
                                    "fontWeight": "bold",
                                    "fill": "#333"
                                }
                            }]
                        }
                    },
                    {
                        "id": "panel-2",
                        "type": "timeseries",
                        "title": "Performance Metrics",
                        "gridPos": {"x": 4, "y": 0, "w": 4, "h": 2},
                        "query": "SELECT real_timestamp as timestamp, metric_value as value, metric_name FROM metrics WHERE metric_name IN ('cpu_usage', 'memory_usage') ORDER BY real_timestamp",
                        "echartsOption": {
                            "title": {"text": "Performance Metrics", "left": "center"},
                            "tooltip": {"trigger": "axis"},
                            "legend": {"data": ["CPU Usage", "Memory Usage"], "bottom": 10},
                            "xAxis": {"type": "time"},
                            "yAxis": {"type": "value", "name": "Usage %"},
                            "series": []
                        }
                    },
                    {
                        "id": "panel-3",
                        "type": "table",
                        "title": "Recent Events",
                        "gridPos": {"x": 8, "y": 0, "w": 4, "h": 2},
                        "query": "SELECT timestamp, event_name, data FROM events ORDER BY timestamp DESC LIMIT 10",
                        "echartsOption": {
                            "title": {"text": "Recent Events", "left": "center"},
                            "tooltip": {"show": True},
                            "grid": {"containLabel": True},
                            "dataZoom": {"type": "inside"},
                            "series": [{
                                "type": "custom",
                                "renderItem": "table"
                            }]
                        }
                    }
                ],
                "refresh": "30s",
                "time": {
                    "from": "now-1h",
                    "to": "now"
                }
            }
            
            self.create_dashboard({
                'id': 'system-overview',
                'uid': 'system-overview-001',
                'title': 'System Overview',
                'description': 'Main dashboard showing system health and key metrics',
                'config': system_overview_config,
                'tags': ['system', 'overview', 'health'],
                'is_default': True
            })
            
            # Performance Analytics Dashboard
            performance_config = {
                "panels": [
                    {
                        "id": "panel-1",
                        "type": "timeseries",
                        "title": "CPU Usage Over Time",
                        "gridPos": {"x": 0, "y": 0, "w": 6, "h": 3},
                        "query": "SELECT real_timestamp as timestamp, metric_value as value FROM metrics WHERE metric_name = 'cpu_usage' ORDER BY real_timestamp",
                        "echartsOption": {
                            "title": {"text": "CPU Usage Over Time", "left": "center"},
                            "tooltip": {"trigger": "axis"},
                            "xAxis": {"type": "time"},
                            "yAxis": {"type": "value", "name": "CPU %", "max": 100},
                            "series": [{
                                "name": "CPU Usage",
                                "type": "line",
                                "smooth": True,
                                "lineStyle": {"width": 3},
                                "areaStyle": {"opacity": 0.1},
                                "data": []
                            }]
                        }
                    },
                    {
                        "id": "panel-2",
                        "type": "timeseries",
                        "title": "Memory Usage Over Time",
                        "gridPos": {"x": 6, "y": 0, "w": 6, "h": 3},
                        "query": "SELECT real_timestamp as timestamp, metric_value as value FROM metrics WHERE metric_name = 'memory_usage' ORDER BY real_timestamp",
                        "echartsOption": {
                            "title": {"text": "Memory Usage Over Time", "left": "center"},
                            "tooltip": {"trigger": "axis"},
                            "xAxis": {"type": "time"},
                            "yAxis": {"type": "value", "name": "Memory %", "max": 100},
                            "series": [{
                                "name": "Memory Usage",
                                "type": "line",
                                "smooth": True,
                                "lineStyle": {"width": 3},
                                "areaStyle": {"opacity": 0.1},
                                "data": []
                            }]
                        }
                    },
                    {
                        "id": "panel-3",
                        "type": "stat",
                        "title": "Average Response Time",
                        "gridPos": {"x": 0, "y": 3, "w": 4, "h": 2},
                        "query": "SELECT AVG(metric_value) AS value FROM metrics WHERE metric_name = 'response_time'",
                        "echartsOption": {
                            "tooltip": {"show": False},
                            "graphic": [{
                                "type": "text",
                                "left": "center",
                                "top": "center",
                                "style": {
                                    "text": "",
                                    "fontSize": 24,
                                    "fontWeight": "bold",
                                    "fill": "#2196F3"
                                }
                            }, {
                                "type": "text",
                                "left": "center",
                                "top": "bottom",
                                "style": {
                                    "text": "ms",
                                    "fontSize": 14,
                                    "fill": "#666"
                                }
                            }]
                        }
                    },
                    {
                        "id": "panel-4",
                        "type": "stat",
                        "title": "Error Rate",
                        "gridPos": {"x": 4, "y": 3, "w": 4, "h": 2},
                        "query": "SELECT COUNT(*) AS value FROM events WHERE event_name = 'error'",
                        "echartsOption": {
                            "tooltip": {"show": False},
                            "graphic": [{
                                "type": "text",
                                "left": "center",
                                "top": "center",
                                "style": {
                                    "text": "",
                                    "fontSize": 24,
                                    "fontWeight": "bold",
                                    "fill": "#F44336"
                                }
                            }, {
                                "type": "text",
                                "left": "center",
                                "top": "bottom",
                                "style": {
                                    "text": "errors/min",
                                    "fontSize": 14,
                                    "fill": "#666"
                                }
                            }]
                        }
                    },
                    {
                        "id": "panel-5",
                        "type": "table",
                        "title": "Performance Alerts",
                        "gridPos": {"x": 8, "y": 3, "w": 4, "h": 2},
                        "query": "SELECT timestamp, event_name, data FROM events WHERE event_name LIKE '%alert%' ORDER BY timestamp DESC LIMIT 5",
                        "echartsOption": {
                            "title": {"text": "Performance Alerts", "left": "center"},
                            "tooltip": {"show": True},
                            "grid": {"containLabel": True},
                            "series": [{
                                "type": "custom",
                                "renderItem": "table"
                            }]
                        }
                    }
                ],
                "refresh": "15s",
                "time": {
                    "from": "now-6h",
                    "to": "now"
                }
            }
            
            self.create_dashboard({
                'id': 'performance-analytics',
                'uid': 'performance-analytics-001',
                'title': 'Performance Analytics',
                'description': 'Detailed performance metrics and analysis',
                'config': performance_config,
                'tags': ['performance', 'analytics', 'metrics']
            })
            
            # Network Monitoring Dashboard
            network_config = {
                "panels": [
                    {
                        "id": "panel-1",
                        "type": "stat",
                        "title": "Network Status",
                        "gridPos": {"x": 0, "y": 0, "w": 3, "h": 2},
                        "options": {
                            "query": "SELECT status FROM network_status WHERE id = 1",
                            "unit": "status"
                        }
                    },
                    {
                        "id": "panel-2",
                        "type": "timeseries",
                        "title": "Network Traffic",
                        "gridPos": {"x": 3, "y": 0, "w": 6, "h": 2},
                        "options": {
                            "query": "SELECT * FROM metrics WHERE metric_name IN ('bytes_in', 'bytes_out')",
                            "lineWidth": 2
                        }
                    },
                    {
                        "id": "panel-3",
                        "type": "stat",
                        "title": "Active Connections",
                        "gridPos": {"x": 9, "y": 0, "w": 3, "h": 2},
                        "options": {
                            "query": "SELECT COUNT(*) FROM active_connections",
                            "unit": "connections"
                        }
                    },
                    {
                        "id": "panel-4",
                        "type": "table",
                        "title": "Network Events",
                        "gridPos": {"x": 0, "y": 2, "w": 12, "h": 3},
                        "options": {
                            "query": "SELECT * FROM events WHERE event_name LIKE '%network%' ORDER BY timestamp DESC LIMIT 10"
                        }
                    }
                ],
                "refresh": "10s",
                "time": {
                    "from": "now-30m",
                    "to": "now"
                }
            }
            
            self.create_dashboard({
                'id': 'network-monitoring',
                'uid': 'network-monitoring-001',
                'title': 'Network Monitoring',
                'description': 'Real-time network status and connectivity',
                'config': network_config,
                'tags': ['network', 'monitoring', 'connectivity']
            })
            
            self.logger.info("Default dashboards created successfully")
            
        except Exception as e:
            self.logger.error("Error creating default dashboards", error=str(e))

    def ensure_dashboards_table_exists(self) -> bool:
        """Ensure the dashboards table exists, create it if it doesn't."""
        if not self.sqlite_conn:
            return False
        
        try:
            # Check if dashboards table exists
            cursor = self.sqlite_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='dashboards'")
            table_exists = cursor.fetchone() is not None
            
            if not table_exists:
                self.logger.info("Creating dashboards table")
                self.sqlite_conn.execute("""
                    CREATE TABLE dashboards (
                        id TEXT PRIMARY KEY,
                        uid TEXT UNIQUE NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        config TEXT NOT NULL,
                        tags TEXT,
                        created_at TEXT DEFAULT (datetime('now', 'localtime')),
                        updated_at TEXT DEFAULT (datetime('now', 'localtime')),
                        created_by TEXT DEFAULT 'system',
                        is_default BOOLEAN DEFAULT 0,
                        schema_version INTEGER DEFAULT 1
                    )
                """)
                self.sqlite_conn.execute("CREATE INDEX idx_dashboards_uid ON dashboards(uid)")
                self.sqlite_conn.execute("CREATE INDEX idx_dashboards_title ON dashboards(title)")
                self.sqlite_conn.execute("CREATE INDEX idx_dashboards_created_at ON dashboards(created_at)")
                self.sqlite_conn.commit()
                self.logger.info("Dashboards table created successfully")
                return True
            else:
                self.logger.info("Dashboards table already exists")
                return True
                
        except Exception as e:
            self.logger.error("Error ensuring dashboards table exists", error=str(e))
            return False