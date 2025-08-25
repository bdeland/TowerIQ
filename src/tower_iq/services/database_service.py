"""
TowerIQ Database Management Service

This module provides the DatabaseService class for managing the SQLite database
used by the embedded application architecture.
"""

import json
import sqlite3
import os
from typing import Any, Optional, Dict, List, cast
from pathlib import Path
from datetime import datetime
import pandas as pd
import functools

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
    
    DB_VERSION = "3" # Updated to include dashboards table
    
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
            
            # Enable WAL mode for better concurrency
            self.sqlite_conn.execute("PRAGMA journal_mode=WAL;")
            
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
        
        # For this major change, we will create the new V2 schema.
        # A more advanced system would have sequential migration scripts (e.g., migrate_v1_to_v2).
        self._create_schema_v2()

        self.set_setting("db_version", self.DB_VERSION)
        self.logger.info("Database migration to version %s completed.", self.DB_VERSION)
        
        # Create default dashboards after schema is ready
        self.create_default_dashboards()

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

    @db_operation()
    def write_metric(self, run_id: str, real_timestamp: int, game_timestamp: float, current_wave: int, metrics: Dict[str, float]) -> None:
        """
        Insert new metric rows in 'long' format.
        This method is now fully dynamic and requires no changes to add new metrics.
        """
        if not self.sqlite_conn:
            return
        metric_data = [
            (
                str(run_id),
                int(real_timestamp),
                float(game_timestamp),
                int(current_wave),
                str(name),
                float(value)
            )
            for name, value in metrics.items() if value is not None
        ]

        if not metric_data:
            return

        sql = """
            INSERT INTO metrics 
            (run_id, real_timestamp, game_timestamp, current_wave, metric_name, metric_value) 
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
        query = """
            SELECT real_timestamp, metric_value 
            FROM metrics 
            WHERE run_id = ? AND metric_name = ? 
            ORDER BY real_timestamp
        """
        df = pd.read_sql_query(query, self.sqlite_conn, params=(run_id, metric_name))
        df.rename(columns={'metric_value': metric_name}, inplace=True)
        return df

    @db_operation()
    def write_event(self, run_id: str, timestamp: int, event_name: str, data: Optional[dict] = None) -> None:
        """Insert a new event row."""
        if not self.sqlite_conn:
            return
        data_json = json.dumps(data if data is not None else {})
        self.sqlite_conn.execute(
            "INSERT INTO events (run_id, timestamp, event_name, data) VALUES (?, ?, ?, ?)",
            (str(run_id), int(timestamp), str(event_name), data_json)
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
        Insert a new run record at the start of a round.
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
        # Calculate CPH (coins per hour)
        CPH = None
        if coins_earned is not None and duration_realtime and duration_realtime > 0:
            hours = duration_realtime / 3600.0
            if hours > 0:
                CPH = float(coins_earned) / hours
        self.sqlite_conn.execute(
            """
            UPDATE runs SET end_time = ?, final_wave = ?, coins_earned = ?, duration_realtime = ?, duration_gametime = ?, CPH = ?, round_cells = ?, round_gems = ?, round_cash = ?
            WHERE run_id = ?
            """,
            (
                int(end_time) if end_time is not None else None,
                int(final_wave) if final_wave is not None else None,
                float(coins_earned) if coins_earned is not None else None,
                int(duration_realtime) if duration_realtime is not None else None,
                float(duration_gametime) if duration_gametime is not None else None,
                float(CPH) if CPH is not None else None,
                float(round_cells) if round_cells is not None else None,
                float(round_gems) if round_gems is not None else None,
                float(round_cash) if round_cash is not None else None,
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
        return pd.read_sql_query(query, self.sqlite_conn, params=(run_id,))

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
        df = pd.read_sql_query(query, self.sqlite_conn, params=(run_id,))
        if df.empty:
            return pd.DataFrame(columns=["real_timestamp", "total_gems"])
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
        return result

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
        df = pd.read_sql_query(query, conn, params=(run_id,))
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
            if backup_path is None:
                # Create backup in data/backups directory
                backup_dir = Path(self.db_path).parent / "backups"
                backup_dir.mkdir(exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = str(backup_dir / f"toweriq_backup_{timestamp}.sqlite")
            
            # Create backup using SQLite backup API
            backup_conn = sqlite3.connect(backup_path)
            self.sqlite_conn.backup(backup_conn)
            backup_conn.close()
            
            # Update last backup timestamp
            self.set_setting('last_backup_timestamp', datetime.now().isoformat())
            
            self.logger.info("Database backup created successfully", backup_path=str(backup_path))
            return True
            
        except Exception as e:
            self.logger.error("Database backup failed", error=str(e))
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
            # Generate UID if not provided
            if 'uid' not in dashboard_data:
                import uuid
                dashboard_data['uid'] = str(uuid.uuid4())
            
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
                        "options": {
                            "query": "SELECT COUNT(*) FROM metrics WHERE metric_name = 'system_health'",
                            "unit": "status"
                        }
                    },
                    {
                        "id": "panel-2",
                        "type": "timeseries",
                        "title": "Performance Metrics",
                        "gridPos": {"x": 4, "y": 0, "w": 4, "h": 2},
                        "options": {
                            "query": "SELECT * FROM metrics WHERE metric_name IN ('cpu_usage', 'memory_usage')",
                            "lineWidth": 2
                        }
                    },
                    {
                        "id": "panel-3",
                        "type": "table",
                        "title": "Recent Events",
                        "gridPos": {"x": 8, "y": 0, "w": 4, "h": 2},
                        "options": {
                            "query": "SELECT * FROM events ORDER BY timestamp DESC LIMIT 10"
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
                        "options": {
                            "query": "SELECT * FROM metrics WHERE metric_name = 'cpu_usage'",
                            "lineWidth": 3,
                            "fillOpacity": 0.1
                        }
                    },
                    {
                        "id": "panel-2",
                        "type": "timeseries",
                        "title": "Memory Usage Over Time",
                        "gridPos": {"x": 6, "y": 0, "w": 6, "h": 3},
                        "options": {
                            "query": "SELECT * FROM metrics WHERE metric_name = 'memory_usage'",
                            "lineWidth": 3,
                            "fillOpacity": 0.1
                        }
                    },
                    {
                        "id": "panel-3",
                        "type": "stat",
                        "title": "Average Response Time",
                        "gridPos": {"x": 0, "y": 3, "w": 4, "h": 2},
                        "options": {
                            "query": "SELECT AVG(metric_value) FROM metrics WHERE metric_name = 'response_time'",
                            "unit": "ms"
                        }
                    },
                    {
                        "id": "panel-4",
                        "type": "stat",
                        "title": "Error Rate",
                        "gridPos": {"x": 4, "y": 3, "w": 4, "h": 2},
                        "options": {
                            "query": "SELECT COUNT(*) FROM events WHERE event_name = 'error'",
                            "unit": "errors/min"
                        }
                    },
                    {
                        "id": "panel-5",
                        "type": "table",
                        "title": "Performance Alerts",
                        "gridPos": {"x": 8, "y": 3, "w": 4, "h": 2},
                        "options": {
                            "query": "SELECT * FROM events WHERE event_name LIKE '%alert%' ORDER BY timestamp DESC LIMIT 5"
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