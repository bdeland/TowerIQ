"""
TowerIQ Database Management Service

This module provides the DatabaseService class for managing the SQLite database
used by the embedded application architecture.
"""

import json
import sqlite3
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
    
    DB_VERSION = "2" # Using a "long" schema for metrics
    
    def __init__(self, config: ConfigurationManager, logger: Any, db_path: str = '') -> None:
        """
        Initialize the database service.
        Args:
            config: ConfigurationManager instance
            logger: Logger instance for this service
            db_path: Optional override for the database file path
        """
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