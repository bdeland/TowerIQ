"""
TowerIQ Database Management Service

This module provides the DatabaseService class for managing the SQLite database
used by the embedded application architecture.
"""

import json
import sqlite3
from typing import Any, Optional, Dict, List
from pathlib import Path
from datetime import datetime
import pandas as pd

from ..core.config import ConfigurationManager


class DatabaseService:
    """
    Service for managing SQLite database operations.
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
        
        # SQLite configuration
        self.db_path = config.get('database.sqlite_path', 'data/toweriq.sqlite')
        
        # Database connection
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
        Create database tables if they don't exist, using the new wide schema.
        Drops old tables if present (for simplicity).
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return
        try:
            # Drop old tables if they exist (for a clean migration)
            self.sqlite_conn.execute("DROP TABLE IF EXISTS metrics")
            self.sqlite_conn.execute("DROP TABLE IF EXISTS events")

            # Create new runs table (wide format)
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    start_time INTEGER NOT NULL,
                    end_time INTEGER,
                    duration_realtime INTEGER,
                    duration_gametime REAL,
                    final_wave INTEGER,
                    coins_earned REAL,
                    game_version TEXT,
                    tier INTEGER
                )
            """)

            # Create new metrics table (wide format)
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    real_timestamp INTEGER NOT NULL,
                    game_timestamp REAL NOT NULL,
                    current_wave INTEGER NOT NULL,
                    coins REAL,
                    gems INTEGER,
                    stones REAL
                    -- Add more nullable columns for future metrics as needed
                )
            """)
            self.sqlite_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_run_time 
                ON metrics(run_id, real_timestamp)
            """)

            # Create new events table (wide format)
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    event_name TEXT NOT NULL,
                    data TEXT
                )
            """)

            # Logs and settings tables remain unchanged
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    timestamp INTEGER,
                    level TEXT,
                    source TEXT,
                    event TEXT,
                    data TEXT
                )
            """)
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            self.sqlite_conn.commit()
            self.logger.info("Database migrations completed successfully (wide format)")
        except Exception as e:
            self.logger.error("Failed to run database migrations", error=str(e))
            if self.sqlite_conn:
                self.sqlite_conn.rollback()
            raise
    
    def write_metric(self, run_id: str, real_timestamp: int, game_timestamp: float, current_wave: int, metrics: dict) -> None:
        """
        Insert a new metric row in wide format. Missing metrics are inserted as NULL.
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return
        try:
            known_metrics = ["coins", "gems", "stones"]
            columns = ["run_id", "real_timestamp", "game_timestamp", "current_wave"] + known_metrics
            values = [
                str(run_id),
                int(real_timestamp),
                float(game_timestamp),
                int(current_wave)
            ]
            for m in known_metrics:
                v = metrics.get(m)
                if v is None:
                    values.append(None)
                elif m == "gems":
                    values.append(int(v))
                else:
                    values.append(float(v))
            placeholders = ", ".join(["?" for _ in columns])
            sql = f"INSERT INTO metrics ({', '.join(columns)}) VALUES ({placeholders})"
            self.sqlite_conn.execute(sql, values)
            self.sqlite_conn.commit()
            self.logger.debug("Wide metric inserted", run_id=run_id, real_timestamp=real_timestamp)
        except Exception as e:
            self.logger.error("Failed to insert wide metric", error=str(e), run_id=run_id)

    def write_event(self, run_id: str, timestamp: int, event_name: str, data: Optional[dict] = None) -> None:
        """
        Insert a new event row in wide format.
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return
        try:
            data_json = json.dumps(data if data is not None else {})
            self.sqlite_conn.execute(
                "INSERT INTO events (run_id, timestamp, event_name, data) VALUES (?, ?, ?, ?)",
                (str(run_id), int(timestamp), str(event_name), data_json)
            )
            self.sqlite_conn.commit()
            self.logger.debug("Wide event inserted", run_id=run_id, event_name=event_name)
        except Exception as e:
            self.logger.error("Failed to insert wide event", error=str(e), run_id=run_id, event_name=event_name)

    def write_log_entry(self, log_entry: dict) -> None:
        """
        Write a log entry to the database.
        This is the target for the SQLiteLogHandler.
        
        Args:
            log_entry: Processed structlog dictionary
        """
        if not self.sqlite_conn:
            return
        
        try:
            timestamp = int(log_entry.get('timestamp', datetime.now().timestamp()))
            level = log_entry.get('level', 'INFO')
            source = log_entry.get('source', 'unknown')
            event = log_entry.get('event', 'unknown')
            
            # Remove standard fields and serialize the rest as data
            data_dict = {k: v for k, v in log_entry.items() 
                        if k not in ['timestamp', 'level', 'source', 'event']}
            data_json = json.dumps(data_dict)
            
            self.sqlite_conn.execute(
                "INSERT INTO logs (timestamp, level, source, event, data) VALUES (?, ?, ?, ?, ?)",
                (timestamp, level, source, event, data_json)
            )
            self.sqlite_conn.commit()
            
        except Exception as e:
            # Don't log database errors in the log handler to avoid recursion
            print(f"Failed to write log entry to database: {e}")
    
    def get_run_metrics(self, run_id: str, metric_name: str) -> pd.DataFrame:
        """
        Get all metrics for a given run and metric name (wide format).
        Args:
            run_id: Unique identifier for the run (now the roundSeed from the game, as a string)
            metric_name: Name of the metric (must match a column in the wide table)
        Returns:
            DataFrame of metrics
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return pd.DataFrame()
        try:
            # Only allow known metric columns
            allowed_metrics = ["coins", "gems", "stones"]
            if metric_name not in allowed_metrics:
                self.logger.error("Requested unknown metric column", metric_name=metric_name)
                return pd.DataFrame()
            query = f"SELECT real_timestamp, {metric_name} FROM metrics WHERE run_id = ? AND {metric_name} IS NOT NULL ORDER BY real_timestamp"
            cursor = self.sqlite_conn.execute(query, (run_id,))
            rows = cursor.fetchall()
            df = pd.DataFrame(rows, columns=["real_timestamp", metric_name])
            return df
        except Exception as e:
            self.logger.error("Failed to get run metrics", error=str(e), run_id=run_id, metric_name=metric_name)
            return pd.DataFrame()
    
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
        
        try:
            cursor = self.sqlite_conn.execute(
                "SELECT value FROM settings WHERE key = ?",
                (key,)
            )
            result = cursor.fetchone()
            return result[0] if result else None
            
        except Exception as e:
            self.logger.error("Failed to get setting", key=key, error=str(e))
            return None
    
    def set_setting(self, key: str, value: str) -> None:
        """
        Set a setting value in the database.
        
        Args:
            key: Setting key
            value: Setting value
        """
        if not self.sqlite_conn:
            return
        
        try:
            self.sqlite_conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, value)
            )
            self.sqlite_conn.commit()
            
        except Exception as e:
            self.logger.error("Failed to set setting", key=key, error=str(e))

    def insert_run_start(self, run_id: str, start_time: int, game_version: Optional[str] = None, tier: Optional[int] = None) -> None:
        """
        Insert a new run record at the start of a round.
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return
        try:
            self.sqlite_conn.execute(
                "INSERT OR IGNORE INTO runs (run_id, start_time, game_version, tier) VALUES (?, ?, ?, ?)",
                (str(run_id), int(start_time), str(game_version) if game_version is not None else None, int(tier) if tier is not None else None)
            )
            self.sqlite_conn.commit()
            self.logger.debug("Run start inserted", run_id=run_id, start_time=start_time)
        except Exception as e:
            self.logger.error("Failed to insert run start", error=str(e), run_id=run_id)

    def update_run_end(self, run_id: str, end_time: int, final_wave: Optional[int] = None, coins_earned: Optional[float] = None, duration_realtime: Optional[int] = None, duration_gametime: Optional[float] = None) -> None:
        """
        Update an existing run record at the end of a round.
        duration_realtime is now passed directly from the handler (calculated using roundStartTime and timestamp).
        Argument order: run_id, end_time, final_wave, coins_earned, duration_realtime, duration_gametime
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return
        try:
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
            self.sqlite_conn.execute(
                """
                UPDATE runs SET end_time = ?, final_wave = ?, coins_earned = ?, duration_realtime = ?, duration_gametime = ?
                WHERE run_id = ?
                """,
                (
                    int(end_time) if end_time is not None else None,
                    int(final_wave) if final_wave is not None else None,
                    float(coins_earned) if coins_earned is not None else None,
                    int(duration_realtime) if duration_realtime is not None else None,
                    float(duration_gametime) if duration_gametime is not None else None,
                    str(run_id)
                )
            )
            self.sqlite_conn.commit()
            self.logger.debug("Run end updated", run_id=run_id, end_time=end_time)
        except Exception as e:
            self.logger.error("Failed to update run end", error=str(e), run_id=run_id)