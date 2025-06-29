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
        Create database tables if they don't exist.
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return
        
        try:
            # Create runs table
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    start_time INTEGER,
                    end_time INTEGER,
                    game_version TEXT,
                    tier INTEGER
                )
            """)
            
            # Create metrics table with index
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    run_id TEXT,
                    timestamp INTEGER,
                    name TEXT,
                    value REAL
                )
            """)
            self.sqlite_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_run_name_time 
                ON metrics(run_id, name, timestamp)
            """)
            
            # Create events table
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    run_id TEXT,
                    timestamp INTEGER,
                    name TEXT,
                    data TEXT
                )
            """)
            
            # Create logs table
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    timestamp INTEGER,
                    level TEXT,
                    source TEXT,
                    event TEXT,
                    data TEXT
                )
            """)
            
            # Create settings table
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            
            self.sqlite_conn.commit()
            self.logger.info("Database migrations completed successfully")
            
        except Exception as e:
            self.logger.error("Failed to run database migrations", error=str(e))
            if self.sqlite_conn:
                self.sqlite_conn.rollback()
            raise
    
    def write_metric(self, run_id: str, timestamp: int, name: str, value: float) -> None:
        """
        Write a metric to the database.
        Args:
            run_id: Unique identifier for the run (now the roundSeed from the game, as a string)
            timestamp: Unix timestamp
            name: Metric name
            value: Metric value
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return
        
        try:
            self.sqlite_conn.execute(
                "INSERT INTO metrics (run_id, timestamp, name, value) VALUES (?, ?, ?, ?)",
                (run_id, timestamp, name, value)
            )
            self.sqlite_conn.commit()
            self.logger.debug("Metric written to database", run_id=run_id, name=name, value=value)
            
        except Exception as e:
            self.logger.error("Failed to write metric", error=str(e), run_id=run_id, name=name)
    
    def write_event(self, run_id: str, timestamp: int, name: str, data: dict) -> None:
        """
        Write an event to the database.
        Args:
            run_id: Unique identifier for the run (now the roundSeed from the game, as a string)
            timestamp: Unix timestamp
            name: Event name
            data: Event data dictionary
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return
        
        try:
            data_json = json.dumps(data)
            self.sqlite_conn.execute(
                "INSERT INTO events (run_id, timestamp, name, data) VALUES (?, ?, ?, ?)",
                (run_id, timestamp, name, data_json)
            )
            self.sqlite_conn.commit()
            self.logger.debug("Event written to database", run_id=run_id, name=name)
            
        except Exception as e:
            self.logger.error("Failed to write event", error=str(e), run_id=run_id, name=name)
    
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
        Get all metrics for a given run and metric name.
        Args:
            run_id: Unique identifier for the run (now the roundSeed from the game, as a string)
            metric_name: Name of the metric
        Returns:
            DataFrame of metrics
        """
        if not self.sqlite_conn:
            self.logger.error("SQLite connection not available")
            return pd.DataFrame()
        
        try:
            cursor = self.sqlite_conn.execute(
                "SELECT timestamp, value FROM metrics WHERE run_id = ? AND name = ? ORDER BY timestamp",
                (run_id, metric_name)
            )
            rows = cursor.fetchall()
            
            # Convert to DataFrame
            df = pd.DataFrame(rows, columns=['timestamp', 'value'])
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