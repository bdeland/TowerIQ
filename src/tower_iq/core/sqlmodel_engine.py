"""
SQLModel engine configuration for TowerIQ.

This module provides SQLModel engine setup compatible with SQLCipher,
enabling type-safe database operations while maintaining existing security.
"""

from sqlmodel import SQLModel, create_engine, Session
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class SQLModelEngine:
    """SQLModel engine manager with SQLCipher compatibility."""

    def __init__(self, database_path: str, password: Optional[str] = None):
        self.database_path = database_path
        self.password = password
        self.engine = None
        self._create_engine()

    def _create_engine(self):
        """Create SQLModel engine with SQLCipher compatibility."""
        try:
            # SQLCipher connection string with SQLModel
            if self.password:
                # Use SQLCipher with password
                connection_string = f"sqlite:///{self.database_path}?_pragma=key='{self.password}'"
            else:
                # Use regular SQLite
                connection_string = f"sqlite:///{self.database_path}"

            # Create engine with SQLModel
            self.engine = create_engine(
                connection_string,
                echo=False,  # Set to True for SQL debugging
                pool_pre_ping=True,
                connect_args={
                    "check_same_thread": False,  # Allow multi-threading
                }
            )

            logger.info(f"SQLModel engine created for database: {self.database_path}")

        except Exception as e:
            logger.error(f"Failed to create SQLModel engine: {str(e)}")
            raise

    def get_session(self) -> Session:
        """Get a new SQLModel session."""
        if not self.engine:
            raise RuntimeError("SQLModel engine not initialized")

        return Session(self.engine)

    def create_tables(self):
        """Create all tables defined in SQLModel models."""
        try:
            SQLModel.metadata.create_all(self.engine)
            logger.info("SQLModel tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create SQLModel tables: {str(e)}")
            raise

    def close(self):
        """Close the engine connection."""
        if self.engine:
            self.engine.dispose()
            logger.info("SQLModel engine closed")


# Global engine instance
_sqlmodel_engine: Optional[SQLModelEngine] = None


def initialize_sqlmodel_engine(database_path: str, password: Optional[str] = None) -> SQLModelEngine:
    """Initialize the global SQLModel engine."""
    global _sqlmodel_engine

    if _sqlmodel_engine:
        logger.warning("SQLModel engine already initialized, closing existing engine")
        _sqlmodel_engine.close()

    _sqlmodel_engine = SQLModelEngine(database_path, password)
    return _sqlmodel_engine


def get_sqlmodel_session() -> Session:
    """Get a SQLModel session from the global engine."""
    if not _sqlmodel_engine:
        raise RuntimeError("SQLModel engine not initialized. Call initialize_sqlmodel_engine() first.")

    return _sqlmodel_engine.get_session()


def get_sqlmodel_engine() -> SQLModelEngine:
    """Get the global SQLModel engine."""
    if not _sqlmodel_engine:
        raise RuntimeError("SQLModel engine not initialized. Call initialize_sqlmodel_engine() first.")

    return _sqlmodel_engine


def close_sqlmodel_engine():
    """Close the global SQLModel engine."""
    global _sqlmodel_engine

    if _sqlmodel_engine:
        _sqlmodel_engine.close()
        _sqlmodel_engine = None
        logger.info("SQLModel engine closed and cleared")
