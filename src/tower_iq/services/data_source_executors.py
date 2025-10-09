"""
TowerIQ Data Source Abstraction Layer

This module provides a pluggable architecture for different data source types,
allowing the dashboard system to query SQLite, PostgreSQL, Prometheus, or REST APIs
through a unified interface.
"""

import asyncio
import logging
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

# Import data source configuration models
from tower_iq.models.dashboard_config_models import DataSourceConfig


@dataclass
class QueryResponse:
    """Response from query execution"""
    data: List[Dict[str, Any]]
    row_count: int
    execution_time_ms: float
    cache_hit: bool = False
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ConnectionTestResult:
    """Result of connection test"""
    is_successful: bool
    message: str
    response_time_ms: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None


class DataSourceError(Exception):
    """Base exception for data source operations"""
    pass


class ConnectionError(DataSourceError):
    """Exception raised when connection to data source fails"""
    pass


class QueryExecutionError(DataSourceError):
    """Exception raised when query execution fails"""
    pass


# ============================================================================
# Abstract Base Class
# ============================================================================

class DataSourceExecutor(ABC):
    """Abstract base class for data source executors"""

    def __init__(self, config: DataSourceConfig, logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self._connection = None

    @abstractmethod
    async def execute(self, query: str, variables: Dict[str, Any] = None) -> QueryResponse:
        """Execute a query against the data source"""
        pass

    @abstractmethod
    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to the data source"""
        pass

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the data source"""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the data source"""
        pass

    def is_connected(self) -> bool:
        """Check if connected to the data source"""
        return self._connection is not None

    def get_config(self) -> DataSourceConfig:
        """Get data source configuration"""
        return self.config


# ============================================================================
# SQLite Implementation
# ============================================================================

class SQLiteExecutor(DataSourceExecutor):
    """SQLite data source executor"""

    async def connect(self) -> None:
        """Establish SQLite connection"""
        try:
            database_path = self.config.config.get('database_path', ':memory:')
            timeout = self.config.config.get('connection_timeout', 30)

            # Use asyncio.to_thread for file operations
            self._connection = await asyncio.to_thread(
                sqlite3.connect,
                database_path,
                timeout=timeout,
                check_same_thread=False
            )

            # Enable row factory for dict-like results
            self._connection.row_factory = sqlite3.Row

            self.logger.debug(f"Connected to SQLite database: {database_path}")

        except Exception as e:
            raise ConnectionError(f"Failed to connect to SQLite database: {str(e)}")

    async def disconnect(self) -> None:
        """Close SQLite connection"""
        if self._connection:
            await asyncio.to_thread(self._connection.close)
            self._connection = None
            self.logger.debug("Disconnected from SQLite database")

    async def execute(self, query: str, variables: Dict[str, Any] = None) -> QueryResponse:
        """Execute SQL query against SQLite database with safe parameter substitution"""
        if not self._connection:
            await self.connect()

        start_time = datetime.now()

        try:
            # Basic SQL injection protection
            query_upper = query.strip().upper()
            if not query_upper.startswith('SELECT'):
                raise QueryExecutionError("Only SELECT queries are allowed")

            # Execute query with safe variable substitution
            sql_params = {}
            if variables:
                query = self._safe_substitute_variables(query, variables, sql_params)

            # Type narrowing: ensure connection is established
            if not self._connection:
                raise QueryExecutionError("Database connection not available")

            # Execute the query with parameterized values
            if sql_params:
                cursor = await asyncio.to_thread(self._connection.execute, query, sql_params)
            else:
                cursor = await asyncio.to_thread(self._connection.execute, query)
            rows = await asyncio.to_thread(cursor.fetchall)

            # Convert sqlite3.Row objects to dictionaries
            data = [dict(row) for row in rows]

            execution_time = (datetime.now() - start_time).total_seconds() * 1000

            self.logger.debug("SQLite query executed successfully",
                            extra={"query": query, "row_count": len(data), "execution_time_ms": execution_time})

            return QueryResponse(
                data=data,
                row_count=len(data),
                execution_time_ms=execution_time,
                cache_hit=False
            )

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            self.logger.error("SQLite query execution failed",
                            extra={"query": query, "error": str(e), "execution_time_ms": execution_time})
            raise QueryExecutionError(f"Query execution failed: {str(e)}")

    def _safe_substitute_variables(self, query: str, variables: Dict[str, Any], sql_params: Dict[str, Any]) -> str:
        """
        Safely substitute variables into SQL query.
        
        For simple values: Convert to SQL parameters (:param_name)
        For clause builders (like filters): Validate and safely construct SQL fragments
        """
        import re
        
        for key, value in variables.items():
            placeholder = f"${{{key}}}"
            if placeholder not in query:
                continue
            
            # Handle special clause placeholders (tier_filter, limit_clause, etc.)
            if key.endswith('_filter'):
                # Build a safe WHERE/AND clause for filters
                if isinstance(value, list) and len(value) > 0 and not (len(value) == 1 and value[0] == 'all'):
                    # Sanitize list values - only allow alphanumeric, underscore, and numbers
                    sanitized = []
                    for v in value:
                        if isinstance(v, (int, float)):
                            sanitized.append(str(v))
                        elif isinstance(v, str) and re.match(r'^[a-zA-Z0-9_-]+$', v):
                            sanitized.append(v)
                        else:
                            raise QueryExecutionError(f"Invalid filter value: {v}")
                    
                    # Use parameterized query for IN clause
                    param_names = [f":filter_{key}_{i}" for i in range(len(sanitized))]
                    for i, val in enumerate(sanitized):
                        sql_params[f"filter_{key}_{i}"] = val
                    
                    # Determine if we need WHERE or AND
                    filter_clause = f"AND {key.replace('_filter', '')} IN ({','.join(param_names)})"
                    query = query.replace(placeholder, filter_clause)
                else:
                    # Remove placeholder if no filtering needed
                    query = query.replace(placeholder, "")
            
            elif key.endswith('_clause'):
                # Handle clauses like LIMIT
                if key == 'limit_clause' and value and value != 'all':
                    # Sanitize limit value - must be a positive integer
                    try:
                        limit_val = int(value)
                        if limit_val > 0:
                            query = query.replace(placeholder, f"LIMIT {limit_val}")
                        else:
                            query = query.replace(placeholder, "")
                    except (ValueError, TypeError):
                        query = query.replace(placeholder, "")
                else:
                    query = query.replace(placeholder, "")
            
            else:
                # For simple values, use SQL parameters
                param_name = f":{key}"
                sql_params[key] = value
                query = query.replace(placeholder, param_name)
        
        return query

    async def test_connection(self) -> ConnectionTestResult:
        """Test SQLite connection"""
        start_time = datetime.now()

        try:
            if not self._connection:
                await self.connect()
            
            # Type narrowing: ensure connection is established
            if not self._connection:
                raise QueryExecutionError("Failed to establish database connection")

            # Execute a simple test query
            await asyncio.to_thread(self._connection.execute, "SELECT 1")

            response_time = (datetime.now() - start_time).total_seconds() * 1000

            return ConnectionTestResult(
                is_successful=True,
                message="SQLite connection successful",
                response_time_ms=response_time,
                metadata={"database_path": self.config.config.get('database_path')}
            )

        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            return ConnectionTestResult(
                is_successful=False,
                message=f"SQLite connection failed: {str(e)}",
                response_time_ms=response_time
            )


# ============================================================================
# PostgreSQL Implementation (Placeholder)
# ============================================================================

class PostgreSQLExecutor(DataSourceExecutor):
    """PostgreSQL data source executor (placeholder for future implementation)"""

    async def connect(self) -> None:
        """Establish PostgreSQL connection"""
        raise NotImplementedError("PostgreSQL executor not yet implemented")

    async def disconnect(self) -> None:
        """Close PostgreSQL connection"""
        raise NotImplementedError("PostgreSQL executor not yet implemented")

    async def execute(self, query: str, variables: Dict[str, Any] = None) -> QueryResponse:
        """Execute SQL query against PostgreSQL database"""
        raise NotImplementedError("PostgreSQL executor not yet implemented")

    async def test_connection(self) -> ConnectionTestResult:
        """Test PostgreSQL connection"""
        return ConnectionTestResult(
            is_successful=False,
            message="PostgreSQL executor not yet implemented"
        )


# ============================================================================
# Prometheus Implementation (Placeholder)
# ============================================================================

class PrometheusExecutor(DataSourceExecutor):
    """Prometheus data source executor (placeholder for future implementation)"""

    async def connect(self) -> None:
        """Establish Prometheus connection"""
        raise NotImplementedError("Prometheus executor not yet implemented")

    async def disconnect(self) -> None:
        """Close Prometheus connection"""
        raise NotImplementedError("Prometheus executor not yet implemented")

    async def execute(self, query: str, variables: Dict[str, Any] = None) -> QueryResponse:
        """Execute PromQL query against Prometheus"""
        raise NotImplementedError("Prometheus executor not yet implemented")

    async def test_connection(self) -> ConnectionTestResult:
        """Test Prometheus connection"""
        return ConnectionTestResult(
            is_successful=False,
            message="Prometheus executor not yet implemented"
        )


# ============================================================================
# REST API Implementation (Placeholder)
# ============================================================================

class RestAPIExecutor(DataSourceExecutor):
    """REST API data source executor (placeholder for future implementation)"""

    async def connect(self) -> None:
        """Establish REST API connection"""
        raise NotImplementedError("REST API executor not yet implemented")

    async def disconnect(self) -> None:
        """Close REST API connection"""
        raise NotImplementedError("REST API executor not yet implemented")

    async def execute(self, query: str, variables: Dict[str, Any] = None) -> QueryResponse:
        """Execute REST API query"""
        raise NotImplementedError("REST API executor not yet implemented")

    async def test_connection(self) -> ConnectionTestResult:
        """Test REST API connection"""
        return ConnectionTestResult(
            is_successful=False,
            message="REST API executor not yet implemented"
        )


# ============================================================================
# Factory Pattern
# ============================================================================

class DataSourceExecutorFactory:
    """Factory for creating data source executors"""

    _executors = {
        'sqlite': SQLiteExecutor,
        'postgresql': PostgreSQLExecutor,
        'prometheus': PrometheusExecutor,
        'rest_api': RestAPIExecutor
    }

    @classmethod
    def create(cls, config: DataSourceConfig, logger: Optional[logging.Logger] = None) -> DataSourceExecutor:
        """Create a data source executor based on configuration"""
        executor_class = cls._executors.get(config.type)

        if not executor_class:
            raise ValueError(f"Unsupported data source type: {config.type}")

        return executor_class(config, logger)

    @classmethod
    def get_supported_types(cls) -> List[str]:
        """Get list of supported data source types"""
        return list(cls._executors.keys())

    @classmethod
    def register_executor(cls, data_source_type: str, executor_class: type):
        """Register a new data source executor"""
        if not issubclass(executor_class, DataSourceExecutor):
            raise ValueError("Executor class must inherit from DataSourceExecutor")

        cls._executors[data_source_type] = executor_class


# ============================================================================
# Data Source Manager
# ============================================================================

class DataSourceManager:
    """Manager for data source connections and caching"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self._executors: Dict[str, DataSourceExecutor] = {}
        self._configs: Dict[str, DataSourceConfig] = {}

    async def register_data_source(self, config: DataSourceConfig) -> None:
        """Register a data source configuration"""
        self._configs[config.id] = config

        # Create executor but don't connect yet (lazy connection)
        executor = DataSourceExecutorFactory.create(config, self.logger)
        self._executors[config.id] = executor

        self.logger.info(f"Registered data source: {config.name} ({config.type})")

    async def get_executor(self, data_source_id: str) -> DataSourceExecutor:
        """Get data source executor by ID"""
        if data_source_id not in self._executors:
            raise ValueError(f"Data source not found: {data_source_id}")

        return self._executors[data_source_id]

    async def execute_query(self, data_source_id: str, query: str, variables: Dict[str, Any] = None) -> QueryResponse:
        """Execute query against specified data source"""
        executor = await self.get_executor(data_source_id)
        return await executor.execute(query, variables)

    async def test_connection(self, data_source_id: str) -> ConnectionTestResult:
        """Test connection to specified data source"""
        executor = await self.get_executor(data_source_id)
        return await executor.test_connection()

    async def disconnect_all(self) -> None:
        """Disconnect from all data sources"""
        for executor in self._executors.values():
            try:
                await executor.disconnect()
            except Exception as e:
                self.logger.error(f"Error disconnecting from data source: {str(e)}")

        self.logger.info("Disconnected from all data sources")

    def list_data_sources(self) -> List[DataSourceConfig]:
        """List all registered data sources"""
        return list(self._configs.values())

    def get_data_source_config(self, data_source_id: str) -> Optional[DataSourceConfig]:
        """Get data source configuration by ID"""
        return self._configs.get(data_source_id)


# ============================================================================
# Global Instance
# ============================================================================

# Global data source manager instance
_data_source_manager: Optional[DataSourceManager] = None


def get_data_source_manager() -> DataSourceManager:
    """Get global data source manager instance"""
    global _data_source_manager
    if _data_source_manager is None:
        _data_source_manager = DataSourceManager()
    return _data_source_manager


async def initialize_default_data_source(database_path: str) -> None:
    """Initialize default SQLite data source"""
    from tower_iq.models.dashboard_config_models import (DataSourceConfig,
                                                         DataSourceType)

    default_config = DataSourceConfig(
        id="default",
        name="TowerIQ SQLite Database",
        type=DataSourceType.SQLITE,
        config={
            "database_path": database_path,
            "connection_timeout": 30
        },
        is_active=True
    )

    manager = get_data_source_manager()
    await manager.register_data_source(default_config)
