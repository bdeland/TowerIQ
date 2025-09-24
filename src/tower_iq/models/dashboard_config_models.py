"""
TowerIQ Dashboard Config Models for v2 API

These models define the data structures for the new hierarchical dashboard system,
matching the frontend DashboardConfig types from the domain model.
"""

from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


# ============================================================================
# Data Source Models
# ============================================================================

class DataSourceType(str, Enum):
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    PROMETHEUS = "prometheus"
    REST_API = "rest_api"


class DataSourceConfig(BaseModel):
    id: str
    name: str
    type: DataSourceType
    config: Dict[str, Any]
    credentials: Optional[Dict[str, Any]] = None
    is_active: bool = True


# ============================================================================
# Variable Models
# ============================================================================

class VariableType(str, Enum):
    STATIC = "static"
    QUERY = "query"
    RANGE = "range"


class VariableOption(BaseModel):
    label: str
    value: Union[str, int, float, bool]


class VariableConfig(BaseModel):
    name: str
    type: VariableType
    label: str
    description: Optional[str] = None
    default_value: Union[str, int, float, bool, List[Any]]
    options: Optional[List[VariableOption]] = None
    options_query: Optional[str] = None
    data_source_id: Optional[str] = None
    validation_schema: Optional[Dict[str, Any]] = None
    is_required: bool = True
    is_multi_select: bool = False


# ============================================================================
# Panel Models
# ============================================================================

class PanelType(str, Enum):
    CHART = "chart"
    TABLE = "table"
    STAT = "stat"
    GAUGE = "gauge"
    CALENDAR = "calendar"
    TREEMAP = "treemap"


class GridPosition(BaseModel):
    x: int
    y: int
    w: int
    h: int


class QueryDefinition(BaseModel):
    raw_query: str
    data_source_id: str = "default"
    timeout_ms: Optional[int] = 30000
    cache_ttl_ms: Optional[int] = 300000


class VisualizationConfig(BaseModel):
    chart_type: Optional[str] = None
    echarts_option: Optional[Dict[str, Any]] = None
    table_config: Optional[Dict[str, Any]] = None
    stat_config: Optional[Dict[str, Any]] = None


class PanelConfig(BaseModel):
    id: str
    title: str
    type: PanelType
    grid_pos: GridPosition
    query: QueryDefinition
    visualization: VisualizationConfig
    description: Optional[str] = None
    drilldown_config: Optional[Dict[str, Any]] = None


# ============================================================================
# Dashboard Models
# ============================================================================

class DashboardMetadata(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    is_system: bool = False


class DashboardConfig(BaseModel):
    """Complete dashboard configuration matching frontend domain model"""
    id: str
    metadata: DashboardMetadata
    panels: List[PanelConfig]
    variables: List[VariableConfig] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)  # Data source IDs
    layout: Optional[Dict[str, Any]] = None
    theme: Optional[Dict[str, Any]] = None


# ============================================================================
# API Request/Response Models
# ============================================================================

class DashboardListResponse(BaseModel):
    """Response for listing dashboards (metadata only)"""
    dashboards: List[DashboardMetadata]
    total: int


class CreateDashboardRequest(BaseModel):
    name: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    config: DashboardConfig
    is_system: bool = False


class UpdateDashboardRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    config: Optional[DashboardConfig] = None


class DataSourceCreateRequest(BaseModel):
    name: str
    type: DataSourceType
    config: Dict[str, Any]
    credentials: Optional[Dict[str, Any]] = None
    is_active: bool = True


class DataSourceUpdateRequest(BaseModel):
    name: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    credentials: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class VariableOptionsRequest(BaseModel):
    query: str
    data_source_id: str = "default"
    dependencies: Optional[Dict[str, Any]] = None


# ============================================================================
# Migration Models
# ============================================================================

class MigrationStatus(BaseModel):
    """Status of dashboard migration from hardcoded to database"""
    total_dashboards: int
    migrated_dashboards: int
    failed_migrations: List[str] = Field(default_factory=list)
    is_complete: bool
    started_at: datetime
    completed_at: Optional[datetime] = None


class LegacyDashboardFormat(BaseModel):
    """Legacy dashboard format for migration purposes"""
    id: str
    uid: str
    title: str
    description: Optional[str] = None
    config: Dict[str, Any]
    tags: List[str] = Field(default_factory=list)
    created_by: str = "system"
    is_default: bool = False
    schema_version: int = 1
