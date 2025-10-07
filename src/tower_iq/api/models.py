"""
Pydantic models for TowerIQ API requests and responses.
Centralized location for all API models.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


# Connection and Hook Management Models
class ConnectionRequest(BaseModel):
    device_serial: str


class HookActivationRequest(BaseModel):
    device_id: str
    process_info: Dict[str, Any]
    script_id: Optional[str] = None  # Script ID for selection
    script_name: Optional[str] = None  # Script name for selection (fallback)


class HookDeactivationRequest(BaseModel):
    device_id: str
    process_info: Dict[str, Any]


class ScriptCompatibilityRequest(BaseModel):
    package_name: str
    app_version: str


class TestModeRequest(BaseModel):
    test_mode: bool
    test_mode_replay: bool = False
    test_mode_generate: bool = False


class SessionState(BaseModel):
    is_connected: bool
    current_device: Optional[str] = None
    current_process: Optional[Dict[str, Any]] = None
    test_mode: bool = False
    connection_state: Optional[str] = None
    connection_sub_state: Optional[str] = None
    device_monitoring_active: bool = False
    last_error: Optional[Dict[str, Any]] = None


# Dashboard API Models
class DashboardCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    config: Dict[str, Any]
    tags: Optional[List[str]] = None


class DashboardUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None


class DashboardResponse(BaseModel):
    id: str
    uid: str
    title: str
    description: Optional[str] = None
    config: Dict[str, Any]
    tags: List[str]
    created_at: str
    updated_at: str
    created_by: str
    is_default: bool
    schema_version: int


# Backup and Database Models
class BackupSettings(BaseModel):
    enabled: bool
    backup_dir: str
    retention_count: int
    interval_seconds: int
    on_shutdown: bool
    compress_zip: bool
    filename_prefix: str


class BackupRunResponse(BaseModel):
    success: bool
    message: str


class DatabasePathResponse(BaseModel):
    sqlite_path: str


class DatabasePathUpdate(BaseModel):
    sqlite_path: str


class RestoreRequest(BaseModel):
    backup_path: str


class RestoreSuggestion(BaseModel):
    suggest: bool
    reason: Optional[str] = None
    latest_backup: Optional[str] = None


# Query Models
class QueryRequest(BaseModel):
    query: str
    variables: Optional[Dict[str, Any]] = None


class QueryResponse(BaseModel):
    data: List[Dict[str, Any]]
    row_count: int
    execution_time_ms: Optional[float] = None
    cache_hit: bool = False


class QueryPreviewRequest(BaseModel):
    query: str


class QueryPreviewResponse(BaseModel):
    status: str
    message: str
    plan: Optional[List[Dict[str, Any]]] = None


# Settings Models
class SettingValue(BaseModel):
    value: Any


class SettingUpdate(BaseModel):
    key: str
    value: Any


# Grafana Integration Models
class GrafanaSettings(BaseModel):
    enabled: bool
    bind_address: str
    port: int
    allow_read_only: bool
    query_timeout: int
    max_rows: int


class GrafanaValidateResponse(BaseModel):
    success: bool
    message: str
    errors: Optional[List[str]] = None
    errors: Optional[List[str]] = None
