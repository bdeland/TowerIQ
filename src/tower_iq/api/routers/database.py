"""
Database Management Router

Handles:
- Database backup and restore operations
- Database path configuration
- Database statistics and health metrics
- Backup settings management
- Grafana integration settings
"""

import asyncio
import re
import socket
from pathlib import Path

from fastapi import APIRouter, HTTPException

from ..models import (BackupRunResponse, BackupSettings, DatabasePathResponse,
                      DatabasePathUpdate, GrafanaSettings,
                      GrafanaValidateResponse, RestoreRequest,
                      RestoreSuggestion)

router = APIRouter()

# Module-level dependencies
logger = None
db_service = None
config = None


def initialize(log, db_svc, cfg):
    """Initialize module-level dependencies."""
    global logger, db_service, config
    logger = log
    db_service = db_svc
    config = cfg


@router.get("/api/settings/database/backup", response_model=BackupSettings)
async def get_backup_settings():
    try:
        if not config:
            raise HTTPException(status_code=503, detail="Configuration not available")
        return BackupSettings(
            enabled=bool(config.get('database.backup.enabled', True)),
            backup_dir=str(config.get('database.backup.backup_dir', 'data/backups')),
            retention_count=int(config.get('database.backup.retention_count', 7)),
            interval_seconds=int(config.get('database.backup.interval_seconds', 86400)),
            on_shutdown=bool(config.get('database.backup.on_shutdown', True)),
            compress_zip=bool(config.get('database.backup.compress_zip', True)),
            filename_prefix=str(config.get('database.backup.filename_prefix', 'toweriq_backup_'))
        )
    except Exception as e:
        if logger:
            logger.error("Error getting backup settings", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get backup settings: {str(e)}")


@router.put("/api/settings/database/backup", response_model=BackupSettings)
async def update_backup_settings(new: BackupSettings):
    try:
        if not config:
            raise HTTPException(status_code=503, detail="Configuration not available")
        # Persist settings into DB-backed config
        config.set('database.backup.enabled', new.enabled, description='Enable scheduled backups')
        config.set('database.backup.backup_dir', new.backup_dir, description='Backup directory path')
        config.set('database.backup.retention_count', new.retention_count,
                  description='Number of backups to retain')
        config.set('database.backup.interval_seconds', new.interval_seconds,
                  description='Backup interval in seconds')
        config.set('database.backup.on_shutdown', new.on_shutdown, description='Run backup on shutdown')
        config.set('database.backup.compress_zip', new.compress_zip, description='Compress backups to zip')
        config.set('database.backup.filename_prefix', new.filename_prefix,
                  description='Backup filename prefix')
        return new
    except Exception as e:
        if logger:
            logger.error("Error updating backup settings", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to update backup settings: {str(e)}")


@router.post("/api/database/backup", response_model=BackupRunResponse)
async def run_backup_now():
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        ok = db_service.backup_database()
        return BackupRunResponse(success=bool(ok), message="Backup completed" if ok else "Backup failed")
    except Exception as e:
        if logger:
            logger.error("Error running backup", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to run backup: {str(e)}")


@router.get("/api/database/restore-suggestion", response_model=RestoreSuggestion)
async def get_restore_suggestion():
    try:
        # Return computed suggestion captured during startup
        from tower_iq.api import dependencies
        suggest = dependencies.get_restore_suggestion()
        if suggest is None:
            # Fallback compute if cache is missing
            if not config:
                return RestoreSuggestion(suggest=False)
            db_path = Path(str(config.get('database.sqlite_path', 'data/toweriq.sqlite')))
            db_missing = not db_path.exists()
            db_empty = db_path.exists() and db_path.stat().st_size == 0
            if db_missing or db_empty:
                backup_dir = Path(str(config.get('database.backup.backup_dir', 'data/backups')))
                if backup_dir.exists():
                    backups = sorted(
                        list(backup_dir.glob("*.sqlite*")),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True
                    )
                    if backups:
                        return RestoreSuggestion(
                            suggest=True,
                            reason="database missing" if db_missing else "database empty",
                            latest_backup=str(backups[0])
                        )
            return RestoreSuggestion(suggest=False)
        return RestoreSuggestion(**suggest)
    except Exception as e:
        if logger:
            logger.error("Error getting restore suggestion", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get restore suggestion: {str(e)}")


@router.post("/api/database/restore")
async def restore_database(req: RestoreRequest):
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        ok = db_service.restore_database(req.backup_path)
        if not ok:
            raise HTTPException(status_code=500, detail="Restore failed")
        return {"message": "Restore completed"}
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error restoring database", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to restore database: {str(e)}")


@router.get("/api/settings/database/path", response_model=DatabasePathResponse)
async def get_database_path():
    try:
        if not config:
            raise HTTPException(status_code=503, detail="Configuration not available")
        path = str(config.get('database.sqlite_path', 'data/toweriq.sqlite'))
        return DatabasePathResponse(sqlite_path=path)
    except Exception as e:
        if logger:
            logger.error("Error getting database path", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get database path: {str(e)}")


@router.put("/api/settings/database/path", response_model=DatabasePathResponse)
async def update_database_path(update: DatabasePathUpdate):
    try:
        if not config:
            raise HTTPException(status_code=503, detail="Configuration not available")
        # Persist to DB-backed config
        config.set('database.sqlite_path', update.sqlite_path,
                  description='Primary SQLite database path')
        return DatabasePathResponse(sqlite_path=update.sqlite_path)
    except Exception as e:
        if logger:
            logger.error("Error updating database path", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to update database path: {str(e)}")


@router.get("/api/v1/database/statistics")
async def get_database_statistics():
    """Get comprehensive database statistics including file metrics and table row counts."""
    if not db_service:
        raise HTTPException(status_code=500, detail="Database service not available")

    try:
        if logger:
            logger.info("Database statistics request received")

        # Get database statistics using the existing service method
        stats = await asyncio.to_thread(db_service.get_database_statistics)

        if logger:
            logger.info("Database statistics retrieved successfully",
                       total_rows=stats.get('total_rows', 0),
                       file_size=stats.get('file_size', 0))

        return stats

    except Exception as e:
        if logger:
            logger.error("Failed to get database statistics", error=str(e))

        raise HTTPException(status_code=500, detail=f"Failed to get database statistics: {str(e)}")


@router.post("/api/v1/database/collect-metrics")
async def collect_database_metrics():
    """Trigger collection and storage of database health metrics."""
    if not db_service:
        raise HTTPException(status_code=500, detail="Database service not available")

    try:
        if logger:
            logger.info("Database metrics collection request received")

        # Trigger metrics collection using the new service method
        success = await asyncio.to_thread(db_service.collect_and_store_db_metrics)

        if success:
            if logger:
                logger.info("Database metrics collected and stored successfully")
            return {"success": True, "message": "Database metrics collected and stored successfully"}
        else:
            if logger:
                logger.error("Database metrics collection failed")
            raise HTTPException(status_code=500, detail="Database metrics collection failed")

    except Exception as e:
        if logger:
            logger.error("Failed to collect database metrics", error=str(e))

        raise HTTPException(status_code=500, detail=f"Failed to collect database metrics: {str(e)}")


# Grafana Integration Endpoints

@router.get("/api/settings/grafana", response_model=GrafanaSettings)
async def get_grafana_settings():
    """Get Grafana integration settings."""
    try:
        if not config:
            raise HTTPException(status_code=503, detail="Configuration not available")
        
        return GrafanaSettings(
            enabled=bool(config.get('grafana.enabled', False)),
            bind_address=str(config.get('grafana.bind_address', '127.0.0.1')),
            port=int(config.get('grafana.port', 8000)),
            allow_read_only=bool(config.get('grafana.allow_read_only', True)),
            query_timeout=int(config.get('grafana.query_timeout', 30)),
            max_rows=int(config.get('grafana.max_rows', 10000))
        )
    except Exception as e:
        if logger:
            logger.error("Error getting Grafana settings", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get Grafana settings: {str(e)}")


@router.put("/api/settings/grafana", response_model=GrafanaSettings)
async def update_grafana_settings(settings: GrafanaSettings):
    """Update Grafana integration settings."""
    try:
        if not config:
            raise HTTPException(status_code=503, detail="Configuration not available")
        
        # Validate settings before saving
        errors = []
        
        # Validate bind address
        if not _is_valid_ip_address(settings.bind_address):
            errors.append(f"Invalid bind address: {settings.bind_address}")
        
        # Validate port
        if not (1024 <= settings.port <= 65535):
            errors.append(f"Port must be between 1024 and 65535 (got {settings.port})")
        
        # Validate query timeout
        if settings.query_timeout < 1 or settings.query_timeout > 300:
            errors.append(f"Query timeout must be between 1 and 300 seconds (got {settings.query_timeout})")
        
        # Validate max rows
        if settings.max_rows < 1 or settings.max_rows > 100000:
            errors.append(f"Max rows must be between 1 and 100,000 (got {settings.max_rows})")
        
        if errors:
            raise HTTPException(status_code=400, detail="; ".join(errors))
        
        # Save settings
        config.set('grafana.enabled', settings.enabled, 
                  description='Enable Grafana integration')
        config.set('grafana.bind_address', settings.bind_address, 
                  description='Bind address for API server (requires restart)')
        config.set('grafana.port', settings.port, 
                  description='Port for API server (requires restart)')
        config.set('grafana.allow_read_only', settings.allow_read_only, 
                  description='Allow read-only queries')
        config.set('grafana.query_timeout', settings.query_timeout, 
                  description='Query timeout in seconds')
        config.set('grafana.max_rows', settings.max_rows, 
                  description='Maximum rows per query')
        
        if logger:
            logger.info("Grafana settings updated", 
                       enabled=settings.enabled,
                       bind_address=settings.bind_address,
                       port=settings.port)
        
        return settings
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error updating Grafana settings", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to update Grafana settings: {str(e)}")


@router.post("/api/settings/grafana/validate", response_model=GrafanaValidateResponse)
async def validate_grafana_settings():
    """Validate Grafana settings and test connectivity."""
    try:
        if not config or not db_service:
            raise HTTPException(status_code=503, detail="Services not available")
        
        errors = []
        warnings = []
        
        # Get current settings
        enabled = bool(config.get('grafana.enabled', False))
        bind_address = str(config.get('grafana.bind_address', '127.0.0.1'))
        port = int(config.get('grafana.port', 8000))
        
        if not enabled:
            return GrafanaValidateResponse(
                success=False,
                message="Grafana integration is disabled",
                errors=["Enable Grafana integration to validate settings"]
            )
        
        # Validate bind address
        if not _is_valid_ip_address(bind_address):
            errors.append(f"Invalid bind address: {bind_address}")
        
        # Validate port
        if not (1024 <= port <= 65535):
            errors.append(f"Port must be between 1024 and 65535")
        
        # Check if port is available (if binding to 0.0.0.0 or localhost)
        if bind_address in ['0.0.0.0', '127.0.0.1']:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((bind_address if bind_address != '0.0.0.0' else '127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    # Port is in use (which is expected if server is running)
                    warnings.append(f"Port {port} is currently in use (expected if TowerIQ is running)")
            except Exception as e:
                warnings.append(f"Could not check port availability: {str(e)}")
        
        # Test database query execution
        try:
            cursor = db_service.sqlite_conn.cursor()
            cursor.execute("SELECT 1 as test")
            result = cursor.fetchone()
            if result[0] != 1:
                errors.append("Database query test failed")
        except Exception as e:
            errors.append(f"Database query test failed: {str(e)}")
        
        # Security warnings
        if bind_address == '0.0.0.0':
            warnings.append("⚠️ Binding to 0.0.0.0 exposes the database to all network interfaces. Ensure your firewall is configured.")
        
        if errors:
            return GrafanaValidateResponse(
                success=False,
                message="Validation failed",
                errors=errors + warnings
            )
        
        success_msg = "Grafana integration is properly configured"
        if warnings:
            success_msg += f" (with {len(warnings)} warning(s))"
        
        return GrafanaValidateResponse(
            success=True,
            message=success_msg,
            errors=warnings if warnings else None
        )
    
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error validating Grafana settings", error=str(e))
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


def _is_valid_ip_address(ip: str) -> bool:
    """Validate IPv4 address format."""
    # Allow 0.0.0.0 for binding to all interfaces
    if ip == '0.0.0.0':
        return True
    
    # Validate IPv4 format
    pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = pattern.match(ip)
    
    if not match:
        return False
    
    # Check each octet is 0-255
    for octet in match.groups():
        if int(octet) > 255:
            return False
    
    return True

