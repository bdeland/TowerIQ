"""
Database Management Router

Handles:
- Database backup and restore operations
- Database path configuration
- Database statistics and health metrics
- Backup settings management
"""

import asyncio
from pathlib import Path
from fastapi import APIRouter, HTTPException

from ..models import (
    BackupSettings, BackupRunResponse, DatabasePathResponse,
    DatabasePathUpdate, RestoreRequest, RestoreSuggestion
)

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
        import builtins
        suggest = getattr(builtins, '_restore_suggestion_cache', None)
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

