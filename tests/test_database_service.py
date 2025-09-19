import sqlite3
import sys
import types
import uuid
from pathlib import Path

import pytest


class DummyLogger:
    def bind(self, **_kwargs):
        return self

    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


# Ensure the src directory is on the path for imports during testing
PROJECT_ROOT = Path(__file__).resolve().parents[1]
src_services_path = PROJECT_ROOT / "src" / "tower_iq" / "services"
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Provide minimal stubs for optional dependencies when they are not available
try:  # pragma: no cover - optional dependency
    import structlog  # type: ignore  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - executed when structlog missing
    structlog_stub = types.ModuleType("structlog")

    def _get_logger(*_args, **_kwargs):
        return DummyLogger()

    structlog_stub.get_logger = _get_logger
    sys.modules["structlog"] = structlog_stub

try:  # pragma: no cover - optional dependency
    import pandas as _pd  # type: ignore  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - executed when pandas missing
    pandas_stub = types.ModuleType("pandas")

    class _StubDataFrame:  # pragma: no cover - simple placeholder
        def __init__(self, *_args, **_kwargs):
            self._rows = []

        @property
        def empty(self):
            return True

        def rename(self, *_args, **_kwargs):
            return self

    def _stub_read_sql_query(*_args, **_kwargs):  # pragma: no cover - not used in tests
        raise NotImplementedError("pandas stub does not support read_sql_query")

    pandas_stub.DataFrame = _StubDataFrame
    pandas_stub.read_sql_query = _stub_read_sql_query
    sys.modules["pandas"] = pandas_stub

# Stub out ConfigurationManager to avoid importing PyQt and yaml dependencies during tests
config_stub = types.ModuleType("tower_iq.core.config")


class _StubConfigurationManager:
    def __init__(self, *_args, **_kwargs):
        pass

    def get(self, key: str, default=None):
        return default


config_stub.ConfigurationManager = _StubConfigurationManager
sys.modules["tower_iq.core.config"] = config_stub

# Stub the services package to avoid importing heavy dependencies from __init__
services_stub = types.ModuleType("tower_iq.services")
services_stub.__path__ = [str(src_services_path)]
sys.modules["tower_iq.services"] = services_stub

from tower_iq.services.database_service import DatabaseService


class DummyConfig:
    def __init__(self, db_path: Path):
        self._db_path = str(db_path)

    def get(self, key: str, default=None):
        if key == 'database.sqlite_path':
            return self._db_path
        return default


def create_database_service(tmp_path):
    db_path = tmp_path / "test.sqlite"
    config = DummyConfig(db_path)
    logger = DummyLogger()
    service = DatabaseService(config=config, logger=logger)
    service.connect()
    return service


def test_integrity_error_triggers_rollback_and_allows_subsequent_operations(tmp_path):
    service = create_database_service(tmp_path)
    run_id = str(uuid.uuid4())

    # Attempt to write metrics for a run that does not exist, which should
    # violate the foreign key constraint and raise an IntegrityError.
    with pytest.raises(sqlite3.IntegrityError):
        service.write_metric(
            run_id=run_id,
            real_timestamp=0,
            game_duration=0,
            current_wave=0,
            metrics={"coins": 1.0},
        )

    # After the failed transaction the connection should have been rolled back,
    # allowing us to insert the run and write metrics successfully.
    service.insert_run_start(run_id=run_id, start_time=0)
    service.write_metric(
        run_id=run_id,
        real_timestamp=1,
        game_duration=10,
        current_wave=1,
        metrics={"coins": 5.0},
    )

    cursor = service.sqlite_conn.execute(
        "SELECT metric_value FROM metrics WHERE run_id = ?",
        (uuid.UUID(run_id).bytes,),
    )
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == 5

    service.close()
