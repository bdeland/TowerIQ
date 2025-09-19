import sys
import types

from pathlib import Path

import asyncio

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

if "fastapi" not in sys.modules:
    fastapi_stub = types.ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail=None) -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class BackgroundTasks:
        def add_task(self, *args, **kwargs) -> None:  # pragma: no cover - stub
            pass

    class FastAPI:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def add_middleware(self, *args, **kwargs) -> None:  # pragma: no cover - stub
            pass

        def _route_decorator(self, *args, **kwargs):  # pragma: no cover - stub
            def decorator(func):
                return func

            return decorator

        def get(self, *args, **kwargs):  # pragma: no cover - stub
            return self._route_decorator(*args, **kwargs)

        def post(self, *args, **kwargs):  # pragma: no cover - stub
            return self._route_decorator(*args, **kwargs)

        def put(self, *args, **kwargs):  # pragma: no cover - stub
            return self._route_decorator(*args, **kwargs)

        def delete(self, *args, **kwargs):  # pragma: no cover - stub
            return self._route_decorator(*args, **kwargs)

    fastapi_stub.FastAPI = FastAPI
    fastapi_stub.HTTPException = HTTPException
    fastapi_stub.BackgroundTasks = BackgroundTasks

    middleware_module = types.ModuleType("fastapi.middleware")
    cors_module = types.ModuleType("fastapi.middleware.cors")

    class CORSMiddleware:  # pragma: no cover - stub
        def __init__(self, *args, **kwargs) -> None:
            pass

    cors_module.CORSMiddleware = CORSMiddleware
    middleware_module.cors = cors_module

    fastapi_stub.middleware = middleware_module

    sys.modules["fastapi"] = fastapi_stub
    sys.modules["fastapi.middleware"] = middleware_module
    sys.modules["fastapi.middleware.cors"] = cors_module

if "pydantic" not in sys.modules:
    pydantic_stub = types.ModuleType("pydantic")

    class BaseModel:  # pragma: no cover - stub
        def __init__(self, **data) -> None:
            for key, value in data.items():
                setattr(self, key, value)

    pydantic_stub.BaseModel = BaseModel
    sys.modules["pydantic"] = pydantic_stub

if "uvicorn" not in sys.modules:
    uvicorn_stub = types.ModuleType("uvicorn")

    def run(*args, **kwargs) -> None:  # pragma: no cover - stub
        pass

    uvicorn_stub.run = run
    sys.modules["uvicorn"] = uvicorn_stub

if "structlog" not in sys.modules:
    structlog_stub = types.ModuleType("structlog")

    class _StubLogger:  # pragma: no cover - stub
        def __getattr__(self, name):
            def method(*args, **kwargs):
                return None

            return method

    def get_logger(*args, **kwargs):  # pragma: no cover - stub
        return _StubLogger()

    structlog_stub.get_logger = get_logger
    sys.modules["structlog"] = structlog_stub

if "tower_iq.core" not in sys.modules:
    sys.modules["tower_iq.core"] = types.ModuleType("tower_iq.core")

if "tower_iq.core.config" not in sys.modules:
    config_module = types.ModuleType("tower_iq.core.config")

    class ConfigurationManager:  # pragma: no cover - stub
        def __init__(self, *args, **kwargs) -> None:
            self._store: dict[str, object] = {}

        def _recreate_logger(self) -> None:
            pass

        def get(self, key: str, default=None):  # pragma: no cover - stub
            return self._store.get(key, default)

        def set(self, key: str, value, description: str | None = None) -> None:  # pragma: no cover - stub
            self._store[key] = value

        def link_database_service(self, db_service) -> None:  # pragma: no cover - stub
            pass

    config_module.ConfigurationManager = ConfigurationManager
    sys.modules["tower_iq.core.config"] = config_module
    sys.modules["tower_iq.core"].config = config_module

if "tower_iq.core.logging_config" not in sys.modules:
    logging_config_module = types.ModuleType("tower_iq.core.logging_config")

    def setup_logging(config) -> None:  # pragma: no cover - stub
        pass

    logging_config_module.setup_logging = setup_logging
    sys.modules["tower_iq.core.logging_config"] = logging_config_module
    sys.modules["tower_iq.core"].logging_config = logging_config_module

if "tower_iq.services" not in sys.modules:
    sys.modules["tower_iq.services"] = types.ModuleType("tower_iq.services")

if "tower_iq.services.database_service" not in sys.modules:
    db_module = types.ModuleType("tower_iq.services.database_service")

    class DatabaseService:  # pragma: no cover - stub
        def __init__(self, *args, **kwargs) -> None:
            self.sqlite_conn = None

        def connect(self) -> None:  # pragma: no cover - stub
            pass

        def ensure_dashboards_table_exists(self) -> bool:  # pragma: no cover - stub
            return True

        def backup_database(self) -> bool:  # pragma: no cover - stub
            return True

        def collect_and_store_db_metrics(self) -> bool:  # pragma: no cover - stub
            return True

        def close(self) -> None:  # pragma: no cover - stub
            pass

        def get_all_dashboards(self):  # pragma: no cover - stub
            return []

        def get_dashboard_by_id(self, dashboard_id):  # pragma: no cover - stub
            return None

        def create_dashboard(self, dashboard_data) -> bool:  # pragma: no cover - stub
            return True

        def update_dashboard(self, dashboard_id, update_data) -> bool:  # pragma: no cover - stub
            return True

        def delete_dashboard(self, dashboard_id) -> bool:  # pragma: no cover - stub
            return True

        def set_default_dashboard(self, dashboard_id) -> bool:  # pragma: no cover - stub
            return True

        def get_default_dashboard(self):  # pragma: no cover - stub
            return None

        def restore_database(self, backup_path) -> bool:  # pragma: no cover - stub
            return True

        def get_database_statistics(self):  # pragma: no cover - stub
            return {}

    db_module.DatabaseService = DatabaseService
    sys.modules["tower_iq.services.database_service"] = db_module
    sys.modules["tower_iq.services"].database_service = db_module

if "tower_iq.main_controller" not in sys.modules:
    main_controller_module = types.ModuleType("tower_iq.main_controller")

    class MainController:  # pragma: no cover - stub
        def __init__(self, *args, **kwargs) -> None:
            self.session = None
            self.frida_service = None
            self.hook_script_manager = None
            self.loading_manager = types.SimpleNamespace(
                start_loading=lambda: None,
                mark_step_complete=lambda *args, **kwargs: None,
            )

        def signal_loading_complete(self) -> None:  # pragma: no cover - stub
            pass

        def start_background_operations(self) -> None:  # pragma: no cover - stub
            pass

        def stop_background_operations(self) -> None:  # pragma: no cover - stub
            pass

    main_controller_module.MainController = MainController
    sys.modules["tower_iq.main_controller"] = main_controller_module

from tower_iq.api_server import HTTPException, HookActivationRequest, activate_hook


class DummySession:
    def __init__(self) -> None:
        self.set_inactive_calls = 0
        self.frida_script = "preexisting-script"
        self.frida_session = "preexisting-session"
        self.frida_device = "preexisting-device"
        self.frida_attached_pid = 9999

    def set_script_inactive(self) -> None:
        self.set_inactive_calls += 1


class DummyFridaService:
    def __init__(self, session: DummySession) -> None:
        self.session = session
        self.detach_calls = 0

    async def attach(self, pid: int, device_id: str) -> bool:
        # Simulate successful attach that records session details
        self.session.frida_session = object()
        self.session.frida_device = f"device:{device_id}"
        self.session.frida_attached_pid = pid
        return True

    async def inject_script(self, script_content: str) -> bool:
        # Force an injection failure
        return False

    async def detach(self) -> None:
        self.detach_calls += 1


class DummyController:
    def __init__(self) -> None:
        self.session = DummySession()
        self.frida_service = DummyFridaService(self.session)
        self.hook_script_manager = object()
        self.start_background_operations_called = False

    async def _load_script_by_id(self, script_id: str) -> str:
        return "dummy-script"

    async def _load_script_by_name(self, script_name: str, package_name: str, version: str) -> str:
        return "dummy-script"

    async def _load_compatible_script(self, package_name: str, version: str) -> str:
        return "dummy-script"

    def start_background_operations(self) -> None:
        self.start_background_operations_called = True


def test_activate_hook_detaches_on_injection_failure(monkeypatch) -> None:
    from tower_iq import api_server

    dummy_controller = DummyController()
    monkeypatch.setattr(api_server, "controller", dummy_controller, raising=False)

    request = HookActivationRequest(
        device_id="emulator-5554",
        process_info={"pid": 4242},
        script_id="script-123",
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(activate_hook(request, BackgroundTasks()))

    assert exc_info.value.status_code == 500
    assert dummy_controller.frida_service.detach_calls == 1
    assert not dummy_controller.start_background_operations_called

    session = dummy_controller.session
    assert session.set_inactive_calls == 1
    assert session.frida_session is None
    assert session.frida_device is None
    assert session.frida_attached_pid is None
    assert session.frida_script is None
