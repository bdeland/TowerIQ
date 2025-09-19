import importlib.util
import json
import sys
import types
from pathlib import Path

stub_structlog = types.ModuleType("structlog")


class _StubLogger:
    def bind(self, **_kwargs):
        return self

    def warning(self, *_args, **_kwargs):
        pass


def _get_logger():
    return _StubLogger()


stub_structlog.get_logger = _get_logger
sys.modules.setdefault("structlog", stub_structlog)

MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "tower_iq" / "services" / "hook_script_manager.py"
spec = importlib.util.spec_from_file_location("hook_script_manager", MODULE_PATH)
hook_script_manager = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hook_script_manager)

HookScriptManager = hook_script_manager.HookScriptManager


def _write_script(tmp_path, file_name, metadata, newline):
    metadata_json = json.dumps(metadata)
    content = f"/** TOWERIQ_HOOK_METADATA{newline}{metadata_json}{newline}*/{newline}console.log('hello');{newline}"
    script_path = tmp_path / file_name
    script_path.write_text(content, encoding="utf-8")
    return script_path


def test_discover_scripts_extracts_metadata_with_lf(tmp_path):
    metadata = {
        "fileName": "ignored.js",
        "scriptName": "LF script",
        "targetPackage": "com.example.app",
        "supportedVersions": ["1.0.0"],
    }
    _write_script(tmp_path, "lf_script.js", metadata, "\n")

    manager = HookScriptManager(str(tmp_path))
    manager.discover_scripts()

    assert len(manager.scripts) == 1
    script = manager.scripts[0]
    assert script["fileName"] == "lf_script.js"
    assert script["scriptName"] == metadata["scriptName"]
    assert script["targetPackage"] == metadata["targetPackage"]
    assert script["supportedVersions"] == metadata["supportedVersions"]


def test_discover_scripts_extracts_metadata_with_crlf(tmp_path):
    metadata = {
        "fileName": "ignored_again.js",
        "scriptName": "CRLF script",
        "targetPackage": "com.example.other",
        "supportedVersions": ["2.0.0"],
    }
    _write_script(tmp_path, "crlf_script.js", metadata, "\r\n")

    manager = HookScriptManager(str(tmp_path))
    manager.discover_scripts()

    assert len(manager.scripts) == 1
    script = manager.scripts[0]
    assert script["fileName"] == "crlf_script.js"
    assert script["scriptName"] == metadata["scriptName"]
    assert script["targetPackage"] == metadata["targetPackage"]
    assert script["supportedVersions"] == metadata["supportedVersions"]
