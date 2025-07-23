"""
TowerIQ Configuration Management Module

This module provides the ConfigurationManager class, which serves as the single
source of truth for all application configuration settings.
"""

import structlog
import yaml
from typing import Any, Optional
from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal

# Forward reference for type hinting
class DatabaseService:
    def get_all_settings(self): ...
    def set_setting(self, key: str, value: str): ...

class ConfigurationManager(QObject):
    """
    Manages application configuration with a layered approach and signals.
    1. Loads default settings from a YAML file.
    2. Loads and overlays user-specific settings from the database.
    3. Provides a unified interface to get/set settings and emits signals on change.
    """
    settingChanged = pyqtSignal(str, object)

    def __init__(self, yaml_path: str = 'config/main_config.yaml'):
        super().__init__()
        self.logger = structlog.get_logger().bind(source="ConfigurationManager")
        self._db_service: Optional[DatabaseService] = None
        self._file_config: dict = self._load_from_file(yaml_path)
        self._user_settings: dict = {}

    def get_project_root(self) -> str:
        """
        Get the project root directory path.
        
        Returns:
            str: The absolute path to the project root directory
        """
        # The project root is typically 3 levels up from this file
        # src/tower_iq/core/config.py -> project root
        current_file = Path(__file__)
        project_root = current_file.parent.parent.parent.parent
        return str(project_root.resolve())

    def link_database_service(self, db_service: DatabaseService):
        """Links the DatabaseService and loads all user settings from the DB."""
        self._db_service = db_service
        self._load_all_user_settings()

    def _load_from_file(self, config_path: str) -> dict:
        path = Path(config_path)
        if not path.exists():
            self.logger.warning("Configuration file not found", path=str(path))
            return {}
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}

    def _load_all_user_settings(self):
        """Loads all settings from the 'settings' table."""
        if not self._db_service: return
        
        settings_list = self._db_service.get_all_settings()
        if settings_list is None:
            settings_list = []
        self._user_settings = {s['key']: s['value'] for s in settings_list}
        self.logger.info("Loaded user settings from DB", count=len(self._user_settings))

    def get(self, key: str, default: Any = None) -> Any:
        """
        Gets a config value, checking user settings (DB) first, then file settings.
        Supports dot notation for nested keys.
        """
        # 1. Check user settings (from DB)
        if key in self._user_settings:
            # Attempt to cast to the same type as the file setting, if it exists
            file_val = self._get_from_dict(self._file_config, key.split('.'))
            if file_val is not None:
                try:
                    return type(file_val)(self._user_settings[key])
                except (ValueError, TypeError):
                    return self._user_settings[key]
            return self._user_settings[key]

        # 2. Check file settings
        file_val = self._get_from_dict(self._file_config, key.split('.'))
        if file_val is not None:
            return file_val
            
        # 3. Return default
        return default

    def _get_from_dict(self, data_dict: dict, keys: list) -> Any:
        value = data_dict
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return None

    def set(self, key: str, value: Any):
        """Sets a config value, saving to DB if available."""
        if not self._db_service:
            self.logger.error("Cannot set config value - DatabaseService not linked", key=key)
            return

        current_value = self.get(key)
        if current_value == value:
            return # No change, do nothing

        self._user_settings[key] = value
        self._db_service.set_setting(key, str(value))
        self.settingChanged.emit(key, value) 