"""
TowerIQ Configuration Management Module

This module provides the ConfigurationManager class, which serves as the single
source of truth for all application configuration settings.
"""

import structlog
import yaml
import json
from typing import Any, Optional, Dict, Union
from pathlib import Path
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal

# Forward reference for type hinting
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..services.database_service import DatabaseService

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
        self._setting_metadata: dict = {}  # Store metadata for each setting

    def _recreate_logger(self):
        """Recreate the logger after logging system is configured."""
        self.logger = structlog.get_logger().bind(source="ConfigurationManager")

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

    def link_database_service(self, db_service: 'DatabaseService'):
        """Links the DatabaseService and loads all user settings from the DB."""
        self._db_service = db_service
        self._load_all_user_settings()
        # Initialize defaults after loading existing settings
        self._initialize_default_settings()

    def _initialize_default_settings(self):
        """Initialize database with default settings if they don't exist."""
        if not self._db_service:
            return
            
        system_defaults = self._file_config.get('system_defaults', {})
        
        # Flatten the nested defaults structure
        default_settings = self._flatten_dict(system_defaults)
        
        self.logger.info("Initializing default settings", count=len(default_settings), defaults=list(default_settings.keys()))
        self.logger.debug("Existing user settings", user_settings=list(self._user_settings.keys()))
        self.logger.debug("Database service path", db_path=self._db_service.db_path if self._db_service else "None")
        
        for key, value in default_settings.items():
            # Only set if the setting doesn't already exist in the database
            if key not in self._user_settings:
                self.logger.debug("Setting default", key=key, value=value)
                self.set(key, value, description=f"Default setting for {key}")
            else:
                self.logger.debug("Skipping existing setting", key=key)
        
        self.logger.info("Default settings initialization completed", total_settings=len(self._user_settings))
        
        # Debug: Check what's actually in the database
        if self._db_service:
            db_settings = self._db_service.get_all_settings()
            self.logger.debug("Settings in database after initialization", count=len(db_settings), keys=[s.get('key') for s in db_settings])
        
        # Reload settings from database to update the cache
        self._load_all_user_settings()

    def _flatten_dict(self, d: dict, parent_key: str = '', sep: str = '.') -> dict:
        """Flatten a nested dictionary using dot notation."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

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
        
        self._user_settings = {}
        self._setting_metadata = {}
        
        for setting in settings_list:
            key = setting['key']
            value = setting['value']
            value_type = setting.get('value_type', 'string')
            
            # Deserialize based on type
            try:
                deserialized_value = self._deserialize_value(value, value_type)
                self._user_settings[key] = deserialized_value
                self._setting_metadata[key] = setting
            except Exception as e:
                self.logger.warning("Failed to deserialize setting", key=key, error=str(e))
                # Fallback to string value
                self._user_settings[key] = value
        
        self.logger.info("Loaded user settings from DB", count=len(self._user_settings))

    def _deserialize_value(self, value: str, value_type: str) -> Any:
        """Deserialize a value based on its type."""
        if value_type == 'string':
            return value
        elif value_type == 'int':
            return int(value)
        elif value_type == 'float':
            return float(value)
        elif value_type == 'bool':
            # Handle both string representations and actual boolean values
            if isinstance(value, bool):
                return value
            elif isinstance(value, str):
                return value.lower() in ('true', '1', 'yes', 'on')
            else:
                return bool(value)
        elif value_type == 'json':
            return json.loads(value)
        elif value_type == 'yaml':
            return yaml.safe_load(value)
        else:
            # Fallback to string
            return value

    def _serialize_value(self, value: Any) -> tuple[str, str]:
        """Serialize a value and return (serialized_value, value_type)."""
        if isinstance(value, str):
            return value, 'string'
        elif isinstance(value, int):
            return str(value), 'int'
        elif isinstance(value, float):
            return str(value), 'float'
        elif isinstance(value, bool):
            return str(value).lower(), 'bool'
        elif isinstance(value, (dict, list)):
            return json.dumps(value), 'json'
        else:
            return str(value), 'string'

    def _get_setting_category(self, key: str) -> str:
        """Determine the category for a setting based on its key."""
        if key.startswith('logging.'):
            return 'logging'
        elif key.startswith('database.'):
            return 'database'
        elif key.startswith('frida.'):
            return 'frida'
        elif key.startswith('gui.'):
            return 'gui'
        elif key.startswith('emulator.'):
            return 'emulator'
        else:
            return 'general'

    def get(self, key: str, default: Any = None) -> Any:
        """
        Gets a config value, checking user settings (DB) first, then system defaults.
        Supports dot notation for nested keys.
        """
        # 1. Check user settings (from DB)
        if key in self._user_settings:
            return self._user_settings[key]

        # 2. Check system defaults (from YAML)
        system_val = self._get_from_dict(self._file_config.get('system_defaults', {}), key.split('.'))
        if system_val is not None:
            return system_val
            
        # 3. Check direct file settings (for system config like database.sqlite_path)
        file_val = self._get_from_dict(self._file_config, key.split('.'))
        if file_val is not None:
            return file_val
            
        # 4. Return default
        return default

    def _get_from_dict(self, data_dict: dict, keys: list) -> Any:
        value = data_dict
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return None

    def set(self, key: str, value: Any, description: Optional[str] = None, is_sensitive: bool = False):
        """
        Sets a config value, saving to DB if available.
        
        Args:
            key: Setting key
            value: Setting value
            description: Optional description of the setting
            is_sensitive: Whether this setting contains sensitive data
        """
        if not self._db_service:
            self.logger.error("Cannot set config value - DatabaseService not linked", key=key)
            return

        current_value = self.get(key)
        if current_value == value:
            return # No change, do nothing

        # Serialize the value
        serialized_value, value_type = self._serialize_value(value)
        
        # Determine category
        category = self._get_setting_category(key)
        
        # Update local cache
        self._user_settings[key] = value
        
        # Save to database with metadata
        self._db_service.set_setting_with_metadata(
            key=key,
            value=serialized_value,
            value_type=value_type,
            description=description,
            category=category,
            is_sensitive=is_sensitive
        )
        
        self.logger.debug("Setting saved to database", key=key, value=value, value_type=value_type)
        self.settingChanged.emit(key, value)

    def get_setting_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a setting."""
        return self._setting_metadata.get(key)

    def get_settings_by_category(self, category: str) -> Dict[str, Any]:
        """Get all settings in a specific category."""
        return {k: v for k, v in self._user_settings.items() 
                if self._get_setting_category(k) == category}

    def reset_setting(self, key: str):
        """Reset a setting to its file-based default value."""
        if key in self._user_settings:
            del self._user_settings[key]
            if key in self._setting_metadata:
                del self._setting_metadata[key]
            
            if self._db_service:
                self._db_service.delete_setting(key)
            
            self.settingChanged.emit(key, self.get(key))

    def export_settings(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Export all settings as a dictionary."""
        export_data = {
            'settings': {},
            'metadata': {}
        }
        
        for key, value in self._user_settings.items():
            metadata = self._setting_metadata.get(key, {})
            
            # Skip sensitive settings unless explicitly requested
            if metadata.get('is_sensitive', False) and not include_sensitive:
                continue
                
            export_data['settings'][key] = value
            export_data['metadata'][key] = metadata
        
        return export_data

    def import_settings(self, settings_data: Dict[str, Any], overwrite: bool = False):
        """Import settings from a dictionary."""
        settings = settings_data.get('settings', {})
        metadata = settings_data.get('metadata', {})
        
        for key, value in settings.items():
            if key in self._user_settings and not overwrite:
                self.logger.warning("Skipping existing setting", key=key)
                continue
                
            setting_metadata = metadata.get(key, {})
            description = setting_metadata.get('description')
            is_sensitive = setting_metadata.get('is_sensitive', False)
            
            self.set(key, value, description, is_sensitive) 