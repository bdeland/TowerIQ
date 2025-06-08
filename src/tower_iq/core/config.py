"""
TowerIQ Configuration Management Module

This module provides the ConfigurationManager class, which serves as the single
source of truth for all application configuration settings.
"""

import os
import yaml
from typing import Any, Optional, Dict
from dotenv import load_dotenv


class ConfigurationManager:
    """
    Single source of truth for all configuration values.
    Loads, validates, and provides access to settings from YAML and .env files.
    """

    def __init__(self, yaml_path: str, env_path: str) -> None:
        """
        Initialize the configuration manager.
        
        Args:
            yaml_path: Absolute path to main_config.yaml
            env_path: Absolute path to the .env file
        """
        self.yaml_path = yaml_path
        self.env_path = env_path
        self.settings: Dict[str, Any] = {}

    def load_and_validate(self) -> None:
        """
        Main method to perform the entire loading sequence.
        Reads YAML, reads .env, merges them, validates the result.
        """
        yaml_config = self._load_yaml()
        env_config = self._load_dotenv()
        self._merge_configs(yaml_config, env_config)
        self._validate_config()

    def get(self, key: str, default: Any = None) -> Any:
        """
        Provides dictionary-like access to the final, merged settings.
        Supports dot notation for nested keys (e.g., "logging.level").
        
        Args:
            key: Configuration key, supports dot notation
            default: Default value if key is not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.settings
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def _load_yaml(self) -> Dict[str, Any]:
        """
        Load the main_config.yaml file.
        
        Returns:
            Dictionary representing the YAML content
            
        Raises:
            FileNotFoundError: If YAML file doesn't exist
            yaml.YAMLError: If YAML is invalid
        """
        if not os.path.exists(self.yaml_path):
            raise FileNotFoundError(f"Configuration file not found: {self.yaml_path}")
        
        try:
            with open(self.yaml_path, 'r', encoding='utf-8') as file:
                return yaml.safe_load(file) or {}
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Invalid YAML in {self.yaml_path}: {e}")

    def _load_dotenv(self) -> Dict[str, Any]:
        """
        Load the .env file using python-dotenv.
        
        Returns:
            Dictionary of environment variables from .env file
        """
        env_config = {}
        
        if os.path.exists(self.env_path):
            load_dotenv(self.env_path)
            
            # Load specific environment variables that TowerIQ uses
            env_vars = [
                'SQLITE_ENCRYPTION_KEY',
                'FRIDA_SIGNATURE_KEY',
                'DEBUG_MODE'
            ]
            
            for var in env_vars:
                value = os.getenv(var)
                if value is not None:
                    # Convert boolean strings
                    if value.lower() in ('true', 'false'):
                        value = value.lower() == 'true'
                    env_config[var.lower()] = value
        
        return env_config

    def _merge_configs(self, yaml_config: Dict[str, Any], env_config: Dict[str, Any]) -> None:
        """
        Merge the two configurations. Environment variables take precedence.
        
        Args:
            yaml_config: Configuration from YAML file
            env_config: Configuration from .env file
        """
        self.settings = yaml_config.copy()
        
        # Apply environment variable overrides
        if 'sqlite_encryption_key' in env_config:
            self.settings.setdefault('database', {}).setdefault('sqlite', {})['encryption_key'] = env_config['sqlite_encryption_key']
        
        if 'frida_signature_key' in env_config:
            self.settings.setdefault('frida', {})['signature_key'] = env_config['frida_signature_key']
        
        if 'debug_mode' in env_config:
            self.settings.setdefault('app', {})['debug'] = env_config['debug_mode']

    def _validate_config(self) -> None:
        """
        Validate the final merged configuration.
        Checks for the presence of essential keys.
        
        Raises:
            ValueError: If a required configuration key is missing
        """
        required_keys = [
            'app.name',
            'app.version',
            'logging.level',
            'database.sqlite_path',
            'emulator.package_name',
            'frida.server_port'
        ]
        
        missing_keys = []
        for key in required_keys:
            if self.get(key) is None:
                missing_keys.append(key)
        
        if missing_keys:
            raise ValueError(f"Missing required configuration keys: {', '.join(missing_keys)}")
        
        # Validate specific values
        log_level = self.get('logging.level', '').upper()
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError(f"Invalid logging level: {log_level}")
        
        # Validate frida port is integer
        frida_port = self.get('frida.server_port')
        if not isinstance(frida_port, int) or frida_port <= 0:
            raise ValueError("Frida server port must be a positive integer") 