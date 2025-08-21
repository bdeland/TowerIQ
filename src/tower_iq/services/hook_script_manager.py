"""
Hook Script Management Service

This module provides the HookScriptManager class which discovers hook scripts,
parses embedded metadata blocks, filters by compatibility, and loads script
contents for injection.
"""

from __future__ import annotations

import os
import json
import re
from pathlib import Path
from typing import List, Dict, Optional


class HookScriptManager:
    """
    Manages discovery and retrieval of hook scripts and their metadata.

    Each script must include a metadata block at the top of the file in the
    following format:

    /** TOWERIQ_HOOK_METADATA
    { ... JSON ... }
    */
    """

    def __init__(self, hooks_dir_path: str) -> None:
        self.hooks_dir_path = Path(hooks_dir_path)
        self.scripts: List[Dict] = []

    def discover_scripts(self) -> None:
        """
        Scan the hooks directory for .js files, extract metadata blocks, and
        store valid script dictionaries in self.scripts.
        """
        self.scripts.clear()
        if not self.hooks_dir_path.exists():
            return

        for script_path in self.hooks_dir_path.glob("*.js"):
            try:
                file_content = script_path.read_text(encoding="utf-8")
            except Exception:
                continue

            match = re.search(r"/\*\* TOWERIQ_HOOK_METADATA\n(.*?)\n\*/", file_content, re.DOTALL)
            if not match:
                continue

            json_str = match.group(1)
            try:
                metadata = json.loads(json_str)
                # Ensure fileName is present; if not, fill from actual filename
                metadata.setdefault("fileName", script_path.name)
                self.scripts.append(metadata)
            except Exception:
                # Ignore malformed metadata blocks
                continue

    def get_compatible_scripts(self, package_name: str, app_version: str) -> list:
        """
        Return scripts whose targetPackage matches and app_version is in supportedVersions.
        """
        compatible: List[Dict] = []
        for script in self.scripts:
            try:
                if (
                    script.get("targetPackage") == package_name
                    and app_version in (script.get("supportedVersions") or [])
                ):
                    compatible.append(script)
            except Exception:
                continue
        return compatible

    def get_available_scripts(self) -> List[Dict]:
        """
        Return all available scripts with their content loaded.
        """
        available_scripts = []
        for script in self.scripts:
            try:
                # Load the script content
                file_name = script.get("fileName", "")
                content = self.get_script_content(file_name)
                
                # Create a script object with content and compatibility info
                script_with_content = {
                    "id": file_name,
                    "name": script.get("scriptName", script.get("fileName", "Script")),
                    "description": script.get("scriptDescription", script.get("description", "No description available")),
                    "content": content,
                    "targetPackage": script.get("targetPackage", ""),
                    "targetApp": script.get("targetApp", ""),
                    "supportedVersions": script.get("supportedVersions", [])
                }
                available_scripts.append(script_with_content)
            except Exception:
                continue
        return available_scripts

    def get_script_content(self, file_name: str) -> str:
        """
        Read and return the content of the script by file name. Returns empty string if not found.
        """
        full_path = self.hooks_dir_path / file_name
        try:
            return full_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""
        except Exception:
            return ""

    def get_default_tower_script(self) -> Optional[Dict]:
        """
        Get the default script for The Tower game.
        
        Returns:
            Script dictionary with content if found, None otherwise
        """
        try:
            # First, discover all scripts
            self.discover_scripts()
            
            # Look for scripts targeting The Tower
            tower_scripts = []
            for script in self.scripts:
                target_package = script.get("targetPackage", "")
                if target_package == "com.TechTreeGames.TheTower":
                    tower_scripts.append(script)
            
            if not tower_scripts:
                return None
            
            # If multiple scripts found, prefer the one with "main" or "default" in the name
            # or just take the first one
            selected_script = tower_scripts[0]
            for script in tower_scripts:
                script_name = script.get("scriptName", "").lower()
                if "main" in script_name or "default" in script_name or "tower" in script_name:
                    selected_script = script
                    break
            
            # Load the script content
            file_name = selected_script.get("fileName", "")
            content = self.get_script_content(file_name)
            
            if not content:
                return None
            
            # Return the script with content
            return {
                "id": file_name,
                "name": selected_script.get("scriptName", selected_script.get("fileName", "The Tower Script")),
                "description": selected_script.get("scriptDescription", selected_script.get("description", "Default script for The Tower game")),
                "content": content,
                "targetPackage": selected_script.get("targetPackage", ""),
                "targetApp": selected_script.get("targetApp", ""),
                "supportedVersions": selected_script.get("supportedVersions", [])
            }
            
        except Exception:
            return None


