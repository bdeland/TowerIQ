"""
TowerIQ v1.0 - Asset Management

This module provides utilities for accessing bundled application assets like icons,
ensuring they work correctly when bundled into a PyInstaller executable.
"""

import sys
from pathlib import Path
from typing import Optional


def get_asset_path(asset_name: str) -> str:
    """
    Resolve the path to a bundled asset.
    
    This function handles both development (running from source) and production
    (PyInstaller bundle) environments to correctly locate asset files.
    
    Args:
        asset_name: The name/path of the asset relative to the assets directory
                   (e.g., "icons/connected.svg", "images/logo.png")
    
    Returns:
        Absolute path to the asset file as a string
        
    Raises:
        FileNotFoundError: If the asset file doesn't exist
    """
    # Check if running in a PyInstaller bundle
    if getattr(sys, '_MEIPASS', None):  # type: ignore[attr-defined]
        # Running in PyInstaller bundle
        bundle_dir = Path(sys._MEIPASS)  # type: ignore[attr-defined]
        asset_path = bundle_dir / "resources" / "assets" / asset_name
    else:
        # Running from source - find the project root
        # This file is in src/tower_iq/gui/assets.py
        current_file = Path(__file__)
        project_root = current_file.parent.parent.parent.parent
        asset_path = project_root / "resources" / "assets" / asset_name
    
    # Convert to string and verify the file exists
    asset_path_str = str(asset_path)
    
    if not asset_path.exists():
        raise FileNotFoundError(f"Asset not found: {asset_name} (looked in: {asset_path})")
    
    return asset_path_str


def get_icon_path(icon_name: str) -> str:
    """
    Convenience function to get an icon path.
    
    Args:
        icon_name: The icon filename (e.g., "connected.svg", "logo.png")
    
    Returns:
        Absolute path to the icon file
    """
    return get_asset_path(f"icons/{icon_name}")


def get_image_path(image_name: str) -> str:
    """
    Convenience function to get an image path.
    
    Args:
        image_name: The image filename (e.g., "background.jpg", "splash.png")
    
    Returns:
        Absolute path to the image file
    """
    return get_asset_path(f"images/{image_name}")


def list_available_assets() -> dict:
    """
    List all available assets in the assets directory.
    
    Returns:
        Dictionary with asset categories as keys and lists of filenames as values
    """
    assets = {"icons": [], "images": [], "other": []}
    
    try:
        # Determine base assets directory
        if getattr(sys, '_MEIPASS', None):  # type: ignore[attr-defined]
            assets_dir = Path(sys._MEIPASS) / "resources" / "assets"  # type: ignore[attr-defined]
        else:
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent.parent
            assets_dir = project_root / "resources" / "assets"
        
        if assets_dir.exists():
            # Scan for icons
            icons_dir = assets_dir / "icons"
            if icons_dir.exists():
                assets["icons"] = [f.name for f in icons_dir.iterdir() if f.is_file()]
            
            # Scan for images
            images_dir = assets_dir / "images"
            if images_dir.exists():
                assets["images"] = [f.name for f in images_dir.iterdir() if f.is_file()]
            
            # Scan for other assets
            for item in assets_dir.iterdir():
                if item.is_file():
                    assets["other"].append(item.name)
                elif item.is_dir() and item.name not in ["icons", "images"]:
                    subdir_files = [f"{item.name}/{f.name}" for f in item.iterdir() if f.is_file()]
                    assets["other"].extend(subdir_files)
    
    except Exception:
        # Return empty dict if there's any error accessing the assets
        pass
    
    return assets


def asset_exists(asset_name: str) -> bool:
    """
    Check if an asset file exists.
    
    Args:
        asset_name: The name/path of the asset relative to the assets directory
    
    Returns:
        True if the asset exists, False otherwise
    """
    try:
        get_asset_path(asset_name)
        return True
    except FileNotFoundError:
        return False


def get_asset_path_safe(asset_name: str, fallback: Optional[str] = None) -> Optional[str]:
    """
    Safely get an asset path without raising exceptions.
    
    Args:
        asset_name: The name/path of the asset relative to the assets directory
        fallback: Optional fallback asset name to try if the primary asset is not found
    
    Returns:
        Path to the asset if found, path to fallback if provided and found, None otherwise
    """
    try:
        return get_asset_path(asset_name)
    except FileNotFoundError:
        if fallback:
            try:
                return get_asset_path(fallback)
            except FileNotFoundError:
                pass
        return None


# Predefined asset paths for commonly used assets
class CommonAssets:
    """
    Predefined paths for commonly used assets.
    
    This class provides easy access to frequently used assets with
    fallback handling for missing files.
    """
    
    @staticmethod
    def app_icon() -> Optional[str]:
        """Get the main application icon."""
        return get_asset_path_safe("icons/toweriq_icon.png", "icons/default_icon.png")
    
    @staticmethod
    def connected_icon() -> Optional[str]:
        """Get the connected status icon."""
        return get_asset_path_safe("icons/connected.svg", "icons/status_green.png")
    
    @staticmethod
    def disconnected_icon() -> Optional[str]:
        """Get the disconnected status icon."""
        return get_asset_path_safe("icons/disconnected.svg", "icons/status_red.png")
    
    @staticmethod
    def loading_icon() -> Optional[str]:
        """Get the loading/processing icon."""
        return get_asset_path_safe("icons/loading.svg", "icons/status_yellow.png")
    
    @staticmethod
    def warning_icon() -> Optional[str]:
        """Get the warning icon."""
        return get_asset_path_safe("icons/warning.svg", "icons/status_orange.png")
    
    @staticmethod
    def error_icon() -> Optional[str]:
        """Get the error icon."""
        return get_asset_path_safe("icons/error.svg", "icons/status_red.png")


# Module-level convenience functions using CommonAssets
def get_app_icon() -> Optional[str]:
    """Get the main application icon path."""
    return CommonAssets.app_icon()


def get_status_icon(status: str) -> Optional[str]:
    """
    Get a status icon based on status string.
    
    Args:
        status: Status string ("connected", "disconnected", "loading", "warning", "error")
    
    Returns:
        Path to appropriate status icon or None if not found
    """
    status_map = {
        "connected": CommonAssets.connected_icon,
        "disconnected": CommonAssets.disconnected_icon,
        "loading": CommonAssets.loading_icon,
        "warning": CommonAssets.warning_icon,
        "error": CommonAssets.error_icon
    }
    
    icon_func = status_map.get(status.lower())
    return icon_func() if icon_func else None 