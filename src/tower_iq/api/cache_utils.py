"""
Device caching utilities for the API.
Reduces duplicate device discovery calls with short-lived cache.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional


class DeviceCache:
    """Encapsulates device caching state with proper lifecycle management."""
    
    def __init__(self, cache_duration: int = 5):
        self._cache_data: Optional[List[Dict[str, Any]]] = None
        self._cache_timestamp: Optional[datetime] = None
        self._cache_duration = cache_duration  # seconds
        self._lock: Optional[asyncio.Lock] = None
    
    def _get_lock(self) -> asyncio.Lock:
        """Lazily create lock in the current event loop."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock
    
    async def get_cached_devices(self, controller, logger, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """Get devices with caching to reduce duplicate discovery calls."""
        async with self._get_lock():
            now = datetime.now()

            # Check if cache is valid and not expired
            cache_valid = (
                not force_refresh and
                self._cache_data is not None and
                self._cache_timestamp is not None and
                (now - self._cache_timestamp).total_seconds() < self._cache_duration
            )

            if cache_valid:
                # Type narrowing: we know these are not None because of cache_valid check
                assert self._cache_timestamp is not None
                assert self._cache_data is not None
                
                if logger:
                    logger.debug("Using cached device list",
                               cache_age=(now - self._cache_timestamp).total_seconds(),
                               device_count=len(self._cache_data))
                return self._cache_data.copy()  # Return a copy to prevent modification

            # Cache miss or expired - fetch fresh data
            if logger:
                cache_reason = "forced refresh" if force_refresh else "cache miss/expired"
                logger.debug("Fetching fresh device list", reason=cache_reason)

            if not controller:
                raise RuntimeError("Backend not initialized")

            # Use the simplified device discovery method
            devices = await controller.emulator_service.discover_devices(clear_cache=force_refresh)

            # Convert Device objects to dictionaries for JSON serialization
            device_dicts = []
            for device in devices:
                device_dicts.append({
                    'id': device.serial,  # Use serial as ID for frontend compatibility
                    'name': device.device_name or device.model,
                    'type': device.device_type,
                    'status': device.status,
                    'serial': device.serial,
                    'model': device.model,
                    'device_name': device.device_name,
                    'brand': device.brand,
                    'android_version': device.android_version,
                    'api_level': device.api_level,
                    'architecture': device.architecture,
                    'is_network_device': device.is_network_device,
                    'ip_address': device.ip_address,
                    'port': device.port
                })

            # Update cache
            self._cache_data = device_dicts
            self._cache_timestamp = now

            if logger:
                logger.debug("Device list cached", device_count=len(device_dicts))

            return device_dicts.copy()


# Global cache instance
_device_cache = DeviceCache()


async def get_cached_devices(controller, logger, force_refresh: bool = False) -> List[Dict[str, Any]]:
    """Get devices with caching to reduce duplicate discovery calls."""
    return await _device_cache.get_cached_devices(controller, logger, force_refresh)


async def get_device_by_id(controller, logger, device_id: str, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
    """Get a specific device by ID using cached results when possible."""
    device_dicts = await _device_cache.get_cached_devices(controller, logger, force_refresh=force_refresh)
    return next((d for d in device_dicts if d['serial'] == device_id), None)


def device_dict_to_device_object(device_dict: Dict[str, Any]):
    """Convert a device dictionary back to a Device object for compatibility."""
    # Import here to avoid circular imports
    from ..services.emulator_service import Device

    return Device(
        serial=device_dict['serial'],
        model=device_dict['model'],
        android_version=device_dict['android_version'],
        api_level=device_dict['api_level'],
        architecture=device_dict['architecture'],
        status=device_dict['status'],
        is_network_device=device_dict['is_network_device'],
        brand=device_dict.get('brand'),
        device_name=device_dict.get('device_name'),
        ip_address=device_dict.get('ip_address'),
        port=device_dict.get('port')
    )

