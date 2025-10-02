"""
Device caching utilities for the API.
Reduces duplicate device discovery calls with short-lived cache.
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime


# Shared device cache for Phase 1.3 of duplication fix
_device_cache_data: Optional[List[Dict[str, Any]]] = None
_device_cache_timestamp: Optional[datetime] = None
_device_cache_duration = 5  # seconds
_device_cache_lock = asyncio.Lock()


async def get_cached_devices(controller, logger, force_refresh: bool = False) -> List[Dict[str, Any]]:
    """Get devices with caching to reduce duplicate discovery calls."""
    global _device_cache_data, _device_cache_timestamp, _device_cache_duration, _device_cache_lock

    async with _device_cache_lock:
        now = datetime.now()

        # Check if cache is valid and not expired
        cache_valid = (
            not force_refresh and
            _device_cache_data is not None and
            _device_cache_timestamp is not None and
            (now - _device_cache_timestamp).total_seconds() < _device_cache_duration
        )

        if cache_valid:
            # Type narrowing: we know these are not None because of cache_valid check
            assert _device_cache_timestamp is not None
            assert _device_cache_data is not None
            
            if logger:
                logger.debug("Using cached device list",
                           cache_age=(now - _device_cache_timestamp).total_seconds(),
                           device_count=len(_device_cache_data))
            return _device_cache_data.copy()  # Return a copy to prevent modification

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
        _device_cache_data = device_dicts
        _device_cache_timestamp = now

        if logger:
            logger.debug("Device list cached", device_count=len(device_dicts))

        return device_dicts.copy()


async def get_device_by_id(controller, logger, device_id: str, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
    """Get a specific device by ID using cached results when possible."""
    device_dicts = await get_cached_devices(controller, logger, force_refresh=force_refresh)
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

