"""Core exception types used across TowerIQ modules."""

from __future__ import annotations

from typing import Optional


class DeviceConnectionError(Exception):
    """Raised when ADB reports an abnormal device connection state."""

    def __init__(
        self,
        device_serial: str,
        reason: str,
        *,
        status: Optional[str] = None,
        details: Optional[str] = None,
    ) -> None:
        self.device_serial = device_serial
        self.reason = reason
        self.status = status
        self.details = details

        status_part = f" status={status}" if status else ""
        details_part = f" details={details}" if details else ""
        message = (
            f"Device connection error for {device_serial}: {reason}" + status_part + details_part
        )

        super().__init__(message)


__all__ = ["DeviceConnectionError"]

