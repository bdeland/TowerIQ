"""Utility helpers for working with TCP ports.

These helpers are used during application start-up to locate an available
network port for the backend server. They prefer user-configured ports when
possible, but gracefully fall back to any free ephemeral port to avoid
start-up failures when the preferred port is already in use.
"""

from __future__ import annotations

import contextlib
import socket
from typing import Iterable, Optional

DEFAULT_BIND_HOST = "127.0.0.1"


def _normalize_host(host: Optional[str]) -> str:
    """Return a usable bind host string, defaulting to localhost."""
    if not host:
        return DEFAULT_BIND_HOST
    host = host.strip()
    if host in {"", "*"}:
        return "0.0.0.0"
    return host


def is_port_available(port: int, host: Optional[str] = None) -> bool:
    """Return True if the given TCP port can be bound on the requested host.

    A small TCP socket is bound and closed immediately. If binding fails with
    an "address already in use" style error, the port is considered busy.
    """
    bind_host = _normalize_host(host)

    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as test_socket:
        # Ensure the OS releases the port immediately when the socket closes
        test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if bind_host == "0.0.0.0":
            # When binding to all interfaces, try the IPv4 unspecified address first.
            bind_address = ("", port)
        else:
            bind_address = (bind_host, port)

        try:
            test_socket.bind(bind_address)
        except OSError:
            return False

    return True


def find_available_port(
    preferred_ports: Optional[Iterable[int]] = None,
    host: Optional[str] = None,
) -> int:
    """Return an open TCP port.

    Args:
        preferred_ports: Optional iterable of ports to try first, in order.
        host: Optional host/interface the eventual server will bind to.

    Raises:
        RuntimeError: If no port can be reserved.
    """
    bind_host = _normalize_host(host)

    # Try configured/preferred ports first so existing URLs continue working.
    if preferred_ports:
        for port in preferred_ports:
            if port and port > 0 and port < 65536 and is_port_available(port, bind_host):
                return port

    # Fall back to asking the OS for any ephemeral port.
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as temp_socket:
        if bind_host == "0.0.0.0":
            bind_address = ("", 0)
        else:
            bind_address = (bind_host, 0)

        try:
            temp_socket.bind(bind_address)
        except OSError as exc:  # pragma: no cover - extremely unlikely
            raise RuntimeError("Unable to locate an available TCP port") from exc

        port = temp_socket.getsockname()[1]

    if not port:
        raise RuntimeError("Operating system did not supply a port")

    return port
