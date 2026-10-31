"""Write-path abuse limits for a public hub.

Writes need no account (ADR 0005), so the hub bounds them per client address with a token bucket
and caps the number of projects. Reads are not limited here (put a CDN or proxy in front).
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    writes_per_minute: float = 120.0   # entries + blob uploads + cosignatures per client
    burst: int = 60
    projects_per_hour: float = 20.0    # project creations per client (refill rate)
    project_burst: int = 10            # a lab behind one NAT address sets up several at once
    max_projects: int = 100_000        # hub-wide


class TokenBuckets:
    """Per-key token buckets with bounded memory (least-recently-used keys are evicted; an
    evicted key simply starts again with a full bucket)."""

    def __init__(self, rate_per_sec: float, burst: float, max_keys: int = 100_000):
        self.rate, self.burst, self.max_keys = rate_per_sec, burst, max_keys
        self._state: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, last = self._state.pop(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            allowed = tokens >= 1
            self._state[key] = (tokens - 1 if allowed else tokens, now)  # most recent at end
            while len(self._state) > self.max_keys:
                self._state.popitem(last=False)
            return allowed


def client_key(address: str) -> str:
    """Rate-limit identity: IPv4 address, or the /64 for IPv6 (one host owns a whole /64)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)
