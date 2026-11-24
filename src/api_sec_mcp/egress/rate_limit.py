"""
Request budget and rate limiting (SPEC-004).

Three independent limits, checked in this order: total engagement budget, global
concurrency, per-host sliding window. Fail-fast: nothing here ever sleeps or queues.
Synchronous and await-free, so each check+reserve is atomic on the event loop.
"""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Callable
from enum import StrEnum

from api_sec_mcp.egress.scope_guard import ScopeConfig

_WINDOW_SECONDS = 60.0


class LimitKind(StrEnum):
    TOTAL_BUDGET = "TOTAL_BUDGET"
    CONCURRENCY = "CONCURRENCY"
    HOST_RATE = "HOST_RATE"


class RateLimitExceededError(Exception):
    """A limit was hit. Carries only a closed kind and a numeric retry hint (no target text)."""

    def __init__(self, kind: LimitKind, retry_after: int | None = None) -> None:
        self.kind = kind
        self.retry_after = retry_after
        msg = f"Rate limit exceeded: {kind.value}"
        if retry_after is not None:
            msg += f"; retry after {retry_after}s"
        super().__init__(msg)


class Lease:
    """A reserved slot. ``release`` frees concurrency; ``cancel`` also refunds the budget."""

    def __init__(self, limiter: RateLimiter, host: str, stamp: float) -> None:
        self._limiter = limiter
        self._host = host
        self._stamp = stamp
        self._done = False

    def release(self) -> None:
        if not self._done:
            self._done = True
            self._limiter._inflight -= 1

    def cancel(self) -> None:
        """Nothing was sent: free the slot and refund the budget/window entry."""
        if not self._done:
            self.release()
            self._limiter._used -= 1
            window = self._limiter._windows.get(self._host)
            if window and self._stamp in window:
                window.remove(self._stamp)


class RateLimiter:
    def __init__(
        self,
        config: ScopeConfig,
        clock: Callable[[], float] = time.monotonic,
        used: int = 0,
    ) -> None:
        self._max_total = config.max_requests_total
        self._max_host = config.max_requests_per_host_per_minute
        self._max_inflight = config.max_concurrent_requests
        self._clock = clock
        self._used = used
        self._inflight = 0
        self._windows: dict[str, deque[float]] = {}

    @property
    def used(self) -> int:
        return self._used

    @property
    def inflight(self) -> int:
        return self._inflight

    def _window(self, host: str, now: float) -> deque[float]:
        window = self._windows.setdefault(host.lower(), deque())
        while window and window[0] <= now - _WINDOW_SECONDS:
            window.popleft()
        return window

    def check_capacity(self, host: str, n: int = 1) -> None:
        """Raise if *n* more sequential requests to *host* would not fit. Reserves nothing."""
        now = self._clock()
        if self._used + n > self._max_total:
            raise RateLimitExceededError(LimitKind.TOTAL_BUDGET)
        if self._inflight >= self._max_inflight:
            raise RateLimitExceededError(LimitKind.CONCURRENCY, 1)
        window = self._window(host, now)
        overflow = len(window) + n - self._max_host
        if overflow > 0:
            if not window:
                retry = int(_WINDOW_SECONDS)
            else:
                oldest = window[min(overflow, len(window)) - 1]
                retry = max(1, math.ceil(oldest + _WINDOW_SECONDS - now))
            raise RateLimitExceededError(LimitKind.HOST_RATE, retry)

    def acquire(self, host: str) -> Lease:
        self.check_capacity(host, 1)
        now = self._clock()
        self._window(host, now).append(now)
        self._used += 1
        self._inflight += 1
        return Lease(self, host.lower(), now)
