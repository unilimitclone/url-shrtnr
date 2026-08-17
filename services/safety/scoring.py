"""CreationPatternScorer — L1: the signal no external feed can see.

Fixed-window Redis counters over link CREATION (the hotness detector's
math pointed at creates instead of clicks): creates per destination
registrable domain and creates per creator IP hash, each at a burst
window (minutes) and a daily window. A counter crossing its threshold —
exact equality, so each window fires exactly once — pushes the
destination into the same analyzer the reports feed (`trigger="pattern"`).
IP crossings have no single destination, so they surface as an operator
review notification; folding creators into a ban ladder is a later slice.

Counters live on the QUEUE Redis (noeviction): the cache Redis runs
allkeys-lru and would silently evict them. No queue Redis means scoring
is a no-op — pattern detection is an enhancement, never a dependency.
Everything here is best-effort by contract: record_create never raises
and never blocks a write.

Thresholds are private tuning (SAFETY_L1_* env vars, never committed):
calibrate by replaying past campaigns against candidate values.
"""

from __future__ import annotations

import hashlib
import time

from infrastructure.logging import get_logger
from infrastructure.ops_notify import OpsNotifier
from services.safety.events import SafetyAnalyzeEvent
from services.safety.sinks import SafetySink

log = get_logger(__name__)

_DAILY_WINDOW = 86_400


def _hash_ip(ip: str) -> str:
    """Raw IPs never land in Redis keys."""
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


class CreationPatternScorer:
    def __init__(
        self,
        redis_client,
        sink: SafetySink,
        notifier: OpsNotifier,
        *,
        burst_window_seconds: int = 600,
        domain_burst_threshold: int = 50,
        domain_daily_threshold: int = 300,
        ip_burst_threshold: int = 40,
        ip_daily_threshold: int = 200,
    ) -> None:
        self._redis = redis_client
        self._sink = sink
        self._notifier = notifier
        self._burst_window = burst_window_seconds
        self._thresholds = {
            ("dom", burst_window_seconds): domain_burst_threshold,
            ("dom", _DAILY_WINDOW): domain_daily_threshold,
            ("ip", burst_window_seconds): ip_burst_threshold,
            ("ip", _DAILY_WINDOW): ip_daily_threshold,
        }

    async def record_create(
        self,
        url: str,
        host: str,
        registrable_domain: str,
        client_ip: str | None,
    ) -> None:
        """Count one successful create; act on any threshold crossing."""
        if self._redis is None or not registrable_domain:
            return
        try:
            counts = await self._bump(registrable_domain, client_ip)
        except Exception as exc:
            log.warning(
                "l1_scoring_failed", error=str(exc), error_type=type(exc).__name__
            )
            return
        for (family, window), count in counts.items():
            # Exact equality: each window fires exactly once (hotness
            # precedent); a sustained campaign re-fires each new window.
            if count != self._thresholds[(family, window)]:
                continue
            if family == "dom":
                await self._on_domain_burst(
                    url, host, registrable_domain, window, count
                )
            else:
                await self._on_ip_burst(url, client_ip, window, count)

    async def _bump(
        self, registrable_domain: str, client_ip: str | None
    ) -> dict[tuple[str, int], int]:
        now = int(time.time())
        keys: list[tuple[str, int, str]] = []
        for window in (self._burst_window, _DAILY_WINDOW):
            bucket = now // window
            keys.append(
                ("dom", window, f"l1:dom:{window}:{registrable_domain}:{bucket}")
            )
        if client_ip:
            ip_hash = _hash_ip(client_ip)
            for window in (self._burst_window, _DAILY_WINDOW):
                bucket = now // window
                keys.append(("ip", window, f"l1:ip:{window}:{ip_hash}:{bucket}"))
        pipe = self._redis.pipeline(transaction=False)
        for _, window, key in keys:
            pipe.incr(key)
            # 2x window: inspectable after the window closes, self-decaying.
            pipe.expire(key, window * 2)
        results = await pipe.execute()
        return {
            (family, window): int(results[i * 2])
            for i, (family, window, _) in enumerate(keys)
        }

    async def _on_domain_burst(
        self, url: str, host: str, registrable_domain: str, window: int, count: int
    ) -> None:
        log.warning(
            "l1_domain_burst",
            registrable_domain=registrable_domain,
            window_seconds=window,
            creates=count,
        )
        # Same pipe as reports: analyzer -> verdict -> enforcement/review.
        await self._sink.emit(
            SafetyAnalyzeEvent(
                url=url,
                host=host,
                registrable_domain=registrable_domain,
                trigger="pattern",
                context={"window_seconds": window, "creates": count},
            )
        )

    async def _on_ip_burst(
        self, url: str, client_ip: str | None, window: int, count: int
    ) -> None:
        ip_hash = _hash_ip(client_ip) if client_ip else "unknown"
        log.warning(
            "l1_ip_burst", ip_hash=ip_hash, window_seconds=window, creates=count
        )
        # No single destination to judge — surface the creator to a human.
        # (Automated creator action is the ban-ladder slice.)
        await self._notifier.safety_review(
            host=f"creator {ip_hash}",
            trigger="pattern",
            sample_url=url,
            context={
                "ip_hash": ip_hash,
                "creates": count,
                "window_seconds": window,
            },
        )
