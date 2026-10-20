import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request

from app.config import settings

# In-memory store: fine for one process. Several workers would each keep their own
# counters, so a production deployment would move this to Redis.
_hits: dict[tuple[str, str], deque] = defaultdict(deque)
_lock = Lock()


def reset_limits() -> None:
    with _lock:
        _hits.clear()


def rate_limit(name: str, limit: int, window_seconds: int):
    def dependency(request: Request) -> None:
        if not settings.rate_limit_enabled:
            return
        # Use the direct peer address. X-Forwarded-For is NOT trusted, because a client
        # can fake it. Behind a real proxy, configure a trusted-proxy setting instead.
        ip = request.client.host if request.client else "unknown"
        key = (name, ip)
        now = time.monotonic()
        with _lock:
            hits = _hits[key]
            while hits and hits[0] <= now - window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                retry_after = max(1, int(window_seconds - (now - hits[0])) + 1)
                raise HTTPException(
                    status_code=429,
                    detail="Too many requests",
                    headers={"Retry-After": str(retry_after)},
                )
            hits.append(now)

    return dependency
