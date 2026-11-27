from __future__ import annotations

import logging
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from fatbox import __version__
from fatbox.fetch.common import FetchError, ProgressFn

log = logging.getLogger("fatbox.fetch")

CONNECT_TIMEOUT = 15     # seconds to establish TCP/TLS
STALL_SECONDS = 45       # no bytes received for this long -> abort (also the socket read timeout)
PROGRESS_EVERY = 5.0     # seconds between progress lines


def make_session(user_agent: str = f"FatBox/{__version__} (research lab)") -> requests.Session:
    """Retries only connect failures and 429/5xx (honours Retry-After).
    Read timeouts are NOT retried: on a slow link a silent retry loop looks exactly like a hang."""
    retry = Retry(
        total=3, connect=3, read=0, status=3, other=0,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    s = requests.Session()
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers["User-Agent"] = user_agent
    return s


def timeouts(stall_seconds: float = STALL_SECONDS) -> tuple[float, float]:
    return (CONNECT_TIMEOUT, stall_seconds)


def stall_within(deadline_s: float) -> float:
    """The socket read timeout for a download with deadline_s left: a silent connection must not keep it
    alive past the fetch's time budget (the deadline check in stream_body only runs when bytes arrive)."""
    return max(1.0, min(STALL_SECONDS, deadline_s))


def _fmt(n: float) -> str:
    return f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / 1024 / 1024:.2f} MB"


def stream_body(r: requests.Response, max_bytes: int, label: str, deadline_s: float,
                stall_seconds: float = STALL_SECONDS, progress: ProgressFn | None = None) -> bytes:
    """Read a streamed response with progress logging, a size cap, a stall guard and an overall deadline."""
    total = int(r.headers.get("Content-Length") or 0) if hasattr(r, "headers") else 0
    if total > max_bytes:
        r.close()
        raise FetchError(f"{label}: {_fmt(total)} exceeds cap {_fmt(max_bytes)}")
    buf = bytearray()
    start = last_log = time.monotonic()
    try:
        for chunk in r.iter_content(16384):
            buf += chunk
            if progress:
                progress(len(buf), total)
            now = time.monotonic()
            if len(buf) > max_bytes:
                raise FetchError(f"{label}: exceeded cap {_fmt(max_bytes)}")
            if now - start > deadline_s:
                raise FetchError(f"{label}: gave up after {deadline_s:.0f}s at {_fmt(len(buf))} "
                                 f"({len(buf) / (now - start) / 1024:.1f} KB/s)")
            if now - last_log >= PROGRESS_EVERY:
                pct = f" / {_fmt(total)} ({100 * len(buf) / total:.0f}%)" if total else ""
                log.info("  %s: %s%s, %.1f KB/s, %.0fs", label, _fmt(len(buf)), pct,
                         len(buf) / (now - start) / 1024, now - start)
                last_log = now
    except requests.exceptions.ConnectionError as e:  # urllib3 read timeout surfaces here mid-stream
        raise FetchError(f"{label}: stalled, no data for {stall_seconds:.0f}s after {_fmt(len(buf))} ({e.__class__.__name__})")
    finally:
        r.close()
    elapsed = time.monotonic() - start
    log.info("  %s: done, %s in %.1fs", label, _fmt(len(buf)), elapsed)
    return bytes(buf)
