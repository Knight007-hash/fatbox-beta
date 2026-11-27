"""Source-agnostic fetch loop. Every source ends in the same place: an AES zip in the vault."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

import requests

from fatbox.fetch.meta import TYPE_GROUPS, Filters, prefilter as meta_prefilter  # noqa: F401 (re-exported)
from fatbox.static.basics import local_file_type
from fatbox.store import UNPACKED_CAP, SampleTooLarge, Store, read_sample_from_zip, sha256_bytes

log = logging.getLogger(__name__)

# SPEC F-1 / Limits. Checked in the VM too, not only by the host (the VM trusts no caller).
MAX_SAMPLES = 30
MIN_BUDGET_S, MAX_BUDGET_S = 60, 1800
MIN_START_S = 10   # with less time left than this, don't start another download
TOO_BIG = "too big to analyze (unpacks past {} MB, limit for this lab): {}"
UNPACK_LIMITS_MB = (25, 50, 100)   # 0.23.0: the zip-bomb guard can be set LOWER from the host, never higher or off

# 0.23.0: file-type choices the host may send (--types). Each one lists MalwareBazaar's labels for it and the
# label local_file_type() gives the real bytes (both are checked). Office documents and MSI installers are all
# OLE files, so the bytes say "doc" for each. Scripts (js/vbs) are left out: their bytes can't be recognised
# reliably, so they would be downloaded and then dropped.
ProgressFn = Callable[[int, int], None]  # (bytes_received, total_or_0)


class FetchError(Exception):
    pass


class AuthError(FetchError):
    """Bad/missing API key. Fatal for the run: retrying won't help."""


class Source(Protocol):
    name: str

    def list_candidates(self) -> list[dict]:
        """Normalised dicts: sha256 (required), file_type, file_size, file_name, signature, tags, first_seen."""

    def download_zip(self, sha256: str, zip_password: str, max_bytes: int, deadline_s: float,
                     progress: ProgressFn | None = None) -> bytes:
        """Return an AES zip (password zip_password) holding exactly the sample."""


@dataclass
class FetchStats:
    """What happened to every sample a fetch tried or wanted, for the one-line summary."""
    stored: int = 0
    too_big: int = 0
    wrong_type: int = 0
    failed: int = 0
    cut_off: int = 0         # download in progress when the time budget ran out (discarded)
    skipped_budget: int = 0  # wanted, but never started: no time left

    def summary(self, used_s: float) -> str:
        return (f"summary: {self.stored} stored, {self.too_big} too big, {self.wrong_type} wrong type, "
                f"{self.failed} failed, {self.cut_off} cut off, {self.skipped_budget} skipped (budget), "
                f"{used_s:.0f} s used")


def prefilter(item: dict, f: Filters, max_bytes: int, cap: int = UNPACKED_CAP) -> str | None:
    """Filter on metadata the source gave us. Returns a skip reason or None. The rules live in fetch.meta
    (no libraries), so the host's Browse list applies exactly the same ones (0.29.0)."""
    return meta_prefilter(item, f, max_bytes, cap)


def run_fetch(store: Store, source: Source, f: Filters, zip_password: str, max_bytes: int,
              deadline: float | None = None, stats: FetchStats | None = None, cap: int = UNPACKED_CAP,
              keep_info: bool = False) -> list[str]:
    """deadline: time.monotonic() value when the whole fetch must be over (shared by all sources).
    cap: the unpack limit (zip-bomb guard), at most UNPACKED_CAP. keep_info (0.23.0): a sample past the cap gets
    an index row with its metadata only (status too_big); the file itself is never kept."""
    cap = min(cap, UNPACKED_CAP)
    max_bytes = min(max_bytes, cap)
    mb = cap // (1024 * 1024)

    def too_big(item: dict, how: str) -> None:
        stats.too_big += 1
        if keep_info:
            size = item.get("file_size")
            store.add_info(item["sha256"], item, source.name,
                           f"too big ({how}, limit {mb} MB): not analysed, file not kept, sha256 from the feed (not checked)"
                           + (f"; listed size {size / (1024 * 1024):.0f} MB" if size else ""))
        log.info("%s %s", item["sha256"][:16], TOO_BIG.format(mb, "metadata kept" if keep_info else "skipped"))
    stats = stats if stats is not None else FetchStats()
    items = source.list_candidates()
    log.info("%s returned %d candidates", source.name, len(items))

    queue = []
    for item in items:
        sha = (item.get("sha256") or "").lower()
        if len(sha) != 64 or store.has(sha):
            continue
        why = prefilter(item, f, max_bytes, cap)
        if why == "too big to analyze":
            too_big({**item, "sha256": sha}, "listed size")
            continue
        if why:
            log.debug("skip %s (%s)", sha[:12], why)
            continue
        queue.append({**item, "sha256": sha})
    if f.small_first:
        queue.sort(key=lambda i: i.get("file_size") or 0)
    log.info("%d pass filters (types=%s, cap=%d MB); downloading up to %d",
             len(queue), f.file_types or "any", max_bytes // (1024 * 1024), f.max_per_run)

    added: list[str] = []
    attempts = queue[:f.max_attempts]
    for i, item in enumerate(attempts):
        if len(added) >= f.max_per_run:
            break
        left = None if deadline is None else deadline - time.monotonic()
        if left is not None and left < MIN_START_S:
            stats.skipped_budget += min(len(attempts) - i, f.max_per_run - len(added))
            log.info("time budget used up: %d stored, %d skipped", len(added), stats.skipped_budget)
            break
        sha = item["sha256"]
        size = item.get("file_size")
        log.info("[%d/%d] %s %s %s%s", len(added) + 1, f.max_per_run, sha[:16],
                 f"{size / 1024:.0f} KB" if size else "size ?", item.get("signature") or "",
                 "" if left is None else f"  ({left:.0f} s left)")
        try:
            outcome, ftype, secs = fetch_one(store, source, item, zip_password, max_bytes, f.file_types,
                                             f.download_timeout if left is None else min(left, f.download_timeout),
                                             cap=cap)
            if outcome == "stored":
                added.append(sha)
                stats.stored += 1
                log.info("  stored (%s, %.1fs)", ftype, secs)
            else:
                stats.wrong_type += 1
                log.info("  dropped: real type is %s", ftype)
        except AuthError:
            raise
        except SampleTooLarge:
            too_big(item, "unpacked")
        except FETCH_ERRORS as e:
            if deadline is not None and time.monotonic() >= deadline - 1:
                stats.cut_off += 1
                log.info("  cut off: the time budget ran out mid-download (partial file discarded)")
            else:
                stats.failed += 1
                log.warning("  FAILED %s: %s", sha[:16], e)
        finally:
            if i + 1 < len(attempts) and len(added) < f.max_per_run:  # 0.39.0: no polite pause after the last one
                pause = f.delay_seconds if deadline is None else min(f.delay_seconds, max(0.0, deadline - time.monotonic()))
                time.sleep(pause)
    return added


FETCH_ERRORS = (FetchError, SampleTooLarge, requests.RequestException, ValueError, RuntimeError)  # GUI uses it


def fetch_one(store: Store, source: Source, item: dict, zip_password: str, max_bytes: int,
              file_types: list[str], deadline_s: float, progress: ProgressFn | None = None,
              cap: int = UNPACKED_CAP) -> tuple[str, str, float]:
    """Download, verify and vault one sample. Returns (stored|dropped, real_file_type, seconds)."""
    sha = item["sha256"]
    t0 = time.monotonic()
    zip_bytes = source.download_zip(sha, zip_password, max_bytes, deadline_s, progress)
    # The download cap (max_bytes) bounds what crosses the network; unpacking has its own fixed cap.
    _, data = read_sample_from_zip(zip_bytes, zip_password, min(cap, UNPACKED_CAP))
    if sha256_bytes(data) != sha:
        raise FetchError("sha256 mismatch after download")
    # Authoritative type from the bytes themselves; source labels are often missing or coarse.
    ftype = local_file_type(data)
    del data
    if file_types and ftype not in {t.lower() for t in file_types}:
        return "dropped", ftype, time.monotonic() - t0
    store.add(sha, zip_bytes, {**item, "file_type": ftype}, source=source.name)
    return "stored", ftype, time.monotonic() - t0
