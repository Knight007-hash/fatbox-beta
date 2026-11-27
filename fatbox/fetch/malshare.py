"""MalShare (https://malshare.com/doc.php). Free API key on signup; daily quota (check with getlimit).

MalShare serves RAW binaries. They are wrapped into an AES zip in memory immediately, so plaintext
never touches disk, same invariant as every other source.
"""
from __future__ import annotations

import logging

import requests

from fatbox.fetch.common import AuthError, FetchError
from fatbox.fetch.http import STALL_SECONDS, make_session, stall_within, stream_body, timeouts
from fatbox.store import make_sample_zip

API_URL = "https://malshare.com/api.php"
# urllib3 logs every retry with the full URL ("Retrying ... /api.php?api_key=<key>&action=getlimit"), at WARNING.
URLLIB3_LOGGERS = ("urllib3.connectionpool", "urllib3.util.retry", "urllib3.connection")


class HideKey(logging.Filter):
    """0.19.3: blanks the MalShare key out of urllib3's own log lines (they reach the console and the host log)."""

    def __init__(self, key: str):
        super().__init__()
        self.key = key

    def filter(self, record: logging.LogRecord) -> bool:
        text = record.getMessage()
        if self.key in text:
            record.msg, record.args = text.replace(self.key, "<api_key>"), None
        return True


class MalShareSource:
    name = "malshare"

    def __init__(self, api_key: str, type_filter: str = "", session: requests.Session | None = None):
        if not api_key:
            raise AuthError("MalShare API key missing: set MALSHARE_API_KEY or [malshare].api_key")
        self.key, self.type_filter = api_key, type_filter
        self.s = session or make_session()
        for name in URLLIB3_LOGGERS:
            lg = logging.getLogger(name)
            for f in [f for f in lg.filters if isinstance(f, HideKey)]:
                lg.removeFilter(f)  # one key per process; never stack filters
            lg.addFilter(HideKey(api_key))

    def _get(self, action: str, _stall: float = STALL_SECONDS, **params) -> requests.Response:
        # MalShare wants the key in the URL, and requests puts the full URL in its error messages. Those reach the
        # host's activity log, so the key is blanked out of every message first (0.19.2).
        try:
            r = self.s.get(API_URL, params={"api_key": self.key, "action": action, **params},
                           timeout=timeouts(_stall), stream=action == "getfile")
            if r.status_code in (401, 403):
                raise AuthError(f"MalShare rejected the API key (HTTP {r.status_code})")
            if r.status_code == 429:
                raise AuthError("MalShare daily quota exhausted (HTTP 429)")
            r.raise_for_status()
        except requests.RequestException as e:
            raise FetchError(f"MalShare {action}: {type(e).__name__}: {self.hide(str(e))}") from None
        return r

    def hide(self, text: str) -> str:
        return text.replace(self.key, "<api_key>") if self.key else text

    def limits(self) -> dict:
        return self._get("getlimit").json()

    def list_candidates(self) -> list[dict]:
        # "type" = server-side type filter (names from action=gettypes, e.g. "PE32"); else everything from 24h.
        r = self._get("type", type=self.type_filter) if self.type_filter else self._get("getlist")
        try:
            rows = r.json()
        except ValueError:
            raise FetchError(f"MalShare list: unexpected response {r.text[:120]!r}")
        if isinstance(rows, dict):  # error payloads come back as objects
            raise FetchError(f"MalShare list error: {rows}")
        return [{"sha256": row.get("sha256")} for row in rows if isinstance(row, dict)]

    def download_zip(self, sha256: str, zip_password: str, max_bytes: int, deadline_s: float = 300,
                     progress=None) -> bytes:
        stall = stall_within(deadline_s)
        r = self._get("getfile", _stall=stall, hash=sha256)
        data = stream_body(r, max_bytes, sha256[:16], deadline_s, stall_seconds=stall, progress=progress)
        if data.startswith(b"Sample not found") or data.startswith(b"ERROR") or not data:
            raise FetchError(f"getfile {sha256[:16]}: {data[:80]!r}")
        return make_sample_zip(f"{sha256}.bin", data, zip_password)
