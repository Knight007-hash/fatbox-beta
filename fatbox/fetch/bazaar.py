"""MalwareBazaar (https://bazaar.abuse.ch/api/). Free Auth-Key from https://auth.abuse.ch/."""
from __future__ import annotations

import json
import logging

import requests

from fatbox.fetch.common import AuthError, FetchError
from fatbox.fetch.http import STALL_SECONDS, make_session, stall_within, stream_body, timeouts

API_URL = "https://mb-api.abuse.ch/api/v1/"

# mode -> (api query, parameter carrying query_value)
LIST_QUERIES = {
    "tag": ("get_taginfo", "tag"),
    "signature": ("get_siginfo", "signature"),
    "file_type": ("get_file_type", "file_type"),
}
EMPTY_STATUSES = {"no_results", "tag_not_found", "signature_not_found", "no_data", "illegal_file_type"}


class BazaarSource:
    name = "malwarebazaar"

    def __init__(self, api_key: str, mode: str = "recent", value: str = "", limit: int = 100,
                 session: requests.Session | None = None):
        if not api_key:
            raise AuthError("MalwareBazaar API key missing: set MB_API_KEY or [bazaar].api_key")
        if mode in LIST_QUERIES and not value:
            raise FetchError(f"mode '{mode}' needs a value (--value)")
        if mode not in LIST_QUERIES and mode not in ("recent", "latest"):
            raise FetchError(f"unknown bazaar mode: {mode}")
        self.mode, self.value, self.limit = mode, value, limit
        self.s = session or make_session()
        self.s.headers["Auth-Key"] = api_key

    def _post(self, data: dict, stream: bool = False, stall: float = STALL_SECONDS) -> requests.Response:
        r = self.s.post(API_URL, data=data, timeout=timeouts(stall), stream=stream)
        if r.status_code in (401, 403):
            raise AuthError(f"MalwareBazaar rejected the Auth-Key (HTTP {r.status_code})")
        r.raise_for_status()
        return r

    def list_candidates(self) -> list[dict]:
        if self.mode == "recent":
            payload = {"query": "get_recent", "selector": "time"}   # everything from the last 60 min
        elif self.mode == "latest":
            payload = {"query": "get_recent", "selector": "100"}    # newest 100, regardless of age
        else:
            query, param = LIST_QUERIES[self.mode]
            payload = {"query": query, param: self.value, "limit": str(self.limit)}
        body = self._post(payload).json()
        status = body.get("query_status")
        if status in ("unknown_auth_key", "user_blacklisted"):
            raise AuthError(f"MalwareBazaar: {status}")
        if status in EMPTY_STATUSES:
            return []
        if status != "ok":
            raise FetchError(f"MalwareBazaar list query failed: {status}")
        return [_row(d) for d in body.get("data") or []]

    def info(self, sha256: str) -> dict | None:
        """Metadata of one sample (get_info): signature, tags, size... None if MalwareBazaar doesn't know it."""
        body = self._post({"query": "get_info", "hash": sha256}).json()
        status = body.get("query_status")
        if status in ("unknown_auth_key", "user_blacklisted"):
            raise AuthError(f"MalwareBazaar: {status}")
        data = body.get("data") or []
        return _row(data[0]) if status == "ok" and data and isinstance(data[0], dict) else None

    def download_zip(self, sha256: str, zip_password: str, max_bytes: int, deadline_s: float = 300,
                     progress=None) -> bytes:
        if zip_password != "infected":  # 0.19.2: checked before downloading, not after
            raise FetchError("MalwareBazaar zips use password 'infected'; set [vault].zip_password accordingly")
        stall = stall_within(deadline_s)
        r = self._post({"query": "get_file", "sha256_hash": sha256}, stream=True, stall=stall)
        # zip overhead is small; allow a little headroom over the sample cap
        body = stream_body(r, max_bytes + 65536, sha256[:16], deadline_s, stall_seconds=stall, progress=progress)
        if not body.startswith(b"PK"):
            try:
                status = json.loads(body).get("query_status")
            except ValueError:
                status = body[:120]
            if status in ("unknown_auth_key", "user_blacklisted"):
                raise AuthError(f"MalwareBazaar: {status}")
            raise FetchError(f"get_file {sha256[:16]}: {status}")
        return body


class PickedSource:
    """T-13: exactly the sha256s the user picked in the host GUI, nothing else. Metadata comes from get_info
    (one small query each); if that fails the sample is still downloaded and checked against its sha256."""

    def __init__(self, bazaar: BazaarSource, shas: list[str]):
        self.b, self.shas = bazaar, shas
        self.name = bazaar.name

    def list_candidates(self) -> list[dict]:
        out = []
        for sha in self.shas:
            try:
                meta = self.b.info(sha) or {}
            except AuthError:
                raise
            except Exception as e:  # metadata is nice to have; the sha256 check after download is what counts
                meta = {}
                logging.getLogger(__name__).info("%s: no metadata (%s)", sha[:16], type(e).__name__)
            out.append({**meta, "sha256": sha})
        return out

    def download_zip(self, *a, **kw) -> bytes:
        return self.b.download_zip(*a, **kw)


def _row(d: dict) -> dict:
    return {
        "sha256": d.get("sha256_hash"),
        "file_type": d.get("file_type"),
        "file_size": d.get("file_size"),
        "file_name": d.get("file_name"),
        "signature": d.get("signature"),
        "tags": d.get("tags") or [],
        "first_seen": d.get("first_seen"),
        "reporter": d.get("reporter"),
        "origin_country": d.get("origin_country"),
        "delivery_method": d.get("delivery_method"),
    }
