"""0.23.0: the GUI's Settings tab. Saved on the host, never in the VM:

    <host home>\\settings.json   {"version": 1, "fetch": {...}, "filters": {...}, "analysis": {...}, "big": {...}}

The host sends these values as allow-listed command options with each fetch and triage; the VM checks every
one again (it trusts no caller). The VM's config.toml is never edited from the GUI. API keys are not settings:
they stay in the VM and are never shown or typed in the browser.

The unpack limit is the SPEC zip-bomb guard: 25, 50 or 100 MB. It can go lower, never higher or off.
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from fatbox.host.library import _atomic_write

TYPES = ("exe", "dll", "office", "lnk", "elf", "pdf", "ps1")   # same keys as fatbox.fetch.meta.TYPE_GROUPS
NAME_RE = re.compile(r"^[A-Za-z0-9._\- ]{1,40}\Z")              # same rule as the VM's name_list
MAX_NAMES = 20
UNPACK_LIMITS_MB = (25, 50, 100)
MAX_BYTES = 64 * 1024


def defaults(sample_time_s: int = 60, capa_time_s: int = 120) -> dict:
    """Same values the GUI used before 0.23.0; the analysis times start from host.toml."""
    return {
        "fetch": {"max": 3, "size_limit": True, "max_size_mb": 5, "budget": 400, "small_first": True},
        "filters": {"types": ["exe", "dll"], "tags": [], "skip_families": [], "min_size_kb": 0},
        "analysis": {"sample_time_s": sample_time_s, "capa_time_s": capa_time_s, "parallel": 0, "capa_packed": "skip"},
        "big": {"unpack_limit_mb": 100, "too_big": "skip"},
    }


def _int(v, lo: int, hi: int, what: str) -> int:
    if isinstance(v, bool):
        raise ValueError(f"{what} must be a whole number {lo}..{hi}")
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be a whole number {lo}..{hi}")
    if n != v and not (isinstance(v, str) and v.strip().lstrip("-").isdigit()):
        raise ValueError(f"{what} must be a whole number {lo}..{hi}")
    if not lo <= n <= hi:
        raise ValueError(f"{what} must be {lo}..{hi}")
    return n


def _bool(v, what: str) -> bool:
    if not isinstance(v, bool):
        raise ValueError(f"{what} must be on or off")
    return v


def _choice(v, options, what: str):
    if v not in options:
        raise ValueError(f"{what} must be one of: {', '.join(map(str, options))}")
    return v


def _names(v, what: str) -> list[str]:
    if isinstance(v, str):
        v = [n for n in v.split(",")]
    if not isinstance(v, list):
        raise ValueError(f"{what}: a comma-separated list")
    out = []
    for n in v:
        if not isinstance(n, str):
            raise ValueError(f"{what}: names only")
        n = n.strip()
        if not n:
            continue
        if not NAME_RE.match(n):
            raise ValueError(f"{what}: '{n[:40]}' has characters other than letters, digits, . _ - and space (max 40)")
        if n.lower() not in (x.lower() for x in out):
            out.append(n)
    if len(out) > MAX_NAMES:
        raise ValueError(f"{what}: at most {MAX_NAMES} names")
    return out


def check(obj) -> dict:
    """A full, clean settings dict from untrusted input (the browser, or a damaged file). Raises ValueError
    with words for people on the first bad value."""
    if not isinstance(obj, dict):
        raise ValueError("settings must be an object")
    f, fl, a, b = (obj.get(k) for k in ("fetch", "filters", "analysis", "big"))
    if not all(isinstance(x, dict) for x in (f, fl, a, b)):
        raise ValueError("settings: missing a section")
    types = fl.get("types")
    if not isinstance(types, list) or not types or any(t not in TYPES for t in types):
        raise ValueError("File types: tick at least one")
    return {
        "fetch": {"max": _int(f.get("max"), 1, 30, "Samples per fetch"),
                  "size_limit": _bool(f.get("size_limit"), "Download limit"),
                  "max_size_mb": _int(f.get("max_size_mb"), 1, 100, "Download limit (MB)"),
                  "budget": _int(f.get("budget"), 60, 1800, "Time budget"),
                  "small_first": _bool(f.get("small_first"), "Smallest first")},
        "filters": {"types": [t for t in TYPES if t in types],
                    "tags": _names(fl.get("tags", []), "Only these tags"),
                    "skip_families": _names(fl.get("skip_families", []), "Never these families"),
                    "min_size_kb": _int(fl.get("min_size_kb"), 0, 10240, "Smallest file (KB)")},
        "analysis": {"sample_time_s": _int(a.get("sample_time_s"), 10, 300, "Time per sample"),
                     "capa_time_s": _int(a.get("capa_time_s"), 30, 600, "Extra time for capa"),
                     "parallel": _int(a.get("parallel"), 0, 10, "Samples at once"),
                     "capa_packed": _choice(a.get("capa_packed"), ("skip", "run"), "capa on packed programs")},
        "big": {"unpack_limit_mb": _choice(_int(b.get("unpack_limit_mb"), 25, 100, "Unpack limit"), UNPACK_LIMITS_MB,
                                           "Unpack limit (MB)"),
                "too_big": _choice(b.get("too_big"), ("skip", "info"), "When a sample is bigger")},
    }


class Prefs:
    def __init__(self, home: Path, sample_time_s: int = 60, capa_time_s: int = 120):
        self.path = Path(home) / "settings.json"
        self.base = defaults(sample_time_s, capa_time_s)
        self.lock = threading.RLock()
        self.notes: list[str] = []

    def load(self) -> dict:
        """The saved settings, or the defaults. A damaged file is never guessed at: defaults, plus a note."""
        with self.lock:
            if not self.path.exists():
                return json.loads(json.dumps(self.base))
            try:
                if self.path.stat().st_size > MAX_BYTES:
                    raise ValueError("too big")
                obj = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(obj, dict) or obj.get("version") != 1:
                    raise ValueError("not a FatBox settings file")
                return check(obj)
            except (OSError, ValueError) as e:
                note = f"settings.json is damaged ({e}): using the defaults until you save Settings again"
                if note not in self.notes:
                    self.notes.append(note)
                return json.loads(json.dumps(self.base))

    def save(self, obj) -> dict:
        clean = check(obj)
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(self.path, json.dumps({"version": 1, **clean}, indent=1))
        return clean

    def reset(self) -> dict:
        with self.lock:
            self.path.unlink(missing_ok=True)
        return self.load()

    def take_notes(self) -> list[str]:
        with self.lock:
            n, self.notes = self.notes, []
        return n


def browse_filters(p: dict):
    """0.29.0: the Settings filters as the VM's own Filters, so Browse hides what a fetch would skip: file type,
    tags, never-these families, smallest file, download limit and unpack limit. Same rules, same code (prefilter)."""
    from fatbox.fetch.meta import TYPE_GROUPS, Filters
    p = check(p)
    fl, f, b = p["filters"], p["fetch"], p["big"]
    cap = b["unpack_limit_mb"] * 1024 * 1024
    max_bytes = min(f["max_size_mb"] * 1024 * 1024, cap) if f["size_limit"] else cap
    types = [x for t in fl["types"] for x in TYPE_GROUPS[t]]
    return (Filters(file_types=types, tags_any=fl["tags"], signatures_none=fl["skip_families"],
                    min_size_kb=fl["min_size_kb"]), max_bytes, cap)


def fetch_flags(p: dict, picked: bool = False) -> list[str]:
    """The Settings part of a fetch command. Picks (Browse) are exact samples: type/tag/family/size filters
    don't apply to them, but the unpack limit and too-big rule always do."""
    p = check(p)
    fl, b = p["filters"], p["big"]
    out = []
    if not picked:
        out += ["--types", ",".join(fl["types"])]
        if fl["tags"]:
            out += ["--tags", ",".join(fl["tags"])]
        if fl["skip_families"]:
            out += ["--skip-families", ",".join(fl["skip_families"])]
        if fl["min_size_kb"]:
            out += ["--min-size-kb", str(fl["min_size_kb"])]
    out += ["--unpack-limit-mb", str(b["unpack_limit_mb"]), "--too-big", b["too_big"]]
    return out
