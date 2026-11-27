"""T-8: which snapshot is the clean default, which ones FatBox checked, and whether auto-revert is on.

    <host home>\\snapshots.json   {"version": 1, "default": {name, uuid}, "checked": [...], "auto_revert": bool}

Host-written, but read back with checks like everything else: a damaged file means "no default from the
file" (host.toml's clean_snapshot is the fallback) and auto-revert OFF, never a guess. A snapshot is
recognised by its VirtualBox uuid, so a renamed one keeps its "checked" mark and a new snapshot that
reuses an old name doesn't get it.
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from fatbox.host.library import _atomic_write
from fatbox.host.vmctl import UUID_RE

VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
MAX_CHECKED = 200
MAX_BYTES = 256 * 1024
# 0.19.2: any name VirtualBox allows ("Snapshot 1" has a space). A snapshot is found by its uuid; the name is
# only shown (textContent), so it just has to be a short line without control characters.
NAME_RE = re.compile(r"[^\x00-\x1f\x7f]{1,200}")


def _entry(d) -> dict | None:
    if not isinstance(d, dict):
        return None
    name, uuid = d.get("name"), d.get("uuid")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name) or not isinstance(uuid, str) or not UUID_RE.match(uuid):
        return None
    out = {"name": name, "uuid": uuid.lower()}
    v, t = d.get("version"), d.get("taken")
    if isinstance(v, str) and VERSION_RE.match(v):
        out["version"] = v
    if isinstance(t, str) and len(t) <= 32 and re.match(r"^[0-9T:+\- Z]+$", t):
        out["taken"] = t
    return out


class SnapshotPrefs:
    def __init__(self, home: Path, fallback_name: str = ""):
        self.path = Path(home) / "snapshots.json"
        self.fallback_name = fallback_name   # host.toml clean_snapshot: used until a default is picked here
        self.lock = threading.RLock()
        self.notes: list[str] = []

    def load(self) -> dict:
        empty = {"default": None, "checked": [], "auto_revert": False}
        with self.lock:
            if not self.path.exists():
                return empty
            try:
                if self.path.stat().st_size > MAX_BYTES:
                    raise ValueError("too big")
                obj = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(obj, dict) or obj.get("version") != 1:
                    raise ValueError("not a FatBox snapshots file")
            except (OSError, ValueError, UnicodeDecodeError) as e:
                self.notes.append(f"snapshots.json is damaged ({e}): no default from it, auto-revert OFF")
                return empty
            raw = obj.get("checked") if isinstance(obj.get("checked"), list) else []
            checked = [c for c in (_entry(x) for x in raw[:MAX_CHECKED]) if c and "version" in c]
            return {"default": _entry(obj.get("default")), "checked": checked,
                    "auto_revert": obj.get("auto_revert") is True}

    def save(self, prefs: dict) -> None:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(self.path, json.dumps({"version": 1, **prefs}, indent=1))

    def update(self, **kw) -> dict:
        with self.lock:
            p = {**self.load(), **kw}
            self.save(p)
            return p

    def add_checked(self, name: str, uuid: str, version: str, taken: str) -> None:
        with self.lock:
            p = self.load()
            p["checked"] = [c for c in p["checked"] if c["uuid"] != uuid][-(MAX_CHECKED - 1):]
            p["checked"].append({"name": name, "uuid": uuid, "version": version, "taken": taken})
            p["default"] = {"name": name, "uuid": uuid}
            self.save(p)

    def take_notes(self) -> list[str]:
        with self.lock:
            out, self.notes = self.notes, []
        return out

    def view(self, rows: list[dict], current: str | None, host_version: str) -> dict:
        """Join VirtualBox's live list with what FatBox knows. Picks the default (by uuid; else host.toml's
        name) and says what's wrong with it, if anything."""
        p = self.load()
        checked = {c["uuid"]: c for c in p["checked"]}
        default = None
        if p["default"]:
            default = next((r for r in rows if r["uuid"] == p["default"]["uuid"]), None)
        elif self.fallback_name:
            default = next((r for r in rows if r["name"] == self.fallback_name), None)
        warning = None
        if p["default"] and default is None:
            warning = f"The default snapshot '{p['default']['name']}' is gone: pick a new default."
            if p["auto_revert"]:
                self.update(auto_revert=False)
                self.notes.append("auto-revert turned OFF: its default snapshot was deleted")
        elif default is None:
            warning = "No default snapshot yet: click Make clean snapshot, or pick one."
        elif default["uuid"] not in checked:
            warning = f"The default snapshot '{default['name']}' was not checked by FatBox."
        elif checked[default["uuid"]]["version"] != host_version:
            warning = (f"The default snapshot has FatBox {checked[default['uuid']]['version']}, the host "
                       f"{host_version}: make a new clean snapshot.")
        out = []
        for r in rows:
            c = checked.get(r["uuid"])
            out.append({**r, "current": r["uuid"] == current, "default": default is not None and r["uuid"] == default["uuid"],
                        "checked": c is not None, "version": c["version"] if c else None,
                        "taken": c.get("taken") if c else None})
        return {"rows": out, "default": default, "warning": warning,
                "auto_revert": p["auto_revert"] and default is not None}
