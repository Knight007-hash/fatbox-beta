"""T-7: the host's report library (F-9). The VM is a bench that gets wiped; this is the notebook that stays.

    <host home>\\library\\index.json          one row per sample (metadata only)
    <host home>\\library\\reports\\<sha>.json  one checked static report per sample

0.26.0: every report is still copied off the VM automatically (nothing is lost on a revert), but a new one
waits as "not saved" (saved=false) until you Save or Discard it in the New view; Library shows saved ones only.
A discarded report's file is deleted; while its sample is still in the VM the row stays as a hidden
discarded=true mark so the next Refresh doesn't copy it back. The mark goes when the sample leaves the VM.

Reports only, never samples (INV-1). Everything here came from the VM, so it is checked when it arrives AND
every time it is read back from disk (INV-4): a file changed on disk can't get past the checks either.
File names are built only from a checked 64-hex sha256, so no VM text can pick a path.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
from pathlib import Path
from typing import Callable

from fatbox.host import validate
from fatbox.host.vbox import GuestError

MAX_ROWS = validate.LIBRARY_MAX_ROWS   # nothing is ever deleted automatically; past this, new ones aren't saved
MIN_FREE_BYTES = 500 * 1024 * 1024    # below this free disk on the host, new reports aren't saved
ROW_KEYS = ("status", "priority", "score", "signature", "file_type", "file_name", "tags", "fetched_at", "error")


def _atomic_write(path: Path, text: str) -> None:
    """Write next to the target, then swap it in: a crash leaves the old file, never half a file."""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _row_from_report(sha: str, rep: dict) -> dict:
    meta = rep.get("source_meta") if isinstance(rep.get("source_meta"), dict) else {}
    tags = meta.get("tags") if isinstance(meta.get("tags"), list) else []

    def s(v, n):
        return validate.printable(v[:n]) if isinstance(v, str) else None
    return {"sha256": sha, "status": "static_done", "priority": rep["priority"], "score": rep.get("score"),
            "signature": s(meta.get("signature"), 300), "file_type": s(meta.get("file_type"), 300),
            "file_name": s(meta.get("file_name"), 300), "tags": [s(t, 60) for t in tags[:30] if isinstance(t, str)],
            "fetched_at": None, "error": None, "in_vm": False, "has_report": True,
            "analyzed_at": s(rep.get("analyzed_at"), 32), "file_badge": validate.file_badge(rep),
            "code_badge": validate.code_badge(rep), "saved": True, "discarded": False}


class Library:
    def __init__(self, home: Path):
        self.dir = Path(home) / "library"
        self.reports = self.dir / "reports"
        self.index_path = self.dir / "index.json"
        self.legacy = Path(home) / "reports"   # before T-7 the host kept only the reports you had clicked
        self.lock = threading.RLock()
        self.notes: list[str] = []              # one-off lines for the activity log (index rebuilt, ...)

    # ---- disk ----------------------------------------------------------------
    def free_bytes(self) -> int:
        return shutil.disk_usage(self.dir).free

    def _path(self, sha: str) -> Path:
        return self.reports / f"{validate.sha(sha)}.json"

    def _load(self) -> dict[str, dict]:
        with self.lock:
            self.reports.mkdir(parents=True, exist_ok=True)
            if not self.index_path.exists():
                return self._rebuild("")
            try:
                rows, dropped = validate.library_index(self.index_path.read_bytes())
            except (validate.Invalid, OSError) as e:
                os.replace(self.index_path, self.index_path.with_name("index.json.bad"))
                return self._rebuild(f"the library index was damaged ({e}); kept it as index.json.bad and ")
            if dropped:
                self.notes.append(f"library: {dropped} damaged row(s) in index.json ignored")
            return {r["sha256"]: r for r in rows}

    def _rebuild(self, why: str) -> dict[str, dict]:
        """Index missing or damaged: rebuild it from the report files (each checked again). On the first start
        after T-7 this also takes in the reports the host had cached from clicking rows."""
        lib: dict[str, dict] = {}
        for folder in (self.reports, self.legacy):
            if not folder.is_dir():
                continue
            for p in sorted(folder.glob("*.json")):
                sha = p.stem.lower()
                if sha in lib or not validate.SHA_RE.match(sha) or len(lib) >= MAX_ROWS:
                    continue
                try:
                    if p.stat().st_size > validate.REPORT_MAX_BYTES:
                        continue
                    rep = validate.report(p.read_bytes(), sha)
                except (validate.Invalid, OSError):
                    continue
                if folder is self.legacy:
                    _atomic_write(self._path(sha), json.dumps(rep, indent=1))
                lib[sha] = _row_from_report(sha, rep)
        self._save(lib)
        if why:
            self.notes.append(f"library: {why}rebuilt the index from {len(lib)} saved report(s)")
        elif lib:
            self.notes.append(f"library: built the index from {len(lib)} saved report(s)")
        return lib

    def _save(self, lib: dict[str, dict]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(self.index_path, json.dumps({"version": 1, "rows": list(lib.values())}, indent=0))

    # ---- read ----------------------------------------------------------------
    def rows(self) -> list[dict]:
        """All rows except discarded marks, newest first. Re-checked on every read."""
        with self.lock:
            rows = [r for r in self._load().values() if not r["discarded"]]
        rows.sort(key=lambda r: (r.get("fetched_at") or r.get("analyzed_at") or ""), reverse=True)
        return rows

    def report(self, sha: str) -> dict | None:
        p = self._path(sha)
        if not p.exists():
            return None
        if p.stat().st_size > validate.REPORT_MAX_BYTES:
            raise validate.Invalid("the saved report is too big")
        return validate.report(p.read_bytes(), sha)

    def take_notes(self) -> list[str]:
        with self.lock:
            out, self.notes = self.notes, []
        return out

    # ---- write ---------------------------------------------------------------
    def put_report(self, sha: str, rep: dict) -> None:
        """A report that was just checked (validate.report). Written as our own re-serialization."""
        with self.lock:
            lib = self._load()         # first: a rebuilt index must not take this file in as already saved
            if lib.get(sha, {}).get("discarded"):
                return                 # you discarded it: shown once if asked for, never kept
            _atomic_write(self._path(sha), json.dumps(rep, indent=1))
            fresh = _row_from_report(sha, rep)
            if sha in lib:
                lib[sha].update(has_report=True, analyzed_at=fresh["analyzed_at"], file_badge=fresh["file_badge"],
                                code_badge=fresh["code_badge"])
            elif len(lib) < MAX_ROWS:  # opened straight from the VM (Re-fetch): it was in the VM a moment ago
                lib[sha] = {**fresh, "in_vm": True, "saved": False}
            self._save(lib)

    def sync(self, vm_rows: list[dict], get_report: Callable[[str], dict], say: Callable[[str], None],
             complete: bool = True) -> dict:
        """Copy what the VM has into the library. vm_rows: validate.sample_list() output. Only new or changed
        reports are asked for. complete=False when the VM's list hit its cap: then rows missing from it are not
        marked "not in VM". Returns {"saved", "missing", "total"}."""
        with self.lock:
            lib = self._load()
        saved = missing = 0
        full = low = False
        updates: dict[str, dict] = {}
        for r in vm_rows:
            sha, old = r["sha256"], lib.get(r["sha256"])
            if old is None and len(lib) + sum(1 for s in updates if s not in lib) >= MAX_ROWS:
                full, missing = True, missing + 1
                continue
            row = {"has_report": False, "analyzed_at": None, "saved": False, "discarded": False, **(old or {}),
                   **{k: r.get(k) for k in ROW_KEYS}, "sha256": sha, "in_vm": True}
            changed = old is None or any(old.get(k) != row[k] for k in ("status", "score", "priority"))
            if row["discarded"]:
                pass                   # you discarded it: never copied again while it stays in the VM
            elif row["status"] == "static_done" and (changed or not row["has_report"]):
                if self.free_bytes() < MIN_FREE_BYTES:
                    low, missing = True, missing + 1
                else:
                    try:
                        rep = get_report(sha)
                        with self.lock:
                            self.reports.mkdir(parents=True, exist_ok=True)
                            _atomic_write(self._path(sha), json.dumps(rep, indent=1))
                        fresh = _row_from_report(sha, rep)
                        row.update(has_report=True, analyzed_at=fresh["analyzed_at"], file_badge=fresh["file_badge"],
                                   code_badge=fresh["code_badge"])
                        saved += 1
                    except (GuestError, validate.Invalid, OSError, ValueError) as e:
                        missing += 1
                        say(f"--- library: report {sha[:16]}… not saved: {e}")
            updates[sha] = row
        with self.lock:  # merge into the CURRENT index (a delete may have happened meanwhile)
            lib = self._load()
            lib.update(updates)
            if complete:
                for sha, row in list(lib.items()):
                    if sha not in updates:
                        row["in_vm"] = False
                        if row["discarded"]:
                            del lib[sha]   # the sample left the VM: the "don't copy back" mark isn't needed
            self._save(lib)
            total = sum(1 for r in lib.values() if not r["discarded"])
        for note in self.take_notes():
            say("--- " + note)
        say(f"--- library: {saved} new report(s) saved ({total} total)")
        if missing:
            say(f"--- library: {missing} report(s) could not be saved; Refresh tries again")
        if full:
            say(f"--- library is full ({MAX_ROWS} reports): delete old ones in the Triage tab to save new ones")
        if low:
            say("--- library: less than 500 MB free disk on the host: new reports are not saved")
        return {"saved": saved, "missing": missing, "total": total}

    def mark_all_gone(self) -> None:
        """After a revert the VM's samples are gone (the next Refresh corrects any that a snapshot kept)."""
        with self.lock:
            lib = {s: r for s, r in self._load().items() if not r["discarded"]}
            for row in lib.values():
                row["in_vm"] = False
            self._save(lib)

    @staticmethod
    def _picked(shas, what: str) -> list[str]:
        if not isinstance(shas, list) or not 1 <= len(shas) <= MAX_ROWS:
            raise ValueError(f"pick 1 or more reports to {what}")
        want = []
        for s in shas:
            if not isinstance(s, str) or not validate.SHA_RE.match(s):
                raise ValueError("not a sha256")
            want.append(s)
        return list(dict.fromkeys(want))

    def save(self, shas) -> int:
        """0.26.0: keep these not-saved reports: they show in Library from now on."""
        want = self._picked(shas, "save")
        with self.lock:
            lib = self._load()
            n = 0
            for s in want:
                r = lib.get(s)
                if r and not r["discarded"] and not r["saved"]:
                    r["saved"], n = True, n + 1
            self._save(lib)
        return n

    def discard(self, shas) -> int:
        """0.26.0: drop these not-saved reports. Saved ones are refused (delete those from Library). A sample
        still in the VM keeps a hidden mark so Refresh doesn't copy its report back."""
        want = self._picked(shas, "discard")
        with self.lock:
            lib = self._load()
            if any(lib.get(s, {}).get("saved") for s in want):
                raise ValueError("already saved: delete it from Library instead")
            n = 0
            for s in want:
                r = lib.get(s)
                if r is None or r["discarded"]:
                    continue
                if r["in_vm"]:
                    r.update(discarded=True, has_report=False)
                else:
                    del lib[s]
                self._path(s).unlink(missing_ok=True)
                n += 1
            self._save(lib)
        return n

    def delete(self, shas) -> int:
        """Delete rows and their reports. Only rows marked not in the VM: one still in the VM would just be
        copied back at the next Refresh."""
        want = self._picked(shas, "delete")
        with self.lock:
            lib = self._load()
            if any(lib.get(s, {}).get("in_vm") for s in want):
                raise ValueError("only reports of samples no longer in the VM can be deleted")
            n = 0
            for s in want:
                if lib.pop(s, None) is not None:
                    n += 1
                self._path(s).unlink(missing_ok=True)
            self._save(lib)
        return n
