"""T-9 File Analysis (F-7): what the file is. Type, compiler, packer, protector, installer/SFX, overlay,
signature, a packed? verdict and the runtime.

The engines (Detect It Easy through die-python, Authenticode through signify) are native code and ASN.1
parsers that read hostile bytes, so they run in their own sub-helper process (`file-analysis-one`), started
by the per-sample helper (`triage-one`, T-5):

    triage-one <sha>            entropy, PE, IOCs, YARA, score; waits at most half the sample limit for:
      file-analysis-one <sha>   DIE + signature; opens the .zip.quarantine itself, in memory (INV-2)
                                prints one JSON object on stdout; the helper reads at most OUT_CAP bytes

No bytes are passed between the two, and the sample is never written to disk in plain form: DIE reads it
from memory (scan_memory). If the sub-helper hangs, crashes, or the engine is not installed, the report is
still made: only "file_analysis.status" says what went wrong.

Everything the sub-helper prints is treated as untrusted (it parsed the sample): size-capped, parsed, and
rebuilt here with caps; the host checks it again (fatbox/host/validate.py, INV-4).
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from fatbox.static.basics import entropy

OUT_CAP = 1024 * 1024        # bytes read from the sub-helper's stdout
MAX_ITEMS = 50               # per list in the report
MAX_STR = 300                # per string in the report
MAX_DETECTS = 200            # raw DIE values kept by the sub-helper
HIGH_ENTROPY = 7.2           # same threshold as the score's high-entropy rule
STATUSES = ("ok", "timeout", "crashed", "not_installed", "error")
NO_MATCH = "DIE: no signature matched"

# DIE's own categories (the init("<type>", ...) of its rule files), lower case, "(heur)" removed
CATEGORIES = {
    "packer": ("packer", "joiner"),
    "protector": ("protector", "protection", "obfuscator", "cryptor", "scrambler", "immunizer"),
    "compiler": ("compiler", "linker", "language"),
    "installer": ("installer", "sfx"),
    "runtime": ("library",),
}
_CATEGORY_OF = {t: field for field, types in CATEGORIES.items() for t in types}
# DIE types that name one malware family (e.g. PE/_simpleNetAntivirus.1.sg matches NjRAT, XWorm, VenomRAT,
# RevengeRAT on their own stub code). They land in "other" as "malware: NjRAT 0.7D (Obfuscated)".
FAMILY_TYPES = ("malware", "virus")
IGNORED = {"unknown", "sign tool", "overlay"}  # signature and overlay come from pefile + signify instead


def _s(v, n: int = MAX_STR) -> str:
    return v[:n] if isinstance(v, str) else ""


# ---- the sub-helper's side ------------------------------------------------------------------------------
def die_flags(die) -> int:
    f = die.ScanFlags
    return int(f.RESULT_AS_JSON | f.DEEP_SCAN | f.HEURISTIC_SCAN)


def rules_path(die) -> Path:
    """die-python 0.4.0 keeps the rule folders in die/db/db, 0.5.0 in die/db."""
    p = Path(die.database_path)
    return p / "db" if (p / "db").is_dir() else p


def scan(data: bytes) -> dict:
    """Run the engines on bytes in memory. Returns the sub-helper's JSON object."""
    try:
        import die
    except Exception as e:  # not installed, or its native library can't load on this Windows
        hint = ("; install the Microsoft Visual C++ Redistributable 2015-2022 (x64): the engine needs MSVCP140.dll"
                if "DLL load failed" in str(e) else "; run Update VM (it installs the pinned libraries)")
        return {"status": "not_installed", "error": _s(f"die-python: {type(e).__name__}: {e}{hint}")}
    engine = {"die": _s(str(getattr(die, "die_version", "")), 40), "die_python": _s(str(getattr(die, "__version__", "")), 40)}
    # bytes -> TypeError, and without the right database path every answer is "Unknown" (tested, 0.4.0 + 0.5.0)
    raw = die.scan_memory(bytearray(data), die_flags(die), str(rules_path(die)))
    obj = json.loads(raw) if raw else {}
    detects, filetype = [], ""
    for d in obj.get("detects") or []:
        if not isinstance(d, dict):
            continue
        filetype = filetype or _s(d.get("filetype"), 40)
        for v in d.get("values") or []:
            if isinstance(v, dict) and len(detects) < MAX_DETECTS:
                detects.append({k: _s(v.get(k)) for k in ("type", "name", "version", "info")})
    return {"status": "ok", "engine": engine, "filetype": filetype, "detects": detects,
            "signature": signature(data, engine) if data[:2] == b"MZ" else None}


def signature(data: bytes, engine: dict) -> dict | None:
    """Authenticode check from memory, offline (signify's bundled trust store, no revocation lookups)."""
    try:
        import signify
        from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult
        engine["signify"] = _s(str(getattr(signify, "__version__", "")), 40)
    except Exception as e:  # e.g. its crypto backend can't load: say so, never guess
        return {"checked": False, "reason": f"signature check unavailable: {type(e).__name__}: {e}"}
    try:
        f = AuthenticodeFile.from_stream(io.BytesIO(data))
        result, err = f.explain_verify()
    except Exception as e:
        return {"checked": False, "reason": f"{type(e).__name__}: {e}"}
    if result == AuthenticodeVerificationResult.NOT_SIGNED:
        return {"checked": True, "signed": False}
    signer = None
    try:
        for sig in f.signatures:
            info = sig.signer_info
            for cert in sig.certificates:
                if cert.serial_number == info.serial_number:
                    signer = cert.subject.dn
                    break
            break
    except Exception:
        pass
    ok = result == AuthenticodeVerificationResult.OK
    return {"checked": True, "signed": True, "valid": ok, "signer": _s(signer),
            "reason": None if ok else _s(f"{result.name}: {err}" if err else result.name)}


def cmd_file_analysis_one(cfg, store, args) -> int:
    """`fatbox file-analysis-one <sha>` (internal): the sub-helper. One JSON object on stdout."""
    from fatbox.store import UNPACKED_CAP, read_sample_from_zip
    row = store.get(args.sha256.lower())
    if not row:
        print(json.dumps({"status": "error", "error": "unknown sha256"}))
        return 1
    _, data = read_sample_from_zip(Path(row["zip_path"]), cfg.zip_password, UNPACKED_CAP)
    try:
        out = scan(data)
    except Exception as e:
        out = {"status": "error", "error": _s(f"{type(e).__name__}: {e}")}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    return 0


# ---- the helper's side ------------------------------------------------------------------------------------
class Run:
    """A sub-helper, started before the rest of triage so they run side by side. T-9 file analysis by default;
    T-14 code analysis (capa) uses the same class with its own command, label and statuses."""

    def __init__(self, sha: str, config_path: str, budget_s: float, command: str = "file-analysis-one",
                 label: str = "file analysis", statuses: tuple[str, ...] = STATUSES, extra: tuple[str, ...] = ()):
        self.budget_s, self.started = budget_s, time.monotonic()
        self.proc, self.error, self.label, self.statuses = None, None, label, statuses
        root = str(Path(__file__).resolve().parents[2])
        env = {**os.environ, "PYTHONPATH": root + os.pathsep + os.environ.get("PYTHONPATH", "")}
        cmd = [sys.executable, "-m", "fatbox", "-c", config_path, command, sha, *extra]
        try:
            self.proc = subprocess.Popen(cmd, env=env, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL)
        except OSError as e:
            self.error = f"could not start the {label} helper: {e}"

    def result(self) -> tuple[str, str | None, dict | None]:
        """-> (status, error, sub-helper JSON). Waits at most what is left of the budget."""
        if self.proc is None:
            return "error", self.error, None
        box: dict = {}
        reader = threading.Thread(target=lambda: box.setdefault("out", self.proc.stdout.read(OUT_CAP + 1)),
                                  daemon=True)
        reader.start()
        reader.join(max(0.0, self.budget_s - (time.monotonic() - self.started)))
        if reader.is_alive():
            self.stop()
            return "timeout", f"{self.label} took longer than {self.budget_s:.0f} s: stopped", None
        out = box.get("out", b"")
        if len(out) > OUT_CAP:
            self.stop()
            return "error", f"{self.label} printed more than {OUT_CAP} bytes", None
        try:
            rc = self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.stop()
            rc = None
        try:
            obj = json.loads(out.decode("utf-8")) if out else None
        except (UnicodeDecodeError, ValueError):
            obj = None
        if not isinstance(obj, dict):
            return "crashed", f"{self.label} helper crashed (exit {rc})", None
        status = obj.get("status") if obj.get("status") in self.statuses else "error"
        return status, (_s(obj.get("error")) or None) if status != "ok" else None, obj if status == "ok" else None

    def stop(self) -> None:
        if self.proc is None:
            return
        try:
            self.proc.kill()
            self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _fmt(v: dict) -> str:
    name, ver, info = _s(v.get("name"), 120), _s(v.get("version"), 60), _s(v.get("info"), 100)
    out = f"{name} {ver}".strip()
    return _s(f"{out} ({info})" if info else out)


def _heur(v: dict) -> tuple[str, bool]:
    t = _s(v.get("type"), 60).strip().lower()
    if t.startswith("(heur)"):
        return t[6:].strip(), True
    return t, False


def overlay(data: bytes, pe: dict | None) -> dict | None:
    """Bytes after the last section, without the Authenticode blob when it sits at the end (pefile)."""
    ov = (pe or {}).get("overlay")
    if not ov:
        return None
    start, end = int(ov["offset"]), len(data)
    blob = (pe or {}).get("signature_blob")
    if blob and start <= blob["offset"] <= end and blob["offset"] + blob["size"] >= end - 8:
        end = blob["offset"]  # the certificate table is where Windows puts signatures: not an overlay
    if end <= start:
        return None
    return {"offset": start, "size": end - start, "entropy": entropy(data[start:end])}


def build(status: str, error: str | None, sub: dict | None, data: bytes, pe: dict | None) -> dict:
    """The report's "file_analysis" object, rebuilt from the sub-helper's answer with every cap applied."""
    fa: dict = {"status": status, "error": _s(error) or None, "engine": {}, "type": None,
                **{k: [] for k in CATEGORIES}, "other": [], "overlay": overlay(data, pe), "signature": None}
    heur = []
    if sub:
        eng = sub.get("engine") if isinstance(sub.get("engine"), dict) else {}
        fa["engine"] = {k: _s(eng.get(k), 40) for k in ("die", "die_python", "signify") if _s(eng.get(k), 40)}
        fa["type"] = _s(sub.get("filetype"), 40) or None
        for v in (sub.get("detects") or [])[:MAX_DETECTS]:
            if not isinstance(v, dict):
                continue
            t, is_heur = _heur(v)
            if t in IGNORED:
                continue
            field = _CATEGORY_OF.get(t)
            text = _fmt(v)
            if field is None:
                text = _s(f"{t}: {text}")
                field = "other"
            if is_heur:
                heur.append(f"{t} {text}")
                text = _s(f"(heuristic) {text}")
                if field in ("packer", "protector"):
                    field = "other"  # a guess is shown, but it doesn't name a packer
            if text and text not in fa[field] and len(fa[field]) < MAX_ITEMS:
                fa[field].append(text)
        sig = sub.get("signature")
        if isinstance(sig, dict):
            fa["signature"] = {"signed": bool(sig.get("signed")) if sig.get("checked") else None,
                               "checked": sig.get("checked") is True,
                               "valid": sig.get("valid") if isinstance(sig.get("valid"), bool) else None,
                               "signer": _s(sig.get("signer")) or None, "reason": _s(sig.get("reason")) or None}
    if pe is not None:
        has_blob = bool(pe.get("has_signature_blob"))
        s = fa["signature"]
        if s is None or not s["checked"]:
            fa["signature"] = {"signed": has_blob, "checked": False, "valid": None, "signer": None,
                               "reason": ((s or {}).get("reason") or "validity not checked") if has_blob else None}
    if status == "ok" and not any(fa[k] for k in (*CATEGORIES, "other")):
        fa["other"] = [NO_MATCH]  # 0.17.1: DIE ran and matched nothing; say so instead of a column of "-"
    fa["packed"], fa["packed_why"] = verdict(fa, pe, heur)
    return fa


def verdict(fa: dict, pe: dict | None, heur: list[str]) -> tuple[str, str]:
    if fa["protector"]:
        return "yes", _s(f"protector {fa['protector'][0]} found")
    if fa["packer"]:
        return "yes", _s(f"packer {fa['packer'][0]} found")
    hi = [f"{s['name']} {s['entropy']:.1f}" for s in (pe or {}).get("sections", [])
          if s.get("entropy", 0) > HIGH_ENTROPY and s.get("raw_size", 0) > 1024]
    if hi:
        return "likely", _s(f"no packer named, but high-entropy section: {', '.join(hi[:5])}")
    if heur:
        return "likely", _s(f"DIE heuristic: {heur[0]}")
    if fa["status"] != "ok":
        return "unknown", f"engine {fa['status']}: only section entropy checked, none high" if pe else \
            f"engine {fa['status']}"
    names = (pe or {}).get("packer_hints") or []
    if names:  # 0.17.1: packer-like section names that DIE doesn't confirm and entropy doesn't back up
        top = max((s.get("entropy", 0) for s in pe.get("sections", []) if s.get("raw_size", 0) > 0), default=0)
        return "no", _s(f"section names say {', '.join(names[:3])}, but DIE found no {names[0]} code and entropy "
                        f"is low (max {top:.1f}): renamed sections?")
    return "no", "no packer or protector found, no high-entropy section" if pe else "no packer or protector found"


def families(fa: dict | None) -> list[str]:
    """0.17.2: malware families DIE named by signature (not by heuristic), as "NjRAT 0.7D"."""
    if not fa or fa.get("status") != "ok":
        return []
    out = []
    for x in fa.get("other") or []:
        t, _, rest = x.partition(": ")
        name = rest.split(" (")[0].strip()
        if t in FAMILY_TYPES and name and name not in out:
            out.append(name)
    return out
