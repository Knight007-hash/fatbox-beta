"""Validation of everything that comes back from the VM. The VM is assumed hostile.

Reports are parsed as data only, checked against a small schema, size-capped, and re-serialized
by us before being stored or shown. The page renders them with textContent (never innerHTML).
Every string is also made printable here, so no VM text can drive a terminal or hide what it says.
"""
from __future__ import annotations

import json
import math
import re

SHA_RE = re.compile(r"^[0-9a-f]{64}\Z")  # 0.39.3: \Z, since $ also matches before a final newline
LIST_MAX_BYTES = 2 * 1024 * 1024
REPORT_MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 12
PRIORITIES = {"low", "medium", "high"}
STATUSES = {"fetched", "static_done", "dynamic_done", "error", "timeout", "too_big"}  # too_big: 0.23.0, metadata only
# Characters that act instead of showing: terminal controls (ESC sequences can retitle or wipe the console
# the host CLI prints into), bidi overrides that make "gpj.exe" read as "exe.jpg", zero-width and
# invisible tag characters, lone surrogates. They are shown as \xNN / \uNNNN instead.
HIDDEN_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\xad\u061c\u180e\u200b-\u200f\u2028-\u202e"
                       "\u2060-\u206f\ufeff\ufff9-\ufffb\ud800-\udfff\U000e0000-\U000e007f]")


class Invalid(ValueError):
    pass


def _reject_constant(name):
    raise Invalid(f"non-JSON constant {name}")


def _escape(m: re.Match) -> str:
    c = ord(m.group())
    return f"\\x{c:02x}" if c < 0x100 else f"\\u{c:04x}" if c < 0x10000 else f"\\U{c:08x}"


def printable(s: str, newlines: bool = False) -> str:
    """Make VM text safe to print or show. Tabs stay; newlines stay only when asked for."""
    s = HIDDEN_RE.sub(_escape, s)
    return s if newlines else s.replace("\n", "\\x0a")


def parse(raw: bytes, cap: int):
    if len(raw) > cap:
        raise Invalid(f"{len(raw)} bytes > cap {cap}")
    try:
        obj = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise Invalid(f"not JSON: {e}") from None
    except RecursionError:  # the parser recurses before _clean() can look: [[[[... x 200k
        raise Invalid("nested too deep") from None
    except ValueError as e:  # 0.39.3: e.g. an integer with more than 4300 digits
        raise Invalid(f"bad number: {str(e)[:80]}") from None
    return _clean(obj, 0)


def _clean(o, d: int):
    """Depth check plus printable() on every key and string, in one walk."""
    if d > MAX_DEPTH:
        raise Invalid("nested too deep")
    if isinstance(o, str):
        return printable(o, newlines=True)
    if isinstance(o, dict):
        return {printable(k): _clean(v, d + 1) for k, v in o.items()}
    if isinstance(o, list):
        return [_clean(v, d + 1) for v in o]
    if isinstance(o, float) and not math.isfinite(o):  # 0.39.3: 1e999 parses to inf (INV-4: no NaN/Infinity)
        raise Invalid("number out of range")
    return o


def _str(v, n: int = 300) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str):
        raise Invalid(f"expected string, got {type(v).__name__}")
    return printable(v[:n])  # one line: table cells and CLI rows


def _int(v, lo: int, hi: int) -> int | None:
    if v is None:
        return None
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise Invalid(f"bad integer {v!r}")
    return v


def sha(v) -> str:
    if not isinstance(v, str) or not SHA_RE.match(v):
        raise Invalid("bad sha256")
    return v


def sample_list(raw: bytes) -> list[dict]:
    obj = parse(raw, LIST_MAX_BYTES)
    if not isinstance(obj, dict) or not isinstance(obj.get("rows"), list):
        raise Invalid("expected {rows: [...]}")
    out = []
    for r in obj["rows"][:1000]:
        if not isinstance(r, dict):
            raise Invalid("row is not an object")
        status = _str(r.get("status"), 20)
        prio = _str(r.get("priority"), 10)
        tags = r.get("tags") or []
        if not isinstance(tags, list):
            raise Invalid("tags not a list")
        out.append({
            "sha256": sha(r.get("sha256")),
            "status": status if status in STATUSES else "unknown",
            "priority": prio if prio in PRIORITIES else None,
            "score": _int(r.get("score"), 0, 100),
            "tags": [_str(t, 60) for t in tags[:30] if isinstance(t, str)],
            **{k: _str(r.get(k)) for k in ("source", "first_seen", "file_name", "file_type", "signature",
                                            "fetched_at", "error")},
        })
    return out


CANDIDATE_MAX_ROWS = 1000


def candidate_list(raw: bytes) -> tuple[list[dict], int]:
    """T-13 Browse list from the VM: MalwareBazaar metadata as the VM relayed it. Anyone can upload a sample
    with any name or tags, and the VM may be hacked, so every row is checked; a bad row is dropped (counted),
    not trusted. Returns (rows, dropped)."""
    obj = parse(raw, LIST_MAX_BYTES)
    if not isinstance(obj, dict) or not isinstance(obj.get("rows"), list):
        raise Invalid("expected {rows: [...]}")
    out, dropped, seen = [], 0, set()
    for r in obj["rows"][:CANDIDATE_MAX_ROWS]:
        try:
            if not isinstance(r, dict):
                raise Invalid("row is not an object")
            s = sha(str(r.get("sha256") or "").lower())
            if s in seen:
                raise Invalid("duplicate")
            tags = r.get("tags") or []
            if not isinstance(tags, list):
                raise Invalid("tags not a list")
            in_vm = r.get("in_vm")
            out.append({
                "sha256": s,
                "file_size": _int(r.get("file_size"), 0, 1 << 40),
                "tags": [_str(t, 40) for t in tags[:20] if isinstance(t, str)],
                "in_vm": in_vm if isinstance(in_vm, bool) else False,
                "file_type": _str(r.get("file_type"), 16),
                "file_name": _str(r.get("file_name"), 120),
                "signature": _str(r.get("signature"), 64),
                "first_seen": _str(r.get("first_seen"), 32),
            })
            seen.add(s)
        except Invalid:
            dropped += 1
    return out, dropped + max(0, len(obj["rows"]) - CANDIDATE_MAX_ROWS)


def report(raw: bytes, expected_sha: str) -> dict:
    """Static report. We check the parts the UI relies on and keep the rest as inert data."""
    obj = parse(raw, REPORT_MAX_BYTES)
    if not isinstance(obj, dict):
        raise Invalid("report is not an object")
    hashes = obj.get("hashes")
    if not isinstance(hashes, dict) or hashes.get("sha256") != expected_sha:
        raise Invalid("report sha256 does not match the requested sample")
    if obj.get("priority") not in PRIORITIES:
        raise Invalid("bad priority")
    _int(obj.get("score"), 0, 100)
    for key, typ in (("reasons", list), ("iocs", dict), ("behaviour", list), ("yara", list), ("errors", list),
                     ("source_meta", dict)):
        if key in obj and not isinstance(obj[key], typ):
            raise Invalid(f"{key} has wrong type")
    if "pe" in obj and obj["pe"] is not None and not isinstance(obj["pe"], dict):
        raise Invalid("pe has wrong type")
    _shapes(obj)
    if obj.get("file_analysis") is not None:  # T-9; reports made before 0.17.0 have none and stay valid
        obj["file_analysis"] = file_analysis(obj["file_analysis"])
    if obj.get("code_analysis") is not None:  # T-14; reports made before 0.18.0 have none and stay valid
        obj["code_analysis"] = code_analysis(obj["code_analysis"])
    return obj


def _list_of(v, typ, what: str) -> None:
    if v is not None and (not isinstance(v, list) or not all(isinstance(x, typ) for x in v)):
        raise Invalid(f"{what} has wrong type")


def _shapes(obj: dict) -> None:
    """0.19.2: the nested lists the report page walks (pe.suspicious_imports.map, ...) must be lists of the right
    kind, so a hacked VM can't break the report view with a string where a list belongs."""
    _list_of(obj.get("behaviour"), dict, "behaviour")
    _list_of(obj.get("yara"), dict, "yara")
    meta = obj.get("source_meta") or {}
    _list_of(meta.get("tags"), str, "source_meta.tags")
    pe = obj.get("pe") or {}
    _list_of(pe.get("suspicious_imports"), dict, "pe.suspicious_imports")
    _list_of(pe.get("packer_hints"), str, "pe.packer_hints")
    _list_of(pe.get("sections"), dict, "pe.sections")
    dn = pe.get("dotnet")
    if dn is not None:
        if not isinstance(dn, dict):
            raise Invalid("pe.dotnet has wrong type")
        _list_of(dn.get("pinvoke"), str, "pe.dotnet.pinvoke")


# ---- T-9 File Analysis ------------------------------------------------------------------------------------
FA_STATUSES = {"ok", "timeout", "crashed", "not_installed", "error"}
FA_PACKED = {"yes", "likely", "no", "unknown"}
FA_LISTS = ("compiler", "packer", "protector", "installer", "runtime", "other")
FA_MAX_ITEMS = 50
FA_MAX_STR = 300 * 10      # the VM caps at 300 characters; printable() may write one hidden one as 10 (\U000e0041)
FA_MAX_BYTES = 100 * 1024 * 1024   # the unpacked cap: no offset or size can be bigger


def _fa_str(v, n: int = FA_MAX_STR) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or len(v) > n:
        raise Invalid("file_analysis: bad string")
    return printable(v)


def _fa_bool(v, nullable: bool = True) -> bool | None:
    if v is None and nullable:
        return None
    if not isinstance(v, bool):
        raise Invalid("file_analysis: expected true/false")
    return v


def file_analysis(fa) -> dict:
    """Rebuilt from scratch: only the keys below survive; any value that breaks the schema refuses the whole
    report (same rule as the other fields: a hacked VM gets no half-trusted report)."""
    if not isinstance(fa, dict):
        raise Invalid("file_analysis is not an object")
    if fa.get("status") not in FA_STATUSES or fa.get("packed") not in FA_PACKED:
        raise Invalid("file_analysis: bad status or packed verdict")
    eng = fa.get("engine") or {}
    if not isinstance(eng, dict):
        raise Invalid("file_analysis: engine is not an object")
    out = {"status": fa["status"], "error": _fa_str(fa.get("error")), "packed": fa["packed"],
           "packed_why": _fa_str(fa.get("packed_why")), "type": _fa_str(fa.get("type"), 400),
           "engine": {k: _fa_str(eng.get(k), 400) for k in ("die", "die_python", "signify") if eng.get(k) is not None}}
    for k in FA_LISTS:
        v = fa.get(k) or []
        if not isinstance(v, list) or len(v) > FA_MAX_ITEMS:
            raise Invalid(f"file_analysis: {k} is not a list of at most {FA_MAX_ITEMS}")
        out[k] = [_fa_str(x) for x in v]
        if None in out[k]:
            raise Invalid(f"file_analysis: {k} holds a non-string")
    ov = fa.get("overlay")
    if ov is not None:
        if not isinstance(ov, dict):
            raise Invalid("file_analysis: overlay is not an object")
        e = ov.get("entropy")
        if not isinstance(e, (int, float)) or isinstance(e, bool) or not 0 <= e <= 8:
            raise Invalid("file_analysis: bad overlay entropy")
        ov = {"offset": _int(ov.get("offset"), 0, FA_MAX_BYTES), "size": _int(ov.get("size"), 1, FA_MAX_BYTES),
              "entropy": float(e)}
        if ov["offset"] is None or ov["size"] is None:
            raise Invalid("file_analysis: overlay without offset or size")
    out["overlay"] = ov
    sig = fa.get("signature")
    if sig is not None:
        if not isinstance(sig, dict):
            raise Invalid("file_analysis: signature is not an object")
        sig = {"signed": _fa_bool(sig.get("signed")), "checked": _fa_bool(sig.get("checked"), nullable=False),
               "valid": _fa_bool(sig.get("valid")), "signer": _fa_str(sig.get("signer")),
               "reason": _fa_str(sig.get("reason"))}
    out["signature"] = sig
    return out


def file_badge(rep: dict) -> str | None:
    """The Triage table's "File" cell, written by the host from checked fields only (at most 60 characters)."""
    fa = rep.get("file_analysis")
    if not fa:
        return None
    if fa["status"] != "ok":
        return {"timeout": "timeout", "crashed": "engine crashed", "not_installed": "engine missing",
                "error": "engine error"}[fa["status"]]
    sig = fa.get("signature") or {}
    fam = [x for x in fa["other"] if x.split(": ")[0] in ("malware", "virus")]  # DIE named a family (0.17.2)
    warn = bool(fam) or bool(fa["protector"]) or (sig.get("checked") and sig.get("signed") and sig.get("valid") is False)
    if fam:
        what, word = fam[0].partition(": ")[2], "malware"
    elif fa["protector"]:
        what, word = fa["protector"][0], "protected"
    elif fa["packer"]:
        what, word = fa["packer"][0], "packed"
    elif fa["installer"]:
        what, word = fa["installer"][0], "installer"
    else:
        what = fa["compiler"][0] if fa["compiler"] else (fa["runtime"][0] if fa["runtime"] else "")
        word = {"yes": "packed", "likely": "likely packed", "no": "not packed", "unknown": ""}[fa["packed"]]
    what = what.split(" (")[0][:40]  # name and version, no DIE notes
    text = " · ".join(x for x in (fa.get("type") or "", what, word) if x) + (" ⚠" if warn else "")
    return text if len(text) <= 60 else text[:59] + "…"


# ---- T-14 Code Analysis (capa) --------------------------------------------------------------------------
CA_STATUSES = {"ok", "timeout", "crashed", "not_installed", "error", "skipped"}
CA_FORMATS = {"pe", "dotnet"}
CA_TOPICS = {"malware-family", "injection", "anti-analysis", "persistence", "collection", "load-code",
             "communication", "impact", "encryption", "other"}
CA_MAX_CAPS = 200
CA_MAX_ATTACK = 10
CA_MAX_NAME = 120 * 10     # the VM caps names at 120 characters; printable() may write one hidden one as 10
CA_MAX_STR = 300 * 10
ATTACK_RE = re.compile(r"T\d{4}(\.\d{3})?")
# the badge's order of interest: the first topic found is shown; these get the warning mark
CA_BADGE_ORDER = ("malware-family", "injection", "impact", "anti-analysis", "collection", "persistence",
                  "load-code", "communication", "encryption")
CA_WARN = {"malware-family", "injection", "impact", "anti-analysis", "collection"}


def _ca_str(v, n: int) -> str:
    if not isinstance(v, str) or len(v) > n:
        raise Invalid("code_analysis: bad string")
    return printable(v)


def _ca_bool(v) -> bool:
    if not isinstance(v, bool):
        raise Invalid("code_analysis: expected true/false")
    return v


def code_analysis(ca) -> dict:
    """Rebuilt from scratch like file_analysis: only the keys below survive, every value from a fixed set or
    capped; anything that breaks the schema refuses the whole report."""
    if not isinstance(ca, dict):
        raise Invalid("code_analysis is not an object")
    if ca.get("status") not in CA_STATUSES:
        raise Invalid("code_analysis: bad status")
    if ca.get("format") is not None and ca.get("format") not in CA_FORMATS:
        raise Invalid("code_analysis: bad format")
    eng = ca.get("engine") or {}
    if not isinstance(eng, dict):
        raise Invalid("code_analysis: engine is not an object")
    caps = ca.get("capabilities", [])
    if not isinstance(caps, list) or len(caps) > CA_MAX_CAPS:
        raise Invalid(f"code_analysis: capabilities is not a list of at most {CA_MAX_CAPS}")
    out = {"status": ca["status"],
           "error": None if ca.get("error") is None else _ca_str(ca.get("error"), CA_MAX_STR),
           "engine": {k: _ca_str(eng[k], 400) for k in ("capa", "rules") if eng.get(k) is not None},
           "format": ca.get("format"), "capabilities": []}
    for c in caps:
        if not isinstance(c, dict):
            raise Invalid("code_analysis: capability is not an object")
        if c.get("topic") not in CA_TOPICS or c.get("scope") not in ("code", "file"):
            raise Invalid("code_analysis: bad topic or scope")
        attack = c.get("attack") or []
        if not isinstance(attack, list) or len(attack) > CA_MAX_ATTACK or \
                not all(isinstance(a, str) and ATTACK_RE.fullmatch(a) for a in attack):
            raise Invalid("code_analysis: bad ATT&CK list")
        name = _ca_str(c.get("name"), CA_MAX_NAME)
        if not name:
            raise Invalid("code_analysis: capability without a name")
        out["capabilities"].append({"name": name, "topic": c["topic"],
                                    "namespace": _ca_str(c.get("namespace"), CA_MAX_NAME), "attack": list(attack),
                                    "scope": c["scope"], "nursery": _ca_bool(c.get("nursery")),
                                    "scored": _ca_bool(c.get("scored"))})
    return out


def code_badge(rep: dict) -> str | None:
    """The Triage table's "Code" cell, written by the host from checked fields only (at most 60 characters)."""
    ca = rep.get("code_analysis")
    if not ca:
        return None
    if ca["status"] == "skipped" and (ca.get("error") or "").startswith(("packed", "protected")):
        return "packed: capa skipped"  # 0.21.0: DIE named a packer/protector, capa would only see the stub
    if ca["status"] != "ok":
        return {"timeout": "capa: timeout", "crashed": "capa crashed", "not_installed": "capa missing",
                "error": "capa error", "skipped": "not a PE: skipped"}[ca["status"]]
    caps = ca["capabilities"]
    found = {c["topic"] for c in caps if c["scored"]}
    top = next((t for t in CA_BADGE_ORDER if t in found), None)
    n = len(caps)
    text = f"{n} capabilit{'y' if n == 1 else 'ies'}"
    if top:
        text += f" · {top}" + (" ⚠" if top in CA_WARN else "")
    elif (rep.get("file_analysis") or {}).get("packed") == "yes":
        text += " · packed: code hidden"  # capa sees the unpacking stub, not the payload
    return text if len(text) <= 60 else text[:59] + "…"


INDEX_MAX_BYTES = 16 * 1024 * 1024
LIBRARY_MAX_ROWS = 5000


def _opt_bool(v) -> bool:
    if not isinstance(v, bool):
        raise Invalid("expected true/false")
    return v


def library_index(raw: bytes) -> tuple[list[dict], int]:
    """T-7: the host's own library index, read back from disk. The host wrote it, but every value in it came
    from the VM and the file could have been changed since, so it gets the same checks as VM output.
    A bad row is dropped (counted); a file that isn't an index at all raises Invalid (the library rebuilds)."""
    obj = parse(raw, INDEX_MAX_BYTES)
    if not isinstance(obj, dict) or obj.get("version") != 1 or not isinstance(obj.get("rows"), list):
        raise Invalid("not a FatBox library index")
    out, dropped, seen = [], 0, set()
    for r in obj["rows"][:LIBRARY_MAX_ROWS]:
        try:
            if not isinstance(r, dict):
                raise Invalid("row is not an object")
            s = sha(r.get("sha256"))
            if s in seen:
                raise Invalid("duplicate")
            status, prio, tags = _str(r.get("status"), 20), _str(r.get("priority"), 10), r.get("tags") or []
            if not isinstance(tags, list):
                raise Invalid("tags not a list")
            out.append({
                "sha256": s,
                "status": status if status in STATUSES else "unknown",
                "priority": prio if prio in PRIORITIES else None,
                "score": _int(r.get("score"), 0, 100),
                "tags": [_str(t, 60) for t in tags[:30] if isinstance(t, str)],
                **{k: _str(r.get(k)) for k in ("signature", "file_type", "file_name", "fetched_at", "error")},
                "analyzed_at": _str(r.get("analyzed_at"), 32),
                "file_badge": _str(r.get("file_badge"), 60), "code_badge": _str(r.get("code_badge"), 60),
                "in_vm": _opt_bool(r.get("in_vm")),
                "has_report": _opt_bool(r.get("has_report")),
                # 0.26.0: rows from before Save existed count as saved; a discarded row is only a "don't copy" mark
                "saved": _opt_bool(r.get("saved", True)),
                "discarded": _opt_bool(r.get("discarded", False)),
            })
            seen.add(s)
        except Invalid:
            dropped += 1
    return out, dropped + max(0, len(obj["rows"]) - LIBRARY_MAX_ROWS)
