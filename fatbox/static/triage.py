"""Static triage orchestrator: bytes in, structured report out."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fatbox import __version__
from fatbox.static.basics import entropy, file_kind, hashes
from fatbox.static import code_analysis
from fatbox.static.file_analysis import families
from fatbox.static.strings_iocs import behaviour_hits, extract_iocs, extract_strings, network_iocs
from fatbox.static.yara_scan import YaraScanner

log = logging.getLogger(__name__)


def triage(data: bytes, name: str, yara_scanner: YaraScanner | None = None) -> dict:
    kind = file_kind(data)
    strings = extract_strings(data)
    report: dict = {
        "tool": f"FatBox {__version__}",
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "file_name": name,
        "size": len(data),
        "kind": kind,
        "entropy": entropy(data),
        "hashes": hashes(data),
        "pe": None,
        "iocs": extract_iocs(strings),
        "behaviour": behaviour_hits(strings),
        "yara": yara_scanner.scan(data) if yara_scanner else [],
        "string_count": len(strings),
        "errors": [],
    }
    if getattr(yara_scanner, "last_error", None):  # 0.39.3: YARA failed, the rest of the report stays
        report["errors"].append(yara_scanner.last_error)
    if kind == "pe":
        try:
            from fatbox.static.pe import analyze_pe
            report["pe"] = analyze_pe(data)
        except Exception as e:  # malformed PEs are normal in this domain
            report["errors"].append(f"pe: {type(e).__name__}: {e}")
    report["score"], report["reasons"] = score(report)
    report["priority"] = priority(report["score"])
    return report


# YARA rules that only say "this packer" (section names, stub marker): one fact with the packer rules above.
PACKER_RULES = {"FB_UPX_Packed", "MB_UPX_Packed"}


def score(r: dict) -> tuple[int, list[str]]:
    """Transparent additive heuristic. Every point has a reason so the result is explainable."""
    pts, why = 0, []

    def add(n: int, reason: str):
        nonlocal pts
        pts += n
        why.append(f"+{n} {reason}")

    fa = r.get("file_analysis") or {}
    named_packer = fa.get("status") == "ok" and fa.get("packer")
    packer_scored = bool(named_packer)
    if named_packer:  # T-9: DIE names it; replaces the section-name rule below (one fact, points once)
        add(15, f"packer (DIE): {', '.join(fa['packer'][:3])}")
    ca = r.get("code_analysis") or {}
    caps = [c for c in ca.get("capabilities") or [] if c.get("scored")] if ca.get("status") == "ok" else []
    fams, capa_fams = families(fa), code_analysis.families(ca)
    if fams:  # 0.17.2: a family signature on the sample's own code; stronger than a generic YARA hit (+20)
        also = f" (capa too: {', '.join(capa_fams[:3])})" if capa_fams else ""
        add(25, f"DIE names a malware family: {', '.join(fams[:3])}{also}")
    elif capa_fams:  # T-14: same fact, same points, counted once whichever engine names it
        add(25, f"capa names a malware family: {', '.join(capa_fams[:3])}")
    if fa.get("protector"):
        add(20, f"protector / cryptor / obfuscator (DIE): {', '.join(fa['protector'][:3])}")
    sig = fa.get("signature") or {}
    if sig.get("signed") and sig.get("checked") and sig.get("valid") is False:
        add(10, f"signature invalid: {sig.get('reason') or 'verification failed'}")
    if fa.get("installer"):
        why.append(f"+0 installer / SFX (DIE): {', '.join(fa['installer'][:2])}: the payload may sit in the overlay")
    if fa and fa.get("status") != "ok":
        why.append(f"+0 file analysis: {fa.get('status')}, score incomplete")

    # capa topics that will get points (dry run of code_points below, same inputs)
    capa_topics: set[str] = set()
    code_points(caps, {b["attack"] for b in r["behaviour"]}, lambda n, t: None, [], capa_topics)

    pe = r.get("pe")
    if pe:
        if pe["packer_hints"] and not named_packer:
            packer_scored = True
            add(15, f"packer section names: {', '.join(pe['packer_hints'])}")
        hi = [s["name"] for s in pe["sections"] if s["entropy"] > 7.2 and s["raw_size"] > 1024]
        if hi:
            add(10, f"high-entropy sections: {', '.join(hi)}")
        if any(s["perms"] == "RWX" for s in pe["sections"]):
            add(10, "RWX section")
        if pe["entrypoint_section"] is None or (pe["entrypoint_section"] and
                                                pe["entrypoint_section"].lower() not in (".text", "code", ".code")):
            add(5, f"entrypoint outside .text ({pe['entrypoint_section']})")
        if pe["import_count"] < 10 and not pe["is_dotnet"]:
            add(10, f"very few imports ({pe['import_count']}) -> likely packed / dynamic resolution")
        cats = {i["category"] for i in pe["suspicious_imports"]}
        for cat, n in (("injection", 15), ("anti-analysis", 5), ("collection", 10), ("crypto", 5),
                       ("persistence", 5), ("network", 5), ("load-code", 10)):  # load-code: .NET only (0.19.0)
            if cat not in cats:
                continue
            topic = IMPORT_TO_CAPA.get(cat, cat)
            if topic in capa_topics:  # 0.19.1: capa found the same behaviour in the code: score it once
                why.append(f"+0 {cat} APIs imported: same fact as code (capa) {topic}")
            else:
                add(n, f"{cat} APIs imported")
        if pe["compile_time_anomaly"]:
            add(5, "zero/future compile timestamp")
        # 0.19.1: File Analysis' overlay leaves out only the certificate table itself, so a small (fake)
        # signature no longer hides a big appended payload. Reports without file_analysis: old rule.
        ov = fa.get("overlay") if fa else (pe["overlay"] if not pe["has_signature_blob"] else None)
        if ov and ov["size"] > 4096 and ov["entropy"] > 7.0:
            add(10, "large high-entropy overlay")
        if pe["tls_callbacks"]:
            add(5, "TLS directory present (pre-EP code)")
    elif r["entropy"] > 7.5:
        add(5, "high overall entropy")

    seen = set()
    for b in r["behaviour"]:
        if b["indicator"] in seen:
            continue  # 0.17.2: vssadmin and wmic both delete shadow copies: one behaviour, points once
        seen.add(b["indicator"])
        add(8, f"string indicator: {b['indicator']} ({b['attack']})")
    code_points(caps, {b["attack"] for b in r["behaviour"]}, add, why)
    if ca and ca.get("status") not in ("ok", "skipped"):
        why.append(f"+0 code analysis: {ca.get('status')}, score incomplete")
    wiped = "shadow copy deletion" in seen or any("T1490" in c["attack"] for c in caps)
    locked = "ransom note language" in seen or any(c["topic"] == "encryption" for c in caps)
    if {"shadow copy deletion", "ransom note language"} <= seen:
        add(15, "ransomware pattern: backups wiped + ransom note (T1490 + T1486)")
    elif wiped and locked:  # T-14: one or both halves come from the code (capa)
        a = "backups wiped" + ("" if "shadow copy deletion" in seen else " (capa)")
        b = "ransom note" if "ransom note language" in seen else "file encryption code (capa)"
        add(15, f"ransomware pattern: {a} + {b} (T1490 + T1486)")
    rules = [h["rule"] for h in r["yara"]]
    same = [x for x in rules if x in PACKER_RULES] if packer_scored else []
    rest = [x for x in rules if x not in same]
    if rest:
        add(20, f"YARA: {', '.join(rest[:5])}")
    if same:  # 0.17.2: the packer line above already scored this fact
        why.append(f"+0 YARA {', '.join(same)}: same fact as the packer line")
    counted, ignored = network_iocs(r["iocs"])
    noise = f", {ignored} ignored as noise" if ignored else ""
    if counted:
        add(5, f"embedded network IOCs ({len(counted)} counted{noise})")
    elif ignored:
        why.append(f"+0 network IOCs: {ignored} found, all noise (schema, certificate, version number, OID, public DNS)")
    return min(pts, 100), why


# T-14: points per capa topic, each topic once, all of capa together at most CAPA_CAP. Only "scored"
# capabilities count (code findings from stable rules; see code_analysis.scored). Topics not listed here
# (impact, encryption, other) give no points of their own; impact and encryption feed the ransomware pattern.
CAPA_POINTS = (("injection", 15), ("anti-analysis", 10), ("persistence", 10), ("collection", 10),
               ("load-code", 10), ("communication", 5))
CAPA_CAP = 40
# 0.19.1: import categories that are the same behaviour as a capa topic (scored once, capa wins)
IMPORT_TO_CAPA = {"network": "communication"}


def code_points(caps: list[dict], string_attack: set[str], add, why: list[str],
                scored_topics: set[str] | None = None) -> None:
    left = CAPA_CAP
    for topic, n in CAPA_POINTS:
        mine = [c for c in caps if c["topic"] == topic]
        if not mine:
            continue
        # a capability whose techniques the string indicators already scored is the same fact: no new points
        new = [c for c in mine if not c["attack"] or not set(c["attack"]) <= string_attack]
        shown = new or mine
        names = ", ".join(c["name"] for c in shown[:3]) + (f" +{len(shown) - 3} more" if len(shown) > 3 else "")
        if not new:
            ids = ", ".join(sorted({a for c in mine for a in c["attack"]}))
            why.append(f"+0 code (capa) {topic}: {names}: also seen in strings ({ids})")
            continue
        got = min(n, left)
        left -= got
        ids = sorted({a for c in new for a in c["attack"]})
        text = f"code (capa) {topic}: {names}" + (f" ({', '.join(ids[:3])})" if ids else "")
        if got:
            add(got, text)
            if scored_topics is not None:
                scored_topics.add(topic)
        else:
            why.append(f"+0 {text}: capa limit of {CAPA_CAP} reached")


def priority(points: int) -> str:
    if points >= 60:
        return "high"
    if points >= 30:
        return "medium"
    return "low"
