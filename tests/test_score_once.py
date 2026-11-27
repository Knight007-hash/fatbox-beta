"""0.19.1: one fact, points once (imports vs capa), and a small certificate no longer hides an overlay."""
from __future__ import annotations

from fatbox.static.triage import score


def pe(imports=(), overlay=None, blob=False):
    return {"packer_hints": [], "sections": [{"name": ".text", "entropy": 6.0, "raw_size": 4096, "perms": "R-X"}],
            "entrypoint_section": ".text", "import_count": 50, "is_dotnet": False,
            "suspicious_imports": [{"api": a, "category": c, "attack": ""} for a, c in imports],
            "compile_time_anomaly": False, "overlay": overlay, "has_signature_blob": blob, "tls_callbacks": False}


def cap(name, topic, attack=()):
    return {"name": name, "namespace": "", "topic": topic, "attack": list(attack), "scope": "code",
            "nursery": False, "scored": True}


def rep(p, caps=(), fa=None):
    r = {"pe": p, "behaviour": [], "yara": [], "iocs": {}, "entropy": 6.0}
    if caps:
        r["code_analysis"] = {"status": "ok", "capabilities": list(caps)}
    if fa is not None:
        r["file_analysis"] = fa
    return r


def test_same_behaviour_from_imports_and_capa_scores_once():
    p = pe([("VirtualAllocEx", "injection"), ("WSAStartup", "network"), ("RegSetValueExW", "persistence")])
    pts, why = score(rep(p, [cap("inject thread", "injection", ["T1055"]), cap("connect TCP socket", "communication")]))
    assert pts == 15 + 5 + 5   # capa injection, capa communication, imported persistence (capa found none)
    assert "+0 injection APIs imported: same fact as code (capa) injection" in why
    assert "+0 network APIs imported: same fact as code (capa) communication" in why
    assert "+5 persistence APIs imported" in why


def test_imports_still_count_without_capa():
    pts, why = score(rep(pe([("VirtualAllocEx", "injection")])))
    assert pts == 15 and "+15 injection APIs imported" in why


def test_capa_topic_without_points_does_not_hide_imports():
    # capa's injection technique is already scored by a string indicator: capa gives +0, so imports keep theirs
    r = rep(pe([("VirtualAllocEx", "injection")]), [cap("inject thread", "injection", ["T1055"])])
    r["behaviour"] = [{"indicator": "x", "attack": "T1055"}]
    pts, why = score(r)
    assert "+15 injection APIs imported" in why


BIG = {"offset": 1000, "size": 50_000, "entropy": 7.9}


def test_small_fake_signature_no_longer_hides_a_big_overlay():
    fa = {"status": "ok", "overlay": BIG}      # file analysis already cut the certificate table out
    _, why = score(rep(pe(overlay={**BIG, "size": 50_100}, blob=True), fa=fa))
    assert "+10 large high-entropy overlay" in why


def test_signature_only_is_no_overlay():
    _, why = score(rep(pe(overlay={"offset": 1000, "size": 9000, "entropy": 7.5}, blob=True),
                       fa={"status": "ok", "overlay": None}))
    assert not any("overlay" in x for x in why)


def test_old_reports_without_file_analysis_keep_the_old_rule():
    assert "+10 large high-entropy overlay" in score(rep(pe(overlay=BIG)))[1]
    assert not any("overlay" in x for x in score(rep(pe(overlay=BIG, blob=True)))[1])
