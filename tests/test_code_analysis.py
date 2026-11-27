"""T-14: Code Analysis with capa. capa runs in its own sub-helper; whatever happens to it, the report is made,
and the host checks the new field like everything else from the VM. Synthetic bytes only (no samples)."""
import json
import time
from pathlib import Path

import pytest

from fatbox import cli
from fatbox.host import validate
from fatbox.static import code_analysis as ca
from fatbox.static import file_analysis as fa
from fatbox.static.triage import CAPA_CAP, score
from fatbox.store import Store, make_sample_zip, sha256_bytes

RULES = Path(__file__).resolve().parents[1] / "rules" / "capa"


def m(name, ns, attack=(), scope="code", nursery=False):
    return {"name": name, "namespace": ns, "attack": list(attack), "scope": scope, "nursery": nursery}


def sub(*matches, fmt="pe"):
    return {"status": "ok", "engine": {"capa": "10.0.0", "rules": "10.0.0"}, "format": fmt, "matches": list(matches)}


def caps(*matches):
    return ca.build("ok", None, sub(*matches))


def rep_with(code=None, behaviour=(), file_analysis=None):
    return {"pe": None, "entropy": 5.0, "behaviour": [{"indicator": i, "attack": a, "evidence": "x"} for i, a in behaviour],
            "yara": [], "iocs": {"urls": [], "ipv4": []}, "file_analysis": file_analysis, "code_analysis": code}


# ---- capa namespaces -> topics, and what counts ------------------------------------------------------------
@pytest.mark.parametrize("ns,want", [
    ("host-interaction/process/inject", "injection"), ("host-interaction/process/inject/apc", "injection"),
    ("host-interaction/process/create", "other"),       # creating a process is everyday, not injection
    ("anti-analysis/anti-debugging/debugger-detection", "anti-analysis"),
    ("persistence/registry/run", "persistence"), ("collection/keylog", "collection"),
    ("load-code/pe", "load-code"), ("communication/http/client", "communication"),
    ("impact/inhibit-system-recovery", "impact"), ("data-manipulation/encryption/aes", "encryption"),
    ("data-manipulation/encoding/base64", "other"), ("malware-family/plugx", "malware-family"),
    ("compiler/msvc", "other"), ("", "other"), ("anti-analysisX/y", "other"),
])
def test_topics(ns, want):
    assert ca.topic(ns) == want


def test_only_code_findings_from_stable_rules_count():
    got = {c["name"]: c["scored"] for c in caps(
        m("inject thread", "host-interaction/process/inject", ["T1055"]),
        m("reference analysis tools strings", "anti-analysis", scope="file"),   # a loose string match
        m("load .NET assembly", "load-code/dotnet", ["T1620"], nursery=True),   # a draft rule
        m("read file on Windows", "host-interaction/file-system/read"),         # everyday
        m("match known PlugX module", "malware-family/plugx", scope="file", nursery=True))["capabilities"]}
    assert got == {"inject thread": True, "reference analysis tools strings": False, "load .NET assembly": False,
                   "read file on Windows": False, "match known PlugX module": True}


def test_build_applies_every_cap_and_drops_junk():
    raw = [m("x" * 500, "anti-analysis/" + "y" * 500, ["T1055", "T9", "evil", 5] + [f"T{1000 + i}" for i in range(20)])
           ] + [m(f"c{i}", "collection") for i in range(300)] + ["not a dict", m("", "collection")]
    got = ca.build("ok", None, {**sub(*raw), "format": "elf", "engine": {"capa": "1" * 99, "x": "y"}})
    assert len(got["capabilities"]) == ca.MAX_CAPS and got["format"] is None
    assert got["engine"] == {"capa": "1" * 40}                         # unknown keys dropped
    first = next(c for c in got["capabilities"] if c["name"].startswith("x"))
    assert len(first["name"]) == len(first["namespace"]) == ca.MAX_NAME
    assert first["attack"][0] == "T1055" and len(first["attack"]) == ca.MAX_ATTACK and "T9" not in first["attack"]


def test_failure_keeps_only_status_and_error():
    got = ca.build("timeout", "code analysis took longer than 120 s: stopped", None)
    assert got == {"status": "timeout", "error": "code analysis took longer than 120 s: stopped", "engine": {},
                   "format": None, "capabilities": []}


# ---- score ------------------------------------------------------------------------------------------------
def test_each_topic_counts_once():
    code = caps(m("inject thread", "host-interaction/process/inject", ["T1055"]),
                m("write process memory", "host-interaction/process/inject", ["T1055"]),
                m("check for debugger", "anti-analysis/anti-debugging", ["T1622"]),
                m("send HTTP request", "communication/http/client"))
    pts, why = score(rep_with(code))
    assert pts == 15 + 10 + 5
    assert why == ["+15 code (capa) injection: inject thread, write process memory (T1055)",
                   "+10 code (capa) anti-analysis: check for debugger (T1622)",
                   "+5 code (capa) communication: send HTTP request"]


def test_capa_total_is_capped():
    code = caps(*[m(t, ns) for t, ns in (("i", "host-interaction/process/inject"), ("a", "anti-analysis"),
                                         ("p", "persistence"), ("c", "collection"), ("l", "load-code"),
                                         ("n", "communication"))])
    pts, why = score(rep_with(code))
    assert pts == CAPA_CAP == 40
    assert why[3] == "+5 code (capa) collection: c" and why[4] == "+0 code (capa) load-code: l: capa limit of 40 reached"


def test_what_the_strings_already_scored_is_not_scored_again():
    code = caps(m("check for VMware", "anti-analysis/anti-vm/vm-detection", ["T1497.001"]),
                m("persist via Run key", "persistence/registry/run", ["T1547.001"]),
                m("hide window", "anti-analysis", []))   # no technique: can't be the same fact
    pts, why = score(rep_with(code, behaviour=[("VM/sandbox/tool check", "T1497.001"),
                                               ("Run key persistence", "T1547.001")]))
    assert "+0 code (capa) persistence: persist via Run key: also seen in strings (T1547.001)" in why
    assert "+10 code (capa) anti-analysis: hide window" in why       # the topic still counts for its new finding
    assert pts == 8 + 8 + 10


def test_unscored_findings_give_nothing():
    code = caps(m("reference analysis tools strings", "anti-analysis", scope="file"),
                m("load .NET assembly", "load-code/dotnet", nursery=True), m("read file", "host-interaction/file-system"))
    assert score(rep_with(code)) == (0, [])


def test_everyday_pe_reading_gives_nothing_but_hiding_tricks_count():
    reading = [m(n, "load-code/pe") for n in sorted(ca.EVERYDAY_RULES)]
    assert score(rep_with(caps(*reading))) == (0, [])                # 0.18.3: launchers and runtimes do this too
    got = caps(*reading, m("resolve function by parsing PE exports", "load-code/pe", ["T1129"]))
    assert not any(c["scored"] for c in got["capabilities"] if c["name"] in ca.EVERYDAY_RULES)
    assert score(rep_with(got)) == (10, ["+10 code (capa) load-code: resolve function by parsing PE exports (T1129)"])


def test_everyday_rules_exist_and_the_page_shows_the_same_list():
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    names = {re.search(r"^\s*name: (.+)$", p.read_text(encoding="utf-8"), re.M).group(1).strip()
             for p in (root / "rules/capa/rules/load-code/pe").glob("*.yml")}
    assert ca.EVERYDAY_RULES <= names                                 # a renamed rule would silently score again
    page = (root / "fatbox/host/page.html").read_text(encoding="utf-8")
    listed = re.search(r"CA_EVERYDAY_PE = new Set\(\[(.*?)\]\)", page).group(1)
    assert set(re.findall(r'"([^"]+)"', listed)) == ca.EVERYDAY_RULES


def test_a_family_counts_once_whoever_names_it():
    die = fa.build("ok", None, {"status": "ok", "engine": {}, "filetype": "PE32", "signature": None,
                                "detects": [{"type": "Malware", "name": "PlugX", "version": "", "info": ""}]}, b"", None)
    code = caps(m("match known PlugX module", "malware-family/plugx"))
    assert score(rep_with(code))[1] == ["+25 capa names a malware family: plugx"]
    pts, why = score(rep_with(code, file_analysis=die))
    assert pts == 25 and why == ["+25 DIE names a malware family: PlugX (capa too: plugx)"]


@pytest.mark.parametrize("behaviour,matches,want", [
    ([("shadow copy deletion", "T1490"), ("ransom note language", "T1486")], [],
     "+15 ransomware pattern: backups wiped + ransom note (T1490 + T1486)"),               # unchanged (0.17.2)
    ([("shadow copy deletion", "T1490")], [m("encrypt data using AES", "data-manipulation/encryption/aes")],
     "+15 ransomware pattern: backups wiped + file encryption code (capa) (T1490 + T1486)"),
    ([("ransom note language", "T1486")], [m("delete volume shadow copies", "impact/inhibit-system-recovery", ["T1490"])],
     "+15 ransomware pattern: backups wiped (capa) + ransom note (T1490 + T1486)"),
])
def test_ransomware_pattern_from_strings_or_code(behaviour, matches, want):
    assert want in score(rep_with(caps(*matches), behaviour=behaviour))[1]


def test_encryption_alone_is_no_ransomware():
    why = score(rep_with(caps(m("encrypt data using AES", "data-manipulation/encryption/aes"))))[1]
    assert not any("ransomware" in w for w in why)


def test_failure_says_score_incomplete_but_skipped_does_not():
    assert score(rep_with(ca.build("timeout", "x", None)))[1] == ["+0 code analysis: timeout, score incomplete"]
    assert score(rep_with(ca.build("skipped", "not a Windows program", None))) == (0, [])
    assert score(rep_with(None)) == (0, [])    # reports made before 0.18.0


# ---- the host checks it again ----------------------------------------------------------------------------
def wrap(code):
    return json.dumps({"hashes": {"sha256": "a" * 64}, "priority": "low", "score": 0, "code_analysis": code}).encode()


def good():
    return caps(m("inject thread", "host-interaction/process/inject", ["T1055", "T1055.003"]),
                m("contains PDB path", "executable/pe/pdb", scope="file"))


def test_host_accepts_a_good_field_and_old_reports():
    got = validate.report(wrap(good()), "a" * 64)["code_analysis"]
    assert got == json.loads(json.dumps(good()))
    assert "code_analysis" not in validate.report(json.dumps({"hashes": {"sha256": "a" * 64}, "priority": "low",
                                                              "score": 0}).encode(), "a" * 64)


def _bad(path, value):
    def apply(c):
        if path[0] == "cap":
            c["capabilities"][0][path[1]] = value
        else:
            c[path[0]] = value
        return c
    return apply


@pytest.mark.parametrize("change", [
    _bad(("status",), "fine"), _bad(("format",), "elf"), _bad(("engine",), "capa"), _bad(("capabilities",), {}),
    _bad(("capabilities",), [{}] * 201), _bad(("error",), 5), _bad(("error",), "e" * 4000),
    _bad(("cap", "topic"), "rootkit"), _bad(("cap", "scope"), "process"), _bad(("cap", "name"), ""),
    _bad(("cap", "name"), "n" * 1300), _bad(("cap", "name"), None), _bad(("cap", "attack"), "T1055"),
    _bad(("cap", "attack"), ["T1055; drop"]), _bad(("cap", "attack"), ["T1055"] * 11), _bad(("cap", "attack"), [1055]),
    _bad(("cap", "nursery"), "no"), _bad(("cap", "scored"), 1), _bad(("cap", "namespace"), None),
])
def test_host_refuses_a_bad_field_and_the_whole_report(change):
    with pytest.raises(validate.Invalid):
        validate.report(wrap(change(good())), "a" * 64)


def test_hidden_characters_are_made_visible():
    c = good()
    c["capabilities"][0]["name"] = "inject\u202ethread\x1b[31m"
    got = validate.report(wrap(c), "a" * 64)["code_analysis"]["capabilities"][0]["name"]
    assert "\u202e" not in got and "\x1b" not in got and got.startswith("inject")


@pytest.mark.parametrize("code,fa_packed,want", [
    (good(), None, "2 capabilities · injection ⚠"),
    (caps(m("send HTTP request", "communication/http")), None, "1 capability · communication"),
    (caps(m("read file", "host-interaction/file-system")), "yes", "1 capability · packed: code hidden"),
    (caps(), "no", "0 capabilities"),
    (ca.build("timeout", "x", None), None, "capa: timeout"),
    (ca.build("skipped", "x", None), None, "not a PE: skipped"),
    (ca.build("not_installed", "x", None), None, "capa missing"),
])
def test_code_badge(code, fa_packed, want):
    rep = {"code_analysis": validate.code_analysis(json.loads(json.dumps(code))),
           "file_analysis": {"packed": fa_packed} if fa_packed else None}
    assert validate.code_badge(rep) == want and len(want) <= 60


def test_badge_is_none_for_old_reports():
    assert validate.code_badge({}) is None


# ---- the sub-helper itself -------------------------------------------------------------------------------
def test_non_pe_is_skipped_without_loading_capa():
    assert ca.analyze(b"\x7fELF" + b"\0" * 100, RULES)["status"] == "skipped"


def test_missing_rules_are_said_not_guessed(tmp_path):
    pytest.importorskip("capa")
    got = ca.analyze(b"MZ" + b"\0" * 100, tmp_path / "nowhere")
    assert got["status"] == "not_installed" and "Update VM" in got["error"]


def test_quiet_stdout_keeps_the_json_channel_clean(capfd):
    with ca.quiet_stdout():
        print("FB is None, vivisect noise")
    print("clean")
    assert capfd.readouterr().out == "clean\n"


def test_sub_helper_takes_only_a_sha256():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["capa-one", "C:\\samples\\x.exe"])


def test_rules_are_vendored_at_the_pinned_version():
    assert (RULES / "VERSION").read_text().strip() == "10.0.0"
    assert (RULES / "rules" / "LICENSE.txt").is_file() and len(list((RULES / "sigs").glob("*.sig"))) == 3
    assert len(list((RULES / "rules").rglob("*.yml"))) > 1000
    assert not list(RULES.rglob(".github"))        # only rules and the license came from the zip


def _launcher():
    from test_pipeline import _benign_pe
    p = _benign_pe()
    if not p:
        return None
    for name in ("w64.exe", "w32.exe", "t64.exe", "t32.exe"):   # not the ARM launchers: capa reads x86/x64 code
        if (p.parent / name).is_file():
            return p.parent / name
    return None


def test_real_capa_on_a_benign_program():
    """A clean program gets 0 capa points: library code is skipped (FLIRT), loose and draft rules don't count."""
    pytest.importorskip("capa")
    p = _launcher()
    if not p:
        pytest.skip("no benign PE available")
    out = ca.analyze(p.read_bytes(), RULES)
    assert out["status"] == "ok" and out["format"] == "pe" and out["engine"] == {"capa": "10.0.0", "rules": "10.0.0"}
    built = ca.build("ok", None, out)
    assert built["capabilities"] and validate.code_analysis(json.loads(json.dumps(built)))
    pts, why = score(rep_with(built))
    assert pts == 0, why


# ---- through the helpers: hang, crash, noise --------------------------------------------------------------
HOOK = """
import os, sys, time
import fatbox.static.code_analysis as ca
def _analyze(data, capa_dir, lib_skip=False):
    if b"CA-HANG" in data:
        time.sleep(600)
    if b"CA-CRASH" in data:
        os._exit(9)
    print("FB is None")       # vivisect-style noise on stdout
    return {"status": "ok", "engine": {"capa": "test", "rules": "test"}, "format": "pe",
            "matches": [{"name": "inject thread", "namespace": "host-interaction/process/inject",
                         "attack": ["T1055"], "scope": "code", "nursery": False}]}
ca.analyze = _analyze
"""


@pytest.fixture
def lab(tmp_path, monkeypatch):
    hook = tmp_path / "hook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text(HOOK)
    monkeypatch.setenv("PYTHONPATH", str(hook))
    cfg = tmp_path / "config.toml"
    cfg.write_text('[paths]\ndata_dir = "./data"\nyara_dir = "./rules"\n')
    store = Store(tmp_path / "data")

    def add(name: str, body: bytes) -> str:
        sha = sha256_bytes(body)
        store.add(sha, make_sample_zip(name, body, "infected"), {"file_name": name, "tags": []}, source="manual")
        return sha

    def report(sha):
        return json.loads((store.report_dir_for(sha) / "static.json").read_text())
    return cfg, store, add, report


def test_every_capa_failure_still_saves_the_report(lab):
    cfg, store, add, report = lab
    ok, hang, crash = add("ok.bin", b"CA-OK"), add("slow.bin", b"CA-HANG"), add("crash.bin", b"CA-CRASH")
    t0 = time.monotonic()
    assert cli.main(["-c", str(cfg), "triage", "--sample-time", "10", "--capa-time", "30"]) == 0
    assert time.monotonic() - t0 < 30 + 2 * 15                        # capa's own limit, not the helper's stopwatch
    assert all(store.get(s)["status"] == "static_done" for s in (ok, hang, crash))
    got = {s: report(s)["code_analysis"] for s in (ok, hang, crash)}
    assert got[ok]["status"] == "ok" and got[ok]["capabilities"][0]["topic"] == "injection"   # noise didn't break JSON
    assert "+15 code (capa) injection: inject thread (T1055)" in report(ok)["reasons"]
    assert got[hang]["status"] == "timeout" and got[hang]["error"] == "code analysis took longer than 30 s: stopped"
    assert got[crash]["status"] == "crashed" and "exit 9" in got[crash]["error"]
    for s in (ok, hang, crash):                                        # the host accepts all of them
        raw = (store.report_dir_for(s) / "static.json").read_bytes()
        assert validate.report(raw, s)["code_analysis"]["status"] in validate.CA_STATUSES
