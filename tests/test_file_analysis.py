"""T-9: File Analysis. The engines run in their own sub-helper; whatever happens to it, the report is made, and
the host checks the new field like everything else from the VM. Synthetic bytes only (no samples)."""
import json
import os
import time

import pytest

from fatbox import cli
from fatbox.host import validate
from fatbox.static import file_analysis as fa
from fatbox.static.triage import score
from fatbox.store import Store, make_sample_zip, sha256_bytes


def sub(*values, filetype="PE32", signature=None):
    return {"status": "ok", "engine": {"die": "3.09", "die_python": "0.5.0"}, "filetype": filetype,
            "detects": [dict(zip(("type", "name", "version", "info"), v)) for v in values], "signature": signature}


def pe_info(sections=(), blob=None, overlay=None):
    return {"sections": [{"name": n, "entropy": e, "raw_size": 4096, "perms": "R-X"} for n, e in sections],
            "has_signature_blob": blob is not None, "signature_blob": blob, "overlay": overlay, "packer_hints": [],
            "import_count": 50, "is_dotnet": False, "suspicious_imports": [], "entrypoint_section": ".text",
            "compile_time_anomaly": False, "tls_callbacks": False}


# ---- mapping DIE's categories onto the 9 fields -------------------------------------------------------------
def test_die_categories_become_the_fields():
    got = fa.build("ok", None, sub(("Compiler", "Microsoft Visual C/C++", "19.29", "LTCG/C"), ("Linker", "Microsoft Linker", "14.29", ""),
                                   ("Packer", "UPX", "3.96", "NRV"), ("Cryptor", "SomeCrypt", "", ""),
                                   ("Installer", "Inno Setup", "6.2", ""), ("Library", ".NET", "v4.0", ""),
                                   ("Tool", "Visual Studio", "2019", ""), ("(Heur)Packer", "Compressed", "", "High entropy"),
                                   ("Sign tool", "Windows Authenticode", "2.0", ""), ("Unknown", "Unknown", "", "")),
                   b"", None)
    assert got["type"] == "PE32" and got["engine"] == {"die": "3.09", "die_python": "0.5.0"}
    assert got["compiler"] == ["Microsoft Visual C/C++ 19.29 (LTCG/C)", "Microsoft Linker 14.29"]
    assert got["packer"] == ["UPX 3.96 (NRV)"] and got["protector"] == ["SomeCrypt"]   # cryptor counts as protector
    assert got["installer"] == ["Inno Setup 6.2"] and got["runtime"] == [".NET v4.0"]
    assert got["other"] == ["tool: Visual Studio 2019", "(heuristic) Compressed (High entropy)"]  # a guess names no packer
    assert (got["packed"], got["packed_why"]) == ("yes", "protector SomeCrypt found")


def test_caps_on_lists_and_strings():
    got = fa.build("ok", None, sub(*[("Compiler", f"c{i}" + "x" * 400, "", "") for i in range(80)]), b"", None)
    assert len(got["compiler"]) == fa.MAX_ITEMS and all(len(c) <= fa.MAX_STR for c in got["compiler"])


@pytest.mark.parametrize("sections,detects,want", [
    ([(".text", 6.1)], [], "no"),
    ([(".text", 7.6)], [], "likely"),
    ([(".text", 6.0)], [("(Heur)Protector", "Generic", "", "")], "likely"),
    ([(".text", 6.0)], [("Protector", "Themida", "3.x", "")], "yes"),
])
def test_packed_verdict(sections, detects, want):
    got = fa.build("ok", None, sub(*detects), b"", pe_info(sections))
    assert got["packed"] == want and got["packed_why"]


def test_engine_failure_still_gives_pefile_facts_and_an_honest_verdict():
    data = b"A" * 1000 + os.urandom(3000) + b"S" * 500
    pe = pe_info([(".text", 6.0)], blob={"offset": 4000, "size": 500}, overlay={"offset": 1000, "size": 3500})
    got = fa.build("timeout", "file analysis took longer than 30 s: stopped", None, data, pe)
    assert got["status"] == "timeout" and got["packer"] == [] and got["packed"] == "unknown"
    assert got["overlay"]["offset"] == 1000 and got["overlay"]["size"] == 3000       # the signature blob is not overlay
    assert got["signature"] == {"signed": True, "checked": False, "valid": None, "signer": None,
                                "reason": "validity not checked"}


def test_signature_only_at_the_end_is_no_overlay():
    pe = pe_info(blob={"offset": 900, "size": 100}, overlay={"offset": 900, "size": 100})
    assert fa.build("ok", None, sub(), b"x" * 1000, pe)["overlay"] is None


# ---- score: one fact, points once -----------------------------------------------------------------------
def rep_with(fa_obj, packer_hints=()):
    pe = pe_info([(".text", 6.0)])
    pe["packer_hints"] = list(packer_hints)
    return {"pe": pe, "entropy": 6.0, "behaviour": [], "yara": [], "iocs": {"urls": [], "ipv4": []}, "file_analysis": fa_obj}


def test_score_rules():
    packed = fa.build("ok", None, sub(("Packer", "UPX", "3.96", "")), b"", pe_info())
    pts, why = score(rep_with(packed, ["UPX"]))
    assert why == ["+15 packer (DIE): UPX 3.96"] and pts == 15           # not also +15 for section names
    pts, why = score(rep_with(None, ["UPX"]))
    assert why == ["+15 packer section names: UPX"]                       # engine missing: the old rule still works
    prot = fa.build("ok", None, sub(("Protector", "Themida", "3.x", "")), b"", pe_info())
    assert score(rep_with(prot))[0] == 20
    bad_sig = fa.build("ok", None, sub(signature={"checked": True, "signed": True, "valid": False, "signer": "CN=x",
                                                  "reason": "INVALID_DIGEST"}), b"", pe_info())
    assert score(rep_with(bad_sig))[1] == ["+10 signature invalid: INVALID_DIGEST"]
    good_sig = fa.build("ok", None, sub(signature={"checked": True, "signed": True, "valid": True}), b"", pe_info())
    assert score(rep_with(good_sig))[0] == 0                              # no minus points either
    inst = fa.build("ok", None, sub(("Installer", "NSIS", "3.0", "")), b"", pe_info())
    assert score(rep_with(inst)) == (0, ["+0 installer / SFX (DIE): NSIS 3.0: the payload may sit in the overlay"])
    gone = fa.build("not_installed", "die-python: ImportError", None, b"", pe_info())
    assert score(rep_with(gone))[1] == ["+0 file analysis: not_installed, score incomplete"]


# ---- the real engine, when it is installed (CI installs requirements.txt) --------------------------------------
def test_real_die_on_a_benign_pe_and_text():
    pytest.importorskip("die")
    from test_pipeline import _benign_pe
    p = _benign_pe()
    if not p:
        pytest.skip("no benign PE available")
    out = fa.scan(p.read_bytes())
    assert out["status"] == "ok" and out["filetype"].startswith("PE") and out["engine"]["die"]
    built = fa.build("ok", None, out, p.read_bytes(), None)
    assert built["compiler"] and built["packer"] == [] and validate.file_analysis(json.loads(json.dumps(built)))
    assert fa.scan(b"hello world " * 50)["filetype"] == "Binary"


# ---- through the helpers: hang, crash, missing engine, too much output -------------------------------------
HOOK = """
import os, sys, time
import fatbox.static.file_analysis as fa
if os.environ.get("FAKE_NO_DIE"):
    sys.modules["die"] = None
_real = fa.scan
def _scan(data):
    if b"FA-HANG" in data:
        time.sleep(float(os.environ.get("FA_SLEEP", "600")))
        open(os.environ["FA_MARK"], "w").write("still alive")
    if b"FA-CRASH" in data:
        os._exit(9)
    if b"FA-FLOOD" in data:
        sys.stdout.write("x" * (2 * 1024 * 1024)); sys.stdout.flush(); time.sleep(600)
    if b"FA-OK" in data:
        return {"status": "ok", "engine": {"die": "test"}, "filetype": "Binary",
                "detects": [{"type": "Packer", "name": "UPX", "version": "3.96", "info": ""}], "signature": None}
    return _real(data)
fa.scan = _scan
import fatbox.static.triage as t
_triage = t.triage
def _maybe_hang(data, name, scanner=None):
    if "hang" in name:
        time.sleep(600)
    return _triage(data, name, scanner)
t.triage = _maybe_hang
"""


@pytest.fixture
def lab(tmp_path, monkeypatch):
    hook = tmp_path / "hook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text(HOOK)
    monkeypatch.setenv("PYTHONPATH", str(hook))
    monkeypatch.setenv("FA_MARK", str(tmp_path / "mark"))
    cfg = tmp_path / "config.toml"
    cfg.write_text('[paths]\ndata_dir = "./data"\nyara_dir = "./rules"\n')
    store = Store(tmp_path / "data")

    def add(name: str, body: bytes) -> str:
        sha = sha256_bytes(body)
        store.add(sha, make_sample_zip(name, body, "infected"), {"file_name": name, "tags": []}, source="manual")
        return sha

    def report(sha):
        return json.loads((store.report_dir_for(sha) / "static.json").read_text())
    return cfg, store, add, report, tmp_path


def triage(cfg, limit="10"):
    return cli.main(["-c", str(cfg), "triage", "--sample-time", limit, "--capa-time", "30"])


def test_every_engine_failure_still_saves_the_report(lab, monkeypatch):
    cfg, store, add, report, _ = lab
    ok = add("ok.bin", b"FA-OK sample")
    hang = add("slow.bin", b"FA-HANG sample")
    crash = add("crash.bin", b"FA-CRASH sample")
    flood = add("flood.bin", b"FA-FLOOD sample")
    t0 = time.monotonic()
    assert triage(cfg) == 0
    assert time.monotonic() - t0 < 4 * 10                            # each sample within its own limit
    assert all(store.get(s)["status"] == "static_done" for s in (ok, hang, crash, flood))
    assert report(ok)["file_analysis"]["packer"] == ["UPX 3.96"] and report(ok)["score"] == 15
    got = {s: report(s)["file_analysis"] for s in (hang, crash, flood)}
    assert got[hang]["status"] == "timeout" and got[hang]["error"] == "file analysis took longer than 5 s: stopped"
    assert got[crash]["status"] == "crashed" and "exit 9" in got[crash]["error"]
    assert got[flood]["status"] == "error" and "more than" in got[flood]["error"]
    assert "+0 file analysis: timeout, score incomplete" in report(hang)["reasons"]
    for s in (ok, hang, crash, flood):                                 # the host accepts all of them
        raw = (store.report_dir_for(s) / "static.json").read_bytes()
        assert validate.report(raw, s)["file_analysis"]["status"] in validate.FA_STATUSES


def test_missing_engine_is_said_not_guessed(lab, monkeypatch):
    cfg, store, add, report, _ = lab
    monkeypatch.setenv("FAKE_NO_DIE", "1")
    sha = add("x.txt", b"plain text, engine missing")
    assert triage(cfg) == 0
    got = report(sha)["file_analysis"]
    assert got["status"] == "not_installed" and got["error"].startswith("die-python:")
    assert validate.file_badge({"file_analysis": got}) == "engine missing"


def test_a_stopped_helper_takes_its_sub_helper_with_it(lab, monkeypatch):
    cfg, store, add, _, tmp = lab
    monkeypatch.setenv("FA_SLEEP", "44")                               # longer than 10 s + capa's 30 s
    sha = add("hang.bin", b"FA-HANG and the rest of triage hangs too")
    assert triage(cfg) == 0
    assert store.get(sha)["status"] == "timeout"
    time.sleep(8)                                                      # 40 s limit + 8 s > the 44 s sleep
    assert not (tmp / "mark").exists()                                 # killed with the helper, not left behind


def test_sub_helper_takes_only_a_sha256():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["file-analysis-one", "C:\\samples\\x.exe"])


# ---- host: the new field is checked like everything from the VM (INV-4) -------------------------------------
def good():
    return fa.build("ok", None, sub(("Packer", "UPX", "3.96", ""), ("Compiler", "MSVC", "19", ""),
                                    signature={"checked": True, "signed": True, "valid": False, "signer": "CN=Some Corp",
                                               "reason": "INVALID_DIGEST"}),
                    b"z" * 2000, pe_info(overlay={"offset": 1000, "size": 1000}))


def wrap(fa_obj, sha="a" * 64):
    return json.dumps({"hashes": {"sha256": sha}, "priority": "low", "score": 1, "file_analysis": fa_obj}).encode()


def test_host_accepts_good_and_old_reports():
    got = validate.report(wrap(good()), "a" * 64)["file_analysis"]
    assert got["packer"] == ["UPX 3.96"] and got["signature"]["valid"] is False and got["overlay"]["size"] == 1000
    old = json.dumps({"hashes": {"sha256": "a" * 64}, "priority": "low", "score": 1}).encode()
    assert "file_analysis" not in validate.report(old, "a" * 64)
    extra = {**good(), "evil": "<script>", "engine": {"die": "3.09", "x": 1}}
    got = validate.report(wrap(extra), "a" * 64)["file_analysis"]
    assert "evil" not in got and got["engine"] == {"die": "3.09"}             # outside the schema: dropped


@pytest.mark.parametrize("change", [
    {"status": "pwned"}, {"packed": "maybe"}, {"packer": ["x"] * 51}, {"packer": "UPX"}, {"packer": [{"a": 1}]},
    {"compiler": ["x" * 4000]}, {"overlay": {"offset": 0, "size": 10, "entropy": 9}},
    {"overlay": {"offset": -1, "size": 10, "entropy": 1}}, {"overlay": {"offset": 0, "size": 200 * 1024 * 1024, "entropy": 1}},
    {"overlay": {"offset": 0, "size": 10, "entropy": True}}, {"overlay": "big"},
    {"signature": {"checked": True, "signed": "yes"}}, {"signature": {"signed": True}}, {"signature": []},
    {"engine": "3.09"}, {"type": 7},
])
def test_host_refuses_a_bad_field_and_the_whole_report(change):
    with pytest.raises(validate.Invalid):
        validate.report(wrap({**good(), **change}), "a" * 64)


def test_hidden_characters_are_shown_not_acted_on():
    got = validate.report(wrap({**good(), "packer": ["UPX\u202eexe.gpj"]}), "a" * 64)["file_analysis"]
    assert got["packer"] == ["UPX\\u202eexe.gpj"]


@pytest.mark.parametrize("fields,want", [
    ({"packer": ["UPX 3.96 (NRV)"]}, "PE32 · UPX 3.96 · packed ⚠"),          # good() has a broken signature
    ({"signature": None, "protector": ["Themida 3.x"]}, "PE32 · Themida 3.x · protected ⚠"),
    ({"signature": None, "packer": [], "installer": ["Inno Setup 6.2"]}, "PE32 · Inno Setup 6.2 · installer"),
    ({"signature": None, "packer": [], "packed": "no"}, "PE32 · MSVC 19 · not packed"),
    ({"signature": None, "packer": [], "protector": ["Confuser 1.X"], "other": ["malware: NjRAT 0.7D (Obfuscated)"]},
     "PE32 · NjRAT 0.7D · malware ⚠"),                                         # 0.17.2: a family beats a protector
    ({"status": "timeout"}, "timeout"), ({"status": "crashed"}, "engine crashed"),
    ({"signature": None, "packer": [], "packed": "no", "type": "PE64", "compiler": ["C" * 200]},
     "PE64 · " + "C" * 40 + " · not packed"),
])
def test_badge_is_written_by_the_host(fields, want):
    rep = validate.report(wrap({**good(), **fields}), "a" * 64)
    assert validate.file_badge(rep) == want and len(want) <= 60
    assert validate.file_badge({"hashes": {}}) is None


def test_badge_lands_in_the_library_and_is_checked_on_read(tmp_path):
    from fatbox.host.library import Library
    lib, A = Library(tmp_path), "a" * 64
    rep = validate.report(wrap(good(), A), A)
    lib.sync([{"sha256": A, "status": "static_done", "score": 1, "priority": "low", "tags": []}], lambda s: rep,
             lambda _: None)
    assert lib.rows()[0]["file_badge"] == "PE32 · UPX 3.96 · packed ⚠"
    idx = json.loads(lib.index_path.read_text())
    idx["rows"][0]["file_badge"] = "x\u202e" * 100
    lib.index_path.write_text(json.dumps(idx))
    assert len(lib.rows()[0]["file_badge"]) <= 60 * 6 and "\u202e" not in lib.rows()[0]["file_badge"]
    idx["rows"][0]["file_badge"] = {"html": "<b>"}
    lib.index_path.write_text(json.dumps(idx))
    assert lib.rows() == [] and "1 damaged row" in lib.take_notes()[0]


# ---- 0.17.1: what the live test taught (a sample with UPX section names that isn't UPX-packed) ------------------
def test_renamed_upx_sections_are_explained_not_trusted():
    pe = pe_info([("UPX0", 4.66), ("UPX1", 6.54), (".rsrc", 4.15)])
    pe["packer_hints"] = ["UPX"]
    got = fa.build("ok", None, sub(), b"", pe)
    assert got["packed"] == "no"
    assert got["packed_why"] == ("section names say UPX, but DIE found no UPX code and entropy is low (max 6.5): "
                                 "renamed sections?")
    hot = pe_info([("UPX0", 0.0), ("UPX1", 7.9)])
    hot["packer_hints"] = ["UPX"]
    assert fa.build("ok", None, sub(), b"", hot)["packed"] == "likely"   # high entropy still says likely


def test_no_die_match_is_said():
    got = fa.build("ok", None, sub(("Unknown", "Unknown", "", "")), b"", pe_info())
    assert got["other"] == [fa.NO_MATCH] and validate.file_analysis(json.loads(json.dumps(got)))["other"] == [fa.NO_MATCH]
    assert fa.build("ok", None, sub(("Compiler", "MSVC", "19", "")), b"", pe_info())["other"] == []
    assert fa.build("timeout", "x", None, b"", pe_info())["other"] == []      # only when DIE actually ran


# ---- 0.17.2: DIE names a malware family (found in a review of real reports: njrat scored 13) -------------------
def test_die_family_scores_once():
    got = fa.build("ok", None, sub(("Malware", "NjRAT", "0.7D", "Obfuscated"), ("Malware", "NjRAT", "0.7D", ""),
                                   ("Protector", "Confuser", "1.X", "")), b"", pe_info())
    assert fa.families(got) == ["NjRAT 0.7D"]
    pts, why = score(rep_with(got))
    assert why == ["+25 DIE names a malware family: NjRAT 0.7D", "+20 protector / cryptor / obfuscator (DIE): Confuser 1.X"]
    assert pts == 45


def test_family_heuristic_or_failed_engine_gives_nothing():
    guess = fa.build("ok", None, sub(("(Heur)Malware", "NjRAT", "", "")), b"", pe_info())
    assert fa.families(guess) == [] and score(rep_with(guess))[0] == 0
    assert fa.families({"status": "timeout", "other": ["malware: NjRAT"]}) == []
    assert fa.families(None) == []
    virus = fa.build("ok", None, sub(("Virus", "Jerusalem", "", "")), b"", pe_info())
    assert fa.families(virus) == ["Jerusalem"]


# ---- 0.17.2: YARA FB_UPX_Packed says what the packer line already scored ------------------------------------
def test_upx_yara_not_counted_twice():
    rep = rep_with(None, ["UPX"])
    rep["yara"] = [{"rule": "FB_UPX_Packed"}]
    pts, why = score(rep)
    assert why == ["+15 packer section names: UPX", "+0 YARA FB_UPX_Packed: same fact as the packer line"] and pts == 15
    rep["yara"].append({"rule": "FB_Shadow_Copy_Wipe"})                    # another rule still gives +20
    assert score(rep)[1][1] == "+20 YARA: FB_Shadow_Copy_Wipe"
    alone = rep_with(None)
    alone["yara"] = [{"rule": "FB_UPX_Packed"}]                             # no packer line: YARA is the only voice
    assert score(alone)[1] == ["+20 YARA: FB_UPX_Packed"]


# ---- 0.17.2: one behaviour counts once; backups wiped + ransom note is the ransomware pattern -----------------
def _beh(*labels):
    return [{"indicator": x, "attack": "T1490" if "shadow" in x else "T1486", "evidence": "e"} for x in labels]


def test_behaviour_once_and_ransomware_pattern():
    rep = rep_with(None)
    rep["behaviour"] = _beh("shadow copy deletion", "shadow copy deletion")
    assert score(rep) == (8, ["+8 string indicator: shadow copy deletion (T1490)"])
    rep["behaviour"] = _beh("shadow copy deletion", "shadow copy deletion", "ransom note language")
    pts, why = score(rep)
    assert pts == 31 and why[-1] == "+15 ransomware pattern: backups wiped + ransom note (T1490 + T1486)"
    rep["behaviour"] = _beh("ransom note language")                        # a ransom word alone: no pattern
    assert score(rep)[0] == 8
