"""T-13: browse the MalwareBazaar list in the host GUI, pick exact samples, fetch only those."""
import json
from pathlib import Path

import pytest

from fatbox import cli
from fatbox.fetch.bazaar import BazaarSource, PickedSource
from fatbox.fetch.common import FetchStats, Filters, run_fetch
from fatbox.host import validate
from fatbox.host.controller import browse_args, fetch_args, picks
from fatbox.store import Store, make_sample_zip, sha256_bytes
from test_pipeline import FakeResp, FakeSession

DOC = b"\xd0\xcf\x11\xe0 not a PE, a picked document " * 20


def bazaar_handler(files: dict, info: dict):
    def handler(method, data):
        if data["query"] == "get_info":
            d = info.get(data["hash"])
            return FakeResp(js={"query_status": "ok", "data": [d]} if d else {"query_status": "hash_not_found"})
        if data["query"] == "get_file":
            sha = data["sha256_hash"]
            return FakeResp(content=make_sample_zip(f"{sha}.bin", files[sha], "infected"))
        raise AssertionError(f"picked fetch must not list: {data}")
    return handler


def test_picked_fetch_gets_exactly_those_with_metadata(tmp_path):
    a, b = DOC, b"MZ second picked sample " * 30
    sa, sb = sha256_bytes(a), sha256_bytes(b)
    sess = FakeSession(bazaar_handler({sa: a, sb: b}, {sa: {"sha256_hash": sa, "signature": "Emotet",
                                                            "tags": ["doc"], "file_type": "doc", "file_size": len(a)}}))
    src = PickedSource(BazaarSource("KEY", session=sess), [sa, sb])
    store, stats = Store(tmp_path), FetchStats()
    f = Filters(file_types=[], max_per_run=2, delay_seconds=0)
    assert run_fetch(store, src, f, "infected", 1 << 20, stats=stats) == [sa, sb]
    assert store.get(sa)["signature"] == "Emotet"   # metadata from get_info
    assert store.get(sb)["signature"] is None       # unknown to get_info: still fetched, sha256 checked
    assert [c[1]["query"] for c in sess.calls] == ["get_info", "get_info", "get_file", "get_file"]


def test_picked_fetch_keeps_safety_rules(tmp_path):
    big = b"B" * (2 * 1024 * 1024)
    sbig = sha256_bytes(big)
    liar = sha256_bytes(b"what was promised")
    sess = FakeSession(bazaar_handler({sbig: big, liar: b"something else"},
                                      {sbig: {"sha256_hash": sbig, "file_size": len(big)}}))
    src = PickedSource(BazaarSource("KEY", session=sess), [sbig, liar])
    store, stats = Store(tmp_path), FetchStats()
    added = run_fetch(store, src, Filters(file_types=[], max_per_run=2, delay_seconds=0), "infected", 1024 * 1024,
                      stats=stats)
    assert added == []            # over the 1 MB download limit: skipped before download; wrong bytes: rejected
    assert stats.failed == 1 and not store.has(liar)


def test_cli_fetch_sha256_checks_input_and_skips_known(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[paths]\ndata_dir = "./data"\n')
    store = Store(tmp_path / "data")
    known = sha256_bytes(DOC)
    store.add(known, make_sample_zip("k.doc", DOC, "infected"), {}, "manual")
    for bad in (["--sha256", "abc"], ["--sha256", *[f"{i:064x}" for i in range(31)]]):
        with pytest.raises(SystemExit) if bad[1] == "abc" else _no_raise():
            rc = cli.main(["-c", str(cfg), "fetch", *bad])
            assert rc == 2
    capsys.readouterr()
    seen = {}

    def fake_run_fetch(store, source, f, *a, **kw):
        seen.update(shas=source.shas, types=f.file_types, n=f.max_per_run)
        return []
    monkeypatch.setattr("fatbox.fetch.common.run_fetch", fake_run_fetch)
    monkeypatch.setenv("MB_API_KEY", "k")
    new = "f" * 64
    assert cli.main(["-c", str(cfg), "fetch", "--sha256", known.upper(), new, new]) == 0
    out = capsys.readouterr().out
    assert f"{known[:16]} already in the VM: skipped" in out and "picked: 2 sample(s), 1 already in the VM" in out
    assert seen == {"shas": [new], "types": [], "n": 1}   # only the new one; type filter off for picks


class _no_raise:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_cli_browse_prints_json_with_in_vm(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[paths]\ndata_dir = "./data"\n')
    store = Store(tmp_path / "data")
    have = sha256_bytes(DOC)
    store.add(have, make_sample_zip("k.doc", DOC, "infected"), {}, "manual")

    class Src:
        def list_candidates(self):
            return [{"sha256": have, "signature": "X"}, {"sha256": "d" * 64}, {"sha256": None}]
    monkeypatch.setattr(cli, "make_source", lambda c, n, a: Src())
    assert cli.main(["-c", str(cfg), "browse", "--mode", "tag", "--value", "ransomware"]) == 0
    rows = json.loads(capsys.readouterr().out)["rows"]
    assert [(r["sha256"][:1], r["in_vm"]) for r in rows] == [(have[:1], True), ("d", False)]


def test_host_list_validation_drops_bad_rows():
    raw = json.dumps({"rows": [
        {"sha256": "A" * 64, "signature": "Evil‮gpj.exe", "tags": ["t\x1b[2J", 5], "file_size": 10, "in_vm": "yes"},
        {"sha256": "a" * 64},                     # duplicate after lowercasing
        {"sha256": "nope"}, {"sha256": "b" * 64, "file_size": -1}, {"sha256": "c" * 64, "tags": "x"}, "row",
    ]}).encode()
    rows, dropped = validate.candidate_list(raw)
    assert [r["sha256"] for r in rows] == ["a" * 64] and dropped == 5
    r = rows[0]
    assert "‮" not in r["signature"] and "\x1b" not in r["tags"][0] and r["in_vm"] is False
    with pytest.raises(validate.Invalid):
        validate.candidate_list(b"x" * (validate.LIST_MAX_BYTES + 1))


def test_host_args_for_browse_and_picks():
    assert browse_args({"mode": "tag", "value": "ransomware"}) == ["browse", "--mode", "tag", "--value", "ransomware",
                                                                  "--limit", "100"]
    assert browse_args({"mode": "recent", "limit": "25"})[-2:] == ["--limit", "25"]
    for bad in (10, 1000, "all", True, None):  # 0.29.0: List 25, 50 or 100 only
        with pytest.raises(ValueError):
            browse_args({"mode": "recent", "limit": bad})
    assert cli.build_parser().parse_args(browse_args({"mode": "latest", "limit": 50})).limit == 50  # VM accepts it
    with pytest.raises(ValueError):
        browse_args({"mode": "tag", "value": "a;rm -rf"})
    good = ["a" * 64, "B" * 64, "a" * 64]
    assert picks({"pick": good}) == ["a" * 64, "b" * 64]
    for bad in ([], ["a" * 63], ["a" * 64] * 0 + [f"{i:064x}" for i in range(31)], "a" * 64, [None], ["--help"]):
        with pytest.raises(ValueError):
            picks({"pick": bad})
    args = fetch_args({"pick": good, "max": 99, "max_size_mb": 5, "budget": 400, "small_first": True})
    assert args == ["fetch", "--source", "bazaar", "--sha256", "a" * 64, "b" * 64, "--max-size-mb", "5", "--budget", "400"]
    assert cli.build_parser().parse_args(args).sha256 == ["a" * 64, "b" * 64]  # the real VM CLI accepts it


def test_host_browse_end_to_end(tmp_path, monkeypatch):
    """Through the fake VBoxManage: cable in only while listing, rows checked, pre-score made on the host."""
    import test_host
    ctl, _, _ = test_host.lab.__wrapped__(tmp_path, monkeypatch)
    lines = []
    rows = ctl.browse({"mode": "tag", "value": "ransomware"}, lines.append)
    assert test_host.guest_log() == ["--version cable=off", "browse cable=on"]
    assert ctl.vm.cable() == "off" and "--- network OFF (checked)" in lines
    assert [r["sha256"][0] for r in rows] == ["a", "b"]                 # sorted by host pre-score
    assert rows[0]["categories"] == ["ransomware"] and rows[0]["prescore"] == 25 + 35 + 15 + 10
    assert "‮" not in rows[1]["signature"]
    assert any("2 sample(s) listed, 2 bad row(s) dropped" in ln for ln in lines)
    # 0.29.0: the Settings filters apply to Browse (same rules as a fetch); the page hides skipped rows
    assert rows[0]["skip"] == "" and rows[1]["skip"] == "too large"     # 9 MB dll over the 5 MB download limit
    p = ctl.prefs.load()
    p["filters"]["skip_families"] = ["LockBit"]
    p["fetch"]["size_limit"] = False
    ctl.prefs.save(p)
    rows = {r["sha256"][0]: r for r in ctl.browse({"mode": "tag", "value": "ransomware", "limit": 25}, lines.append)}
    assert rows["a"]["skip"] == "family skipped" and rows["b"]["skip"] == ""
    assert test_host.guest_log()[-1] == "browse cable=on"


def test_new_categories_and_host_needs_no_libraries():
    """0.29.0: more categories for the Show menu; the filter rules the host uses import no third-party library."""
    from fatbox.fetch import meta
    assert meta.categories({"signature": "CobaltStrike"}) == ["backdoor"]
    assert meta.categories({"signature": "XMRig", "tags": ["CoinMiner"]}) == ["miner"]
    assert meta.categories({"tags": ["trickbot"]}) == ["banker"]
    assert set(meta.CATEGORY_WEIGHT) == set(meta.FAMILY_PRESETS)
    code = (Path(meta.__file__)).read_text()
    assert "import requests" not in code and "pyzipper" not in code and "fatbox.store" not in code
    from fatbox.fetch.common import prefilter
    f = meta.Filters(file_types=["exe"], min_size_kb=10)
    assert prefilter({"file_type": "dll"}, f, 5 << 20) == "file_type=dll"
    assert meta.prefilter({"file_type": "exe", "file_size": 2048}, f, 5 << 20, 100 << 20) == "too small"


def test_fetch_tab_is_browse_fetch_triage():
    """0.29.0: no blind 'Fetch + triage' button and no Samples box; List 25/50/100; Triage is its own step."""
    page = (Path(cli.__file__).parent / "host" / "page.html").read_text(encoding="utf-8")
    assert "Fetch + triage" not in page and 'id="max"' not in page and 'id="s-max"' not in page
    assert '<select id="limit"' in page and all(f'<option value="{n}"' in page for n in (25, 50, 100))
    assert 'id="triagebtn"' in page and '"/api/triage"' in page and 'id="fetchstep"' in page
    assert "File type" not in page.split('id="ddbox"')[1].split("</section>")[0]  # Show never repeats Settings


def test_triage_step_unplugs_first_and_runs_offline(tmp_path, monkeypatch):
    import test_host
    ctl, _, _ = test_host.lab.__wrapped__(tmp_path, monkeypatch)
    ctl.vm.set_network(True)   # turned on by hand before Triage
    lines = []
    assert ctl.triage(lines.append) == 0
    assert "triage cable=off" in test_host.guest_log() and ctl.vm.cable() == "off"
    assert lines.index("--- network OFF (checked)") < lines.index("--- starting analysis (network is off)")


def test_fetch_tab_is_simple():
    """0.33.0: no step bar (the Fetch tab label says the step), Settings fold into a 'Fetch rules' hover list,
    the value box shows only for the modes that use it."""
    page = (Path(cli.__file__).parent / "host" / "page.html").read_text(encoding="utf-8")
    assert 'id="steps"' not in page and 'id="st-1"' not in page and 'id="fromchips"' not in page
    assert 'id="tab-fetch"' in page.split('id="fetchstep"')[0].rsplit("<button", 1)[1]  # the label lives in the tab
    assert 'id="rulesbtn"' in page and 'id="rulespop"' in page and ".rules:hover .rpop" in page
    assert '$("value").disabled = $("value").hidden = !needs' in page
    assert "innerHTML" not in page.split("function fromChips")[1].split("\n}\n")[0]  # VM-free, but text nodes only


def test_polite_pause_only_between_downloads(tmp_path, monkeypatch):
    """0.39.0: the pause between MalwareBazaar downloads stays, but none after the last one."""
    from fatbox.fetch import common
    a, b = DOC, b"MZ second picked sample " * 30
    sa, sb = sha256_bytes(a), sha256_bytes(b)
    sess = FakeSession(bazaar_handler({sa: a, sb: b}, {}))
    src = PickedSource(BazaarSource("KEY", session=sess), [sa, sb])
    slept = []
    monkeypatch.setattr(common.time, "sleep", slept.append)
    run_fetch(Store(tmp_path), src, Filters(file_types=[], max_per_run=2, delay_seconds=2), "infected", 1 << 20,
              stats=FetchStats())
    assert slept == [2]
