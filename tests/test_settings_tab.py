"""0.23.0: the Settings tab. Values are saved on the host, sent as allow-listed options, and checked again in the VM.
The unpack limit (zip-bomb guard) can go lower, never higher or off."""
import json
import sys

import pytest

from fatbox.cli import build_parser
from fatbox.config import load_config
from fatbox.fetch.common import FetchStats, Filters, prefilter, run_fetch
from fatbox.host import prefs as P
from fatbox.host import validate
from fatbox.host.controller import fetch_args, triage_args
from fatbox.store import Store, sha256_bytes
from test_limits import F, Src, pe


# --- host: checking and saving ------------------------------------------------------------------------------
def test_defaults_pass_the_check_and_keep_the_old_gui_values():
    d = P.defaults()
    assert P.check(d) == d
    assert d["big"] == {"unpack_limit_mb": 100, "too_big": "skip"} and d["filters"]["types"] == ["exe", "dll"]


@pytest.mark.parametrize("path, value, msg", [
    (("big", "unpack_limit_mb"), 200, "Unpack limit"),        # never higher than 100
    (("big", "unpack_limit_mb"), 0, "Unpack limit"),          # never off
    (("big", "unpack_limit_mb"), 60, "Unpack limit"),         # only 25 / 50 / 100
    (("filters", "types"), [], "tick at least one"),
    (("filters", "types"), ["exe", "js"], "tick at least one"),
    (("filters", "tags"), ["ok", "<script>"], "Only these tags"),
    (("filters", "skip_families"), "a;rm -rf", "Never these families"),
    (("filters", "min_size_kb"), 10241, "Smallest file"),
    (("fetch", "max"), 31, "Samples per fetch"),
    (("fetch", "max"), True, "Samples per fetch"),
    (("fetch", "size_limit"), "yes", "Download limit"),
    (("analysis", "parallel"), 11, "Samples at once"),
    (("analysis", "capa_packed"), "maybe", "capa on packed"),
    (("analysis", "sample_time_s"), 2.5, "Time per sample"),
])
def test_bad_values_are_refused_with_words(path, value, msg):
    d = P.defaults()
    d[path[0]][path[1]] = value
    with pytest.raises(ValueError, match=msg):
        P.check(d)


def test_browser_strings_are_accepted_and_cleaned():
    d = P.defaults()
    d["fetch"]["max"] = "7"
    d["filters"].update(types=["dll", "exe", "office"], tags=" ransomware , stealer,,", skip_families=["Mirai", "mirai"])
    out = P.check(d)
    assert out["fetch"]["max"] == 7
    assert out["filters"]["types"] == ["exe", "dll", "office"]          # fixed order
    assert out["filters"]["tags"] == ["ransomware", "stealer"] and out["filters"]["skip_families"] == ["Mirai"]


def test_save_load_reset_and_a_damaged_file(tmp_path):
    p = P.Prefs(tmp_path, 90, 300)
    assert p.load()["analysis"]["sample_time_s"] == 90                    # defaults start from host.toml
    d = p.load()
    d["big"]["too_big"] = "info"
    p.save(d)
    assert p.load()["big"]["too_big"] == "info"
    assert json.loads((tmp_path / "settings.json").read_text())["version"] == 1
    (tmp_path / "settings.json").write_text('{"version": 1, "big": {"unpack_limit_mb": 500}}')
    assert p.load()["big"]["unpack_limit_mb"] == 100 and "damaged" in p.take_notes()[0]   # never a guess
    assert p.reset()["big"]["too_big"] == "skip" and not (tmp_path / "settings.json").exists()


def test_fetch_flags_and_picks():
    d = P.defaults()
    d["filters"].update(types=["exe", "office"], tags=["stealer"], skip_families=["Mirai"], min_size_kb=10)
    d["big"].update(unpack_limit_mb=50, too_big="info")
    assert P.fetch_flags(d) == ["--types", "exe,office", "--tags", "stealer", "--skip-families", "Mirai",
                                "--min-size-kb", "10", "--unpack-limit-mb", "50", "--too-big", "info"]
    # Browse picks are exact samples: no filters, but the safety limit always goes along
    assert P.fetch_flags(d, picked=True) == ["--unpack-limit-mb", "50", "--too-big", "info"]
    argv = fetch_args({"mode": "recent"}) + P.fetch_flags(d)
    a = build_parser().parse_args(argv)                                   # the VM's parser takes all of it
    assert a.types == ["exe", "office"] and a.unpack_limit_mb == 50 and a.too_big == "info"


def test_triage_args_carry_parallel_and_capa_packed():
    assert triage_args(60, 120) == ["triage", "--sample-time", "60", "--capa-time", "120", "--capa-packed", "skip"]
    assert triage_args(60, 120, 2, "run")[-4:] == ["--parallel", "2", "--capa-packed", "run"]
    for bad in ((60, 120, 11, "skip"), (60, 120, 0, "x"), (60, 120, True, "skip")):
        with pytest.raises(ValueError):
            triage_args(*bad)
    a = build_parser().parse_args(triage_args(60, 120, 2, "run"))
    assert a.parallel == 2 and a.capa_packed == "run"


def test_the_host_accepts_too_big_rows_from_the_vm():
    raw = json.dumps({"rows": [{"sha256": "a" * 64, "status": "too_big", "error": "too big"}]}).encode()
    assert validate.sample_list(raw)[0]["status"] == "too_big"


# --- VM: checks every value again ------------------------------------------------------------------------------
@pytest.mark.parametrize("argv", [["fetch", "--unpack-limit-mb", "200"], ["fetch", "--unpack-limit-mb", "0"],
                                  ["fetch", "--types", "exe,js"], ["fetch", "--types", ""],
                                  ["fetch", "--tags", "a;b"], ["fetch", "--skip-families", "x" * 41],
                                  ["fetch", "--min-size-kb", "10241"], ["fetch", "--too-big", "keep"],
                                  ["triage", "--capa-packed", "always"]])
def test_vm_refuses_bad_settings(argv):
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)


@pytest.mark.parametrize("toml, msg", [
    ("[fetch]\nunpack_limit_mb = 500\n", "unpack_limit_mb"),
    ("[fetch]\ntoo_big = \"keep\"\n", "too_big"),
    ("[triage]\ncapa_packed = \"x\"\n", "capa_packed"),
])
def test_vm_config_refuses_bad_values(tmp_path, toml, msg):
    p = tmp_path / "config.toml"
    p.write_text(toml)
    with pytest.raises(ValueError, match=msg):
        load_config(p)


def test_cap_never_goes_above_100_mb(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("[fetch]\nunpack_limit_mb = 25\ndownload_limit_on = false\n")
    cfg = load_config(p)
    assert cfg.cap == 25 * 1024 * 1024 and cfg.max_bytes == cfg.cap     # download limit off stops at the cap


def test_prefilter_min_size_and_never_these_families():
    f = Filters(file_types=["exe"], min_size_kb=10, signatures_none=["Mirai"])
    big = 1 << 30
    assert prefilter({"file_type": "exe", "file_size": 5 * 1024}, f, big) == "too small"
    assert prefilter({"file_type": "exe", "file_size": 0}, f, big) is None             # unknown size passes
    assert prefilter({"file_type": "exe", "file_size": 50_000, "signature": "mirai"}, f, big) == "family skipped"
    assert prefilter({"file_type": "exe", "file_size": 50_000, "signature": "Formbook"}, f, big) is None
    assert prefilter({"file_type": "exe", "file_size": 30 << 20}, f, big, cap=25 << 20) == "too big to analyze"


def test_too_big_keep_info_makes_a_row_without_a_file(tmp_path):
    store, stats = Store(tmp_path), FetchStats()
    blob = pe() + b"\x00" * 20_000                       # unpacks past the 10 KB cap used here
    sha = sha256_bytes(blob)
    assert run_fetch(store, Src([blob], listed_size=1), Filters(**F), "infected", 1 << 20, stats=stats,
                     cap=10_000, keep_info=True) == []
    row = store.get(sha)
    assert stats.too_big == 1 and row["status"] == "too_big" and row["zip_path"] == ""
    assert "not analysed, file not kept" in row["error"]
    assert not list((tmp_path / "vault").rglob("*"))     # nothing of the sample on disk
    assert store.by_status("fetched") == []              # never triaged
    # listed size alone is enough: no download at all
    other = Src([pe()], listed_size=200 << 20)
    run_fetch(store, other, Filters(**F), "infected", 1 << 20, cap=100 << 20, keep_info=True)
    assert store.get(next(iter(other.blobs)))["status"] == "too_big"


def test_too_big_skip_leaves_no_row(tmp_path):
    store = Store(tmp_path)
    blob = pe() + b"\x00" * 20_000
    run_fetch(store, Src([blob], listed_size=1), Filters(**F), "infected", 1 << 20, cap=10_000)
    assert not store.has(sha256_bytes(blob))


def test_triage_refuses_a_too_big_row(tmp_path, capsys):
    from fatbox.cli import main
    (tmp_path / "config.toml").write_text('[paths]\ndata_dir = "./data"\n')
    store = Store(tmp_path / "data")
    store.add_info("c" * 64, {"signature": "X"}, "bazaar", "too big")
    store.db.close()
    assert main(["-c", str(tmp_path / "config.toml"), "triage", "--sha256", "c" * 64]) == 1
    assert "no file to analyse" in capsys.readouterr().err


# --- server: /api/prefs ----------------------------------------------------------------------------------------
pytestmark_server = pytest.mark.skipif(sys.platform == "win32", reason="fake VBoxManage is a POSIX shell wrapper")


@pytestmark_server
def test_prefs_api(lab):  # noqa: F811
    import urllib.error
    import urllib.request
    from test_windowless import _serve
    ctl, _, _ = lab
    httpd, port, job = _serve(ctl)

    def call(body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/prefs", None if body is None else json.dumps(body).encode(),
                                     method="GET" if body is None else "POST",
                                     headers={"Cookie": "fbx=tok123", "X-FatBox": "1", "Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(req).read())

    try:
        d = call()["prefs"]
        d["big"]["unpack_limit_mb"] = 25
        assert call({"prefs": d})["prefs"]["big"]["unpack_limit_mb"] == 25
        d["big"]["unpack_limit_mb"] = 1000
        with pytest.raises(urllib.error.HTTPError) as e:
            call({"prefs": d})
        assert e.value.code == 400 and "Unpack limit" in json.loads(e.value.read())["error"]
        assert call()["prefs"]["big"]["unpack_limit_mb"] == 25                     # the bad save changed nothing
        assert call({"reset": True})["prefs"]["big"]["unpack_limit_mb"] == 100
    finally:
        httpd.shutdown()
        httpd.server_close()


from test_host import lab  # noqa: E402,F401  (fixture)
