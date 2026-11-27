"""T-5: every sample is analysed in its own helper process with a time limit, so one file built to hang a
parser can't block the lab. A test-only sitecustomize makes the helper hang on samples named *hang*."""
import os
import sys
from pathlib import Path

import pytest

from fatbox import cli
from fatbox.store import Store, make_sample_zip, sha256_bytes

HANG = """
import fatbox.static.triage as t
_real = t.triage
def _maybe_hang(data, name, scanner=None):
    if "hang" in name:
        import time
        time.sleep(600)
    if "crash" in name:
        import os
        os._exit(7)
    return _real(data, name, scanner)
t.triage = _maybe_hang
"""


@pytest.fixture
def lab(tmp_path, monkeypatch):
    hook = tmp_path / "hook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text(HANG)
    monkeypatch.setenv("PYTHONPATH", str(hook))
    cfg = tmp_path / "config.toml"
    cfg.write_text('[paths]\ndata_dir = "./data"\nyara_dir = "./rules"\n')
    store = Store(tmp_path / "data")

    def add(name: str, body: bytes) -> str:
        sha = sha256_bytes(body)
        store.add(sha, make_sample_zip(name, body, "infected"), {"file_name": name, "tags": []}, source="manual")
        return sha
    return cfg, store, add


def run(cfg, *extra):
    return cli.main(["-c", str(cfg), "triage", *extra])


def test_a_hanging_sample_is_stopped_and_the_rest_still_run(lab, capsys):
    cfg, store, add = lab
    ok1 = add("a.txt", b"hello http://example.com " * 10)
    bad = add("hang.bin", b"x" * 100)
    ok2 = add("b.txt", b"plain text")
    assert run(cfg, "--sample-time", "10", "--capa-time", "30", "--parallel", "1") == 0
    out = capsys.readouterr().out
    assert "triage: 3 waiting, limit 10 s per sample + 30 s for capa" in out
    assert "summary: 2 done, 1 timeout, 0 error" in out
    assert store.get(ok1)["status"] == store.get(ok2)["status"] == "static_done"
    row = store.get(bad)
    assert row["status"] == "timeout" and row["error"] == "analysis took longer than 40 s: stopped"  # 10 + capa 30
    assert not (store.report_dir_for(bad) / "static.json").exists()
    # never picked again, not even with --retry-errors: it can't block the next run
    assert run(cfg, "--retry-errors") == 0
    assert "nothing to triage" in capsys.readouterr().out
    assert store.get(bad)["status"] == "timeout"


def test_a_crashing_helper_marks_the_sample_error(lab, capsys):
    cfg, store, add = lab
    sha = add("crash.bin", b"y" * 50)
    assert run(cfg) == 0
    assert "summary: 0 done, 0 timeout, 1 error" in capsys.readouterr().out
    assert store.get(sha)["status"] == "error" and "crashed (exit 7)" in store.get(sha)["error"]


def test_at_most_30_per_run_oldest_first(lab, capsys, monkeypatch):
    cfg, store, add = lab
    shas = [add(f"s{i}.txt", f"sample {i}".encode()) for i in range(32)]
    seen = []
    monkeypatch.setattr(cli, "triage_isolated", lambda c, s, row, lim, p, capa, **kw: seen.append(row["sha256"]) or "done")
    assert run(cfg, "--parallel", "1") == 0
    out = capsys.readouterr().out
    assert "triage: 32 waiting, limit 60 s per sample + 120 s for capa, up to 1 at a time (" in out
    assert "2 left for the next run\n" in out
    assert seen == [r["sha256"] for r in store.by_status("fetched")][:30] and len(seen) == 30
    assert set(seen) <= set(shas)


@pytest.mark.parametrize("bad", ["9", "301", "abc"])
def test_sample_time_range_is_checked_in_the_vm(lab, bad, capsys):
    cfg, _, _ = lab
    with pytest.raises(SystemExit):
        run(cfg, "--sample-time", bad)


@pytest.mark.parametrize("bad", ["29", "601"])
def test_capa_time_range_is_checked_in_the_vm(lab, bad):
    cfg, _, _ = lab
    with pytest.raises(SystemExit):
        run(cfg, "--capa-time", bad)


def test_capa_time_in_config_is_checked(tmp_path, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[triage]\ncapa_time_s = 900\n")
    assert cli.main(["-c", str(cfg), "list"]) == 2
    assert "capa_time_s must be 30..600" in capsys.readouterr().err


def test_sample_time_in_config_is_checked(tmp_path, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[triage]\nsample_time_s = 5\n")
    assert cli.main(["-c", str(cfg), "list"]) == 2
    assert "sample_time_s must be 10..300" in capsys.readouterr().err


def test_host_sends_the_limit_and_runs_its_own_stopwatch():
    from fatbox.host.controller import triage_args, triage_deadline_s
    args = triage_args(60, 120)
    assert args == ["triage", "--sample-time", "60", "--capa-time", "120", "--capa-packed", "skip"]
    assert triage_deadline_s(args) == 30 * (60 + 120) + 120  # T-14: capa's own limit is part of each sample's time
    got = cli.build_parser().parse_args(args)  # the real VM CLI accepts what the host sends
    assert (got.sample_time, got.capa_time) == (60, 120)
    for bad in (9, 301, "60", True):
        with pytest.raises(ValueError):
            triage_args(bad)
    for bad in (29, 601, "120", None):
        with pytest.raises(ValueError):
            triage_args(60, bad)


def test_host_setting_is_checked(tmp_path):
    from fatbox.host.settings import load_settings
    pw = tmp_path / "guest.pw"
    pw.write_text("x")
    p = tmp_path / "host.toml"
    p.write_text(f"password_file = '{pw}'\nsample_time_s = 900\n")
    with pytest.raises(ValueError, match="10..300"):
        load_settings(p)
    p.write_text(f"password_file = '{pw}'\ncapa_time_s = 20\n")
    with pytest.raises(ValueError, match="30..600"):
        load_settings(p)
    p.write_text(f"password_file = '{pw}'\n")
    assert (load_settings(p).sample_time_s, load_settings(p).capa_time_s) == (60, 120)


def test_host_accepts_timeout_status():
    import json
    from fatbox.host import validate
    rows = validate.sample_list(json.dumps({"rows": [{"sha256": "a" * 64, "status": "timeout",
                                                      "error": "analysis took longer than 60 s: stopped"}]}).encode())
    assert rows[0]["status"] == "timeout"
