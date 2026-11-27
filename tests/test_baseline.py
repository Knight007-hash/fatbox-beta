"""0.18.5: clean-file baseline. Files here are synthetic (built in code, not runnable), never real samples."""
from __future__ import annotations

import json

from fatbox.baseline import NOISY_SHARE, pick_files, rule_key, summarize, to_markdown
from fatbox.cli import main
from test_compile_time import FUTURE, PAST, build_pe


def ok(name, score, reasons, caps=()):
    return {"status": "ok", "name": name, "score": score, "priority": "low" if score < 30 else "medium",
            "reasons": reasons, "capa_scored": list(caps)}


def test_rule_key_strips_points_and_details():
    assert rule_key("+10 high-entropy sections: .rsrc, .data") == ("high-entropy sections", 10)
    assert rule_key("+5 entrypoint outside .text (INIT)") == ("entrypoint outside .text", 5)
    assert rule_key("+5 anti-analysis APIs imported") == ("anti-analysis APIs imported", 5)
    assert rule_key("+0 network IOCs: 1 found, all noise") is None
    assert rule_key("not a reason") is None


def test_pick_files_spreads_evenly_and_skips_others(tmp_path):
    for i in range(20):
        (tmp_path / f"f{i:02}.dll").write_bytes(b"MZ")
    (tmp_path / "notes.txt").write_bytes(b"x")
    (tmp_path / "empty.exe").write_bytes(b"")
    (tmp_path / "big.exe").write_bytes(b"MZ" * 10)
    (tmp_path / "sub.exe").mkdir()
    picked = pick_files(tmp_path, 5, max_bytes=10)
    assert [p.name for p in picked] == ["f00.dll", "f04.dll", "f08.dll", "f12.dll", "f16.dll"]
    assert len(pick_files(tmp_path, 100, max_bytes=10)) == 20


def test_summary_flags_rules_on_more_than_a_tenth_of_clean_files():
    results = [ok(f"a{i}.dll", 5, ["+5 anti-analysis APIs imported"], ["parse PE exports"]) for i in range(3)]
    results += [ok(f"b{i}.dll", 0, []) for i in range(16)]
    results.append(ok("c.dll", 10, ["+10 RWX section", "+0 network IOCs: 1 found, all noise"]))
    results.append({"status": "timeout", "name": "slow.dll", "error": "took longer"})
    s = summarize(results, "C:/x", True, 1.0)
    rules = {r["rule"]: r for r in s["rules"]}
    assert s["files"] == 21 and s["scored"] == 20
    assert rules["anti-analysis APIs imported"]["files"] == 3 and rules["anti-analysis APIs imported"]["noisy"]
    assert 3 / 20 > NOISY_SHARE and not rules["RWX section"]["noisy"]
    assert s["capa_rules"] == [{"rule": "parse PE exports", "files": 3, "share": 0.15}]
    assert s["top"][0]["name"] == "c.dll" and s["not_scored"][0]["status"] == "timeout"
    md = to_markdown(s)
    assert "| anti-analysis APIs imported | +5 | 3 | 15% | NOISY |" in md and "slow.dll" in md


def test_baseline_end_to_end_without_capa(tmp_path, monkeypatch, capsys):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.exe").write_bytes(build_pe(PAST))
    (clean / "future.dll").write_bytes(build_pe(FUTURE))
    (clean / "garbage.dll").write_bytes(b"MZ not a pe")
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[paths]\ndata_dir = "{(tmp_path / "data").as_posix()}"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["-c", str(cfg), "baseline", "--dir", str(clean), "--max", "10", "--no-capa"]) == 0
    out = capsys.readouterr().out
    assert "3 clean files" in out and "capa off" in out
    js = list((tmp_path / "data" / "baseline").glob("baseline-*.json"))
    assert len(js) == 1 and js[0].with_suffix(".md").is_file()
    s = json.loads(js[0].read_text(encoding="utf-8"))
    assert s["files"] == 3 and not s["capa"]
    by = {r["name"]: r for r in s["results"]}
    assert all(r["status"] == "ok" and r["code_analysis"] == "off" for r in by.values()), by
    assert any("zero/future compile timestamp" in x for x in by["future.dll"]["reasons"])
    assert not (tmp_path / "data" / "vault").exists() or not any((tmp_path / "data" / "vault").iterdir())


def test_baseline_one_reports_an_unreadable_file_as_error(tmp_path, capsys):
    assert main(["baseline-one", str(tmp_path / "missing.exe"), "--no-capa"]) == 0
    obj = json.loads(capsys.readouterr().out)
    assert obj["status"] == "error" and "FileNotFoundError" in obj["error"]


def test_missing_folder_is_an_error(tmp_path):
    assert main(["baseline", "--dir", str(tmp_path / "nope")]) == 1

