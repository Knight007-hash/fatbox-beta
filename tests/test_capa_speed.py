"""0.21.0: capa faster. Samples analysed side by side, rules compiled once, capa skipped on packed programs."""
import json
import time

import pytest

from fatbox import cli
from fatbox.config import auto_parallel, cpu_share, load_config, room_for_one_more
from fatbox.host import validate
from fatbox.static import code_analysis as ca
from fatbox.static.triage import score
from test_code_analysis import rep_with
from test_triage_limit import lab  # noqa: F401  (fixture: helpers hang on *hang*, crash on *crash*)

PE = b"MZ" + b"\0" * 200


def die(status="ok", packer=(), protector=()):
    return {"status": status, "packer": list(packer), "protector": list(protector)}


@pytest.mark.parametrize("cpus,want", [(1, 1), (2, 2), (4, 4), (8, 8), (10, 10), (64, 10)])
def test_auto_parallel_is_one_per_cpu_1_to_10(cpus, want):  # 0.32.0 (was half the CPUs, 1..4)
    assert auto_parallel(cpus) == want


@pytest.mark.parametrize("free,ok", [(None, True), (16.0, True), (2.6, True), (2.5, False), (0.0, False)])
def test_a_new_sample_needs_its_headroom_on_top_of_the_reserve(free, ok):  # 1.1 GB + 1.5 GB kept free
    assert room_for_one_more(free) is ok


@pytest.mark.parametrize("workers,cpus,want", [(1, 4, 1), (4, 4, 1), (5, 4, 2), (8, 4, 2), (10, 4, 3),
                                               (10, 1, 3), (3, 0, 3)])
def test_cpu_share_stretches_the_limits_at_most_3x(workers, cpus, want):
    assert cpu_share(workers, cpus) == want


@pytest.mark.parametrize("value,ok", [(0, True), (1, True), (4, True), (10, True), (11, False), (-1, False)])
def test_parallel_in_config_is_checked(tmp_path, value, ok):
    p = tmp_path / "config.toml"
    p.write_text(f"[triage]\nparallel = {value}\n")
    if ok:
        assert load_config(p).check().parallel == value
    else:
        with pytest.raises(ValueError, match="parallel must be 0..10"):
            load_config(p).check()


@pytest.mark.parametrize("bad", ["0", "11", "x"])
def test_parallel_on_the_command_line_is_checked(lab, bad):  # noqa: F811
    cfg, _, _ = lab
    with pytest.raises(SystemExit):
        cli.main(["-c", str(cfg), "triage", "--parallel", bad])


def test_side_by_side_each_sample_keeps_its_own_stopwatch(lab, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr("os.cpu_count", lambda: 8)  # 3 at a time on 8 CPUs: no stretched limits
    cfg, store, add = lab
    good = [add(f"s{i}.txt", f"sample {i} http://example.com".encode()) for i in range(4)]
    bad, crash = add("hang.bin", b"x" * 100), add("crash.bin", b"y" * 50)
    t0 = time.monotonic()
    assert cli.main(["-c", str(cfg), "triage", "--sample-time", "10", "--capa-time", "30", "--parallel", "3"]) == 0
    took = time.monotonic() - t0
    out = capsys.readouterr().out
    assert "up to 3 at a time" in out and "summary: 4 done, 1 timeout, 1 error" in out
    assert all(store.get(s)["status"] == "static_done" for s in good)
    assert store.get(bad)["status"] == "timeout" and store.get(bad)["error"] == "analysis took longer than 40 s: stopped"
    assert store.get(crash)["status"] == "error"
    assert took < 40 + 30  # the hanging sample ran beside the others, not before or after them


def test_packed_native_program_skips_capa():
    why = ca.skip_reason(die(packer=["UPX(3.96)[NRV,brute]"]), PE)
    assert why.startswith("packed (UPX(3.96)") and "unpacking stub" in why
    assert ca.skip_reason(die(protector=["Themida"]), PE).startswith("protected (Themida)")


@pytest.mark.parametrize("fa", [die(), die(status="timeout", packer=["UPX"]), die(status="error")])
def test_capa_runs_when_nothing_is_named_or_die_failed(fa):
    assert ca.skip_reason(fa, PE) is None


def test_dotnet_always_runs_capa(monkeypatch):
    monkeypatch.setattr(ca, "is_dotnet", lambda data: True)
    assert ca.skip_reason(die(protector=["ConfuserEx"]), PE) is None


def test_skipped_capa_is_not_score_incomplete_and_the_host_shows_it():
    built = ca.build("skipped", ca.skip_reason(die(packer=["UPX"]), PE), None)
    assert score(rep_with(built)) == (0, [])  # no "score incomplete": skipping is a decision, not a failure
    checked = validate.code_analysis(json.loads(json.dumps(built)))
    assert validate.code_badge({"code_analysis": checked}) == "packed: capa skipped"
    not_pe = validate.code_analysis(json.loads(json.dumps(ca.build("skipped", "not a Windows program", None))))
    assert validate.code_badge({"code_analysis": not_pe}) == "not a PE: skipped"


def test_rules_are_prepared_once_before_the_helpers(monkeypatch, tmp_path, capsys):
    calls = []
    monkeypatch.setattr(ca, "rule_set", lambda d: calls.append(d) or time.sleep(0) or (None, [], "x"))
    cfg = type("C", (), {"capa_dir": tmp_path})()
    cli.warm_capa_rules(cfg)
    assert calls == [tmp_path]
    monkeypatch.setattr(ca, "rule_set", lambda d: (_ for _ in ()).throw(ImportError("no capa")))
    cli.warm_capa_rules(cfg)  # a broken capa never stops triage: each report says so itself


class FakeHelper:
    """Stands in for the triage-one helper: records how it was started and how long it was given."""
    seen: list = []

    def __init__(self, cmd, **kw):
        self.cmd, self.pid = cmd, 1

    def wait(self, timeout=None):
        FakeHelper.seen.append((self.cmd, timeout))
        return 0


def test_sharing_cpus_stretches_every_limit_and_tells_the_helper(lab, capsys, monkeypatch):  # noqa: F811
    cfg, store, add = lab
    for i in range(4):
        add(f"s{i}.txt", f"sample {i}".encode())
    monkeypatch.setattr("os.cpu_count", lambda: 2)
    monkeypatch.setattr("subprocess.Popen", FakeHelper)
    FakeHelper.seen = []
    assert cli.main(["-c", str(cfg), "triage", "--sample-time", "10", "--capa-time", "30", "--parallel", "4"]) == 0
    out = capsys.readouterr().out
    assert "up to 4 at a time (2 CPUs" in out and "limits x2 (samples share CPUs)" in out
    assert len(FakeHelper.seen) == 4
    for cmd, timeout in FakeHelper.seen:
        assert timeout == 80  # (10 + 30) x 2: each sample gets half a CPU, so twice the time
        assert cmd[cmd.index("--share") + 1] == "2"


def test_one_cpu_each_keeps_the_limits(lab, capsys, monkeypatch):  # noqa: F811
    cfg, store, add = lab
    add("a.txt", b"a")
    monkeypatch.setattr("os.cpu_count", lambda: 8)
    monkeypatch.setattr("subprocess.Popen", FakeHelper)
    FakeHelper.seen = []
    assert cli.main(["-c", str(cfg), "triage", "--sample-time", "10", "--capa-time", "30", "--parallel", "4"]) == 0
    assert "limits x" not in capsys.readouterr().out
    (cmd, timeout), = FakeHelper.seen
    assert timeout == 40 and cmd[cmd.index("--share") + 1] == "1"


def test_ram_guard_waits_for_a_running_sample_but_never_blocks_the_first(lab, capsys, monkeypatch):  # noqa: F811
    import threading
    cfg, store, add = lab
    for i in range(3):
        add(f"s{i}.txt", f"sample {i}".encode())
    monkeypatch.setattr("os.cpu_count", lambda: 8)
    monkeypatch.setattr(cli, "free_ram_gb", lambda: 0.5)  # always short of RAM
    live, most = [0], [0]
    lock = threading.Lock()

    def fake(cfg_, store_, row, *a, **kw):
        with lock:
            live[0] += 1
            most[0] = max(most[0], live[0])
        time.sleep(0.2)
        with lock:
            live[0] -= 1
        return "done"
    monkeypatch.setattr(cli, "triage_isolated", fake)
    assert cli.main(["-c", str(cfg), "triage", "--parallel", "3"]) == 0
    assert most[0] == 1  # one at a time while RAM is short, and not stuck
    assert "summary: 3 done" in capsys.readouterr().out


def test_samples_that_cannot_finish_inside_the_run_wait_for_the_next(lab, capsys, monkeypatch):  # noqa: F811
    cfg, store, add = lab
    shas = [add(f"s{i}.txt", f"sample {i}".encode()) for i in range(3)]
    monkeypatch.setattr("os.cpu_count", lambda: 8)
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

    def fake(cfg_, store_, row, *a, **kw):
        clock[0] += 30 * (10 + 30) // 2 + 1  # each sample eats just over half of the run's time
        store_.set_result(row["sha256"], "static_done", 0, "low")
        return "done"
    monkeypatch.setattr(cli, "triage_isolated", fake)
    assert cli.main(["-c", str(cfg), "triage", "--sample-time", "10", "--capa-time", "30", "--parallel", "1"]) == 0
    out = capsys.readouterr().out
    assert "summary: 2 done, 0 timeout, 0 error, 1 left for the next run (out of time)" in out
    assert store.get(shas[2])["status"] == "fetched"  # never started: picked again next run


def test_compare_lists_what_each_mode_lost_or_gained():
    full = {"matches": [{"name": "inject thread"}, {"name": "check for debugger"}]}
    fast = {"matches": [{"name": "check for debugger"}, {"name": "persist via Run key"}]}
    assert ca.compare_findings(full, fast) == (["inject thread"], ["persist via Run key"])
    assert ca.compare_findings(full, full) == ([], [])


@pytest.mark.parametrize("value,ok", [("false", True), ("true", True), ('"yes"', False), ("1", False)])
def test_capa_lib_skip_is_on_by_default_and_checked(tmp_path, value, ok):  # 0.34.0 (was off)
    assert load_config(None).capa_lib_skip is True
    p = tmp_path / "config.toml"
    p.write_text(f"[triage]\ncapa_lib_skip = {value}\n")
    if ok:
        assert load_config(p).check().capa_lib_skip is (value == "true")
    else:
        with pytest.raises(ValueError, match="capa_lib_skip must be true or false"):
            load_config(p).check()


def test_lib_skip_reaches_capa_one_only_when_turned_on(monkeypatch):
    seen = []

    class Fake:
        def __init__(self, sha, config_path, budget, command="file-analysis-one", extra=(), **kw):
            seen.append((command, extra, budget))

        def result(self):
            return "error", "fake", None

        def stop(self):
            pass
    from fatbox.config import Config
    from fatbox.static import file_analysis as fa
    monkeypatch.setattr(fa, "Run", Fake)
    monkeypatch.setattr(cli, "read_sample_from_zip", lambda *a: ("a.exe", PE))
    for on in (False, True):
        cfg, seen[:] = Config(capa_lib_skip=on), []
        nostore = type("S", (), {"set_result": lambda *a, **k: None})()
        cli.triage_one(cfg, nostore, None, {"sha256": "a" * 64, "zip_path": "x"}, "c.toml", 10, 30, "run", share=2)
        capa = [s for s in seen if s[0] == "capa-one"]
        assert capa == [("capa-one", ("--lib-skip",) if on else (), 60)]  # capa limit x share
        assert ("file-analysis-one", (), 10) in seen                     # half the sample limit x share


def _counting(monkeypatch, hold=0.3):
    """A fake triage_isolated that records start times and how many ran at once."""
    import threading
    live, most, starts, lock = [0], [0], [], threading.Lock()

    def fake(cfg_, store_, row, *a, **kw):
        with lock:
            live[0] += 1
            most[0] = max(most[0], live[0])
            starts.append(time.monotonic())
        time.sleep(hold)
        with lock:
            live[0] -= 1
        return "done"
    monkeypatch.setattr(cli, "triage_isolated", fake)
    return most, starts


def test_live_ram_gate_lets_more_start_while_the_vm_really_has_room(lab, capsys, monkeypatch):  # noqa: F811
    cfg, store, add = lab
    for i in range(6):
        add(f"s{i}.txt", f"sample {i}".encode())
    monkeypatch.setattr("os.cpu_count", lambda: 8)
    most, _ = _counting(monkeypatch)
    monkeypatch.setattr(cli, "free_ram_gb", lambda: 12.0)  # plenty: CPUs decide
    assert cli.main(["-c", str(cfg), "triage"]) == 0
    out = capsys.readouterr().out
    assert "up to 6 at a time (8 CPUs, 12.0 GB free RAM; each start needs 2.6 GB free)" in out
    assert most[0] == 6 and "at most 6 at once" in out


def test_live_ram_gate_holds_new_starts_when_room_runs_out(lab, capsys, monkeypatch):  # noqa: F811
    import threading
    cfg, store, add = lab
    for i in range(6):
        add(f"s{i}.txt", f"sample {i}".encode())
    monkeypatch.setattr("os.cpu_count", lambda: 8)
    monkeypatch.setattr(cli, "STAGGER_S", 0.1)  # time for the last start's RAM to "show"
    live, most, lock = [0], [0], threading.Lock()

    def fake(cfg_, store_, row, *a, **kw):
        with lock:
            live[0] += 1
            most[0] = max(most[0], live[0])
        time.sleep(0.5)
        with lock:
            live[0] -= 1
        return "done"
    monkeypatch.setattr(cli, "triage_isolated", fake)
    # free RAM as Windows would show it: 5 GB, minus 1 GB for each sample running right now
    monkeypatch.setattr(cli, "free_ram_gb", lambda: 5.0 - 1.0 * live[0])
    assert cli.main(["-c", str(cfg), "triage"]) == 0
    assert most[0] == 3  # 5.0, 4.0, 3.0 free: room; at 2.0 the 4th waits for one to finish
    out = capsys.readouterr().out
    assert "summary: 6 done" in out and "at most 3 at once" in out


def test_plenty_of_ram_starts_without_a_gap(lab, monkeypatch):  # noqa: F811
    """0.39.0: no fixed gap between starts any more (up to 0.38.0 every start waited STAGGER_S)."""
    cfg, store, add = lab
    for i in range(3):
        add(f"s{i}.txt", f"sample {i}".encode())
    monkeypatch.setattr("os.cpu_count", lambda: 8)
    monkeypatch.setattr(cli, "STAGGER_S", 5.0)
    monkeypatch.setattr(cli, "free_ram_gb", lambda: 12.0)
    _, starts = _counting(monkeypatch, hold=1.0)
    assert cli.main(["-c", str(cfg), "triage"]) == 0
    assert len(starts) == 3 and starts[-1] - starts[0] < 1.0


def test_young_helpers_count_as_holding_ram(lab, capsys, monkeypatch):  # noqa: F811
    """0.39.0: free RAM that doesn't show the new helpers yet (constant 5.0 GB) still stops at 3 at once: each
    helper younger than STAGGER_S counts as 1.1 GB (5.0, 3.9, 2.8 >= 2.6 start; 1.7 waits)."""
    cfg, store, add = lab
    for i in range(5):
        add(f"s{i}.txt", f"sample {i}".encode())
    monkeypatch.setattr("os.cpu_count", lambda: 8)
    monkeypatch.setattr(cli, "STAGGER_S", 30.0)
    monkeypatch.setattr(cli, "free_ram_gb", lambda: 5.0)
    most, _ = _counting(monkeypatch, hold=0.5)
    assert cli.main(["-c", str(cfg), "triage"]) == 0
    assert most[0] == 3 and "at most 3 at once" in capsys.readouterr().out
