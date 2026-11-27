"""0.38.0 speed-ups for the whole run: step timers, auto-revert as its own job after a triage (reports first),
one version check per VM boot, and per-sample times from the VM."""
import time

import pytest

from fatbox import __version__
from fatbox.host.controller import Laps
from fatbox.host.vmstatus import badge
from test_snapshots import lab  # noqa: F401  (fake VBoxManage lab with snapshots)


def test_laps_say_where_the_time_went():
    now = [100.0]
    laps = Laps(clock=lambda: now[0])
    now[0] += 1.2
    laps.lap("checks")
    now[0] += 205.4
    laps.lap("analysis")
    assert laps.line("triage") == "--- triage took 207 s: checks 1 s, analysis 205 s"
    assert Laps(clock=lambda: 5.0).line("x") == "--- x took 0 s"


def versions_asked(th):
    return sum(1 for ln in th.guest_log() if ln.startswith("--version"))


def test_the_version_is_asked_once_per_boot(lab):  # noqa: F811
    ctl, _, th = lab
    ctl._ready()
    ctl._ready()
    ctl.pending()
    assert versions_asked(th) == 1                       # same boot: no second guest round trip
    ctl.vm.poweroff()
    ctl.vm.start(headless=True)                          # a new boot: VirtualBox's state-change time moved
    ctl._ready()
    assert versions_asked(th) == 2


def test_update_vm_and_a_failed_check_forget_the_version(lab, monkeypatch):  # noqa: F811
    ctl, _, th = lab
    ctl._ready()
    ctl.forget_version()                                 # what Update VM does first
    ctl._ready()
    assert versions_asked(th) == 2
    monkeypatch.setattr(ctl, "ping", lambda: "FatBox 0.0.1")
    ctl.forget_version()
    from fatbox.host.vbox import GuestError
    with pytest.raises(GuestError, match="Fetch is off until they match"):
        ctl._ready()
    assert ctl._ver_boot is None                         # never remembered as passed


def test_an_old_check_expires(lab, monkeypatch):  # noqa: F811
    ctl, _, th = lab
    ctl._ready()
    ctl._ver_at -= 1801                                  # older than 30 min
    ctl._ready()
    assert versions_asked(th) == 2


def test_triage_prints_its_timer(lab):  # noqa: F811
    ctl, _, th = lab
    lines = []
    assert ctl.fetch({"mode": "recent", "max": 1}, lines.append) == 0
    tri = [ln for ln in lines if ln.startswith("--- triage took ")]
    assert tri and "checks" in tri[0] and "analysis" in tri[0] and "library" in tri[0]


def test_gui_fetch_prints_its_timer(lab):  # noqa: F811
    ctl, sha, _ = lab
    lines = []
    ctl.download({"mode": "recent", "max": 1, "pick": [sha]}, lines.append)
    got = [ln for ln in lines if ln.startswith("--- fetch took ")]
    assert got and all(w in got[0] for w in ("checks", "network on", "download", "network off", "list"))


def test_the_vm_prints_each_samples_time_and_ram_holds(tmp_path, monkeypatch, capsys):
    import test_triage_limit
    from fatbox import cli
    cfg, store, add = test_triage_limit.lab.__wrapped__(tmp_path, monkeypatch)
    for i in range(3):
        add(f"s{i}.txt", f"sample {i}".encode())
    monkeypatch.setattr("os.cpu_count", lambda: 8)
    live = [0]

    def fake(cfg_, store_, row, *a, **kw):
        live[0] += 1
        time.sleep(0.8)
        live[0] -= 1
        return "done"
    monkeypatch.setattr(cli, "triage_isolated", fake)
    monkeypatch.setattr(cli, "STAGGER_S", 0.1)  # time for the last start to show in free RAM
    monkeypatch.setattr(cli, "free_ram_gb", lambda: 3.0 - live[0])  # room for one only
    assert cli.main(["-c", str(cfg), "triage"]) == 0
    out = capsys.readouterr().out
    assert out.count("time   ") == 3 and " s  done" in out
    assert "held back by RAM (added up)" in out and "at most 1 at once" in out


def run_job(job, kind="triage", seen=None):
    job.start({}, kind)
    for _ in range(600):
        if seen is not None:
            with job.lock:
                seen.append((job.kind, job.state))
        if not job.running():
            return
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_gui_triage_shows_reports_then_reverts_as_its_own_job(lab):  # noqa: F811
    from fatbox.host.server import Job
    ctl, sha, th = lab
    ctl.make_clean_snapshot(lambda _: None)
    ctl.set_auto_revert(True)
    ctl.download({"mode": "recent", "max": 1, "pick": [sha]}, lambda _: None)
    job, seen = Job(ctl), []
    run_job(job, "triage", seen)
    kinds = [k for k, _ in seen]
    assert "revert" in kinds and job.kind == "revert" and job.state == "done"
    assert ("triage", "done") not in seen and ("triage", "failed") not in seen   # never idle between the two
    text = [t for _, t in job.lines]
    i = text.index
    assert i("--- triage done (exit 0); reports are in the library") < \
        i("--- revert started (in the background: Fetch and the VM buttons wait for it)")
    assert any(t.startswith("--- auto-revert: going back to clean-fatbox-") for t in text)
    assert f"--- VM back and running; network OFF (checked); FatBox {__version__} ✓" in text
    assert any(t.startswith("--- auto-revert took ") and "restore" in t and "boot" in t for t in text)
    assert ctl.library.report(sha) is not None                                   # saved before the revert
    assert ctl.vm.state() == "running" and ctl.vm.cable() == "off"


def test_gui_triage_without_auto_revert_ends_as_before(lab):  # noqa: F811
    from fatbox.host.server import Job
    ctl, sha, _ = lab
    job = Job(ctl)
    run_job(job, "triage")
    assert job.kind == "triage" and job.state == "done"
    assert not any("revert" in t for _, t in job.lines)


def test_nothing_else_starts_while_the_revert_job_runs(lab, monkeypatch):  # noqa: F811
    import threading
    from fatbox.host.server import Job
    from fatbox.host.vbox import GuestError
    ctl, sha, _ = lab
    ctl.make_clean_snapshot(lambda _: None)
    ctl.set_auto_revert(True)
    gate = threading.Event()
    monkeypatch.setattr(ctl, "auto_revert", lambda say: gate.wait(5))
    job = Job(ctl)
    job.start({}, "triage")
    for _ in range(400):
        if job.kind == "revert":
            break
        time.sleep(0.05)
    assert job.kind == "revert" and job.running()
    with pytest.raises(GuestError, match="a revert is already running"):
        job.start({"mode": "recent", "limit": 100}, "browse")
    gate.set()
    for _ in range(100):
        if not job.running():
            break
        time.sleep(0.05)
    assert job.state == "done"


def test_a_failed_revert_job_says_so(lab, monkeypatch):  # noqa: F811
    from fatbox.host.server import Job
    from fatbox.host.vbox import GuestError
    ctl, sha, _ = lab
    ctl.make_clean_snapshot(lambda _: None)
    ctl.set_auto_revert(True)

    def boom(say):
        raise GuestError("the VM did not get ready within 300 s")
    monkeypatch.setattr(ctl, "auto_revert", boom)
    job = Job(ctl)
    run_job(job, "triage")
    assert job.kind == "revert" and job.state == "failed"
    assert "--- ⚠ auto-revert failed: the VM did not get ready within 300 s" in [t for _, t in job.lines]


@pytest.mark.parametrize("state", ["running", "poweroff", "saved"])
def test_badge_says_reverting_during_the_revert_job(state):
    assert badge(state, 3, job="revert")["label"] == "reverting to clean…"
