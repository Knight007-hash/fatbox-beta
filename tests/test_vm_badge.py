"""0.31.0: the header's VM badge (running, booting, updating, analysing n/30, shutting down, reverting, off...)."""
import json

import pytest

from fatbox.host.vmstatus import NOT_READY_S, badge, progress, run_level
from test_host import lab, vmctl  # noqa: F401  (fixtures)


def key(**kw):
    b = badge(**kw)
    return b["key"], b["label"], b["tone"], b["pulse"]


def test_power_states():
    assert key(state="running", level=3) == ("running", "running", "ok", False)
    assert key(state="running", level=2) == ("running", "running", "ok", False)
    assert key(state="running", level=None) == ("running", "running", "ok", False)  # no Guest Additions info
    assert key(state="poweroff") == ("off", "powered off", "muted", False)
    assert key(state="saved")[:3] == ("saved", "saved", "muted")
    assert key(state="abortedsaved")[0] == "saved"
    assert key(state="aborted") == ("crashed", "crashed", "bad", False)
    assert key(state="paused")[:2] == ("paused", "paused")
    assert key(state="stuck")[:3] == ("not_responding", "not responding", "bad")
    assert key(state="unknown")[0] == "not_responding"
    assert key(state="starting")[:2] == ("booting", "booting…")
    assert key(state="stopping")[0] == "shutting_down"
    assert key(state="restoringsnapshot")[:2] == ("reverting", "reverting…")


def test_booting_ready_and_not_responding():
    assert key(state="running", level=0, booted_s=20) == ("booting", "booting…", "warn", True)
    assert key(state="running", level=1, booted_s=NOT_READY_S - 1)[0] == "booting"
    assert key(state="running", level=1, booted_s=NOT_READY_S + 1) == ("not_responding", "not responding", "bad", False)


def test_shutting_down():
    assert key(state="running", level=3, shutdown_asked=True)[:2] == ("shutting_down", "shutting down…")
    # Windows was ready this boot and has stopped answering: it is going down (Start menu, auto-revert)
    assert key(state="running", level=0, was_ready=True, booted_s=900)[0] == "shutting_down"
    assert key(state="running", level=0, was_ready=True, job="triage")[0] == "shutting_down"


def test_actions_and_jobs():
    assert key(state="poweroff", action="start")[:2] == ("booting", "booting…")
    assert key(state="running", level=3, action="shutdown")[0] == "shutting_down"
    assert key(state="running", level=3, action="revert", revert_clean=True)[1] == "reverting to clean…"
    assert key(state="poweroff", action="revert")[1] == "reverting…"
    assert key(state="running", level=3, action="snapshot")[1] == "taking snapshot…"
    assert key(state="running", level=3, action="network") == ("running", "running", "ok", False)
    assert key(state="running", level=3, job="update") == ("update", "updating FatBox…", "accent", True)
    assert key(state="running", level=3, job="triage", prog=(7, 30))[1:] == ("analysing 7/30", "accent", True)
    assert key(state="running", level=3, job="triage")[1] == "analysing…"
    assert key(state="running", level=3, job="fetch", prog=(4, 12))[1] == "fetching 4/12"
    assert key(state="poweroff", job="triage")[1] == "reverting to clean…"  # T-8 auto-revert after the analysis
    assert key(state="poweroff", job="clean")[1] == "making clean snapshot…"
    assert key(state="running", level=0, job="clean")[1] == "making clean snapshot…"


def test_vm_text_is_checked():
    # the run level and the progress lines come from the guest: strict format, numbers capped
    assert run_level("3") == 3 and run_level("0") == 0
    for bad in (None, "", "4", "-1", "3 ", "x", "10"):
        assert run_level(bad) is None
    assert progress("progress: 7/30", "triage") == (7, 30)
    assert progress("progress: 0/5", "triage") == (0, 5)
    for bad in ("progress: 31/31", "progress: 8/7", "progress: 1/0", "progress: 7/30 extra", "xprogress: 1/2",
                "progress: 9999/9999", "progress: -1/3"):
        assert progress(bad, "triage") is None
    assert progress("progress: 7/30", "fetch") is None and progress("progress: 7/30", None) is None
    line = "INFO [4/12] 0123456789abcdef 120 KB AgentTesla  (300 s left)"
    assert progress(line, "fetch") == (4, 12) and progress(line, "triage") is None
    assert progress("[4/99] 0123456789abcdef ", "fetch") is None
    # a hostile label never reaches the page as anything but our own words or VirtualBox's state, cut short
    assert len(badge("x" * 500)["label"]) == 40


def test_job_tracks_progress(lab):  # noqa: F811
    from fatbox.host.server import Job
    ctl, _, _ = lab
    job = Job(ctl)
    job.add("progress: 3/30")  # no job running: ignored
    assert job.badge_job() == (None, None)
    job.kind, job.state = "triage", "running"
    job.add("progress: 3/30")
    job.add("progress: 99/30")  # bad line: keeps the last good count
    assert job.badge_job() == ("triage", (3, 30))
    assert job.snapshot(0)["progress"] == [3, 30]  # 0.33.0: the Fetch tab label shows it too
    job.state = "done"
    assert job.badge_job() == (None, None) and job.snapshot(0)["progress"] is None


def test_vmcontrol_clocks(vmctl):  # noqa: F811
    vm, f = vmctl
    now = [100.0]
    vm._clock = lambda: now[0]
    vm_file = json.loads(f.read_text())
    f.write_text(json.dumps({**vm_file, "runlevel": 0}))
    i = vm.info()
    assert i["run_level"] == 0 and vm.boot_seen == 100.0 and not vm.was_ready
    now[0] = 160.0
    assert vm.booted_s() == 60.0
    f.write_text(json.dumps({**json.loads(f.read_text()), "runlevel": 3}))
    assert vm.info()["run_level"] == 3 and vm.was_ready
    vm.shutdown()
    assert vm.shutdown_at == 160.0
    vm.info()  # the fake powers off on the ACPI button
    assert (vm.boot_seen, vm.was_ready, vm.shutdown_at) == (None, False, None)
    f.write_text(json.dumps({**json.loads(f.read_text()), "runlevel": "7"}))
    assert vm.info()["run_level"] is None  # garbage from the guest is "unknown"


def test_api_vm_has_badge(lab, vmctl):  # noqa: F811
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer
    from fatbox.host.server import Job, make_handler
    ctl, _, _ = lab
    vm, f = vmctl
    f.write_text(json.dumps({**json.loads(f.read_text()), "runlevel": 1}))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(ctl, Job(ctl), port, "tok", vm=vm)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/vm", headers={"Cookie": "fbx=tok"})
        b = json.loads(urllib.request.urlopen(req).read())["badge"]
        assert (b["key"], b["label"], b["tone"], b["pulse"]) == ("booting", "booting…", "warn", True)
    finally:
        httpd.shutdown()
