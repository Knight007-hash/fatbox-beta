"""Host controller tests. A fake VBoxManage runs the real guest-side fatbox locally (no VM, no network)."""
import http.client
import json
import os
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from pathlib import Path

import pytest

from fatbox.config import load_config
from fatbox.host import codepush, validate
from fatbox.host.controller import Controller, fetch_args, fetch_deadline_s
from fatbox.host.server import Job, make_handler, page_csp
from fatbox.host.settings import HostSettings, default_home
from fatbox.host.vbox import GuestError
from fatbox.report import write_reports
from fatbox.static.triage import triage
from fatbox.store import Store, make_sample_zip, sha256_bytes
from test_pipeline import FAKE

FAKE_VBM = os.path.join(os.path.dirname(__file__), "fakes", "fake_vboxmanage.py")
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="fake VBoxManage is a POSIX shell wrapper")


def git(*args, cwd):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def lab(tmp_path, monkeypatch):
    guest = tmp_path / "guest"
    guest.mkdir()
    (guest / "config.toml").write_text('[paths]\ndata_dir = "./data"\n')
    cfg = load_config(guest / "config.toml")
    assert cfg.data_dir == guest / "data"
    store = Store(cfg.data_dir)
    sha = sha256_bytes(FAKE)
    store.add(sha, make_sample_zip("s.bin", FAKE, "infected"), {"signature": "TestFam", "tags": ["t"]}, "manual")
    rep = triage(FAKE, "s.bin", None)
    write_reports(rep, store.report_dir_for(sha), {"signature": "TestFam"})
    store.set_result(sha, "static_done", rep["score"], rep["priority"])

    vbm = tmp_path / "VBoxManage"
    vbm.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_VBM}" "$@"\n')
    vbm.chmod(vbm.stat().st_mode | stat.S_IEXEC)
    pw = tmp_path / "guest.pw"
    pw.write_text("secret\n")
    monkeypatch.setenv("FAKE_GUEST_CFG", str(guest / "config.toml"))
    monkeypatch.setenv("FAKE_GUEST_CWD", str(tmp_path))
    vmfile = tmp_path / "lab-vm.json"
    vmfile.write_text(json.dumps({"state": "running", "cable": "off", "snaps": [], "current": None}))
    monkeypatch.setenv("FAKE_VM_FILE", str(vmfile))
    # 0.42.0 Update VM copies the host's code in: a tiny host repo (commits A, B) and a guest folder on A
    hostrepo = tmp_path / "hostrepo"
    hostrepo.mkdir()
    git("init", "-q", "-b", "main", cwd=hostrepo)
    for n in ("A", "B"):
        (hostrepo / "VERSION").write_text(n)
        git("add", "VERSION", cwd=hostrepo)
        git("commit", "-q", "-m", n, cwd=hostrepo)
    git("init", "-q", "-b", "main", cwd=guest)
    git("fetch", "-q", str(hostrepo), "main", cwd=guest)
    git("reset", "-q", "--hard", "FETCH_HEAD~1", cwd=guest)
    monkeypatch.setattr("fatbox.host.codepush.HOST_REPO", hostrepo)
    home = tmp_path / "hosthome"
    s = HostSettings(vboxmanage=str(vbm), password_file=str(pw), guest_dir=str(guest), home=home)
    ctl = Controller(s)
    ctl.vm._sleep = lambda s: None
    ctl.net_wait_s = ctl.retry_pause_s = 0
    ctl.not_ready_wait_s, ctl.poll_s = 0.3, 0.05  # 0.39.1: a VM that stays "not ready" fails fast in tests
    return ctl, sha, home


def test_check_list_report(lab):
    ctl, sha, home = lab
    assert ctl.vbox.vm_state() == "running"
    assert ctl.ping().startswith("FatBox ")
    rows = ctl.list_samples()
    assert [r["sha256"] for r in rows] == [sha] and rows[0]["status"] == "static_done"
    rep = ctl.report(sha)
    assert rep["hashes"]["sha256"] == sha and rep["source_meta"]["signature"] == "TestFam"
    assert (home / "library" / "reports" / f"{sha}.json").exists()
    with pytest.raises(GuestError):
        ctl.report("0" * 64)  # no such report in the guest


def test_fetch_streams_log(lab):
    ctl, _, _ = lab
    lines = []
    assert ctl.fetch({"mode": "recent", "max": 2}, lines.append) == 0
    assert "total: 1" in lines and "INFO progress 100%" in lines


def guest_log():
    """What the fake guest ran, each with the cable state at that moment."""
    p = os.environ["FAKE_VM_FILE"] + ".guest"
    return open(p).read().splitlines() if os.path.exists(p) else []


def test_fetch_network_on_only_while_downloading(lab):
    ctl, _, _ = lab
    lines = []
    assert ctl.fetch({"mode": "recent", "max": 1}, lines.append) == 0
    # ping before plugging in, download with network, analysis only after the cable is out (INV-7),
    # then the reports are copied into the host library, still offline (T-7)
    assert guest_log() == ["--version cable=off", "fetch cable=on", "triage cable=off", "list cable=off",
                           "report cable=off"]
    assert "--- library: 1 new report(s) saved (1 total)" in lines
    assert ctl.vm.cable() == "off"
    i = lines.index
    assert i("--- network ON") < i("total: 1") < i("--- network OFF (checked)") < i("--- starting analysis (network is off)")


def test_failed_download_still_unplugs_and_triages(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_GUEST", "fetchfail")
    lines = []
    assert ctl.fetch({"mode": "recent", "max": 1}, lines.append) != 0
    assert guest_log()[1:3] == ["fetch cable=on", "triage cable=off"] and ctl.vm.cable() == "off"


def test_cancel_unplugs_and_skips_analysis(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_GUEST", "slow")
    lines = []
    t = threading.Thread(target=lambda: lines.append(ctl.fetch({"mode": "recent", "max": 1}, lines.append)))
    t.start()
    for _ in range(200):
        if "fetch cable=on" in guest_log():
            break
        threading.Event().wait(0.05)
    assert ctl.cancel()
    t.join(20)
    assert not t.is_alive() and lines[-1] != 0
    assert "--- cancelled, analysis skipped" in lines and ctl.vm.cable() == "off"
    assert not any(g.startswith("triage") for g in guest_log())


def test_stuck_cable_blocks_analysis(lab, monkeypatch):
    from fatbox.host.controller import NetworkStillOn
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_CABLE_STUCK", "1")
    lines = []
    with pytest.raises(NetworkStillOn, match="STILL ON"):
        ctl.fetch({"mode": "recent", "max": 1}, lines.append)
    assert ctl.vm.cable() == "on" and not any(g.startswith("triage") for g in guest_log())
    assert any("STILL ON" in l for l in lines)
    vmlog = open(os.environ["FAKE_VM_FILE"] + ".log").read()
    assert vmlog.count("setlinkstate1 off") == 3  # tried 3 times before giving up


def test_booting_vm_never_gets_network(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_GUEST", "booting")
    with pytest.raises(GuestError, match=r"^Windows in the VM is not ready for FatBox yet: .* Power off and Start the VM again\.$"):
        ctl.fetch({"mode": "recent", "max": 1}, print)
    assert ctl.vm.cable() == "off" and "setlinkstate1 on" not in open(os.environ["FAKE_VM_FILE"] + ".log").read()


def test_stopped_vm_is_refused(lab):
    ctl, _, _ = lab
    ctl.vm.poweroff()
    with pytest.raises(GuestError, match="start it first"):
        ctl.fetch({"mode": "recent", "max": 1}, print)
    assert guest_log() == []


def test_startup_check_unplugs_leftover_network(lab):
    ctl, _, _ = lab
    assert ctl.startup_check() is None
    ctl.vm.set_network(True)                    # left over from a crash, or turned on by hand
    assert "switched it OFF" in ctl.startup_check()
    assert ctl.vm.cable() == "off"


def test_update_vm(lab, monkeypatch):
    """0.42.0: the host's code goes in over guest control with the network OFF; the cable is in only for
    `update --no-fetch` (pinned libraries). The VM never asks GitHub, so no token anywhere."""
    ctl, _, _ = lab
    guest = Path(ctl.s.guest_dir)
    host_head = git("rev-parse", "HEAD", cwd=codepush.HOST_REPO)
    assert git("rev-parse", "HEAD", cwd=guest) != host_head
    lines = []
    assert ctl.update_vm(lines.append) == 0
    assert guest_log() == ["--version cable=off", "copyto cable=off", "push cable=off", "update cable=on",
                           "--version cable=off"]
    assert git("rev-parse", "HEAD", cwd=guest) == host_head and (guest / "VERSION").read_text() == "B"
    assert (guest / "config.toml").exists() and (guest / "data").is_dir()      # untracked: never touched
    assert not list(guest.glob("fatbox-update-*.bundle"))                        # the bundle is deleted
    assert any("(copied from this PC; GitHub not used)" in ln for ln in lines)
    assert "--no-fetch" in Path(os.environ["FAKE_VM_FILE"] + ".log").read_text()
    assert lines[-1].startswith("--- VM now runs FatBox ") and not any("set-token" in ln for ln in lines)
    lines.clear()
    assert ctl.update_vm(lines.append) == 0                                      # second time: nothing to do
    assert any("already has this PC's code" in ln for ln in lines)


def test_update_vm_replaces_edits_inside_the_vm(lab):
    """The client never fixes anything in the VM: edited FatBox files there are simply replaced."""
    ctl, _, _ = lab
    guest = Path(ctl.s.guest_dir)
    (guest / "VERSION").write_text("hacked")
    lines = []
    assert ctl.update_vm(lines.append) == 0
    assert (guest / "VERSION").read_text() == "B" and any("are replaced" in ln for ln in lines)


def test_update_vm_copy_failure_keeps_the_network_off(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_COPY_FAIL", "all")
    lines = []
    assert ctl.update_vm(lines.append) != 0
    assert ctl.vm.cable() == "off" and "cable=on" not in " ".join(guest_log())
    assert lines[-1].startswith("--- update failed: the VM did not take this PC's code")
    assert any("VERR_ACCESS_DENIED" in ln for ln in lines)          # 0.42.1: VirtualBox's own words are shown
    assert not any("\x1b" in ln for ln in lines)                    # ... made printable


def test_update_vm_uses_the_public_folder_when_the_fatbox_folder_refuses(lab, monkeypatch, tmp_path):
    """0.42.1 live: copyto into the FatBox folder failed; a folder every user can write is the second try."""
    ctl, _, _ = lab
    public = tmp_path / "Public"
    public.mkdir()
    ctl.push_fallback_dir = str(public)
    monkeypatch.setenv("FAKE_COPY_FAIL", "first")
    monkeypatch.setenv("FAKE_GUEST_DIR", ctl.s.guest_dir)
    lines = []
    assert ctl.update_vm(lines.append) == 0
    assert (Path(ctl.s.guest_dir) / "VERSION").read_text() == "B" and not list(public.iterdir())   # bundle deleted


def test_update_vm_falls_back_to_github_when_host_is_not_a_git_folder(lab, monkeypatch, tmp_path):
    ctl, _, _ = lab
    monkeypatch.setattr("fatbox.host.codepush.HOST_REPO", tmp_path / "nogit")
    lines = []
    assert ctl.update_vm(lines.append) == 0
    assert guest_log() == ["--version cable=off", "update cable=on", "--version cable=off"]
    assert "--no-fetch" not in Path(os.environ["FAKE_VM_FILE"] + ".log").read_text()
    monkeypatch.setenv("FAKE_GUEST", "notoken")  # GitHub refuses: fails at once, network off, no set-token chore
    lines.clear()
    assert ctl.update_vm(lines.append) != 0
    assert ctl.vm.cable() == "off" and lines[-1] == "--- update failed (see above)"
    assert not any("set-token" in ln for ln in lines)


def test_flooding_guest_is_cut_off(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_GUEST", "flood")
    with pytest.raises(GuestError, match="exceeded"):
        ctl.list_samples()


@pytest.mark.parametrize("opts", [
    {"mode": "evil"}, {"mode": "tag"}, {"mode": "tag", "value": "a&calc"}, {"mode": "tag", "value": "x\" --y"},
    {"mode": "latest", "value": "AsyncRAT"}, {"mode": "recent", "max": 0}, {"mode": "recent", "max": 31},
    {"mode": "recent", "max_size_mb": 101}, {"mode": "recent", "max": "3; calc"},
])
def test_fetch_args_reject(opts):
    with pytest.raises(ValueError):
        fetch_args(opts)


def test_fetch_args_ok():
    assert fetch_args({"mode": "signature", "value": "AgentTesla", "max": "3", "max_size_mb": 5, "small_first": True}) == \
        ["fetch", "--source", "bazaar", "--mode", "signature", "--value", "AgentTesla", "--max", "3",
         "--max-size-mb", "5", "--budget", "400", "--small-first"]  # the budget is always sent


def test_fetch_args_limits():
    a = fetch_args({"mode": "recent", "max": 30, "size_limit": False, "max_size_mb": 5, "budget": "1800"})
    assert a == ["fetch", "--source", "bazaar", "--mode", "recent", "--max", "30", "--budget", "1800", "--no-size-limit"]
    assert fetch_deadline_s(a) == 1800 + 120  # the host's own stopwatch: budget + margin
    for bad in ({"budget": 59}, {"budget": 1801}, {"budget": "4e2"}, {"size_limit": "no"}):
        with pytest.raises(ValueError):
            fetch_args({"mode": "recent", **bad})


def test_host_stopwatch_is_used_for_the_download(lab, monkeypatch):
    ctl, _, _ = lab
    seen = []
    real = ctl.vbox.run
    monkeypatch.setattr(ctl.vbox, "run", lambda args, timeout_s, *a, **k: seen.append((args[0], timeout_s)) or real(args, timeout_s, *a, **k))
    ctl.fetch({"mode": "recent", "budget": 90}, lambda line: None)
    assert ("fetch", 90 + 120) in seen


def test_hostile_guest_text_is_made_printable(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_GUEST", "hostile")
    lines = []
    ctl.update_vm(lines.append)  # fetch would refuse: a hostile version string is not a matching version
    for text in [ctl.ping(), *lines]:
        assert "\x1b" not in text and "\x07" not in text and "\u202e" not in text
    assert ctl.ping() == "FatBox 6.6.6\\x1b]0;pwned\\x07\\x1b[2J"
    assert "saved invoice\\u202egpj.exe\\x1b[8m hidden" in lines


def test_vm_strings_are_made_printable():
    sha = "a" * 64
    row = {"sha256": sha, "status": "fetched", "file_name": "invoice\u202egpj.exe\x1b[2J", "signature": "a\nb",
           "tags": ["\u200bx"]}
    r = validate.sample_list(json.dumps({"rows": [row]}).encode())[0]
    assert r["file_name"] == "invoice\\u202egpj.exe\\x1b[2J" and r["signature"] == "a\\x0ab"
    assert r["tags"] == ["\\u200bx"]
    rep = {"hashes": {"sha256": sha}, "priority": "low", "score": 1,
           "pe": {"sections": [{"n\x1bame": "x\ud800y", "note": "line1\nline2\tz"}]}}
    sec = validate.report(json.dumps(rep).encode(), sha)["pe"]["sections"][0]
    assert sec == {"n\\x1bame": "x\\ud800y", "note": "line1\nline2\tz"}  # newlines and tabs kept in reports


def test_report_validation_rejects_tampering():
    sha = "a" * 64
    good = {"hashes": {"sha256": sha}, "priority": "low", "score": 10, "reasons": []}
    assert validate.report(json.dumps(good).encode(), sha)
    for bad in [{**good, "hashes": {"sha256": "b" * 64}}, {**good, "priority": "<img>"}, {**good, "score": 1e9},
                {**good, "reasons": "x"}]:
        with pytest.raises(validate.Invalid):
            validate.report(json.dumps(bad).encode(), sha)
    with pytest.raises(validate.Invalid):
        validate.report(b'{"score": NaN}', sha)
    with pytest.raises(validate.Invalid):
        validate.report(b"[" * 50 + b"]" * 50, sha)
    deep = b"[" * 200_000 + b"]" * 200_000  # deep enough to blow the parser's own recursion (INV-4)
    with pytest.raises(validate.Invalid, match="nested too deep"):
        validate.report(deep, sha)
    with pytest.raises(validate.Invalid, match="nested too deep"):
        validate.sample_list(deep)
    with pytest.raises(validate.Invalid):
        validate.sample_list(b'{"rows": [{"sha256": "../../x"}]}')


def test_host_gui_endpoints(lab):
    ctl, sha, _ = lab
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(ctl, Job(ctl), port, "tok123")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    cookie = {"Cookie": "fbx=tok123"}

    def get(path):
        return json.loads(urllib.request.urlopen(urllib.request.Request(base + path, headers=cookie)).read())

    def post(path, body, hdr=True):
        req = urllib.request.Request(base + path, json.dumps(body).encode(), method="POST",
                                     headers={**cookie, "X-FatBox": "1"} if hdr else cookie)
        return json.loads(urllib.request.urlopen(req).read())

    try:
        # no token (e.g. something in the VM reaching host loopback through NAT): everything refused
        for path in ("/", "/api/library", "/?t=wrong"):
            with pytest.raises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(base + path)
            assert e.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(urllib.request.Request(base + "/api/fetch", b"{}", method="POST",
                                                          headers={"X-FatBox": "1", "Cookie": "fbx=wrong"}))
        assert e.value.code == 403

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.build_opener(NoRedirect).open(base + "/?t=tok123")
        assert e.value.code == 303 and "fbx=tok123" in e.value.headers["Set-Cookie"]

        assert get("/api/vm")["state"] == "running"
        assert get("/api/library")["rows"] == []  # nothing copied yet: the VM's list is not the table any more
        assert get(f"/api/report?sha256={sha}")["priority"] in ("low", "medium", "high")
        page = urllib.request.urlopen(urllib.request.Request(base + "/", headers=cookie))
        csp = page.headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "script-src 'sha256-" in csp and "'unsafe-inline'" not in csp.split(";")[1]
        assert "innerHTML" not in page.read().decode().split("<script>")[1].replace("Never innerHTML", "")
        with pytest.raises(urllib.error.HTTPError) as e:
            post("/api/fetch", {"mode": "recent"}, hdr=False)
        assert e.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as e:
            post("/api/fetch", {"mode": "tag", "value": "a;b"})
        assert e.value.code == 400
        for bad_len in ("-1", "abc", str(64 * 1024 + 1)):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.putrequest("POST", "/api/fetch")
            for k, v in (("Cookie", "fbx=tok123"), ("X-FatBox", "1"), ("Content-Length", bad_len)):
                conn.putheader(k, v)
            conn.endheaders()
            assert conn.getresponse().status == 400
            conn.close()
        with pytest.raises(urllib.error.HTTPError) as e:  # 0.29.0: Browse first; no blind fetch from the GUI
            post("/api/fetch", {"mode": "recent", "max": 1})
        assert e.value.code == 400

        def wait():
            for _ in range(200):
                j = get("/api/job?since=0")
                if j["state"] != "running":
                    return j
                threading.Event().wait(0.05)
        assert post("/api/fetch", {"pick": [sha, "f" * 64]})["ok"]
        j = wait()
        assert j["state"] == "done" and any("total: 1" in l["t"] for l in j["lines"])
        assert j["kind"] == "fetch" and get("/api/vm")["cable"] == "off"
        assert j["result"] == [{"sha256": sha, "status": "static_done"}, {"sha256": "f" * 64, "status": "missing"}]
        assert not any("starting analysis" in l["t"] for l in j["lines"])   # Fetch only downloads
        assert get("/api/pending") == {"busy": False, "rows": []}            # the lab sample is analysed already
        assert post("/api/triage", {})["ok"]
        j = wait()
        assert (j["kind"], j["state"]) == ("triage", "done") and j["result"] is None
        assert any("starting analysis (network is off)" in l["t"] for l in j["lines"])
        assert post("/api/cancel", {}) == {"cancelled": False}
        assert post("/api/update-vm", {})["ok"]
        for _ in range(100):
            j = get("/api/job?since=0")
            if j["state"] != "running":
                break
            threading.Event().wait(0.05)
        assert (j["kind"], j["state"]) == ("update", "done") and any("VM now runs" in l["t"] for l in j["lines"])
        with pytest.raises(urllib.error.HTTPError) as e:
            post("/api/vm/network", {"on": True})  # no confirmation: refused
        assert e.value.code == 400
    finally:
        httpd.shutdown()


@pytest.fixture
def vmctl(lab, tmp_path, monkeypatch):
    from fatbox.host.vmctl import VmControl
    ctl, _, _ = lab
    f = tmp_path / "vm.json"
    f.write_text(json.dumps({"state": "running", "cable": "on", "snaps": ["clean-host-control-2026-10-24"],
                             "current": "clean-host-control-2026-10-24"}))
    monkeypatch.setenv("FAKE_VM_FILE", str(f))
    return VmControl(ctl.s, sleep=lambda s: None), f


def test_vm_info_power_network_snapshots(vmctl):
    vm, f = vmctl
    i = vm.info()
    assert (i["state"], i["nic1"], i["cable"]) == ("running", "nat", "on")
    assert i["snapshots"] == ["clean-host-control-2026-10-24"] and i["current_snapshot"] == "clean-host-control-2026-10-24"
    vm.set_network(False)                       # running -> controlvm setlinkstate1
    assert vm.info()["cable"] == "off"
    vm.take("before-test")
    assert vm.snapshots()[0] == ["clean-host-control-2026-10-24", "before-test"]
    for bad in ("a b", "x;calc", "", "../x", "before-test"):
        with pytest.raises(ValueError):
            vm.take(bad)
    vm.revert("clean-host-control-2026-10-24")  # powers off first, restores, then unplugs what the snapshot had
    log = (f.parent / "vm.json.log").read_text().splitlines()
    assert log[-3].startswith("controlvm fatbox-vm poweroff") and log[-2].startswith("snapshot fatbox-vm restore")
    assert log[-1] == "modifyvm fatbox-vm --cableconnected1 off"
    assert vm.state() == "poweroff"
    vm.set_network(True)                        # off -> modifyvm --cableconnected1
    assert "modifyvm" in (f.parent / "vm.json.log").read_text().splitlines()[-1]
    vm.start(headless=True)                     # INV-7: never boots with the cable in
    assert vm.state() == "running" and vm.cable() == "off"
    with pytest.raises(ValueError):
        vm.revert("no-such-snapshot")


def test_vm_actions_need_confirmation_and_no_running_fetch(lab, vmctl):
    from fatbox.host.server import Job, vm_action
    ctl, _, _ = lab
    vm, _ = vmctl
    job = Job(ctl)
    for action in ("poweroff", "revert"):
        with pytest.raises(ValueError, match="confirmation"):
            vm_action(vm, job, action, {"name": "clean-host-control-2026-10-24"})
    job.state, job.kind = "running", "fetch"
    for action, body in (("poweroff", {"confirm": True}), ("network", {"on": False}), ("start", {}),
                         ("snapshot", {"name": "x"}), ("network", {"on": True, "confirm": True})):
        with pytest.raises(ValueError, match="a fetch is running"):
            vm_action(vm, job, action, body)
    job.state = "idle"
    vm_action(vm, job, "network", {"on": False})
    with pytest.raises(ValueError, match="confirmation"):  # turning the internet on by hand: the page warns first
        vm_action(vm, job, "network", {"on": True})
    vm_action(vm, job, "network", {"on": True, "confirm": True})
    assert vm.cable() == "on"
    vm_action(vm, job, "poweroff", {"confirm": True})
    assert vm.state() == "poweroff"
    with pytest.raises(LookupError):
        vm_action(vm, job, "deletevm", {"confirm": True})


def test_vm_transient_lock_error_is_retried(lab):
    import subprocess as sp
    from fatbox.host.vmctl import VmControl
    ctl, _, _ = lab
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        if len(calls) < 3:
            return sp.CompletedProcess(argv, 1, b"", b"error: An unexpected process (PID=0x46C4) has tried to lock "
                                                     b"the machine ... code E_ACCESSDENIED (0x80070005)")
        return sp.CompletedProcess(argv, 0, b'VMState="running"\n', b"")
    vm = VmControl(ctl.s, run=run, sleep=lambda s: None)
    assert vm.state() == "running" and len(calls) == 3

    def bad(argv, **kw):
        calls.append(argv)
        return sp.CompletedProcess(argv, 1, b"", b"error: Could not find a registered machine")
    calls.clear()
    with pytest.raises(GuestError):
        VmControl(ctl.s, run=bad, sleep=lambda s: None).state()
    assert len(calls) == 1  # real errors are not retried


def test_vm_actions_follow_state_and_never_overlap(lab, vmctl):
    from fatbox.host.server import Job, vm_action
    ctl, _, _ = lab
    vm, _ = vmctl
    job = Job(ctl)
    with pytest.raises(ValueError, match="can't start while the VM is 'running'"):
        vm_action(vm, job, "start", {})
    vm.action_lock.acquire()                    # another action in flight (e.g. a slow revert)
    vm.action = "revert"
    try:
        with pytest.raises(ValueError, match="'revert' is still in progress"):
            vm_action(vm, job, "network", {"on": True, "confirm": True})
    finally:
        vm.action = None
        vm.action_lock.release()
    vm_action(vm, job, "poweroff", {"confirm": True})
    for action in ("shutdown", "poweroff"):
        with pytest.raises(ValueError, match="while the VM is 'poweroff'"):
            vm_action(vm, job, action, {"confirm": True})
    vm_action(vm, job, "start", {"headless": True})
    assert vm.state() == "running" and vm.action is None and not vm.action_lock.locked()


def test_page_csp_hash_ignores_line_endings():
    page = b"<html><script>\nlet a = 1;\n</script></html>"
    assert page_csp(page) == page_csp(page.replace(b"\n", b"\r\n"))  # git on Windows checks out CRLF
    assert page_csp(page) != page_csp(page.replace(b"a = 1", b"a = 2"))


def test_vm_info_first_line_wins():
    from fatbox.host.vmctl import VmControl
    # VirtualBox's own lines come first; a later line (guest additions data) must not override them
    kv = VmControl._kv('VMState="running"\ncableconnected1="on"\nVMState="poweroff"\ncableconnected1="off"')
    assert kv["VMState"] == "running" and kv["cableconnected1"] == "on"


def test_settings_dir_keeps_pre_rename_setup(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    assert default_home() == tmp_path / "fatbox-host"
    (tmp_path / "malbox-host").mkdir()
    assert default_home() == tmp_path / "malbox-host"
    (tmp_path / "fatbox-host").mkdir()
    assert default_home() == tmp_path / "fatbox-host"


def test_missing_module_points_at_guest_dir(lab):
    ctl, _, _ = lab
    with pytest.raises(GuestError, match="guest_dir in host.toml") as e:
        ctl._check(1, "No module named fatbox", "list")
    assert "malbox" not in str(e.value)


def test_versions_must_match_exactly(lab, monkeypatch):
    from fatbox import __version__
    ctl, _, _ = lab
    assert ctl.version_check() == {"host": __version__, "vm": __version__, "ok": True, "message": None}
    for mode, vm, words in (("oldvm", "0.0.1", "click Update VM"), ("newvm", "999.0.0", "git pull on the host"),
                            ("hostile", None, "unknown version")):
        monkeypatch.setenv("FAKE_GUEST", mode)
        v = ctl.version_check()
        assert (v["vm"], v["ok"]) == (vm, False) and words in v["message"]
        with pytest.raises(GuestError, match="Fetch is off"):
            ctl.fetch({"mode": "recent", "max": 1}, print)
        assert ctl.vm.cable() == "off" and not any(g.startswith("fetch") for g in guest_log())
    monkeypatch.setenv("FAKE_GUEST", "oldvm")
    assert ctl.update_vm(print) == 0               # the update that fixes it is never blocked


def test_version_endpoint_and_cli(lab, monkeypatch, capsys):
    from fatbox.host import cli
    ctl, _, _ = lab
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(ctl, Job(ctl), port, "tok")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    get = lambda: json.loads(urllib.request.urlopen(urllib.request.Request(  # noqa: E731
        f"http://127.0.0.1:{port}/api/version", headers={"Cookie": "fbx=tok"})).read())
    try:
        assert get()["ok"] is True
        monkeypatch.setenv("FAKE_GUEST", "oldvm")
        assert get()["ok"] is False and "0.0.1" in get()["message"]
    finally:
        httpd.shutdown()
    monkeypatch.setattr(cli, "load_settings", lambda path: ctl.s)
    assert cli.main(["check"]) == 1 and "click Update VM" in capsys.readouterr().err
    monkeypatch.setenv("FAKE_GUEST", "real")
    assert cli.main(["check"]) == 0 and "versions match" in capsys.readouterr().out


# --- live-test fixes (T-2 PR): network at boot, plain-words errors, host ahead of GitHub main ------------------
def test_vm_never_boots_with_the_network_on(vmctl, monkeypatch):
    vm, f = vmctl
    f.write_text(json.dumps({"state": "poweroff", "cable": "on", "snaps": [], "current": None}))
    vm.start(headless=True)
    log = (f.parent / "vm.json.log").read_text().splitlines()
    assert log[0] == "modifyvm fatbox-vm --cableconnected1 off" and log[1].startswith("startvm")
    assert vm.cable() == "off"
    # a suspended VM can come back with the cable it was suspended with: unplugged right after start
    vm.poweroff()
    monkeypatch.setenv("FAKE_START_CABLE_ON", "1")
    vm.start(headless=True)
    assert vm.cable() == "off" and "setlinkstate1 off" in (f.parent / "vm.json.log").read_text().splitlines()[-1]
    # VirtualBox won't let go of it: the start is reported as a failure, never silently online
    vm.poweroff()
    monkeypatch.setenv("FAKE_CABLE_STUCK", "1")
    with pytest.raises(GuestError, match="started with its network ON"):
        vm.start(headless=True)


def test_virtualbox_errors_in_plain_words_with_details_kept(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_GUEST", "noadditions")
    with pytest.raises(GuestError) as e:
        ctl.list_samples()
    assert str(e.value) == "Windows in the VM is not ready for FatBox yet: VirtualBox says its Guest Additions are not running. If it just started, wait a minute. If it stays like this, Power off and Start the VM again."
    assert "VBOX_E_GSTCTL_GUEST_ERROR" in e.value.detail and "VBOX_E" not in str(e.value)
    with pytest.raises(GuestError) as e:  # unknown errors: first line only, the rest behind details
        ctl._check(1, "VBoxManage.exe: error: Something new\nVBoxManage.exe: error: Details: code 0x1", "list")
    assert str(e.value) == "list failed (exit 1): Something new" and "Details: code 0x1" in e.value.detail


def test_failed_job_says_why_and_keeps_details(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_GUEST", "noadditions")
    job = Job(ctl)
    job.start({"pick": ["a" * 64]})
    for _ in range(100):
        if not job.running():
            break
        time.sleep(0.05)
    snap = job.snapshot(0)
    assert snap["state"] == "failed" and snap["error"].startswith("Windows in the VM is not ready")
    assert "VBOX_E_GSTCTL_GUEST_ERROR" in snap["detail"]
    assert snap["lines"][-1]["t"] == "--- fetch failed: " + snap["error"]  # the reason is in the log, in plain words
    assert ctl.vm.cable() == "off"


def test_api_errors_carry_details_separately(lab, monkeypatch):
    ctl, sha, _ = lab
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(ctl, Job(ctl), port, "tok")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    monkeypatch.setenv("FAKE_GUEST", "noadditions")
    try:
        with pytest.raises(urllib.error.HTTPError) as e:  # not in the library yet: asks the VM
            urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/api/report?sha256={sha}",
                                                          headers={"Cookie": "fbx=tok"}))
        body = json.loads(e.value.read())
        assert body["error"].startswith("Windows in the VM is not ready") and "GuestWrap" in body["detail"]
    finally:
        httpd.shutdown()


def test_host_ahead_of_github_main_is_explained(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setattr(ctl, "branch", lambda: "claude/some-feature")
    monkeypatch.setenv("FAKE_GUEST", "oldvm")
    msg = ctl.version_check()["message"]
    assert "click Update VM" in msg and "branch 'claude/some-feature', not main" in msg and "git checkout main" in msg
    lines = []
    assert ctl.update_vm(lines.append) == 0     # the update itself is fine: the VM is already on newest main
    assert lines[-1].startswith("--- still different from the host:") and "git checkout main" in lines[-1]
    monkeypatch.setattr(ctl, "branch", lambda: "main")
    assert "not main" not in ctl.version_check()["message"]


def test_update_vm_waits_while_guest_session_is_starting(lab, monkeypatch):
    """0.39.1 live bug: right after a boot VirtualBox says "running" but guest control answers "Error starting
    guest session (current status is: starting)". Update VM (and every step before the cable goes in) waits for
    it instead of failing; the network stays off until FatBox answers."""
    ctl, _, _ = lab
    ctl.not_ready_wait_s = 10
    monkeypatch.setenv("FAKE_GUEST", "starting")
    monkeypatch.setenv("FAKE_GUEST_STARTING", "3")  # the first 3 guest calls fail like that
    lines = []
    assert ctl.update_vm(lines.append) == 0
    assert guest_log()[:4] == ["--version cable=off"] * 4 and "update cable=on" in guest_log()
    assert lines[-1].startswith("--- VM now runs FatBox ")
    assert lines[0].startswith("--- waiting for Windows in the VM to get ready") and "up to 0 min" not in lines[0]
    assert "--- Windows in the VM is ready" in lines   # 0.42.0: the wait is said, not a silent spinner


def test_still_starting_after_the_wait_fails_with_the_network_off(lab, monkeypatch):
    ctl, _, _ = lab
    monkeypatch.setenv("FAKE_GUEST", "starting")
    monkeypatch.setenv("FAKE_GUEST_STARTING", "1000")
    with pytest.raises(GuestError, match="^Windows in the VM is not ready for FatBox yet"):
        ctl.update_vm(print)
    assert ctl.vm.cable() == "off" and all(line == "--version cable=off" for line in guest_log())


def test_terminated_guest_session_counts_as_not_ready():
    """0.39.2 live: a VM still busy after a boot also answers "current status is: terminated"."""
    from fatbox.host.vbox import explain, not_ready
    raw = "VBoxManage.exe: error: Error starting guest session (current status is: terminated)"
    assert not_ready(raw) and explain(raw).startswith("Windows in the VM is not ready for FatBox yet")
    assert not not_ready("VBoxManage.exe: error: VERR_AUTHENTICATION_FAILURE")


# ---- 0.39.3 audit fixes ----------------------------------------------------------------------------------

def test_snapshot_only_while_off(lab, vmctl):
    """A snapshot of a running VM saves its RAM (maybe plain sample bytes) to the host: refused (INV-1, INV-2)."""
    from fatbox.host.server import Job, vm_action
    ctl, _, _ = lab
    vm, f = vmctl
    job = Job(ctl)
    with pytest.raises(ValueError, match="while the VM is 'running'"):
        vm_action(vm, job, "snapshot", {"name": "x"})
    vm_action(vm, job, "poweroff", {"confirm": True})
    vm_action(vm, job, "snapshot", {"name": "x"})
    assert "x" in json.loads(f.read_text())["snaps"]


@pytest.mark.parametrize("state", ["stuck", "paused", "gurumeditation", "stopping", "starting"])
def test_hung_vm_can_be_powered_off(lab, vmctl, state):
    """A VM that ignores ACPI or hangs must still be pulled out with Power off."""
    from fatbox.host.server import Job, vm_action
    ctl, _, _ = lab
    vm, f = vmctl
    f.write_text(json.dumps({**json.loads(f.read_text()), "state": state}))
    vm_action(vm, Job(ctl), "poweroff", {"confirm": True})
    assert vm.state() == "poweroff"


def test_cable_off_retries_a_hung_vboxmanage_call(lab):
    import subprocess as sp
    ctl, _, _ = lab
    real, calls = ctl.vm.set_network, []

    def flaky(on):
        calls.append(on)
        if len(calls) == 1:
            raise sp.TimeoutExpired("VBoxManage", 30)
        return real(on)
    ctl.vm.set_network = flaky
    lines = []
    ctl.cable_off(lines.append)
    assert calls == [False, False] and lines[-1] == "--- network OFF (checked)"


def test_ready_ping_keeps_waiting_on_a_timeout(lab):
    ctl, _, _ = lab
    real, n = ctl.ping, []

    def slow():
        n.append(1)
        if len(n) < 3:
            raise GuestError("guest fatbox --version failed", "timed out after 120s")
        return real()
    ctl.ping = slow
    assert ctl.ready_ping().startswith("FatBox ") and len(n) == 3


def test_validator_rejects_infinity_and_trailing_newline():
    with pytest.raises(validate.Invalid):
        validate.parse(b'{"score": 1e999}', 1000)
    with pytest.raises(validate.Invalid):
        validate.parse(b'{"n": ' + b"9" * 5000 + b"}", 10000)
    assert not validate.SHA_RE.match("a" * 64 + "\n") and validate.SHA_RE.match("a" * 64)
