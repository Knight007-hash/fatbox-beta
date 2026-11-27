"""T-19 lab layout: VirtualBox on this PC or on a test PC over SSH, through the gate there."""
import base64
import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from fatbox.host import lab as labmod
from fatbox.host.settings import HostSettings, LabSettings, check_lab, load_settings
from fatbox.host.vbox import VBox
from fatbox.host.vmctl import VmControl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lab"))
import fatbox_gate as gate  # noqa: E402

FAKES = Path(__file__).parent / "fakes"
CFG = {"vm": "fatbox-vm", "vboxmanage": "VBoxManage", "guest_user": "analyst",
       "guest_python": r"C:\Python313\python.exe", "password_file": r"C:\fatbox-lab\guest.pw"}
REMOTE = LabSettings("two-pcs", "10.99.0.2", "lab", 22)


# ---- settings ---------------------------------------------------------------------------------------------
def test_old_host_toml_is_one_pc(tmp_path):
    pw = tmp_path / "pw"
    pw.write_text("x")
    f = tmp_path / "host.toml"
    f.write_text(f"password_file = '{pw}'\n")
    assert load_settings(f).lab == LabSettings()


def test_two_pcs_needs_no_local_password(tmp_path):
    f = tmp_path / "host.toml"
    f.write_text('[lab]\nlayout = "two-pcs"\naddress = "10.99.0.2"\nlogin = "lab"\n')
    s = load_settings(f)
    assert s.lab.remote and s.lab.address == "10.99.0.2" and s.lab.port == 22
    f.write_text('[lab]\nlayout = "one-pc"\n')
    with pytest.raises(FileNotFoundError):
        load_settings(f)


@pytest.mark.parametrize("raw", [
    {"layout": "bare-metal"},
    {"layout": "two-pcs", "address": "-oProxyCommand=calc", "login": "lab"},   # would be an ssh option
    {"layout": "two-pcs", "address": "10.99.0.2 evil", "login": "lab"},
    {"layout": "two-pcs", "address": "10.99.0.2", "login": "-l"},
    {"layout": "two-pcs", "address": "10.99.0.2", "login": 'a"b'},
    {"layout": "two-pcs", "address": "10.99.0.2", "login": "lab", "port": 0},
    {"layout": "two-pcs", "address": "10.99.0.2", "login": "lab", "port": True},
    {"layout": "two-vms", "address": "", "login": "lab"},
    {"layout": "one-pc", "proxy": "x"},
])
def test_bad_lab_settings_refused(raw):
    with pytest.raises(ValueError):
        check_lab(raw)


# ---- the command line -------------------------------------------------------------------------------------
def decode_remote(argv):
    assert argv[argv.index("--") + 1] == "10.99.0.2"
    assert argv[-2] == labmod.GATE
    return json.loads(base64.urlsafe_b64decode(argv[-1]))


def test_local_is_unchanged():
    s = HostSettings(vboxmanage="VBM")
    assert labmod.vbm_argv(s, ["showvminfo", "x"]) == ["VBM", "showvminfo", "x"]


def test_remote_sends_one_token_and_never_the_password(tmp_path):
    s = HostSettings(password_file=str(tmp_path / "secret.pw"), lab=REMOTE, home=tmp_path)
    argv = VBox(s).argv(["list", "--json"], 60)
    assert str(tmp_path / "secret.pw") not in " ".join(argv)
    args = decode_remote(argv)
    assert args[args.index("--passwordfile") + 1] == "@lab"
    assert "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv
    assert argv[argv.index("-i") + 1] == str(tmp_path / "lab_key")
    assert all(" " not in a for a in argv[-2:])           # nothing for a shell to split


def every_remote_command(tmp_path):
    """Each VirtualBox command the host sends, as the test PC receives it."""
    s = HostSettings(lab=REMOTE, home=tmp_path)
    sent = []

    class R:
        returncode, stdout, stderr = 0, b'VMState="poweroff"\ncableconnected1="off"\n', b""

    def run(argv, **kw):
        sent.append(decode_remote(argv))
        return R()

    vm = VmControl(s, run=run, sleep=lambda x: None)
    vm.info(); vm.snapshots(); vm.state(); vm.cable()
    vm._vbm("startvm", s.vm, "--type", "headless")
    vm._vbm("modifyvm", s.vm, "--cableconnected1", "off")
    for a in (("controlvm", s.vm, "setlinkstate1", "on"), ("controlvm", s.vm, "acpipowerbutton"),
              ("controlvm", s.vm, "poweroff"), ("discardstate", s.vm),
              ("snapshot", s.vm, "take", "clean-1", "--description", "taken from fatbox host GUI"),
              ("snapshot", s.vm, "delete", "0f0e0d0c-0b0a-0908-0706-050403020100"),
              ("snapshot", s.vm, "restore", "0F0E0D0C-0B0A-0908-0706-050403020100")):
        vm._vbm(*a)
    for args, kw in ((["list", "--json"], {}), (["update"], {"env": {"GCM_INTERACTIVE": "Never"}, "profile": True})):
        sent.append(decode_remote(VBox(s).argv(args, 600, **kw)))
    return sent


def test_gate_allows_everything_fatbox_sends(tmp_path):
    for args in every_remote_command(tmp_path):
        out = gate.check(args, CFG)
        if args[0] == "guestcontrol":
            assert out[out.index("--passwordfile") + 1] == CFG["password_file"]   # swapped in on the test PC
            assert "@lab" not in out
        else:
            assert out == args


@pytest.mark.parametrize("args", [
    ["guestcontrol", "fatbox-vm", "copyfrom", "--username", "analyst", "C:\\x", "C:\\y"],  # sample out of VM
    ["sharedfolder", "add", "fatbox-vm", "--name", "s", "--hostpath", "C:\\"],
    ["modifyvm", "fatbox-vm", "--clipboard-mode", "bidirectional"],
    ["modifyvm", "fatbox-vm", "--cableconnected1", "on", "--nic1", "bridged"],
    ["extpack", "install", "x"],
    ["showvminfo", "other vm", "--machinereadable"],
    ["controlvm", "fatbox-vm", "clipboard", "mode", "bidirectional"],
    ["snapshot", "fatbox-vm", "take", "bad name!", "--description", "x"],
    ["snapshot", "fatbox-vm", "restore", "clean"],
    ["guestcontrol", "fatbox-vm", "run", "--username", "analyst", "--passwordfile", "@lab",
     "--", "C:\\Windows\\System32\\cmd.exe", "/c", "dir"],
    ["guestcontrol", "fatbox-vm", "run", "--username", "Admin", "--passwordfile", "@lab",
     "--", CFG["guest_python"], "-m", "fatbox", "list"],
    ["guestcontrol", "fatbox-vm", "run", "--username", "analyst", "--passwordfile", "C:\\other.pw",
     "--", CFG["guest_python"], "-m", "fatbox", "list"],
    ["guestcontrol", "fatbox-vm", "run", "--username", "analyst", "--passwordfile", "@lab",
     "--exe", "C:\\evil.exe", "--", CFG["guest_python"], "-m", "fatbox", "list"],
])
def test_gate_refuses_anything_else(args):
    with pytest.raises(gate.Refused):
        gate.check(args, CFG)


@pytest.mark.parametrize("command", [
    "", "cmd.exe /c whoami", "fatbox-gate", "fatbox-gate !!!",
    "fatbox-gate " + base64.urlsafe_b64encode(b'{"a":1}').decode(),
    "fatbox-gate " + base64.urlsafe_b64encode(json.dumps(["showvminfo", 'x"y']).encode()).decode(),
    "fatbox-gate " + base64.urlsafe_b64encode(json.dumps(["showvminfo", "a\nb"]).encode()).decode(),
    "fatbox-gate " + "A" * (17 * 1024),
    "fatbox-gate a b",
])
def test_gate_refuses_unreadable_commands(command):
    with pytest.raises(gate.Refused):
        gate.decode(command)


def test_gate_main_refuses_and_logs(tmp_path, monkeypatch, capsys):
    (tmp_path / "fatbox_gate.toml").write_text("\n".join(f"{k} = '{v}'" for k, v in CFG.items()))
    monkeypatch.setattr(gate, "CONFIG", tmp_path / "fatbox_gate.toml")
    monkeypatch.setattr(gate, "LOG", tmp_path / "gate.log")
    ran = []
    assert gate.main({"SSH_ORIGINAL_COMMAND": "powershell"}, run=lambda *a, **k: ran.append(a)) == 2
    assert not ran and "refused" in capsys.readouterr().err
    ok = "fatbox-gate " + labmod.encode(["showvminfo", "fatbox-vm", "--machinereadable"])
    assert gate.main({"SSH_ORIGINAL_COMMAND": ok}, run=lambda argv, **k: ran.append(argv) or 0) == 0
    assert ran == [["VBoxManage", "showvminfo", "fatbox-vm", "--machinereadable"]]
    assert "REFUSED" in (tmp_path / "gate.log").read_text()


# ---- end to end through a fake ssh and the real gate ------------------------------------------------------
pytestmark_posix = pytest.mark.skipif(sys.platform == "win32", reason="fake tools are POSIX shell wrappers")


def wrapper(path: Path, script: Path):
    path.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def remote_lab(tmp_path, monkeypatch):
    from test_host import lab as _  # noqa: F401  (the guest data the one-PC tests use)
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    wrapper(bin_ / "ssh", FAKES / "fake_ssh.py")
    wrapper(bin_ / "ssh-keygen", FAKES / "fake_ssh_keygen.py")
    monkeypatch.setenv("PATH", f"{bin_}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.delenv("SystemRoot", raising=False)
    return bin_


@pytestmark_posix
def test_two_pcs_end_to_end(lab, remote_lab, tmp_path, monkeypatch):
    from fatbox.host.controller import Controller
    ctl, sha, home = lab
    gdir = tmp_path / "testpc"
    gdir.mkdir()
    shutil.copy(ROOT / "scripts" / "lab" / "fatbox_gate.py", gdir / "fatbox_gate.py")
    cfg = {**CFG, "vboxmanage": ctl.s.vboxmanage, "guest_python": ctl.s.guest_python,
           "password_file": ctl.s.password_file}
    (gdir / "fatbox_gate.toml").write_text("\n".join(f"{k} = '{v}'" for k, v in cfg.items()))
    monkeypatch.setenv("FAKE_GATE_DIR", str(gdir))
    s = ctl.s
    s.lab, s.home = REMOTE, home
    home.mkdir(parents=True, exist_ok=True)
    s.password_file = ""                                   # only the test PC has it

    # before pairing: no key
    assert labmod.run_checks(s)[0][0] == "bad"
    made, pub = labmod.make_key(s)
    assert made and pub.startswith("ssh-ed25519 ")
    # first check pins the test PC's key, then everything is green
    ctl2 = Controller(s)
    res = labmod.run_checks(s, ctl2.version_check)
    assert [r[0] for r in res] == ["ok", "ok", "ok"], res
    assert "pinned now" in res[0][1]
    # the real work goes through ssh + gate: list and report
    assert [r["sha256"] for r in ctl2.list_samples()] == [sha]
    assert ctl2.report(sha)["hashes"]["sha256"] == sha
    assert "ran guestcontrol" in (gdir / "gate.log").read_text()
    # a different test PC answering at that address is blocked
    monkeypatch.setenv("FAKE_HOST_KEY", "ssh-ed25519 AAAAimpostor")
    res = labmod.run_checks(s, ctl2.version_check)
    assert res[-1][0] == "bad" and "Blocked" in res[-1][1]
    monkeypatch.delenv("FAKE_HOST_KEY")
    monkeypatch.setenv("FAKE_SSH_DOWN", "1")
    assert "Can't reach the test PC" in labmod.run_checks(s)[-1][1]


from test_host import lab  # noqa: E402,F401  (fixture)


# ---- 0.37.0 GUI: Settings → Lab layout ---------------------------------------------------------------------
@pytestmark_posix
def test_lab_gui_endpoints(lab, remote_lab, tmp_path):
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer
    from fatbox.host.server import Job, make_handler
    ctl, sha, home = lab
    home.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(ctl, Job(ctl), port, "tok")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base, hdr = f"http://127.0.0.1:{port}", {"Cookie": "fbx=tok", "X-FatBox": "1"}

    def call(path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(base + path, data, method="GET" if body is None else "POST", headers=hdr)
        try:
            return 200, json.loads(urllib.request.urlopen(req).read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        code, v = call("/api/lab")
        assert code == 200 and v["lab"]["layout"] == "one-pc" and not v["checked"]
        assert call("/api/vm")[1]["lab"] == {"layout": "one-pc", "address": "", "problem": None}
        # a hostile or mistyped address never reaches ssh
        code, e = call("/api/lab/save", {"lab": {"layout": "two-pcs", "address": "-oProxyCommand=calc", "login": "lab"}})
        assert code == 400 and ctl.s.lab.layout == "one-pc" and not (home / "lab.json").exists()
        code, v = call("/api/lab/save", {"lab": {"layout": "two-pcs", "address": "10.99.0.2", "login": "lab", "port": 22}})
        assert code == 200 and ctl.s.lab.remote and json.loads((home / "lab.json").read_text())["address"] == "10.99.0.2"
        # no key yet: the check fails and every VM job is blocked, with the reason
        code, v = call("/api/lab/check", {})
        assert v["results"][0]["status"] == "bad"
        code, e = call("/api/fetch", {"mode": "recent", "max": 1})
        assert code == 400 and "Lab check failed" in e["error"]
        assert call("/api/lab")[1]["results"][0]["status"] == "bad"   # (/api/vm itself needs the link)
        # make the key: the page shows the line for lab-setup.ps1
        code, v = call("/api/lab/pair", {})
        assert v["has_key"] and v["public_key"].startswith("ssh-ed25519 ")
        # forget-key needs a confirmation
        assert call("/api/lab/forget-key", {})[0] == 400
        # back to one PC: lab.json says so, the block is lifted until the next check
        call("/api/lab/save", {"lab": {"layout": "one-pc"}})
        assert not ctl.s.lab.remote and ctl.lab_problem() is None
    finally:
        httpd.shutdown()


def test_lab_json_wins_over_host_toml(tmp_path):
    f = tmp_path / "host.toml"
    f.write_text('[lab]\nlayout = "two-pcs"\naddress = "10.0.0.9"\nlogin = "x"\n')
    (tmp_path / "lab.json").write_text(json.dumps({"layout": "two-vms", "address": "10.99.0.2", "login": "lab", "port": 2222}))
    assert load_settings(f).lab == LabSettings("two-vms", "10.99.0.2", "lab", 2222)
    (tmp_path / "lab.json").write_text("{damaged")
    assert load_settings(f).lab.address == "10.0.0.9"        # damaged file: host.toml, never a guess


# ---- 0.38.1: what the guest says never blocks Update VM ------------------------------------------------------
def _one_pc_running(tmp_path):
    import types
    vbm = tmp_path / "VBoxManage"
    vbm.write_text("")
    s = types.SimpleNamespace(lab=LabSettings("one-pc", "", "", 22), vboxmanage=str(vbm), vm="fatbox-vm")

    def run(argv, **kw):
        return types.SimpleNamespace(returncode=0, stdout=b'VMState="running"\n', stderr=b"")
    return s, run


def test_old_vm_version_only_warns(tmp_path, monkeypatch):
    s, run = _one_pc_running(tmp_path)
    monkeypatch.setattr(labmod, "vbm_argv", lambda s, args, **kw: [s.vboxmanage, *args])
    old = {"vm": "0.30.0", "ok": False, "message": "The VM runs FatBox 0.30.0, the host 0.38.1. ... click Update VM."}
    res = labmod.run_checks(s, lambda: old, run=run)
    assert [r[0] for r in res] == ["ok", "warn"] and "Update VM" in res[-1][1]


def test_guest_not_ready_only_warns(tmp_path, monkeypatch):
    from fatbox.host.vbox import GuestError
    s, run = _one_pc_running(tmp_path)
    monkeypatch.setattr(labmod, "vbm_argv", lambda s, args, **kw: [s.vboxmanage, *args])

    def not_ready():
        raise GuestError("Windows in the VM is not ready for FatBox yet.")
    res = labmod.run_checks(s, not_ready, run=run)
    assert [r[0] for r in res] == ["ok", "warn"] and "doesn't block" in res[-1][1]


def test_lab_problem_ignores_warnings():
    from fatbox.host.controller import Controller
    ctl = Controller.__new__(Controller)
    ctl.lab_results = [("ok", "VirtualBox found VM"), ("warn", "The VM runs FatBox 0.30.0 ... click Update VM.")]
    assert ctl.lab_problem() is None   # so /api/update-vm is not blocked
    ctl.lab_results.append(("bad", "Blocked: the test PC's SSH key ..."))
    assert ctl.lab_problem().startswith("Blocked")
