"""Stand-in for VBoxManage in tests: runs the "guest" fatbox locally instead of in a VM."""
import os
import subprocess
import sys
from pathlib import Path

import json

argv = sys.argv[1:]
STATE = os.environ.get("FAKE_VM_FILE")
vm = json.load(open(STATE)) if STATE else {"state": "running", "cable": "on", "snaps": [], "current": None}


def save(**kw):
    if "state" in kw and kw["state"] != vm.get("state"):  # like VirtualBox's VMStateChangeTime
        vm["since"] = vm.get("since", 0) + 1
    vm.update(kw)
    if STATE:
        json.dump(vm, open(STATE, "w"))
        with open(STATE + ".log", "a") as fh:
            fh.write(" ".join(argv) + "\n")


if argv[:1] == ["showvminfo"]:
    print(f'name="fatbox-vm"\nVMState="{vm["state"]}"\nnic1="nat"\ncableconnected1="{vm["cable"]}"\n'
          f'VMStateChangeTime="2026-11-22T10:00:{vm.get("since", 0):02d}.000000000"\nmemory=8192\ncpus=4')
    if "runlevel" in vm:  # 0.31.0: Guest Additions run level (only some tests set it)
        print(f'GuestAdditionsRunLevel={vm["runlevel"]}')
    sys.exit(0)
if argv[:1] == ["startvm"]:
    if vm["state"] == "running":
        sys.exit("VBoxManage: error: already running")
    # FAKE_NEM: VirtualBox on Hyper-V can't resume saved memory (the 0.18.0 live test, VirtualBox 7.2)
    if vm["state"] in ("saved", "abortedsaved") and os.environ.get("FAKE_NEM"):
        save(state="abortedsaved")
        sys.exit("VBoxManage: error: The VM session was closed before any attempt to power it on")
    # FAKE_START_CABLE_ON: a saved (suspended) VM comes back with the cable it was suspended with
    save(state="running", **({"cable": "on"} if os.environ.get("FAKE_START_CABLE_ON") else {}))
    sys.exit(0)
if argv[:1] == ["controlvm"]:
    # like VirtualBox: a hung VM (stuck, paused, guru meditation, stopping, starting) still takes a hard poweroff
    hung_ok = argv[2] == "poweroff" and vm["state"] in ("stuck", "paused", "gurumeditation", "stopping", "starting")
    if vm["state"] != "running" and not hung_ok:
        sys.exit("VBoxManage: error: Machine is not running")
    if argv[2] == "acpipowerbutton" and os.environ.get("FAKE_ACPI_IGNORED"):
        save()  # Windows ignores the power button (a dialog is open, an update is installing)
    elif argv[2] in ("poweroff", "acpipowerbutton"):
        save(state="poweroff")
    elif argv[2] == "setlinkstate1":
        if argv[3] == "off" and os.environ.get("FAKE_CABLE_STUCK"):  # VirtualBox busy: the call "works", cable stays in
            save()
        else:
            save(cable=argv[3])
    sys.exit(0)
if argv[:1] == ["discardstate"]:
    if vm["state"] not in ("saved", "abortedsaved"):
        sys.exit("VBoxManage: error: Machine does not have a saved state")
    save(state="poweroff")
    sys.exit(0)
if argv[:1] == ["modifyvm"]:
    if vm["state"] in ("running", "saved", "abortedsaved"):
        sys.exit(f"VBoxManage: error: machine is locked ({vm['state']})")
    save(cable=argv[argv.index("--cableconnected1") + 1])
    sys.exit(0)
if argv[:1] == ["snapshot"]:
    import hashlib
    import uuid as uuidlib
    op = argv[2]
    uuids, live = vm.setdefault("uuids", {}), vm.setdefault("live", {})

    def uid(n):  # snapshots a test wrote by name only get a stable uuid
        return uuids.get(n) or str(uuidlib.UUID(hashlib.md5(n.encode()).hexdigest()))

    def find(ref):
        return next((n for n in vm["snaps"] if ref in (n, uid(n))), None)
    if op == "list":
        if not vm["snaps"]:
            sys.exit("This machine does not have any snapshots")
        for i, n in enumerate(vm["snaps"]):
            suffix = "" if i == 0 else "-1" * i
            print(f'SnapshotName{suffix}="{n}"\nSnapshotUUID{suffix}="{uid(n)}"')
        cur = find(vm["current"] or "")
        print(f'CurrentSnapshotName="{vm["current"]}"' + (f'\nCurrentSnapshotUUID="{uid(cur)}"' if cur else ""))
    elif op == "take":
        uuids[argv[3]] = str(uuidlib.uuid4())
        live[argv[3]] = vm["state"] == "running"   # a running VM's snapshot holds its memory
        save(snaps=vm["snaps"] + [argv[3]], current=argv[3])
    elif op == "restore":
        if vm["state"] == "running":
            sys.exit("VBoxManage: error: Cannot restore while running")
        n = find(argv[3])
        if n is None:
            sys.exit("VBoxManage: error: Could not find a snapshot")
        save(current=n, state="saved" if live.get(n) else "poweroff")
    elif op == "delete":
        n = find(argv[3])
        if n is None:
            sys.exit("VBoxManage: error: Could not find a snapshot")
        save(snaps=[x for x in vm["snaps"] if x != n], current=None if vm["current"] == n else vm["current"])
    sys.exit(0)
if argv[:1] == ["guestcontrol"] and argv[2] == "copyto":  # 0.42.0 Update VM: the host's code, host -> VM only
    import shutil
    assert "--passwordfile" in argv and "--password" not in argv
    target = argv[argv.index("--target-directory") + 1]
    if not target.endswith(("/", "\\")):  # 0.42.1 live: VirtualBox 7 takes it as a file name and fails
        sys.exit("VBoxManage: error: File copy failed\nVBoxManage: error: Guest file \"" + target + "\" already exists")
    fail = os.environ.get("FAKE_COPY_FAIL")
    if fail == "all" or (fail == "first" and target.rstrip("/") == os.environ.get("FAKE_GUEST_DIR", "")):
        sys.exit("VBoxManage: error: File copy failed\nVBoxManage: error: Access denied (VERR_ACCESS_DENIED)\x1b[2J")
    shutil.copy(argv[-1], target)
    save()
    if STATE:
        with open(STATE + ".guest", "a") as fh:
            fh.write(f"copyto cable={vm['cable']}\n")
    sys.exit(0)
assert argv[0] == "guestcontrol" and argv[2] == "run", argv
assert "--passwordfile" in argv and "--password" not in argv  # never a password on the command line
guest = argv[argv.index("--") + 1:]
assert "--exe" not in argv  # argv[0] after -- is the executable (see vbox.py)
assert guest[0].endswith("python.exe"), guest
if guest[1] == "-c":  # 0.42.0: the code-push program, run for real (plain stdlib, like in the VM)
    assert "\n" not in guest[2] and '"' not in guest[2]   # one line, survives Windows command-line quoting
    save()
    if STATE:
        with open(STATE + ".guest", "a") as fh:
            fh.write(f"push cable={vm['cable']}\n")
    sys.exit(subprocess.run([sys.executable, "-c", guest[2], *guest[3:]]).returncode)
assert guest[1:4] == ["-m", "fatbox", "-c"], guest
rest = guest[5:]
mode = os.environ.get("FAKE_GUEST", "real")
save()
if STATE:  # what the guest ran and whether it had network at that moment (tests check the order)
    with open(STATE + ".guest", "a") as fh:
        fh.write(f"{rest[0] if rest else '?'} cable={vm['cable']}\n")
if mode == "booting":
    sys.exit("VBoxManage.exe: error: Waiting for guest process failed: The guest execution service is not ready (yet)")
if mode == "starting":  # 0.39.1 live: VM "running", guest control not up yet, for the first N guest calls
    n_file = (STATE or os.environ["FAKE_VM_FILE"]) + ".starting"
    n = int(open(n_file).read()) if os.path.exists(n_file) else 0
    open(n_file, "w").write(str(n + 1))
    if n < int(os.environ.get("FAKE_GUEST_STARTING", "0")):
        sys.exit("VBoxManage.exe: error: Error starting guest session (current status is: starting)")
if mode == "noadditions":  # the exact text VirtualBox 7 printed in the live test while Windows was still booting
    sys.exit("VBoxManage.exe: error: Guest Additions are not installed or not ready (yet)\n"
             "VBoxManage.exe: error: Details: code VBOX_E_GSTCTL_GUEST_ERROR (0x80bb000f), component GuestWrap, "
             "interface IGuest, callee IUnknown\nVBoxManage.exe: error: Context: \"CreateSession(Bstr(pCtx->strUsername)"
             ".raw(), ...)\" at line 751 of file VBoxManageGuestCtrl.cpp")
if mode in ("oldvm", "newvm") and rest[:1] == ["--version"]:  # a VM that missed (or ran ahead of) an update
    print("FatBox 0.0.1" if mode == "oldvm" else "FatBox 999.0.0", flush=True)
    sys.exit(0)
if mode == "flood":
    sys.stdout.write("x" * 10_000_000)
    sys.exit(0)
if mode == "hostile":  # a compromised guest writing terminal escapes and a bidi-spoofed name
    print("FatBox 6.6.6\x1b]0;pwned\x07\x1b[2J", flush=True)
    print("saved invoice\u202egpj.exe\x1b[8m hidden", file=sys.stderr, flush=True)
    sys.exit(0)
if rest[:1] == ["update"]:
    assert "GCM_INTERACTIVE=Never" in argv and "--profile" in argv, argv  # never a hidden login window
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from fatbox.cli import build_parser
    build_parser().parse_args(rest)   # 0.42.0 --no-fetch must exist in the real guest CLI
    if mode == "notoken":
        sys.exit("update failed: git fetch --quiet origin main failed:\nfatal: could not read Username: "
                 "terminal prompts disabled\nGitHub rejected the credentials (private repo).")
    print("already up to date (e9830dc1)", flush=True)
    sys.exit(0)
if rest[:1] == ["shutdown"]:  # 0.18.2: Windows shuts itself down (FAKE_GUEST_SHUTDOWN_IGNORED: it doesn't)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from fatbox.cli import build_parser
    assert build_parser().parse_args(rest).yes
    if not os.environ.get("FAKE_GUEST_SHUTDOWN_IGNORED"):
        save(state="poweroff")
    print("Windows is shutting down", flush=True)
    sys.exit(0)
if rest[:1] == ["browse"]:  # T-13: metadata list; one hostile row, one broken row
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from fatbox.cli import build_parser
    build_parser().parse_args(rest)
    print(json.dumps({"rows": [
        {"sha256": "a" * 64, "file_type": "exe", "file_size": 120000, "signature": "LockBit",
         "tags": ["lockbit", "exe", "ransomware"], "first_seen": "2026-11-08 20:00:00", "in_vm": False},
        {"sha256": "b" * 64, "file_type": "dll", "file_size": 9 * 1024 * 1024, "signature": "Evil\u202egpj.exe",
         "tags": ["x\x1b[2J"], "first_seen": "2026-11-08 19:00:00", "in_vm": False},
        {"sha256": "not-a-sha", "file_type": "exe"},
        {"sha256": "c" * 64, "file_size": "huge"},
    ]}), flush=True)
    sys.exit(0)
if rest[:1] == ["fetch"]:
    if mode == "slow":
        import time
        time.sleep(30)
    if mode == "fetchfail":
        sys.exit("bazaar: fetch failed: ConnectionError: Max retries exceeded")
    # Whatever the host sends must be accepted by the REAL guest CLI (host and VM flags stay in step).
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from fatbox.cli import build_parser
    build_parser().parse_args(rest)
    print("limits: 3 samples, download limit 5 MB, unpacked cap 100 MB, time budget 400 s", flush=True)
    print("bazaar: 1 new sample(s)", flush=True)
    print("INFO progress 50%\rINFO progress 100%", file=sys.stderr, flush=True)
    print("total: 1", flush=True)
    print("summary: 1 stored, 0 too big, 0 wrong type, 0 failed, 0 cut off, 0 skipped (budget), 12 s used", flush=True)
    sys.exit(0)
# real guest code, from a different cwd: relative config paths must follow the config file
repo = Path(__file__).resolve().parents[2]
env = {**os.environ, "PYTHONPATH": str(repo)}
p = subprocess.run([sys.executable, "-m", "fatbox", "-c", os.environ["FAKE_GUEST_CFG"], *rest],
                   cwd=os.environ.get("FAKE_GUEST_CWD", "/"), env=env)
sys.exit(p.returncode)
