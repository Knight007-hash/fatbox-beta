"""Where the test VM's VirtualBox runs (T-19): on this computer, or on another one reached over SSH.

Every VirtualBox command FatBox sends is built here, by `vbm_argv`. Everything above it (allow-lists, size caps,
validate.py, auto-revert) is the same for every layout.

Two-machine layouts: the argument list travels as ONE base64 token to `fatbox_gate.py` on the test PC, which sshd
runs as a forced command (scripts/lab/). So no shell on either side ever parses our arguments, and a stolen key
can't open a shell there. The test PC's host key is pinned in <host home>/lab_known_hosts on the first check and
checked on every call after that. The guest password never travels: the host sends REMOTE_PASSWORD and the gate
puts in the file that lives on the test PC (INV-9).
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

from fatbox.host.settings import HostSettings

GATE = "fatbox-gate"
REMOTE_PASSWORD = "@lab"        # the gate swaps this for its own password file
MAX_TOKEN = 16 * 1024           # the gate refuses longer commands too
KEY_NAME = "lab_key"
KNOWN_HOSTS = "lab_known_hosts"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def openssh(tool: str) -> str:
    """Windows' built-in OpenSSH client (System32\\OpenSSH), else whatever is on PATH."""
    root = os.environ.get("SystemRoot")
    if root:
        p = Path(root) / "System32" / "OpenSSH" / f"{tool}.exe"
        if p.exists():
            return str(p)
    return shutil.which(tool) or tool


def key_path(s: HostSettings) -> Path:
    return s.home / KEY_NAME


def known_hosts(s: HostSettings) -> Path:
    return s.home / KNOWN_HOSTS


def encode(args: list[str]) -> str:
    token = base64.urlsafe_b64encode(json.dumps(args, separators=(",", ":")).encode()).decode()
    if len(token) > MAX_TOKEN:
        raise ValueError("VirtualBox command too long for the lab link")
    return token


def ssh_argv(s: HostSettings, pin_new: bool = False) -> list[str]:
    """ssh up to (not including) the remote command. pin_new: accept and pin the host key if none is pinned yet."""
    lab = s.lab
    return [
        openssh("ssh"), "-T",
        "-F", os.devnull,                              # ignore any ssh config on this PC
        "-o", "BatchMode=yes",                         # never ask for a password
        "-o", "IdentitiesOnly=yes", "-i", str(key_path(s)),
        "-o", f"UserKnownHostsFile={known_hosts(s)}", "-o", f"GlobalKnownHostsFile={os.devnull}",
        "-o", f"StrictHostKeyChecking={'accept-new' if pin_new else 'yes'}",
        "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
        "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
        "-p", str(lab.port), "-l", lab.login, "--", lab.address,
    ]


def vbm_argv(s: HostSettings, args: list[str] | tuple[str, ...], pin_new: bool = False) -> list[str]:
    """The command line that runs `VBoxManage <args>` where the test VM lives."""
    if not s.lab.remote:
        return [s.vboxmanage, *args]
    return [*ssh_argv(s, pin_new), GATE, encode(list(args))]


def password_arg(s: HostSettings) -> str:
    return REMOTE_PASSWORD if s.lab.remote else s.password_file


def is_pinned(s: HostSettings) -> bool:
    p = known_hosts(s)
    return p.exists() and p.stat().st_size > 0


def make_key(s: HostSettings, run=subprocess.run) -> tuple[bool, str]:
    """Make this host's lab key once. Returns (made now, public key line)."""
    k = key_path(s)
    made = False
    if not k.exists():
        k.parent.mkdir(parents=True, exist_ok=True)
        r = run([openssh("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C", "fatbox-host", "-f", str(k)],
                capture_output=True, timeout=60, creationflags=NO_WINDOW)
        if r.returncode != 0:
            raise RuntimeError("ssh-keygen failed: " + r.stderr.decode(errors="replace").strip()[-300:])
        made = True
    return made, Path(str(k) + ".pub").read_text(encoding="ascii").strip()


def pinned_fingerprint(s: HostSettings, run=subprocess.run) -> str | None:
    if not is_pinned(s):
        return None
    r = run([openssh("ssh-keygen"), "-l", "-f", str(known_hosts(s))], capture_output=True, timeout=30,
            creationflags=NO_WINDOW)
    out = r.stdout.decode(errors="replace").split()
    return out[1] if r.returncode == 0 and len(out) > 1 else None


def run_checks(s: HostSettings, version_check=None, run=subprocess.run) -> list[tuple[str, str]]:
    """Test connection: [(ok|warn|bad, plain words)]. The first check run also pins the test PC's SSH key.

    version_check: the controller's, called only when the VM runs. Nothing here comes from the guest except
    through it (validated there); the VM state comes from VirtualBox.
    """
    from fatbox.host.vbox import explain, short   # vbox imports this module
    import re

    out: list[tuple[str, str]] = []
    if s.lab.remote:
        if not key_path(s).exists():
            return [("bad", "No lab key on this PC yet: run 'python -m fatbox.host lab pair' and set up the test PC.")]
        first = not is_pinned(s)
        argv = vbm_argv(s, ["showvminfo", s.vm, "--machinereadable"], pin_new=first)
    else:
        if not Path(s.vboxmanage).exists():
            return [("bad", f"VBoxManage not found at {s.vboxmanage}: install VirtualBox or fix vboxmanage in host.toml.")]
        first = False
        argv = vbm_argv(s, ["showvminfo", s.vm, "--machinereadable"])
    try:
        r = run(argv, capture_output=True, timeout=40, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return out + [("bad", "No answer in 40 s from VirtualBox" + (" on the test PC." if s.lab.remote else "."))]
    except OSError as e:
        return out + [("bad", f"Could not start {'ssh' if s.lab.remote else 'VBoxManage'}: {e}")]
    err = r.stderr.decode(errors="replace")
    if s.lab.remote:
        fp = pinned_fingerprint(s, run)
        if r.returncode == 255 or not fp:
            return out + [("bad", explain(err) or f"Can't reach the test PC: {short(err)}")]
        out.append(("ok", f"Test PC {s.lab.address} answers with key {fp}"
                          + (" (pinned now: compare it with what lab-setup.ps1 printed)" if first else " (pinned)")))
    if r.returncode != 0:
        return out + [("bad", explain(err) or f"VirtualBox: {short(err)}")]
    m = re.search(rb'^VMState="([a-z]+)"', r.stdout, re.M)
    state = m.group(1).decode() if m else "unknown"
    out.append(("ok", f"VirtualBox found VM '{s.vm}' ({state})"))
    if state != "running":
        out.append(("warn", "The VM is not running: start it to compare FatBox versions."))
    elif version_check is not None:
        # 0.38.1: what the GUEST says is only ever a warning here. The lab check is about the wiring (VirtualBox,
        # the test PC, its key); a failed one blocks Update VM too. Windows still booting, or an old FatBox in the
        # VM, must not: Update VM is the fix for the second, and every step waits for Windows anyway. Fetch and
        # Triage still refuse a version mismatch on their own (Controller._ready, T-3).
        try:
            v = version_check()
        except Exception as e:  # GuestError, Invalid: the VM's answer is not trusted, only reported
            out.append(("warn", f"FatBox in the VM did not answer yet: {e} This doesn't block anything; "
                                "FatBox asks again before each step."))
        else:
            out.append(("ok", f"FatBox {v['vm']} in the VM, same as this PC") if v["ok"] else ("warn", v["message"]))
    return out
