"""FatBox lab gate: runs on the TEST PC (the computer whose VirtualBox holds the test VM), never on the host.

sshd starts it as a forced command for FatBox's key (see lab-setup.ps1), so that key can do exactly one thing:
run the VirtualBox commands FatBox needs, on the one test VM. Anything else is refused. It never opens a shell:
VBoxManage gets an argument list. Standard library only, Python 3.11+.

The host sends:  fatbox-gate <base64url JSON list of VBoxManage arguments>
(in SSH_ORIGINAL_COMMAND). Settings: fatbox_gate.toml next to this file.

Why each rule: the host is trusted, but its key could be stolen, and the test VM is assumed hacked. VBoxManage
can do things that would hurt the test PC itself (copy a sample out of the VM with `guestcontrol copyfrom`, add a
shared folder, switch the clipboard on, install an extension pack...). None of those get through.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = HERE / "fatbox_gate.toml"
LOG = HERE / "gate.log"
GATE = "fatbox-gate"
REMOTE_PASSWORD = "@lab"
MAX_TOKEN = 16 * 1024
MAX_ARGS = 80
MAX_ARG = 512
SNAP_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,40}=")
BAD_CHARS = re.compile(r'["\x00-\x1f\x7f]')
ON_OFF = {"on", "off"}


class Refused(Exception):
    pass


def load_config(path: Path | None = None) -> dict:
    path = path or CONFIG
    with open(path, "rb") as fh:
        cfg = tomllib.load(fh)
    for k in ("vm", "vboxmanage", "guest_user", "guest_python", "password_file"):
        if not isinstance(cfg.get(k), str) or not cfg[k]:
            raise Refused(f"{path.name}: {k} is missing")
    return cfg


def decode(command: str) -> list[str]:
    parts = command.split(" ")
    if len(parts) != 2 or parts[0] != GATE:
        raise Refused("not a FatBox command")
    token = parts[1]
    if not 0 < len(token) <= MAX_TOKEN:
        raise Refused("command too long")
    try:
        args = json.loads(base64.urlsafe_b64decode(token.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeError):
        raise Refused("command is not readable") from None
    if not isinstance(args, list) or not 2 <= len(args) <= MAX_ARGS:
        raise Refused("bad argument list")
    for a in args:
        if not isinstance(a, str) or not 0 < len(a) <= MAX_ARG or BAD_CHARS.search(a):
            raise Refused("bad argument")
    return args


def _exact(rest: list[str], *allowed: list[str]) -> None:
    if rest not in allowed:
        raise Refused("arguments not allowed")


def check(args: list[str], cfg: dict) -> list[str]:
    """The VBoxManage argument list to run, or Refused. Only what fatbox/host/vmctl.py and vbox.py send."""
    sub, vm, rest = args[0], args[1], args[2:]
    if vm != cfg["vm"]:
        raise Refused("only the configured test VM")
    if sub == "showvminfo":
        _exact(rest, ["--machinereadable"])
    elif sub == "startvm":
        _exact(rest, ["--type", "headless"], ["--type", "gui"])
    elif sub == "discardstate":
        _exact(rest, [])
    elif sub == "modifyvm":
        _exact(rest, ["--cableconnected1", "on"], ["--cableconnected1", "off"])
    elif sub == "controlvm":
        if rest not in (["acpipowerbutton"], ["poweroff"]) and not (
                len(rest) == 2 and rest[0] == "setlinkstate1" and rest[1] in ON_OFF):
            raise Refused("controlvm action not allowed")
    elif sub == "snapshot":
        if rest == ["list", "--machinereadable"]:
            pass
        elif rest[:1] == ["take"] and len(rest) == 4 and SNAP_RE.match(rest[1]) and rest[2] == "--description":
            pass
        elif len(rest) == 2 and rest[0] in ("delete", "restore") and UUID_RE.match(rest[1]):
            pass
        else:
            raise Refused("snapshot action not allowed")
    elif sub == "guestcontrol":
        return [sub, vm, *_guest_run(rest, cfg)]
    else:
        raise Refused(f"VBoxManage {sub!r} is not a FatBox command")
    return args


def _guest_run(rest: list[str], cfg: dict) -> list[str]:
    """guestcontrol <vm> run: only `guest_python -m fatbox ...` as the configured guest user."""
    if rest[:1] != ["run"] or "--" not in rest:
        raise Refused("only guestcontrol run")
    cut = rest.index("--")
    opts, program = rest[1:cut], rest[cut + 1:]
    out: list[str] = ["run"]
    user = password = False
    i = 0
    while i < len(opts):
        o = opts[i]
        if o in ("--wait-stdout", "--wait-stderr", "--profile"):
            out.append(o)
            i += 1
            continue
        if i + 1 >= len(opts):
            raise Refused("option without a value")
        v = opts[i + 1]
        if o == "--username" and v == cfg["guest_user"]:
            user = True
        elif o == "--passwordfile" and v == REMOTE_PASSWORD:
            password = True
            v = cfg["password_file"]           # the password lives here, never on the wire
        elif o == "--putenv" and ENV_RE.match(v):
            pass
        elif o == "--timeout" and v.isdigit() and int(v) <= 6 * 3600 * 1000:
            pass
        else:
            raise Refused(f"guestcontrol option {o!r} not allowed")
        out += [o, v]
        i += 2
    if not (user and password):
        raise Refused("guestcontrol needs the configured user and @lab password")
    if program[:3] != [cfg["guest_python"], "-m", "fatbox"]:
        raise Refused("only 'python -m fatbox' runs in the VM")
    return [*out, "--", *program]


def log(line: str) -> None:
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line + "\n")
    except OSError:
        pass


def main(environ=os.environ, run=subprocess.call) -> int:
    command = environ.get("SSH_ORIGINAL_COMMAND", "")
    try:
        cfg = load_config()
        args = check(decode(command), cfg)
    except (Refused, OSError, tomllib.TOMLDecodeError) as e:
        log(f"REFUSED {e} from {environ.get('SSH_CLIENT', '?').split(' ')[0]}")
        print(f"fatbox-gate: refused: {e}", file=sys.stderr)
        return 2
    shown = [a if a != cfg["password_file"] else "<password file>" for a in args]
    log("ran " + " ".join(shown[:4]) + (" ..." if len(shown) > 4 else ""))
    sys.stdout.flush()
    return run([cfg["vboxmanage"], *args], stdin=subprocess.DEVNULL)


if __name__ == "__main__":
    sys.exit(main())
