"""Host settings. Lives OUTSIDE the repo (default %APPDATA%\\fatbox-host\\host.toml)."""
from __future__ import annotations

import json
import logging
import os
import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path


def default_home() -> Path:
    base = Path(os.environ.get("APPDATA") or str(Path.home() / ".config"))
    # Setups made before the rename keep working: host.toml points at its guest.pw by absolute path.
    if not (base / "fatbox-host").exists() and (base / "malbox-host").exists():
        return base / "malbox-host"
    return base / "fatbox-host"


EXAMPLE = r'''# FatBox host controller settings. Keep this file OUT of the git repo.
vm = "fatbox-vm"                 # exact VirtualBox VM name
guest_user = "analyst"
password_file = 'C:\Users\YOU\AppData\Roaming\fatbox-host\guest.pw'   # one line: analyst's VM password
guest_python = 'C:\Python313\python.exe' # in the VM run:  where python   (not the WindowsApps alias)
guest_dir = 'C:\fatbox'
vboxmanage = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
sample_time_s = 60                      # triage time limit per sample, 10..300 s
capa_time_s = 120                       # extra time for code analysis (capa) per sample, 30..600 s
port = 8790
clean_snapshot = ""                     # optional: the Snapshots tab's ★ default replaces it

# Where the test VM's VirtualBox runs (T-19). Leave it out for one PC (GUI and test VM on this computer).
# [lab]
# layout = "two-pcs"     # one-pc | two-pcs (test VM on another PC) | two-vms (GUI in a VM, test VM beside it)
# address = "10.99.0.2"  # the computer that runs the test VM's VirtualBox
# login = "lab"          # Windows user there who owns the VM; its key is set up with scripts\lab\lab-setup.ps1
# port = 22
'''


# Keys older host.toml files still have; FatBox no longer uses them, so they are skipped, not refused.
OLD_KEYS = {"fetch_timeout_s"}  # 0.19.2: never read (each step has its own stopwatch in controller.py)


LAB_FILE = "lab.json"   # 0.37.0: Settings → Lab layout writes it; it wins over [lab] in host.toml
LAYOUTS = ("one-pc", "two-pcs", "two-vms")   # two-pcs and two-vms reach VirtualBox over SSH (fatbox/host/lab.py)
# A host name or IP: never starts with "-" (it goes on the ssh command line) and has no spaces or quotes.
ADDRESS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")


@dataclass
class LabSettings:
    layout: str = "one-pc"
    address: str = ""
    login: str = ""
    port: int = 22

    @property
    def remote(self) -> bool:
        return self.layout != "one-pc"


def check_lab(raw: object) -> LabSettings:
    """[lab] from host.toml (or the GUI): every value checked, since address and login end up on a command line."""
    if not isinstance(raw, dict):
        raise ValueError("[lab] must be a table")
    unknown = set(raw) - {"layout", "address", "login", "port"}
    if unknown:
        raise ValueError(f"unknown keys in [lab]: {sorted(unknown)}")
    lab = LabSettings(**raw)
    if lab.layout not in LAYOUTS:
        raise ValueError(f"[lab] layout must be one of {', '.join(LAYOUTS)} (now {lab.layout!r})")
    if not isinstance(lab.port, int) or isinstance(lab.port, bool) or not 1 <= lab.port <= 65535:
        raise ValueError(f"[lab] port must be 1..65535 (now {lab.port!r})")
    if lab.remote:
        if not isinstance(lab.address, str) or not ADDRESS_RE.match(lab.address):
            raise ValueError(f"[lab] address must be the test PC's name or IP, like 10.99.0.2 (now {lab.address!r})")
        if not isinstance(lab.login, str) or not LOGIN_RE.match(lab.login):
            raise ValueError(f"[lab] login must be a Windows user name on the test PC (now {lab.login!r})")
    return lab


@dataclass
class HostSettings:
    vm: str = "fatbox-vm"
    guest_user: str = "analyst"
    password_file: str = ""
    guest_python: str = r"C:\Python313\python.exe"
    guest_dir: str = r"C:\fatbox"
    vboxmanage: str = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    sample_time_s: int = 60
    capa_time_s: int = 120
    port: int = 8790
    clean_snapshot: str = ""
    lab: LabSettings = field(default_factory=LabSettings)
    home: Path = Path(".")


def load_settings(path: str | os.PathLike | None = None) -> HostSettings:
    p = Path(path) if path else default_home() / "host.toml"
    if not p.exists():
        raise FileNotFoundError(f"{p} not found. Create it with:  python -m fatbox.host init")
    with open(p, "rb") as fh:
        raw = tomllib.load(fh)
    names = {f.name for f in fields(HostSettings)} - {"home", "lab"}
    raw = {k: v for k, v in raw.items() if k not in OLD_KEYS}
    lab = check_lab(raw.pop("lab", {}))
    saved = p.parent / LAB_FILE
    if saved.exists():
        try:
            lab = check_lab(json.loads(saved.read_text(encoding="utf-8")))
        except (ValueError, TypeError, OSError) as e:  # damaged: keep host.toml's layout, never a guess
            logging.getLogger("fatbox.host").warning("%s ignored (%s); using host.toml", saved, e)
    unknown = set(raw) - names
    if unknown:
        raise ValueError(f"unknown keys in {p}: {sorted(unknown)}")
    s = HostSettings(**raw, lab=lab, home=p.parent)
    if not isinstance(s.sample_time_s, int) or not 10 <= s.sample_time_s <= 300:
        raise ValueError(f"sample_time_s in {p} must be a whole number 10..300 (now {s.sample_time_s!r})")
    if not isinstance(s.capa_time_s, int) or isinstance(s.capa_time_s, bool) or not 30 <= s.capa_time_s <= 600:
        raise ValueError(f"capa_time_s in {p} must be a whole number 30..600 (now {s.capa_time_s!r})")
    # Two-machine layouts: the guest password stays on the PC that runs the VM (INV-9), the gate there adds it.
    if not s.lab.remote and (not s.password_file or not Path(s.password_file).exists()):
        raise FileNotFoundError(f"password_file not found: {s.password_file!r}")
    return s


def save_lab(home: Path, raw: object) -> LabSettings:
    """Check and save the GUI's lab layout (whole file, written then renamed)."""
    lab = check_lab(raw)
    home.mkdir(parents=True, exist_ok=True)
    tmp = home / (LAB_FILE + ".tmp")
    tmp.write_text(json.dumps({"layout": lab.layout, "address": lab.address, "login": lab.login, "port": lab.port},
                              indent=1), encoding="utf-8")
    os.replace(tmp, home / LAB_FILE)
    return lab


def write_example(path: str | os.PathLike | None = None) -> Path:
    p = Path(path) if path else default_home() / "host.toml"
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        raise FileExistsError(f"{p} already exists, edit it instead")
    p.write_text(EXAMPLE.replace(r"C:\Users\YOU\AppData\Roaming\fatbox-host", str(p.parent)), encoding="utf-8")
    return p
