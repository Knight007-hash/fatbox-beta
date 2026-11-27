"""0.42.0 Update VM without GitHub: the host copies its own checked-out code into the VM.

The VM never logs in to GitHub, so a private repo needs no token in the VM and a client never configures
anything there. Direction is host -> VM only (guest control `copyto`), the same channel FatBox already uses;
nothing comes back this way. The host packs its current commit as a git bundle; a short Python program run in
the guest (with whatever FatBox version it has, even a very old one) moves the VM's checkout to exactly that
commit. config.toml and data/ are untracked and never touched.
"""
from __future__ import annotations

import base64
import secrets
import shutil
import subprocess
from pathlib import Path

from fatbox.host.vbox import NO_WINDOW

HOST_REPO = Path(__file__).resolve().parents[2]

# Runs in the guest as `python -c <loader> <repo> <bundle>`. Plain stdlib, works on any FatBox the VM has.
# The VM must run exactly the host's code: edits to tracked files in the VM folder are replaced (config.toml and
# data/ are untracked and stay). The bundle is deleted whatever happens.
GUEST_CODE = r'''
import os, shutil, subprocess, sys
repo, bundle = sys.argv[1], sys.argv[2]
git = shutil.which("git") or r"C:\Program Files\Git\cmd\git.exe"
env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
def g(*a):
    p = subprocess.run([git, "-C", repo, *a], capture_output=True, text=True, env=env)
    if p.returncode:
        sys.exit("git " + a[0] + " failed: " + (p.stderr or p.stdout).strip()[-1500:])
    return p.stdout.strip()
try:
    if not os.path.isdir(os.path.join(repo, ".git")):
        sys.exit(repo + " is not a FatBox git folder; set the VM up again with the setup script")
    old = g("rev-parse", "HEAD")
    if g("status", "--porcelain", "--untracked-files=no"):
        print("NOTE: edits to FatBox files inside the VM are replaced by the host's code")
    g("fetch", "--quiet", bundle, "HEAD")
    new = g("rev-parse", "FETCH_HEAD")
    if old == new and not g("status", "--porcelain", "--untracked-files=no"):
        print("the VM already has this PC's code (" + old[:8] + ")")
    else:
        g("reset", "--quiet", "--hard", new)
        print("code " + old[:8] + " -> " + new[:8] + " (copied from this PC; GitHub not used)")
finally:
    try:
        os.remove(bundle)
    except OSError:
        pass
'''


def guest_loader() -> str:
    """One line, no quotes or newlines to survive VirtualBox's command-line quoting in the guest."""
    return "import base64;exec(base64.b64decode('%s'))" % base64.b64encode(GUEST_CODE.encode()).decode()


def _git(*args: str, repo: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=300,
                          creationflags=NO_WINDOW)


def make_bundle(out_dir: Path, repo: Path | None = None) -> tuple[Path | None, str]:
    """Pack the host's current commit. Returns (bundle path, note); (None, why) when the host can't (not a git
    checkout, no git): the caller then falls back to the VM's own `fatbox update`."""
    repo = repo or HOST_REPO
    if not (repo / ".git").exists() or not shutil.which("git"):
        return None, "this PC's FatBox is not a git folder (or git is missing)"
    note = ""
    if _git("status", "--porcelain", "--untracked-files=no", repo=repo).stdout.strip():
        note = "this PC has uncommitted edits: the VM gets the last commit"
    path = out_dir / f"fatbox-update-{secrets.token_hex(4)}.bundle"
    r = _git("bundle", "create", "--quiet", str(path), "HEAD", repo=repo)
    if r.returncode != 0 or not path.exists():
        return None, "git bundle failed: " + (r.stderr or r.stdout).strip()[-300:]
    return path, note


def guest_path(guest_dir: str, name: str) -> str:
    sep = "/" if guest_dir.startswith("/") else "\\"   # "/" only in tests (the fake VM runs on Linux)
    return guest_dir.rstrip("\\/") + sep + name
