"""Self-update: fast-forward the git checkout, then make the libraries match the pinned list.

config.toml and data/ are git-ignored, so a pull never touches them.
"""
from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parents[1]
# FatBox's own copy of the read-only GitHub token. Windows Credential Manager hides saved logins from
# sessions the host starts through VBoxManage guestcontrol, so the host's Update VM button can't use it.
TOKEN_FILE = Path.home() / ".fatbox" / "github-token"
TOKEN_RE = re.compile(r"^[A-Za-z0-9_]{20,255}$")  # GitHub token alphabet; also keeps it a safe header value


class UpdateError(Exception):
    pass


AUTH_HINTS = ("authentication failed", "could not read username", "terminal prompts disabled",
              "403", "repository not found", "invalid username or password")


def save_token(token: str, path: Path | None = None) -> Path:
    path = path or TOKEN_FILE
    token = token.strip()
    if not TOKEN_RE.match(token):
        raise UpdateError("that doesn't look like a GitHub token (letters, digits and _ only)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n", encoding="utf-8")
    return path


def _token_args(path: Path | None = None) -> list[str]:
    """`git -c` options that send the token from TOKEN_FILE and skip the credential helper. Passed as -c, not
    through GIT_CONFIG_* variables, which the VM's Git for Windows did not apply. No file: nothing changes and
    Credential Manager is used as before."""
    try:
        token = (path or TOKEN_FILE).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return []
    if not TOKEN_RE.match(token):
        raise UpdateError(f"{path or TOKEN_FILE} is not a valid token; set it again: python -m fatbox set-token")
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return ["-c", "credential.helper=", "-c", f"http.https://github.com/.extraheader=Authorization: Basic {basic}"]


def token_from_credential_manager() -> str | None:
    """The token Git Credential Manager saved in this (interactive) session, if any. Never opens a window."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never"}
    try:
        r = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n\n",
                           capture_output=True, text=True, timeout=30, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in r.stdout.splitlines():
        if line.startswith("password=") and TOKEN_RE.match(line[9:].strip()):
            return line[9:].strip()
    return None


FETCH_TIMEOUT_S = 1800  # 0.18.0 adds ~15 MB (capa rules + signatures): minutes on the VM's slow link


def _git(*args: str, cwd: Path, timeout: int = 300) -> str:
    # No terminal prompts: a missing/expired token must fail loudly, not hang. GCM's window still works.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        r = subprocess.run(["git", *_token_args(), *args], cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise UpdateError(f"git {' '.join(args)} timed out after {timeout}s (slow or blocked network?)")
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip()
        if any(h in msg.lower() for h in AUTH_HINTS):
            msg += ("\nGitHub refused (private repo, no access from this VM). Nothing to set up in the VM: "
                    "click Update VM in the host's GUI, which copies the host's code in (0.42.0).")
        raise UpdateError(f"git {' '.join(args)} failed:\n{msg}")
    return r.stdout.strip()


def update(repo: Path = REPO_DIR, python: str = sys.executable, install: bool = True, fetch: bool = True) -> int:
    """fetch=False (0.42.0, `update --no-fetch`): the host already put its own code in (host.codepush); only
    trim the folder and check the libraries. Never contacts GitHub, so no token is ever needed."""
    if not shutil.which("git"):
        raise UpdateError("git not found. Install Git for Windows: winget install --id Git.Git -e")
    if not (repo / ".git").exists():
        raise UpdateError(f"{repo} is not a git checkout. Run the one-time install from VM.md first.")

    dirty = _git("status", "--porcelain", "--untracked-files=no", cwd=repo)
    if dirty:
        raise UpdateError("local edits to tracked files would be overwritten:\n" + dirty +
                          "\nKeep them: git stash   |   Drop them: git checkout -- .")

    if not fetch:
        keep_only_vm_files(repo)
        if install:
            install_libraries(repo, python)
        print(f"code from the host: {_git('rev-parse', '--short=8', 'HEAD', cwd=repo)}", flush=True)
        return 0

    branch = _git("rev-parse", "--abbrev-ref", "HEAD", cwd=repo)
    if branch == "HEAD":
        raise UpdateError("detached HEAD; run: git checkout main")
    old = _git("rev-parse", "HEAD", cwd=repo)
    print(f"fetching origin/{branch} ...", flush=True)
    _git("fetch", "--quiet", "origin", branch, cwd=repo, timeout=FETCH_TIMEOUT_S)
    new = _git("rev-parse", f"origin/{branch}", cwd=repo)
    if old == new:
        print(f"already up to date ({old[:8]})")
    else:
        if _git("merge-base", old, new, cwd=repo) != old:
            raise UpdateError("local commits diverge from origin; not touching them. Inspect with: git log --oneline --graph --all")
        _git("merge", "--ff-only", "--quiet", new, cwd=repo)
        print(_git("log", "--oneline", "--no-decorate", f"{old}..{new}", cwd=repo))
        changed = set(_git("diff", "--name-only", old, new, cwd=repo).splitlines())
        if "config.example.toml" in changed:
            print("NOTE: config.example.toml changed. New options have defaults; compare with your config.toml if you want them.")

    keep_only_vm_files(repo)

    # Every update, not only when requirements.txt changed: an install that failed last time (slow link) is
    # retried by simply running the update again. When everything already matches, pip downloads nothing.
    if install:
        install_libraries(repo, python)
    else:
        print("libraries not checked (--no-install). To check them: " + " ".join(PIP_ARGS))

    if old != new:
        ver = subprocess.run([python, "-m", "fatbox", "--version"], cwd=repo, capture_output=True, text=True)
        print(f"updated {old[:8]} -> {new[:8]}  ({(ver.stdout or ver.stderr).strip()})")
    return 0


# T-6: the VM's folder holds only what the VM runs. The host code, tests, scripts, CI and design docs stay out,
# so a hacked VM doesn't find the host's code or the safety docs lying next to the samples. Applied on every
# update (git sparse-checkout), so a change to this list reaches the VM by itself. config.toml and data/ are
# untracked and never touched. Note: git's compressed history (.git) still holds every file.
VM_FILES = ["/fatbox/", "!/fatbox/host/", "/rules/", "/requirements.txt", "/config.example.toml", "/README.md",
            "/VM.md", "/LICENSE", "/.gitignore"]


def keep_only_vm_files(repo: Path) -> None:
    try:
        first = _git("config", "--bool", "--default", "false", "core.sparseCheckout", cwd=repo) != "true"
        _git("sparse-checkout", "set", "--no-cone", *VM_FILES, cwd=repo)
    except UpdateError as e:  # old git: everything still works, the folder just keeps all files
        print(f"NOTE: could not trim the VM folder to what it needs ({str(e).splitlines()[0]}); "
              "FatBox works anyway. Updating Git for Windows fixes it.")
        return
    if first:
        print("VM folder trimmed: only what the VM runs is kept (no host code, tests or design docs)")


# T-4: exact versions with sha256 hashes from requirements.txt; never build a package from source (that runs the
# package's own setup code at install time). A file whose hash differs is refused before anything is installed.
PIP_ARGS = ["python", "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
            "--require-hashes", "--only-binary", ":all:", "-r", "requirements.txt"]
# pip lines that are normal and only clutter the GUI log. "Defaulting to user installation": the VM's Python
# folder is read-only for the guest session, so pip installs into the user's site-packages, which Python uses first.
PIP_QUIET = ("Requirement already satisfied", "Defaulting to user installation")
PIN_LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==\S+", re.M)


def install_libraries(repo: Path, python: str) -> None:
    print("checking libraries (pinned + hashed) ...", flush=True)
    cmd = [python, *PIP_ARGS[1:-1], str(repo / "requirements.txt")]
    seen: list[str] = []
    with subprocess.Popen(cmd, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                          errors="replace") as p:
        for line in p.stdout:
            line = line.rstrip()
            seen.append(line)
            if line and not line.startswith(PIP_QUIET):
                print("  " + line, flush=True)
    if p.returncode != 0:
        text = "\n".join(seen[-200:]).lower()
        if "do not match the hashes" in text:
            why = ("a downloaded file did NOT match its fingerprint (hash), so pip refused it and installed nothing."
                   " Corrupt download or tampering. Click Update VM again; if it fails the same way, don't force it: report it.")
        elif "no matching distribution" in text or "could not find a version" in text:
            why = "pip found no ready-made file for this Windows/Python version (building from source is refused)."
        else:
            why = "see the pip lines above (slow or blocked network?)."
        raise UpdateError("library install failed: " + why +
                          " The FatBox code is updated; run Update VM again to retry the libraries.")
    pinned = len(PIN_LINE.findall((repo / "requirements.txt").read_text(encoding="utf-8")))
    print(f"libraries OK: {pinned} pinned", flush=True)
