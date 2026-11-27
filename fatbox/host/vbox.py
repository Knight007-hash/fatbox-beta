"""Thin wrapper over `VBoxManage guestcontrol run` (VirtualBox's built-in host->guest channel).

No network listener in the guest, no shared folders: the host starts `python -m fatbox ...` in the VM
as the guest user and reads its stdout. Every byte read back is capped and treated as untrusted.
"""
from __future__ import annotations

import re
import subprocess
import threading
import time
from typing import Callable

from fatbox.host.lab import password_arg, vbm_argv
from fatbox.host.settings import HostSettings
from fatbox.host.validate import printable

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
LINE_MAX = 2000  # a single log line longer than this is cut


class GuestError(Exception):
    """str(e) is a short message for people; e.detail keeps VirtualBox's raw text, shown only on request."""

    def __init__(self, message: str, detail: str = ""):
        super().__init__(message)
        self.detail = detail


# Known VirtualBox failures -> what they mean for the user. First match wins.
EXPLAIN = (
    (("Guest Additions are not installed or not ready", "execution service is not ready",
      "current status is: starting", "current status is: terminated"),
     "Windows in the VM is not ready for FatBox yet: VirtualBox says its Guest Additions are not running. "
     "If it just started, wait a minute. If it stays like this, Power off and Start the VM again."),
    (("VERR_AUTHENTICATION_FAILURE", "was not able to logon", "logon failure"),
     "Windows in the VM refused FatBox's login: check guest_user and the password file in host.toml."),
    (("is not currently running", "Machine is not running", "machine is not running"),
     "The VM is not running: start it first."),
    (("Could not find a registered machine",),
     "VirtualBox has no VM with that name: check vm in host.toml."),
    (("is already locked", "tried to lock the machine", "E_ACCESSDENIED"),
     "VirtualBox is busy with this VM (another action is running). Try again in a few seconds."),
    # T-19, two-machine layouts: ssh and the gate on the test PC
    (("REMOTE HOST IDENTIFICATION HAS CHANGED", "Host key verification failed"),
     "Blocked: the test PC's SSH key is not the one FatBox paired with. If you reinstalled it, delete "
     "lab_known_hosts in the host folder and run 'python -m fatbox.host lab check' again; otherwise stop and check the cable."),
    (("Permission denied (publickey",),
     "The test PC refused FatBox's key: run scripts\\lab\\lab-setup.ps1 on it with this PC's public key "
     "('python -m fatbox.host lab pair' shows it)."),
    (("Connection timed out", "Connection refused", "No route to host", "Could not resolve hostname",
      "Network is unreachable", "Connection reset", "Connection closed by"),
     "Can't reach the test PC: check the cable, the address in Lab layout, and that OpenSSH Server runs there."),
    (("fatbox-gate: refused",),
     "The test PC's gate refused this command (see gate.log there)."),
)


# 0.39.1: VirtualBox says these while Windows in a running VM is still bringing its Guest Additions up (just
# after a boot or a restore). Steps before the cable goes in wait them out (Controller.ready_ping) instead of failing.
NOT_READY = ("Guest Additions are not installed or not ready", "execution service is not ready",
             "current status is: starting", "current status is: terminated")  # 0.39.2: terminated too (live)


def not_ready(raw: str) -> bool:
    return any(n in raw for n in NOT_READY)


def explain(raw: str) -> str | None:
    for needles, words in EXPLAIN:
        if any(n in raw for n in needles):
            return words
    return None


def short(raw: str, limit: int = 160) -> str:
    """First meaningful line of a VirtualBox error, without the 'VBoxManage.exe: error:' prefix."""
    for line in raw.splitlines():
        line = re.sub(r"^\s*VBoxManage(\.exe)?: error:\s*", "", line).strip()
        if line:
            return line if len(line) <= limit else line[:limit - 1] + "…"
    return "no output"


class VBox:
    def __init__(self, s: HostSettings, popen=subprocess.Popen):
        self.s = s
        self._popen = popen
        self._lock = threading.Lock()
        self._fetch: subprocess.Popen | None = None   # the one cancellable long-running command

    # ---- VM state (host-side only, nothing from the guest) -----------------
    def vm_state(self) -> str:
        out = subprocess.run(vbm_argv(self.s, ["showvminfo", self.s.vm, "--machinereadable"]),
                             capture_output=True, timeout=30, creationflags=NO_WINDOW)
        if out.returncode != 0:
            raise GuestError(out.stderr.decode(errors="replace").strip()[-500:] or "showvminfo failed")
        m = re.search(rb'^VMState="([a-z]+)"', out.stdout, re.M)
        return m.group(1).decode() if m else "unknown"

    # ---- guest commands ----------------------------------------------------
    def argv(self, fatbox_args: list[str], timeout_s: int, env: dict[str, str] | None = None,
             profile: bool = False, python_c: tuple[str, list[str]] | None = None) -> list[str]:
        """python_c=(code, args) runs `python -c code args` instead of FatBox: 0.42.0 Update VM, so a VM with
        any old FatBox can take the host's code (host.codepush)."""
        s = self.s
        cfg = s.guest_dir.rstrip("\\") + "\\config.toml"
        extra = [a for k, v in (env or {}).items() for a in ("--putenv", f"{k}={v}")]
        if profile:  # load the guest user's profile: needed to read the token in Windows Credential Manager
            extra.append("--profile")
        return vbm_argv(s, [
            "guestcontrol", s.vm, "run",
            "--username", s.guest_user, "--passwordfile", password_arg(s),
            "--putenv", f"PYTHONPATH={s.guest_dir}",
            "--putenv", "PYTHONIOENCODING=utf-8",
            "--putenv", "PYTHONUNBUFFERED=1",
            *extra,
            "--timeout", str(timeout_s * 1000),
            "--wait-stdout", "--wait-stderr",
            # No --exe: VirtualBox then runs argv[0] itself. With --exe, some 7.x builds also pass the
            # "argv0" after -- as a real argument (python then tried to open "python.exe" as a script).
            "--", s.guest_python,
            *(["-c", python_c[0], *python_c[1]] if python_c else ["-m", "fatbox", "-c", cfg, *fatbox_args]),
        ])

    def copy_to(self, src: str, guest_dir: str, timeout_s: int = 900) -> None:
        """Copy one host file into a guest folder over guest control (0.42.0 Update VM: the host's code, host to
        VM only; nothing ever comes back this way)."""
        s = self.s
        # 0.42.1 live (VirtualBox 7, win 2): without a trailing separator the target is taken as a FILE name and
        # copyto fails with just "File copy failed". new-test-vm.ps1 always passed "C:\fatbox-setup\".
        sep = "/" if guest_dir.startswith("/") else "\\"
        target = guest_dir.rstrip("\\/") + sep
        out = subprocess.run(vbm_argv(s, ["guestcontrol", s.vm, "copyto", "--username", s.guest_user,
                                          "--passwordfile", password_arg(s), "--target-directory", target, src]),
                             capture_output=True, timeout=timeout_s, creationflags=NO_WINDOW)
        if out.returncode != 0:
            err = out.stderr.decode(errors="replace").strip()
            raise GuestError(explain(err) or f"copying the code into the VM failed: {short(err) if err else out.returncode}",
                             err[-2000:])

    def run(self, fatbox_args: list[str], timeout_s: int, max_stdout: int,
            on_line: Callable[[str], None] | None = None, cancellable: bool = False,
            env: dict[str, str] | None = None, profile: bool = False,
            python_c: tuple[str, list[str]] | None = None) -> tuple[int, bytes, str]:
        """Run FatBox in the guest. Returns (exit code, stdout bytes, stderr tail).

        stdout is capped at max_stdout bytes (the process is killed past it). When on_line is
        given, stdout+stderr are also streamed line by line (for the live log).
        """
        with self._lock:
            if cancellable and self._fetch is not None:
                raise GuestError("a fetch is already running")
            proc = self._popen(self.argv(fatbox_args, timeout_s, env, profile, python_c), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=NO_WINDOW)
            if cancellable:
                self._fetch = proc
        out = bytearray()
        err_tail: list[str] = []
        overflow = threading.Event()

        def pump(stream, keep: bool):
            buf = b""
            for chunk in iter(lambda: stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536), b""):
                if keep:
                    if len(out) + len(chunk) > max_stdout:
                        overflow.set()
                        proc.kill()
                        return
                    out.extend(chunk)
                buf += chunk
                *lines, buf = re.split(rb"\r\n|\r|\n", buf)
                for ln in lines:
                    emit(ln, keep)
                if len(buf) > LINE_MAX:
                    emit(buf, keep)
                    buf = b""
            if buf:
                emit(buf, keep)

        def emit(raw: bytes, is_stdout: bool):
            text = printable(raw[:LINE_MAX].decode("utf-8", errors="replace"))  # the CLI prints these lines
            if not is_stdout:
                err_tail.append(text)
                del err_tail[:-20]
            if on_line and text.strip():
                on_line(text)

        threads = [threading.Thread(target=pump, args=(proc.stdout, True), daemon=True),
                   threading.Thread(target=pump, args=(proc.stderr, False), daemon=True)]
        for t in threads:
            t.start()
        deadline = time.monotonic() + timeout_s + 30
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    proc.kill()
                    raise GuestError(f"timed out after {timeout_s}s")
                time.sleep(0.2)
            for t in threads:
                t.join(5)
        finally:
            if cancellable:
                with self._lock:
                    self._fetch = None
        if overflow.is_set():
            raise GuestError(f"guest output exceeded {max_stdout} bytes, discarded")
        return proc.returncode, bytes(out), "\n".join(err_tail)

    def cancel(self) -> bool:
        with self._lock:
            if self._fetch is None:
                return False
            self._fetch.kill()  # VBoxManage exiting closes the guest session; check the VM if a fetch keeps going
            return True

