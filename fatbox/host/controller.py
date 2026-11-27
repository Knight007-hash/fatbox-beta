"""What the host can ask the VM to do: list, browse, fetch, triage, update. Reports are kept in the
host's own library (T-7), so they outlive a revert.

The VM's network cable is plugged in only around the steps that need the internet (download, update) and
always unplugged afterwards (INV-7). Samples are analysed only once the cable is out.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from fatbox import __version__
from fatbox.host import codepush, validate
from fatbox.host.library import Library
from fatbox.host.prefs import Prefs, browse_filters, fetch_flags
from fatbox.host.snapshots import SnapshotPrefs
from fatbox.host.settings import HostSettings
from fatbox.host.vbox import NO_WINDOW, GuestError, VBox, explain, not_ready, short
from fatbox.host.vmctl import OFF_STATES, VmControl

MODES = {"recent", "latest", "tag", "signature", "file_type"}
VERSION_RE = re.compile(r"^FatBox (\d{1,4}\.\d{1,4}\.\d{1,4})$")
VALUE_RE = re.compile(r"^[A-Za-z0-9._\- ]{0,64}\Z")


MAX_PICKS = 30


def _mode_value(opts: dict) -> tuple[str, str]:
    mode = opts.get("mode") or "recent"
    value = (opts.get("value") or "").strip()
    if mode not in MODES:
        raise ValueError("bad mode")
    if not VALUE_RE.match(value):
        raise ValueError("value: letters, digits, . _ - and space only (max 64)")
    if mode in ("tag", "signature", "file_type") and not value:
        raise ValueError(f"mode {mode} needs a value")
    if mode in ("recent", "latest") and value:  # MalwareBazaar ignores it there; don't pretend to filter
        raise ValueError(f"mode {mode} takes no value; use mode 'signature' to pick a family")
    return mode, value


BROWSE_LIMITS = (25, 50, 100)


def browse_limit(opts: dict) -> int:
    """0.29.0: how many rows Browse lists (the newest first). Only 25, 50 or 100."""
    v = opts.get("limit", 100)
    if isinstance(v, bool) or v not in BROWSE_LIMITS and str(v) not in {str(x) for x in BROWSE_LIMITS}:
        raise ValueError("list 25, 50 or 100 rows")
    return int(v)


def browse_args(opts: dict) -> list[str]:
    """T-13: ask the VM for the candidate list (metadata only)."""
    mode, value = _mode_value(opts)
    return ["browse", "--mode", mode] + (["--value", value] if value else []) + ["--limit", str(browse_limit(opts))]


def picks(opts: dict) -> list[str]:
    """T-13: the sha256s ticked in the Browse list. Only exact 64-hex strings, 1..30, no duplicates."""
    raw = opts.get("pick")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_PICKS:
        raise ValueError(f"pick 1..{MAX_PICKS} samples")
    out = []
    for s in raw:
        if not isinstance(s, str) or not validate.SHA_RE.match(s.lower()):
            raise ValueError("pick: not a sha256")
        if s.lower() not in out:
            out.append(s.lower())
    return out


def fetch_args(opts: dict) -> list[str]:
    """Turn GUI/CLI options into fatbox argv. Strict allow-list: nothing free-form reaches the guest."""
    if opts.get("pick") is not None:  # T-13: exactly the picked samples; mode/value/max don't apply
        args = ["fetch", "--source", "bazaar", "--sha256", *picks(opts)]
        opts = {k: v for k, v in opts.items() if k not in ("max", "small_first")}
    else:
        mode, value = _mode_value(opts)
        args = ["fetch", "--source", "bazaar", "--mode", mode]
        if value:
            args += ["--value", value]
    size_limit = opts.get("size_limit", True)
    if not isinstance(size_limit, bool):
        raise ValueError("size_limit must be true or false")
    # The budget is always sent, so the VM's clock and the host's stopwatch (fetch_deadline_s) agree.
    opts = {**opts, "budget": opts.get("budget") if opts.get("budget") not in (None, "") else DEFAULT_BUDGET_S}
    for key, flag, lo, hi in (("max", "--max", 1, 30), ("max_size_mb", "--max-size-mb", 1, 100),
                              ("budget", "--budget", 60, 1800)):
        v = opts.get(key)
        if key == "max_size_mb" and not size_limit:
            continue
        if v not in (None, ""):
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be a whole number")
            if not lo <= v <= hi:
                raise ValueError(f"{key} must be {lo}..{hi}")
            args += [flag, str(v)]
    if not size_limit:
        args.append("--no-size-limit")
    if opts.get("small_first"):
        args.append("--small-first")
    return args


DEFAULT_BUDGET_S = 400
STOPWATCH_MARGIN_S = 120  # listing, startup and the last stall check, on top of the VM's own budget


def fetch_deadline_s(args: list[str]) -> int:
    """The host's own stopwatch for the download step: the budget it sent plus a margin. If the VM ignores
    its budget (bug or compromise), the host kills the command and the cable still comes out."""
    return int(args[args.index("--budget") + 1]) + STOPWATCH_MARGIN_S


TRIAGE_PER_RUN = 30  # same as the VM's (fatbox.config); more waiting samples go in the next run


# Update VM's stopwatch. 0.18.0 brings ~15 MB of capa rules + signatures through git and ~21 MB of libraries through
# pip, once; on a 30-60 kB/s link that is 10-20 minutes, so the old 15 minutes was too tight.
UPDATE_DEADLINE_S = 3600


def triage_args(sample_time_s: int, capa_time_s: int = 120, parallel: int = 0, capa_packed: str = "skip") -> list[str]:
    if not isinstance(sample_time_s, int) or not 10 <= sample_time_s <= 300:
        raise ValueError("sample_time_s must be 10..300")
    if not isinstance(capa_time_s, int) or not 30 <= capa_time_s <= 600:
        raise ValueError("capa_time_s must be 30..600")
    if not isinstance(parallel, int) or isinstance(parallel, bool) or not 0 <= parallel <= 10:
        raise ValueError("parallel must be 0..10")
    if capa_packed not in ("skip", "run"):
        raise ValueError("capa_packed must be skip or run")
    args = ["triage", "--sample-time", str(sample_time_s), "--capa-time", str(capa_time_s)]
    if parallel:  # 0 = auto: the VM picks from its own CPU count
        args += ["--parallel", str(parallel)]
    return args + ["--capa-packed", capa_packed]


def triage_deadline_s(args: list[str]) -> int:
    """The host's stopwatch for the whole analysis step: 30 samples x (per-sample limit + capa limit), plus a
    margin. If the VM ignores its limits (bug or compromise), the host stops the command; finished reports stay."""
    per = int(args[args.index("--sample-time") + 1]) + int(args[args.index("--capa-time") + 1])
    return TRIAGE_PER_RUN * per + STOPWATCH_MARGIN_S


class NetworkStillOn(GuestError):
    pass


STILL_ON = "the VM's network is STILL ON: click Disconnect, or power off the VM"


def host_branch() -> str | None:
    """The git branch of the HOST's own FatBox checkout (host side, trusted). None when unknown or detached.
    Update VM installs what is on GitHub main, so a host on another branch can run a version the VM can't get."""
    try:
        r = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=Path(__file__).resolve().parents[2],
                           capture_output=True, text=True, timeout=5, creationflags=NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return None
    branch = r.stdout.strip()
    return branch if r.returncode == 0 and branch and branch != "HEAD" else None


def off_main_note(branch: str | None) -> str:
    if not branch or branch == "main":
        return ""
    return (f" Note: the host runs from git branch '{branch}', not main. Update VM only installs what is on GitHub"
            " main, so merge that branch's PR first, or put the host back on main: git checkout main, then git pull.")


class Laps:
    """0.38.0 step timers for the Activity log: `--- triage took 214 s: checks 1 s, analysis 205 s, ...`.
    Host-side clock only; nothing here comes from the VM."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.t0 = self.t = clock()
        self.parts: list[tuple[str, float]] = []

    def lap(self, name: str) -> None:
        now = self.clock()
        self.parts.append((name, now - self.t))
        self.t = now

    def line(self, what: str) -> str:
        parts = ", ".join(f"{n} {s:.0f} s" for n, s in self.parts)
        return f"--- {what} took {self.clock() - self.t0:.0f} s" + (f": {parts}" if parts else "")


VERSION_TTL_S = 1800  # 0.38.0: a passed version check is trusted for this boot, at most 30 min


class Controller:
    net_wait_s = 5.0      # after plugging the cable in: time for Windows to get an address
    retry_pause_s = 2.0   # between attempts to unplug it
    poll_s = 2.0          # while waiting for the VM to stop or for Windows to be ready (0.38.0: was 5 s)
    settle_s = 30.0       # after a fresh boot, before the clean snapshot: let Windows finish its start-up work
    ready_timeout_s = 600      # 0.39.2: was 300; live VBox.log: VBoxService came up 2 to 10 min after power-on
    push_fallback_dir = r"C:\Users\Public"   # 0.42.1: Update VM's second place for the code bundle (any user can write)
    not_ready_wait_s = 600     # 0.39.1 (0.39.2: was 120, 0.39.3: was 300, now = ready_timeout_s): a running VM whose guest control is not up yet: wait this long
    acpi_wait_s = 30           # after the ACPI power button, before asking Windows itself (0.18.2; 0.28.0: was 60)
    shutdown_timeout_s = 30    # after Windows was asked itself; then power off (0.28.0: was 180 s and a failure)
    branch = staticmethod(host_branch)

    def __init__(self, s: HostSettings, vbox: VBox | None = None, vm: VmControl | None = None):
        self.s = s
        self.vbox = vbox or VBox(s)
        self.vm = vm or VmControl(s)
        self.library = Library(s.home)
        self.snaps = SnapshotPrefs(s.home, s.clean_snapshot)
        self.prefs = Prefs(s.home, s.sample_time_s, s.capa_time_s)   # 0.23.0 Settings tab
        self._cancel = threading.Event()
        # 0.37.0 (T-19): the last lab check. "bad" blocks Fetch, Triage, Update VM and Make clean snapshot until
        # a new check passes; None until the first check has run (the GUI starts one at start-up).
        self.lab_results: list[tuple[str, str]] | None = None
        self._lab_lock = threading.Lock()
        # 0.38.0: the boot (VirtualBox's VMStateChangeTime, host side) whose version check passed, and when. Until
        # the VM starts, stops or is restored, or Update VM runs, steps skip the guest round trip of asking again.
        self._ver_boot: str | None = None
        self._ver_at = 0.0
        self.revert_due = False  # 0.38.0: triage left the auto-revert to the caller (the GUI runs it as its own job)

    def lab_check(self, version_check=None) -> list[tuple[str, str]]:
        from fatbox.host.lab import run_checks
        with self._lab_lock:
            self.lab_results = run_checks(self.s, version_check or self.version_check)
            return self.lab_results

    def lab_problem(self) -> str | None:
        """The first failed lab check, if the last check failed."""
        for status, text in self.lab_results or []:
            if status == "bad":
                return text
        return None

    def lab_reset(self) -> None:
        self.lab_results = None

    def _check(self, rc: int, err: str, what: str) -> None:
        """Short words for people; VirtualBox's raw text goes to .detail (the GUI shows it behind "details")."""
        if rc != 0:
            detail = err.strip()[-2000:]
            words = explain(err)
            if words:
                raise GuestError(words, detail)
            hint = ""
            if "No module named fatbox" in err:
                hint = f" Check guest_dir in host.toml: it must be the VM's FatBox folder (now {self.s.guest_dir})."
            raise GuestError(f"{what} failed (exit {rc}): {short(err)}{hint}", detail)

    def ping(self) -> str:
        rc, out, err = self.vbox.run(["--version"], 120, 4096)
        self._check(rc, err, "guest fatbox --version")
        return validate.printable(out.decode("utf-8", errors="replace").strip()[:100])

    def version_check(self, said: str | None = None) -> dict:
        """Host and VM must run the exact same FatBox version, or Fetch is refused (T-3). The VM's answer is
        untrusted: anything but "FatBox N.N.N" counts as unknown."""
        said = self.ping() if said is None else said
        m = VERSION_RE.match(said)
        vm, host = (m.group(1) if m else None), __version__
        if vm == host:
            msg = None
        elif vm is None:
            msg = f"The VM answered with an unknown version. Fetch is off until it runs FatBox {host}: click Update VM."
        elif tuple(map(int, vm.split("."))) < tuple(map(int, host.split("."))):
            msg = (f"The VM runs FatBox {vm}, the host {host}. Fetch is off until they match: click Update VM."
                   + off_main_note(self.branch()))
        else:
            msg = f"The VM is newer ({vm}) than the host ({host}). Fetch is off until they match: run git pull on the host."
        return {"host": host, "vm": vm, "ok": vm == host, "message": msg}

    def list_samples(self) -> list[dict]:
        rc, out, err = self.vbox.run(["list", "--json", "--limit", "1000"], 120, validate.LIST_MAX_BYTES)
        self._check(rc, err, "list")
        return validate.sample_list(out)

    def _vm_report(self, sha: str) -> dict:
        rc, out, err = self.vbox.run(["report", sha], 120, validate.REPORT_MAX_BYTES)
        self._check(rc, err, "report")
        return validate.report(out, sha)

    def report(self, sha: str, refresh: bool = False) -> dict:
        """From the library (works with the VM off); from the VM only if it isn't there yet, or on refresh."""
        sha = validate.sha(sha.lower())
        if not refresh:
            obj = self.library.report(sha)
            if obj is not None:
                return obj
        obj = self._vm_report(sha)
        self.library.put_report(sha, obj)
        return obj

    def sync_library(self, say: Callable[[str], None]) -> dict:
        """T-7: copy the VM's new or changed reports into the host library. Network stays off: these are the
        same list/report commands the GUI always used."""
        state = self.vm.state()
        if state != "running":
            raise GuestError(f"the VM is '{state}': showing the library only")
        rows = self.list_samples()
        return self.library.sync(rows, self._vm_report, say, complete=len(rows) < 1000)

    def save_before_revert(self, say: Callable[[str], None]) -> str | None:
        """Before a revert wipes the VM: copy everything first. Returns what could not be saved, or None."""
        say("--- saving reports to the library before the revert")
        try:
            got = self.sync_library(say)
        except (GuestError, validate.Invalid, OSError) as e:
            return f"The library could not be updated ({e})"
        if got["missing"]:
            return f"{got['missing']} report(s) could not be saved to the library"
        return None

    # ---- snapshots (T-8) ---------------------------------------------------
    def snapshot_view(self) -> dict:
        rows, current = self.vm.snapshot_list()
        return self.snaps.view(rows, current, __version__)

    def set_default_snapshot(self, uuid) -> dict:
        rows = self.vm.snapshot_list()[0]
        hit = next((r for r in rows if isinstance(uuid, str) and r["uuid"] == uuid.lower()), None)
        if hit is None:
            raise ValueError("no such snapshot")
        self.snaps.update(default=hit)
        return hit

    def set_auto_revert(self, on) -> None:
        if not isinstance(on, bool):
            raise ValueError("auto_revert must be true or false")
        if on and self.snapshot_view()["default"] is None:
            raise ValueError("pick a default snapshot first (Snapshots tab)")
        self.snaps.update(auto_revert=on)

    def ready_ping(self, say: Callable[[str], None] | None = None) -> str:
        """0.39.1: ping, but while VirtualBox says the Guest Additions are still coming up (a VM that just booted
        shows "running" before guest control works: "Error starting guest session (current status is: starting)"),
        wait and ask again, up to not_ready_wait_s. Any other error, or a VM that stopped, fails at once."""
        deadline = time.monotonic() + self.not_ready_wait_s
        told = False
        while True:
            try:
                got = self.ping()
                if told and say:
                    say("--- Windows in the VM is ready")
                return got
            except GuestError as e:
                raw = e.detail or str(e)
                # 0.39.3: a guest that is still booting can also just time out; keep waiting while the VM runs
                if not (not_ready(raw) or "timed out after" in raw) or time.monotonic() >= deadline \
                        or self._cancel.is_set():
                    raise
            if say and not told:  # 0.42.0: say why nothing seems to happen (slow boots take minutes on some PCs)
                w = self.not_ready_wait_s
                say(f"--- waiting for Windows in the VM to get ready (its Guest Additions are starting; "
                    f"up to {f'{w // 60} min' if w >= 60 else f'{w} s'}, Cancel stops)")
                told = True
            self._cancel.wait(self.poll_s)
            if self.vm.state() != "running":
                raise GuestError("the VM stopped while FatBox waited for Windows to get ready")

    def wait_ready(self, say: Callable[[str], None]) -> str:
        """After a start: wait until FatBox answers in the VM (Windows booted, Guest Additions up)."""
        deadline = time.time() + self.ready_timeout_s
        while True:
            try:
                return self.ping()
            except GuestError:
                if time.time() >= deadline or self._cancel.is_set():
                    raise GuestError(f"Windows in the VM did not get ready within {self.ready_timeout_s // 60} min "
                                     "(its Guest Additions service never answered). Open the VM window and check "
                                     "Task Manager for what keeps Windows busy, then try again.")
            self._cancel.wait(self.poll_s)

    def auto_revert(self, say: Callable[[str], None]) -> None:
        """T-8: after a fetch whose reports are all in the library, go back to the default snapshot."""
        t0 = time.time()
        view = self.snapshot_view()
        d = view["default"]
        if d is None:
            say("--- auto-revert skipped: no default snapshot (Snapshots tab)")
            return
        say(f"--- auto-revert: going back to {d['name']}")
        laps = Laps()
        self.forget_version()
        self.vm.revert(d["uuid"])
        self.library.mark_all_gone()
        laps.lap("restore")
        # after a restore the VM is off (0.18.1: saved memory is dropped): boot it fresh, headless (Start always
        # unplugs the cable), and wait for FatBox
        if self.vm.state() in OFF_STATES:
            self.vm.start(headless=True)
        said = self.wait_ready(say)
        laps.lap("boot")
        self.cable_off(lambda _: None)  # raises NetworkStillOn after 3 tries
        v = self.version_check(said)  # 0.38.0: the answer that said "ready" is the version: no second round trip
        self._remember_version(v["ok"])
        laps.lap("checks")
        say(f"--- VM back and running; network OFF (checked); FatBox {v['vm'] or '?'} " + ("✓" if v["ok"] else "≠ host"))
        if not v["ok"]:
            say("--- ⚠ " + v["message"])
        say(f"--- auto-revert done in {int(time.time() - t0)} s")
        say(laps.line("auto-revert"))

    def _wait_off(self, seconds: float) -> bool:
        deadline = time.time() + seconds
        while self.vm.state() not in OFF_STATES and time.time() < deadline and not self._cancel.is_set():
            self._cancel.wait(self.poll_s)
        return self.vm.state() in OFF_STATES

    def _shut_down(self, say: Callable[[str], None]) -> None:
        """Clean Windows shutdown: the ACPI power button first. Windows ignores it when its power button is set to
        "do nothing" or "sleep" (0.18.1 live test), so after acpi_wait_s FatBox asks Windows itself
        (`fatbox shutdown --yes` runs shutdown.exe /s in the VM). Returns when the VM is off or time is up."""
        self.vm.shutdown()
        if self._wait_off(self.acpi_wait_s) or self._cancel.is_set():
            return
        say("--- Windows ignored the power button; asking Windows itself to shut down")
        try:  # the guest session may end with an error as Windows goes down: only the VM's state counts
            rc, _, err = self.vbox.run(["shutdown", "--yes"], 60, 4096)
        except GuestError as e:
            rc, err = 1, str(e)
        if not self._wait_off(self.shutdown_timeout_s) and rc != 0:
            # 0.28.0: no error text = the guest session was cut as Windows started going down, not a failure
            why = validate.printable(short(err)) if err.strip() else "no answer (Windows was going down)"
            say("--- the VM's shutdown command: " + why)

    def make_clean_snapshot(self, say: Callable[[str], None]) -> int:
        """T-8: empty the VM, check it, shut it down and photograph it as the new default. Stops at the first
        problem, before any snapshot is taken. Reports are copied to the library before anything is wiped.
        0.18.1: the photo is taken with the VM shut down cleanly (no memory in it), so a revert is a fresh boot
        that works under Hyper-V too; then the VM is started from it, which proves it boots and is still empty.
        0.42.2: no restart before the photo any more. It was one extra slow boot that proved nothing the
        powered-off photo and the boot from it (step 6) don't already prove."""
        self._cancel.clear()
        self._ready(say=say)              # running, same version as the host
        self.cable_off(say)               # and the cable out, as VirtualBox sees it
        say(f"--- clean snapshot 1/6: FatBox {__version__} in the VM, network OFF")
        got = self.sync_library(say)
        if got["missing"]:
            raise GuestError(f"{got['missing']} report(s) could not be saved: nothing was wiped, no snapshot taken")
        say("--- clean snapshot 2/6: every report is in the library")
        rc, out, err = self.vbox.run(["wipe-data", "--yes"], 120, 64 * 1024)
        self._check(rc, err, "wipe-data")
        say("--- clean snapshot 3/6: VM emptied " + validate.printable(out.decode("utf-8", "replace").strip()[:200]))
        left = self.list_samples()
        if left:
            raise GuestError(f"the VM still lists {len(left)} sample(s) after wipe-data: no snapshot taken")
        self.library.mark_all_gone()
        self._cancel.wait(self.settle_s)  # let Windows write the wipe to disk before it goes down
        if self._cancel.is_set():
            raise GuestError("cancelled: no snapshot taken")
        self.cable_off(lambda _: None)
        say("--- clean snapshot 4/6: checked (version, network OFF, 0 samples); shutting down")
        self._shut_down(say)
        if self._cancel.is_set():
            raise GuestError("cancelled: no snapshot taken")
        forced = False
        if self.vm.state() not in OFF_STATES:
            # 0.28.0: don't fail on a slow or stubborn Windows shutdown. The VM has been checked and sat
            # idle (settle_s) with 0 samples and the cable out, so nothing is writing to the disk; power it off and
            # take the photo. Step 6 boots from it and checks it is still empty.
            say("--- Windows did not shut down in time: powering off (the VM is idle, empty and offline)")
            self.vm.poweroff()
            forced = True
            if not self._wait_off(30):
                raise GuestError("the VM did not power off: no snapshot taken")
        if self.vm.state() != "poweroff":
            raise GuestError(f"the VM is '{self.vm.state()}', not powered off: no snapshot taken")
        names = set(self.vm.snapshots()[0])
        base = f"clean-fatbox-{__version__}-{datetime.now(timezone.utc):%Y-%m-%d}"
        name = next(n for n in [base] + [f"{base}-{i}" for i in range(2, 100)] if n not in names)
        how = "powered off after Windows ignored shutdown" if forced else "shut down cleanly"
        uuid = self.vm.take(name, f"clean: checked by FatBox {__version__} (0 samples, network off, {how})")
        if not uuid:
            raise GuestError(f"snapshot {name} was taken but VirtualBox did not list it")
        self.snaps.add_checked(name, uuid, __version__, datetime.now(timezone.utc).isoformat(timespec="seconds"))
        say(f"--- clean snapshot 5/6: {name} taken (VM {'powered off' if forced else 'shut down'}), checked, and set "
            "as the default; starting the VM")
        self.vm.start(headless=True)
        self.wait_ready(say)
        # 0.42.0 (live, win 2): the Guest Additions can answer once, then restart while Windows finishes starting
        # up; wait them out again instead of failing
        v = self.version_check(self.ready_ping(say))
        left = self.list_samples()
        if not v["ok"] or left:
            raise GuestError(f"{name} boots, but is not clean ({len(left)} sample(s), version ok: {v['ok']}): "
                             "make the clean snapshot again")
        say("--- clean snapshot 6/6: the VM booted from it, FatBox answers, 0 samples")
        return 0

    # ---- network (INV-7) ----------------------------------------------------
    def cable_off(self, say: Callable[[str], None]) -> None:
        """Unplug the cable, then ask VirtualBox (host side, not the guest) whether it really is out."""
        for attempt in range(3):
            if attempt:
                time.sleep(self.retry_pause_s)
            try:
                self.vm.set_network(False)
                if self.vm.cable() == "off":
                    say("--- network OFF (checked)")
                    return
            except (GuestError, subprocess.SubprocessError, OSError):  # 0.39.3: a hung VBoxManage call gets retried too
                pass
        say("--- " + STILL_ON)
        raise NetworkStillOn(STILL_ON)

    def _online(self, say: Callable[[str], None], work: Callable[[], int], laps: Laps | None = None,
                label: str = "work") -> int:
        """Run work() with the cable plugged in. The cable comes out however work() ends."""
        try:
            self.vm.set_network(True)
            say("--- network ON")
            self._cancel.wait(self.net_wait_s)
            if laps:
                laps.lap("network on")
            if self._cancel.is_set():
                return 1
            rc = work()
            if laps:
                laps.lap(label)
            return rc
        finally:
            self.cable_off(say)
            if laps:
                laps.lap("network off")

    def startup_check(self) -> str | None:
        """Host start: nothing can be fetching yet, so a plugged-in cable is left over (crash or manual)."""
        if self.vm.cable() != "on":
            return None
        self.cable_off(lambda _: None)
        return "The VM's network was ON when FatBox started (a crash, or turned on by hand). FatBox switched it OFF."

    def _remember_version(self, ok: bool) -> None:
        """0.38.0: after a version check, remember (or forget) that this boot passed it."""
        self._ver_boot, self._ver_at = None, 0.0
        if not ok:
            return
        try:
            state, since = self.vm.state_since()
        except GuestError:
            return
        if state == "running" and since:
            self._ver_boot, self._ver_at = since, time.monotonic()

    def forget_version(self) -> None:
        self._ver_boot, self._ver_at = None, 0.0

    def _ready(self, same_version: bool = True, say: Callable[[str], None] | None = None) -> None:
        """Before the cable goes in: the VM must be up and able to run FatBox, and (except for the update that
        fixes it) run the same version as the host. 0.38.0: a version check that passed in this same boot (same
        VMStateChangeTime, less than 30 min ago) is not asked again: one guest round trip less per step. The
        check is about matching code, not safety: every answer from the VM is still validated (INV-4)."""
        state, since = self.vm.state_since()
        if state != "running":
            raise GuestError(f"the VM is '{state}': start it first")
        if not same_version:
            self.ready_ping(say)
            return
        if since and since == self._ver_boot and time.monotonic() - self._ver_at < VERSION_TTL_S:
            return
        v = self.version_check(self.ready_ping(say))
        if not v["ok"]:
            self.forget_version()
            raise GuestError(v["message"])
        self._remember_version(True)

    def cancel(self) -> bool:
        self._cancel.set()
        return self.vbox.cancel()

    # ---- jobs --------------------------------------------------------------
    def fetch(self, opts: dict, on_line: Callable[[str], None]) -> int:
        """CLI: download, then triage offline (the GUI runs the two as separate steps). A cancel stops before triage."""
        rc = self._download(opts, on_line)
        if self._cancel.is_set():
            on_line("--- cancelled, analysis skipped")
            return rc or 1
        trc = self.triage(on_line, ready=False)  # a failed download still gets what arrived analysed
        return rc or trc

    def download(self, opts: dict, on_line: Callable[[str], None]) -> tuple[int, list[dict]]:
        """0.29.0 GUI step 2: download exactly the picked samples with the cable in, unplug, and say which ones
        are now in the VM. Nothing is analysed here: Triage is its own step."""
        if opts.get("pick") is None:
            raise ValueError("Browse first, then tick the samples to fetch")
        want = picks(opts)
        laps = Laps()
        rc = self._download(opts, on_line, laps)
        try:
            have = {r["sha256"]: r for r in self.list_samples()}
        except (GuestError, validate.Invalid) as e:
            on_line(f"--- could not list the VM's samples ({e})")
            have = {}
        laps.lap("list")
        rows = [{"sha256": s, "status": have[s]["status"] if s in have else "missing"} for s in want]
        n = sum(r["status"] == "fetched" for r in rows)
        on_line(f"--- {n} of {len(want)} picked sample(s) in the VM, waiting for triage")
        on_line(laps.line("fetch"))
        return rc, rows

    def _download(self, opts: dict, on_line: Callable[[str], None], laps: Laps | None = None) -> int:
        prefs = self.prefs.load()
        args = fetch_args(opts) + fetch_flags(prefs, picked=opts.get("pick") is not None)
        self._cancel.clear()
        self._ready(say=on_line)
        if laps:
            laps.lap("checks")

        def download() -> int:
            try:
                return self.vbox.run(args, fetch_deadline_s(args), 256 * 1024, on_line, cancellable=True)[0]
            except GuestError as e:  # timeout etc.: what did arrive can still be triaged
                on_line(f"--- download step failed: {e}")
                return 1

        return self._online(on_line, download, laps, "download")

    def pending(self) -> list[dict]:
        """0.29.0: samples in the VM that wait for triage (status 'fetched'). Network stays off."""
        state = self.vm.state()
        if state != "running":
            raise GuestError(f"the VM is '{state}'")
        return [{k: r[k] for k in ("sha256", "signature", "file_type")} for r in self.list_samples()
                if r["status"] == "fetched"]

    def triage(self, on_line: Callable[[str], None], ready: bool = True, revert_now: bool = True) -> int:
        """0.29.0 GUI step 3: static analysis of the waiting samples, offline; then copy the reports to the
        library and, if it is on, auto-revert. 0.38.0: revert_now=False leaves the revert to the caller
        (self.revert_due): the GUI shows the reports at once and reverts as its own job."""
        laps = Laps()
        self.revert_due = False
        if ready:
            self._cancel.clear()
            self._ready(say=on_line)
            self.cable_off(on_line)  # never analyse with the cable in (INV-7), whatever the badge said
        laps.lap("checks")
        prefs = self.prefs.load()
        on_line("--- starting analysis (network is off)")
        a = prefs["analysis"]
        targs = triage_args(a["sample_time_s"], a["capa_time_s"], a["parallel"], a["capa_packed"])
        try:
            trc = self.vbox.run(targs, triage_deadline_s(targs), 256 * 1024, on_line, cancellable=True)[0]
        except GuestError as e:  # the VM ignored its own limits: the host's stopwatch ended it
            on_line(f"--- analysis step failed: {e}")
            trc = 1
        laps.lap("analysis")
        got = None
        try:  # a library problem never undoes the analysis; the next Refresh tries again
            got = self.sync_library(on_line)
        except (GuestError, validate.Invalid, OSError) as e:
            on_line(f"--- library: could not save reports ({e}); Refresh tries again")
        laps.lap("library")
        on_line(laps.line("triage"))
        if self.snaps.load()["auto_revert"]:
            if self._cancel.is_set():
                on_line("--- cancelled: no auto-revert")
            elif got is None or got["missing"]:
                on_line("--- auto-revert skipped: not every report was saved. Click Refresh, then Revert")
            elif not revert_now:
                self.revert_due = True  # every report is in the library: the caller reverts next
            else:
                try:
                    self.auto_revert(on_line)
                except NetworkStillOn:
                    raise
                except (GuestError, ValueError, OSError) as e:
                    on_line(f"--- ⚠ auto-revert failed: {e}")
        return trc

    def browse(self, opts: dict, on_line: Callable[[str], None]) -> list[dict]:
        """T-13: the VM lists MalwareBazaar candidates with the cable in (metadata only, no files); the host
        checks every row and computes the pre-score itself (it never trusts a score from the VM)."""
        from fatbox.fetch.meta import categories, prefilter, prescore  # standard library only, no network code
        args = browse_args(opts)
        self._cancel.clear()
        laps = Laps()
        self._ready(say=on_line)
        laps.lap("checks")
        got: dict = {}

        def work() -> int:
            rc, out, err = self.vbox.run(args, 180, validate.LIST_MAX_BYTES, cancellable=True)
            got.update(rc=rc, out=out, err=err)
            return rc

        self._online(on_line, work, laps, "list")
        if self._cancel.is_set():
            raise GuestError("browse cancelled")
        self._check(got.get("rc", 1), got.get("err", ""), "browse")
        rows, dropped = validate.candidate_list(got["out"])
        rows = rows[:browse_limit(opts)]   # recent/latest come as one feed window: keep the newest N
        have = {r["sha256"] for r in self.library.rows()}
        f, max_bytes, cap = browse_filters(self.prefs.load())
        for r in rows:
            r["in_library"] = r["sha256"] in have   # T-8: after a revert the VM forgets; the library doesn't
            r["categories"] = categories(r)
            r["prescore"], r["prescore_why"] = prescore(r)
            r["skip"] = prefilter(r, f, max_bytes, cap) or ""   # 0.29.0: Settings filters apply to Browse too
        rows.sort(key=lambda r: -r["prescore"])
        on_line(f"--- browse: {len(rows)} sample(s) listed" + (f", {dropped} bad row(s) dropped" if dropped else ""))
        on_line(laps.line("browse"))
        return rows

    def update_vm(self, on_line: Callable[[str], None]) -> int:
        """0.42.0: copy THIS PC's FatBox code into the VM (host.codepush), then `fatbox update --no-fetch` with the
        cable in only for the pinned libraries. The VM never contacts GitHub, so no token is ever needed in it and
        the VM runs exactly the host's version. Fallback (remote lab, host not a git folder): the VM's own
        `fatbox update` from GitHub, as before."""
        self._cancel.clear()
        self.forget_version()  # whatever happens next, the VM's code may change
        self._ready(same_version=False, say=on_line)
        args = ["update"]
        if self.s.lab.remote:
            on_line("--- remote lab: the VM updates itself from GitHub")
        else:
            with tempfile.TemporaryDirectory(prefix="fatbox-push-") as tmp:
                bundle, note = codepush.make_bundle(Path(tmp))
                if note:
                    on_line(f"--- {note}" + ("" if bundle else "; the VM updates itself from GitHub instead"))
                if bundle:
                    rc = self._push_code(bundle, on_line)
                    if rc != 0:
                        if not self._cancel.is_set():
                            on_line("--- update failed: the VM did not take this PC's code (see above)")
                        return rc
                    args = ["update", "--no-fetch"]
        rc = self._online(on_line, lambda: self.vbox.run(
            args, UPDATE_DEADLINE_S, 256 * 1024, on_line, cancellable=True, env={"GCM_INTERACTIVE": "Never"},
            profile=True)[0])
        if rc == 0:
            said = self.ping()
            on_line(f"--- VM now runs {said}")
            v = self.version_check(said)
            self._remember_version(v["ok"])
            if not v["ok"]:  # e.g. the host runs code that is not on GitHub main yet: say so, don't leave a riddle
                on_line("--- still different from the host: " + v["message"])
            self.lab_check(lambda: v)  # 0.38.1: the header's lab status follows at once (this answer, no 2nd ping)
        elif not self._cancel.is_set():
            on_line("--- update failed (see above)")
        return rc

    def _push_code(self, bundle: Path, on_line: Callable[[str], None]) -> int:
        """Network stays OFF: the code comes from this PC over guest control, host to VM only."""
        on_line(f"--- copying this PC's FatBox code into the VM ({bundle.stat().st_size // 1024} KB, no GitHub, no token)")
        for folder in (self.s.guest_dir, self.push_fallback_dir):   # 0.42.1: a second folder every user can write
            try:
                self.vbox.copy_to(str(bundle), folder)
                break
            except GuestError as e:
                on_line(f"--- {e} (to {folder})")
                for ln in (e.detail or "").splitlines()[-6:]:    # VirtualBox's own words, made printable
                    if ln.strip():
                        on_line("    " + validate.printable(ln.strip())[:300])
        else:
            return 1
        target = codepush.guest_path(folder, bundle.name)
        return self.vbox.run([], 600, 64 * 1024, on_line, cancellable=True,
                             python_c=(codepush.guest_loader(), [self.s.guest_dir, target]))[0]
