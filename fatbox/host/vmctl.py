"""VM control from the host: power, snapshots, NAT cable. Host-side VBoxManage only; nothing runs in the guest."""
from __future__ import annotations

import re
import subprocess
import threading
import time

from fatbox.host.lab import vbm_argv
from fatbox.host.labmap import as_int
from fatbox.host.settings import HostSettings
from fatbox.host.vbox import NO_WINDOW, GuestError, explain, short
from fatbox.host.vmstatus import READY_LEVEL, run_level

SNAP_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}\Z")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
# A VM with saved memory ("saved", or "abortedsaved" after a failed resume, VirtualBox 7). 0.18.1: FatBox never
# resumes one. Under Hyper-V (VirtualBox's NEM mode, used when Windows keeps VT-x for itself: Memory integrity,
# WSL2, Docker) resuming saved memory fails ("The VM session was closed before any attempt to power it on"), so
# FatBox drops the memory and boots fresh instead. A fresh boot is also the cleaner lab state.
SAVED_STATES = {"saved", "abortedsaved", "aborted-saved"}
OFF_STATES = {"poweroff", "aborted"} | SAVED_STATES
# VirtualBox briefly refuses session locks while a VM changes state (start, link change, snapshot):
# "E_ACCESSDENIED ... unexpected process has tried to lock the machine". Retrying a moment later works.
TRANSIENT = ("E_ACCESSDENIED", "VBOX_E_INVALID_OBJECT_STATE", "tried to lock the machine", "is already locked")


class VmControl:
    def __init__(self, s: HostSettings, run=subprocess.run, sleep=time.sleep, clock=time.monotonic):
        self.s = s
        self._run = run
        self._sleep = sleep
        self._clock = clock
        self._lock = threading.Lock()  # one VBoxManage call at a time from this GUI (polls vs actions)
        self.action_lock = threading.Lock()  # one VM action (start, revert, ...) at a time
        self.action: str | None = None
        self.action_note: str | None = None  # revert: "clean" when going back to the ★ default (badge wording)
        # 0.31.0 badge clocks, all host-side: when FatBox first saw this boot running, whether Windows was ready
        # in it, and when FatBox pressed the power button. Reset whenever the VM is seen off.
        self.boot_seen: float | None = None
        self.was_ready = False
        self.shutdown_at: float | None = None

    def _call(self, args: tuple[str, ...], timeout: int, retries: int = 4):
        for attempt in range(retries + 1):
            with self._lock:
                out = self._run(vbm_argv(self.s, args), capture_output=True, timeout=timeout,
                                creationflags=NO_WINDOW)
            err = out.stderr.decode(errors="replace")
            if out.returncode == 0 or attempt == retries or not any(t in err for t in TRANSIENT):
                return out
            self._sleep(1.5)

    def _vbm(self, *args: str, timeout: int = 120) -> str:
        out = self._call(args, timeout)
        if out.returncode != 0:
            err = out.stderr.decode(errors="replace").strip()
            raise GuestError(explain(err) or f"VBoxManage {args[0]} failed: {short(err) if err else 'exit %d' % out.returncode}",
                             err[-2000:])
        return out.stdout.decode(errors="replace")

    @staticmethod
    def _kv(text: str) -> dict[str, str]:
        out = {}
        for line in text.splitlines():
            m = re.match(r'^"?([^"=]+)"?="?(.*?)"?$', line.strip())
            if m:  # first wins: VirtualBox's own lines come before anything the guest additions report
                out.setdefault(m.group(1), m.group(2))
        return out

    # ---- read ------------------------------------------------------------
    def info(self) -> dict:
        kv = self._kv(self._vbm("showvminfo", self.s.vm, "--machinereadable", timeout=30))
        snaps, current = self.snapshots()
        state = kv.get("VMState", "unknown")
        level = run_level(kv.get("GuestAdditionsRunLevel"))
        self.track(state, level)
        return {"vm": self.s.vm, "state": state, "nic1": kv.get("nic1", "unknown"),
                "cable": kv.get("cableconnected1", "unknown"), "snapshots": snaps, "current_snapshot": current,
                "clean_snapshot": self.s.clean_snapshot, "action": self.action, "run_level": level,
                "memory_mb": as_int(kv.get("memory")), "cpus": as_int(kv.get("cpus"))}   # 0.41.0 Lab tab

    def track(self, state: str, level: int | None) -> None:
        """Keep the badge clocks (see __init__) in step with what VirtualBox just said."""
        if state != "running":
            if state in OFF_STATES:
                self.boot_seen, self.was_ready, self.shutdown_at = None, False, None
            return
        if self.boot_seen is None:
            self.boot_seen = self._clock()
        if level is not None and level >= READY_LEVEL:
            self.was_ready = True
            if self.shutdown_at is not None and self._clock() - self.shutdown_at > 120:
                self.shutdown_at = None  # Windows ignored the power button long ago and is still up

    def booted_s(self) -> float | None:
        return None if self.boot_seen is None else self._clock() - self.boot_seen

    def snapshots(self) -> tuple[list[str], str | None]:
        rows, current = self.snapshot_list()
        return [r["name"] for r in rows], next((r["name"] for r in rows if r["uuid"] == current), None)

    def snapshot_list(self) -> tuple[list[dict], str | None]:
        """[{name, uuid}] in VirtualBox's order, and the current snapshot's uuid. The uuid is how FatBox
        recognises a snapshot it checked, even after a rename (T-8)."""
        out = self._call(("snapshot", self.s.vm, "list", "--machinereadable"), 30)
        if out.returncode != 0:  # "This machine does not have any snapshots" exits non-zero
            return [], None
        kv = self._kv(out.stdout.decode(errors="replace"))
        rows = []
        for k, name in kv.items():
            if k.startswith("SnapshotName"):
                uuid = kv.get("SnapshotUUID" + k[len("SnapshotName"):], "")
                if UUID_RE.match(uuid):
                    rows.append({"name": name, "uuid": uuid.lower()})
        cur = kv.get("CurrentSnapshotUUID", "")
        return rows, cur.lower() if UUID_RE.match(cur) else None

    def state(self) -> str:
        return self._kv(self._vbm("showvminfo", self.s.vm, "--machinereadable", timeout=30)).get("VMState", "unknown")

    def state_since(self) -> tuple[str, str]:
        """(VMState, VMStateChangeTime), one host-side call. The time changes whenever the VM starts, stops or is
        restored, so it names this boot (0.38.0: the host remembers a passed version check for it)."""
        kv = self._kv(self._vbm("showvminfo", self.s.vm, "--machinereadable", timeout=30))
        return kv.get("VMState", "unknown"), kv.get("VMStateChangeTime", "")

    def cable(self) -> str:
        """"on" / "off" as VirtualBox itself reports NIC 1's cable (never what the guest says)."""
        return self._kv(self._vbm("showvminfo", self.s.vm, "--machinereadable", timeout=30)).get("cableconnected1", "unknown")

    # ---- power -----------------------------------------------------------
    def start(self, headless: bool) -> None:
        """Start with the network cable OUT (INV-7). A snapshot or an old setting may have it plugged in, and a
        VM that boots with it would be online from the first second. Unplug in the saved settings first, start,
        then check with VirtualBox and unplug again if the VM came up with it in anyway."""
        self.discard_saved()  # 0.18.1: always a fresh boot (see SAVED_STATES)
        if self.state() in OFF_STATES:
            try:
                self._vbm("modifyvm", self.s.vm, "--cableconnected1", "off")
            except GuestError:
                pass  # VirtualBox busy: handled right after start
        self._vbm("startvm", self.s.vm, "--type", "headless" if headless else "gui")
        self._cable_out_after_start()

    def _cable_out_after_start(self, timeout_s: int = 60) -> None:
        for _ in range(timeout_s * 2):
            state = self.state()
            if state == "running":
                break
            if state in ("poweroff", "aborted"):
                raise GuestError(f"the VM stopped right after starting ('{state}')")
            self._sleep(0.5)
        else:
            raise GuestError("the VM did not reach 'running' in time; check the Network badge before using it")
        for attempt in range(3):
            if self.cable() == "off":
                return
            if attempt:
                self._sleep(1.5)
            try:
                self._vbm("controlvm", self.s.vm, "setlinkstate1", "off")
            except GuestError:
                pass
        if self.cable() != "off":
            raise GuestError("the VM started with its network ON and FatBox could not unplug it: "
                             "click Disconnect, or power off the VM")

    def discard_saved(self) -> bool:
        """Drop a saved memory image so the next start is a fresh boot from the disk. True if one was dropped."""
        if self.state() not in SAVED_STATES:
            return False
        self._vbm("discardstate", self.s.vm)
        return True

    def shutdown(self) -> None:
        """Clean shutdown (ACPI power button). Windows may ignore it; Power off is the fallback."""
        self._vbm("controlvm", self.s.vm, "acpipowerbutton")
        self.shutdown_at = self._clock()

    def poweroff(self) -> None:
        self._vbm("controlvm", self.s.vm, "poweroff")

    def _wait_off(self, timeout_s: int = 60) -> None:
        for _ in range(timeout_s * 2):
            if self.state() in OFF_STATES:
                return
            self._sleep(0.5)
        raise GuestError("VM did not power off in time")

    # ---- snapshots -------------------------------------------------------
    def take(self, name: str, description: str = "taken from fatbox host GUI") -> str | None:
        """Returns the new snapshot's uuid (None if VirtualBox didn't list it)."""
        if not SNAP_RE.match(name or ""):
            raise ValueError("snapshot name: letters, digits, . _ - only (max 64)")
        if name in self.snapshots()[0]:
            raise ValueError(f"snapshot {name!r} already exists")
        self._vbm("snapshot", self.s.vm, "take", name, "--description", description, timeout=600)
        return next((r["uuid"] for r in self.snapshot_list()[0] if r["name"] == name), None)

    def delete_snapshot(self, uuid: str) -> None:
        """Delete one snapshot by uuid. VirtualBox merges its disk into the next one, which can take minutes."""
        if not UUID_RE.match(uuid or "") or uuid.lower() not in {r["uuid"] for r in self.snapshot_list()[0]}:
            raise ValueError("no such snapshot")
        self._vbm("snapshot", self.s.vm, "delete", uuid.lower(), timeout=1800)

    def revert(self, ref: str) -> None:
        """Power off if needed, then restore (ref: a snapshot's name or uuid). Discards everything since the
        snapshot. The VM is left powered off; Start boots it fresh. 0.18.1: a snapshot taken while the VM ran
        (FatBox before 0.18.1) holds memory: it is dropped, because resuming it fails under Hyper-V."""
        rows = self.snapshot_list()[0]
        hit = next((r for r in rows if ref and ref.lower() == r["uuid"]), None) or \
            next((r for r in rows if r["name"] == ref), None)
        if hit is None:
            raise ValueError(f"no snapshot named {ref!r}")
        if self.state() not in OFF_STATES:
            self.poweroff()
            self._wait_off()
        self._vbm("snapshot", self.s.vm, "restore", hit["uuid"], timeout=600)
        self.discard_saved()
        if self.state() in ("poweroff", "aborted"):  # the snapshot may have the cable in; Start unplugs it anyway
            try:
                self._vbm("modifyvm", self.s.vm, "--cableconnected1", "off")
            except GuestError:
                pass

    # ---- network ---------------------------------------------------------
    def set_network(self, on: bool) -> None:
        """Connect/disconnect NIC 1's virtual cable. Keeps the NAT config; off = no network at all."""
        flag = "on" if on else "off"
        if self.state() in OFF_STATES:
            self._vbm("modifyvm", self.s.vm, "--cableconnected1", flag)
        else:
            self._vbm("controlvm", self.s.vm, "setlinkstate1", flag)
