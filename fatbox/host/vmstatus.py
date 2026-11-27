"""0.31.0: the header's VM badge in one word. Pure: built from VirtualBox's state, the Guest Additions run level,
FatBox's own VM action or job, and a few host-side clocks. Nothing here comes from the guest except the run level
and the job's progress count, and both are only display: they never enable a button or allow an action."""
from __future__ import annotations

import re

# tones map to the page's colours: ok green, warn amber, accent blue, muted grey, bad red
OK, WARN, ACCENT, MUTED, BAD = "ok", "warn", "accent", "muted", "bad"
NOT_READY_S = 600  # 0.39.3: was 300; the controller waits 10 min for a slow boot. VM on, Windows still not ready after this long: "not responding"
READY_LEVEL = 2    # Guest Additions run level 2 = Userland (VBoxService up: guest control works), 3 = Desktop
SAVED = {"saved", "abortedsaved", "aborted-saved"}
PROGRESS_RE = re.compile(r"^progress: (\d{1,3})/(\d{1,3})$")             # VM triage, one line per finished sample
FETCH_RE = re.compile(r"\[(\d{1,3})/(\d{1,3})\] [0-9a-f]{16} ")            # VM fetch, one line per download started
MAX_N = 30  # a run never has more samples than this (TRIAGE_PER_RUN, MAX_PICKS)


def run_level(raw: str | None) -> int | None:
    """VirtualBox's GuestAdditionsRunLevel. The guest reports it, so anything but 0..3 is "unknown"."""
    return int(raw) if raw in ("0", "1", "2", "3") else None


def progress(line: str, kind: str | None) -> tuple[int, int] | None:
    """(done, total) from one live-log line of a fetch or triage job, or None. The line is VM text, so the
    numbers are checked: 1 <= total <= 30, 0 <= done <= total."""
    m = PROGRESS_RE.match(line.strip()) if kind == "triage" else FETCH_RE.search(line) if kind == "fetch" else None
    if not m:
        return None
    done, total = int(m.group(1)), int(m.group(2))
    return (done, total) if 1 <= total <= MAX_N and 0 <= done <= total else None


def _b(key: str, label: str, tone: str, pulse: bool = False) -> dict:
    return {"key": key, "label": label, "tone": tone, "pulse": pulse}


def badge(state: str, level: int | None = None, action: str | None = None, revert_clean: bool = False,
          job: str | None = None, prog: tuple[int, int] | None = None, booted_s: float | None = None,
          was_ready: bool = False, shutdown_asked: bool = False) -> dict:
    """state: VirtualBox's VMState. level: run_level(). action: the VM button running now (start, revert...).
    job: the kind of the FatBox job running now, or None. booted_s: seconds since FatBox first saw this boot
    running. was_ready: Windows was ready earlier in this boot. shutdown_asked: FatBox pressed the power button."""
    if state in ("stuck", "gurumeditation"):
        return _b("not_responding", "not responding", BAD)
    if action == "revert" or state == "restoringsnapshot":
        return _b("reverting", "reverting to clean…" if revert_clean else "reverting…", WARN, True)
    if action == "start" or state in ("starting", "restoring"):
        return _b("booting", "booting…", WARN, True)
    if action == "shutdown":
        return _b("shutting_down", "shutting down…", WARN, True)
    if action == "poweroff":
        return _b("powering_off", "powering off…", WARN, True)
    if action == "snapshot" or state in ("snapshotting", "livesnapshotting", "onlinesnapshotting"):
        return _b("snapshot", "taking snapshot…", WARN, True)
    if action == "delete-snapshot" or state.startswith("deletingsnapshot"):
        return _b("snapshot", "deleting snapshot…", WARN, True)
    if job == "clean":  # the VM boots, shuts down and is snapshotted along the way: one word for all of it
        return _b("clean", "making clean snapshot…", WARN, True)
    if job == "revert":  # 0.38.0: the auto-revert job after a triage (restore, fresh boot, checks)
        return _b("reverting", "reverting to clean…", WARN, True)
    if job and state == "running" and level is not None and level < READY_LEVEL and was_ready:
        pass  # a job (auto-revert) is shutting Windows down: fall through to the state below
    elif job == "triage" and state != "running":
        return _b("reverting", "reverting to clean…", WARN, True)  # T-8 auto-revert after the analysis
    elif job in ("update", "triage", "fetch", "browse", "sync"):
        word = {"update": "updating FatBox", "triage": "analysing", "fetch": "fetching", "browse": "browsing",
                "sync": "copying reports"}[job]
        return _b(job, f"{word} {prog[0]}/{prog[1]}" if prog else word + "…", ACCENT, True)
    if state == "running":
        if shutdown_asked or (was_ready and level is not None and level < READY_LEVEL):
            return _b("shutting_down", "shutting down…", WARN, True)
        if level is None or level >= READY_LEVEL:  # unknown level (no Guest Additions info): trust "running"
            return _b("running", "running", OK)
        if booted_s is not None and booted_s > NOT_READY_S:
            return _b("not_responding", "not responding", BAD)
        return _b("booting", "booting…", WARN, True)
    if state in ("stopping", "saving"):
        return _b("shutting_down", "shutting down…", WARN, True)
    if state == "poweroff":
        return _b("off", "powered off", MUTED)
    if state in SAVED:
        return _b("saved", "saved", MUTED)
    if state == "aborted":
        return _b("crashed", "crashed", BAD)
    if state == "paused":
        return _b("paused", "paused", MUTED)
    if state == "unknown":
        return _b("not_responding", "not responding", BAD)
    return _b("other", state[:40], WARN, True)
