"""Host GUI: control fetching in the VM and read reports, from a browser on the host (127.0.0.1 only)."""
from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import json
import secrets
import subprocess
import logging
import re
import threading
import time
import webbrowser
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fatbox.host.controller import Controller, browse_args, fetch_args
from fatbox.host.validate import Invalid
from fatbox.host.vbox import GuestError
from fatbox.host.vmctl import OFF_STATES, VmControl
from fatbox.host.vmstatus import badge, progress

log = logging.getLogger("fatbox.host")
PAGE = Path(__file__).with_name("page.html")
# 0.27.0: the only file served besides the page: the browser tab icon. A fixed name, never a path from the URL.
ASSETS = {"/assets/favicon.png": ("favicon.png", "image/png"),
          # 0.43.0: Theodor Kittelsen, Svartedauden (1900), public domain (assets/art/CREDITS.txt)
          "/assets/art/pesta.jpg": ("art/pesta.jpg", "image/jpeg"),
          "/assets/art/forest.jpg": ("art/forest.jpg", "image/jpeg"),
          "/assets/art/ravens.jpg": ("art/ravens.jpg", "image/jpeg")}


class Job:
    """The single background VM job (browse, fetch, triage, update...) and its live log."""

    def __init__(self, ctl: Controller):
        self.ctl = ctl
        self.lock = threading.Lock()
        self.kind, self.state, self.rc, self.started, self.error = None, "idle", None, None, None
        self.detail = ""  # VirtualBox's raw text for a failed job, shown in the GUI only behind "details"
        self.result: list | None = None  # browse: the checked candidate rows
        self.lines: collections.deque[tuple[int, str]] = collections.deque(maxlen=1000)
        self.seq = 0
        self.progress: tuple[int, int] | None = None  # 0.31.0: fetch/triage "done/total" for the VM badge
        self.triage_rc: int | None = None  # 0.38.0: the triage's exit code when a revert job followed it

    def add(self, text: str) -> None:
        with self.lock:
            self.seq += 1
            self.lines.append((self.seq, text))
            p = progress(text, self.kind) if self.state == "running" else None
            if p:
                self.progress = p

    def badge_job(self) -> tuple[str | None, tuple[int, int] | None]:
        """(kind, progress) of the job running now, or (None, None)."""
        with self.lock:
            return (self.kind, self.progress) if self.state == "running" else (None, None)

    def start(self, opts: dict, kind: str = "fetch") -> None:
        if kind == "fetch":  # 0.29.0: download only, exactly the Browse picks; Triage is its own job
            if opts.get("pick") is None:
                raise ValueError("Browse first, then tick the samples to fetch")
            fetch_args(opts)  # validate before spawning anything
            work = lambda: self._fetch(opts)  # noqa: E731
            shown = {k: opts.get(k) for k in sorted(opts) if k != "pick"}
            shown["picked"] = len(opts["pick"])
            label = json.dumps(shown)
        elif kind == "triage":
            work, label = (lambda: self.ctl.triage(self.add, revert_now=False)), ""
        elif kind == "browse":
            browse_args(opts)
            work = lambda: self._browse(opts)  # noqa: E731
            label = json.dumps({k: opts.get(k) for k in ("mode", "value", "limit")})
        elif kind == "sync":
            work, label = self._sync, ""
        elif kind == "clean":
            work, label = (lambda: self.ctl.make_clean_snapshot(self.add)), ""
        else:
            work, label = (lambda: self.ctl.update_vm(self.add)), ""
        with self.lock:
            if self.state == "running":
                raise GuestError(f"a {self.kind} is already running")
            self.kind, self.state, self.rc, self.started, self.error = kind, "running", None, time.time(), None
            self.detail, self.result, self.progress, self.triage_rc = "", None, None, None
        self.add(f"--- {kind} started {label}".rstrip())
        threading.Thread(target=self._run, args=(work,), daemon=True).start()

    def _run(self, work) -> None:
        try:
            rc = work()
            with self.lock:
                if self.kind == "triage" and self.ctl.revert_due:
                    # 0.38.0: every report is in the library, so the Triage tab can show them now, while the VM
                    # goes back to its clean snapshot as a job of its own. The job never leaves "running" in
                    # between, so nothing (Fetch, Update VM, a VM button) can slip in before the revert.
                    self.ctl.revert_due = False
                    self.kind, self.rc, self.started, self.progress = "revert", None, time.time(), None
                    self.triage_rc = rc
                    chained = True
                else:
                    self.rc, self.state = rc, "done" if rc == 0 else "failed"
                    chained = False
            if chained:
                self.add(f"--- triage {'done' if rc == 0 else 'failed'} (exit {rc}); reports are in the library")
                self.add("--- revert started (in the background: Fetch and the VM buttons wait for it)")
                return self._run(self._revert)
        except (GuestError, Invalid, ValueError) as e:  # expected: say it in plain words, keep the raw text aside
            log.info("%s job: %s", self.kind, e)
            with self.lock:
                self.state, self.error, self.detail = "failed", str(e), getattr(e, "detail", "")
        except Exception as e:
            log.exception("%s job", self.kind)
            with self.lock:
                self.state, self.error = "failed", f"{type(e).__name__}: {e}"
        self.add(f"--- {self.kind} {self.state}" + (f" (exit {self.rc})" if self.rc is not None else "")
                 + (f": {self.error}" if self.error else ""))

    def _revert(self) -> int:
        """0.38.0: the auto-revert after a triage, as its own job (see _run). A failure is said, never hidden."""
        from fatbox.host.controller import NetworkStillOn
        try:
            self.ctl.auto_revert(self.add)
        except NetworkStillOn:
            raise
        except (GuestError, ValueError, OSError) as e:
            self.add(f"--- ⚠ auto-revert failed: {e}")
            return 1
        return 0

    def _browse(self, opts: dict) -> int:
        rows = self.ctl.browse(opts, self.add)
        with self.lock:
            self.result = rows
        return 0

    def _fetch(self, opts: dict) -> int:
        rc, rows = self.ctl.download(opts, self.add)
        with self.lock:
            self.result = rows
        return rc

    def _sync(self) -> int:
        self.ctl.sync_library(self.add)
        return 0

    def running(self) -> bool:
        with self.lock:
            return self.state == "running"

    def snapshot(self, since: int) -> dict:
        with self.lock:
            return {"kind": self.kind, "state": self.state, "rc": self.rc, "error": self.error, "detail": self.detail,
                    "started": self.started, "result": self.result if self.kind in ("browse", "fetch") else None,
                    # 0.33.0: the Fetch tab label shows it ("Fetching 2 of 3"); checked numbers, display only
                    "progress": list(self.progress) if self.state == "running" and self.progress else None,
                    "lines": [{"n": n, "t": t} for n, t in self.lines if n > since]}


def page_csp(page: bytes) -> str:
    """CSP that lets exactly the page's own inline script run, by its hash. With 'unsafe-inline', markup that
    ever slipped into the page (say <img onerror=...> in a VM string) could run code; with a hash it can't."""
    m = re.search(rb"<script>(.*?)</script>", page, re.S)
    # Browsers hash the script text after HTML turns CRLF into LF; a Windows checkout has CRLF on disk.
    body = m.group(1).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode()
    return (f"default-src 'none'; script-src 'sha256-{digest}'; style-src 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def report_view(rep: dict) -> dict:
    """0.30.0: the report as checked, plus a few words the host adds for the summary at the top (never stored,
    never from the VM): the categories its family and tags fall in, by the same presets Browse uses."""
    from fatbox.fetch.meta import categories
    meta = rep.get("source_meta") if isinstance(rep.get("source_meta"), dict) else {}
    sig = meta.get("signature") if isinstance(meta.get("signature"), str) else ""
    tags = [t for t in meta.get("tags") or [] if isinstance(t, str)]
    return {**rep, "host_view": {"categories": categories({"signature": sig, "tags": tags})}}


class Unsaved(ValueError):
    """Revert asked while some reports could not be copied to the library: the page asks "revert anyway?"."""


RUNNING, OFF = {"running"}, set(OFF_STATES)
# 0.39.3: a VM that hangs (Windows ignores ACPI, stuck while stopping or starting) must still be pulled out
HUNG = {"paused", "stuck", "gurumeditation", "stopping", "starting"}
# action -> VM states it may start from. Anything else (restoring, snapshotting...) is refused.
# 0.39.3: snapshots only while the VM is off. A snapshot of a running VM saves its RAM to a .sav file on the
# host, and that RAM can hold plain sample bytes (INV-1, INV-2).
VM_ACTIONS = {"start": OFF, "shutdown": RUNNING, "poweroff": RUNNING | HUNG, "network": RUNNING | OFF,
              "snapshot": OFF, "revert": RUNNING | HUNG | OFF, "delete-snapshot": RUNNING | OFF}


def vm_action(vm: VmControl, job: Job, action: str, body: dict) -> None:
    """One VM action at a time, only from a state where it makes sense. Destructive ones, and turning the
    network on by hand, need {"confirm": true} (the page asks first) and no job running. Revert copies the
    VM's reports into the host library first; if that fails it stops, unless {"unsaved_ok": true}."""
    if action not in VM_ACTIONS:
        raise LookupError(action)
    if (action in ("poweroff", "revert", "delete-snapshot") or (action == "network" and body.get("on"))) \
            and body.get("confirm") is not True:
        raise ValueError("confirmation required")
    if not vm.action_lock.acquire(blocking=False):
        raise ValueError(f"wait: '{vm.action or 'another action'}' is still in progress")
    try:
        # 0.19.2: checked while holding the lock that starting a job also takes, so a job and a VM button
        # pressed at the same moment can't both go ahead
        if job.running():  # a job may stop, start or revert the VM itself (T-8): nothing else touches it meanwhile
            raise ValueError(f"a {job.kind or 'job'} is running in the VM; wait or cancel it first")
        vm.action = action
        if action == "revert":
            d = job.ctl.snapshot_view()["default"]
            name = str(body.get("name", ""))
            vm.action_note = "clean" if d and name in (d["name"], d["uuid"]) else None
        state = vm.state()
        if state not in VM_ACTIONS[action]:
            raise ValueError(f"can't {action} while the VM is '{state}'")
        if action == "start":
            vm.start(headless=bool(body.get("headless", True)))
        elif action == "shutdown":
            vm.shutdown()
        elif action == "poweroff":
            vm.poweroff()
        elif action == "snapshot":
            vm.take(str(body.get("name", "")))
        elif action == "revert":
            name = str(body.get("name", ""))
            if name not in vm.snapshots()[0] and name.lower() not in {r["uuid"] for r in vm.snapshot_list()[0]}:
                raise ValueError(f"no snapshot named {name!r}")
            # T-7: the revert wipes the VM's reports; copy them to the host library first
            if state == "running" and body.get("unsaved_ok") is not True:
                problem = job.ctl.save_before_revert(job.add)
                if problem:
                    raise Unsaved(problem)
            vm.revert(name)
            job.ctl.library.mark_all_gone()
            job.add(f"--- VM reverted to '{name}' and left off (Start boots it fresh); its reports stay in the library")
        elif action == "network":
            vm.set_network(bool(body.get("on")))
        elif action == "delete-snapshot":
            uuid = str(body.get("uuid", "")).lower()
            d = job.ctl.snapshot_view()["default"]
            if d and d["uuid"] == uuid:
                raise ValueError("this is the default snapshot: pick another default first")
            vm.delete_snapshot(uuid)
    finally:
        vm.action = vm.action_note = None
        vm.action_lock.release()


def make_handler(ctl: Controller, job: Job, port: int, token: str, vm: VmControl | None = None,
                 on_quit=None):
    vm = vm or ctl.vm
    """token: per-run secret. VirtualBox NAT can map the host's loopback into the guest (10.0.2.2), so a
    127.0.0.1 bind alone does not keep the VM out. Every request must carry the token cookie, which only
    the browser opened from the console URL gets."""
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    def vm_info() -> dict:
        info = vm.info()
        d = ctl.snapshot_view()["default"]  # T-8: the default FatBox remembers (host.toml only as fallback)
        info["clean_snapshot"] = d["name"] if d else ""
        kind, prog = job.badge_job()
        info["badge"] = badge(info["state"], info.get("run_level"), vm.action, vm.action_note == "clean", kind, prog,
                              vm.booted_s(), vm.was_ready, vm.shutdown_at is not None)
        info["lab"] = {"layout": ctl.s.lab.layout, "address": ctl.s.lab.address, "problem": ctl.lab_problem()}
        return info

    def lab_map() -> dict:
        """0.41.0 Lab tab: this PC, its test VM and whether another VM of that size would fit in RAM."""
        from fatbox import __version__
        from fatbox.host.labmap import fits, host_memory
        info = vm_info()
        remote = ctl.s.lab.remote
        mem = None if remote else host_memory()
        size = info.get("memory_mb") or 0
        host = {"total_mb": mem[0], "free_mb": mem[1]} if mem else None
        return {"version": __version__, "layout": ctl.s.lab.layout, "address": ctl.s.lab.address, "host": host,
                "another_fits": fits(mem[1], size) if mem and size else None,
                "vms": [{"name": info["vm"], "active": True, "state": info["state"], "memory_mb": info.get("memory_mb"),
                         "cpus": info.get("cpus"), "clean_snapshot": info.get("clean_snapshot") or "",
                         "cable": info.get("cable"), "badge": info.get("badge")}]}

    def lab_view() -> dict:
        """Settings → Lab layout (0.37.0). Host-side values only; the check results are FatBox's own words."""
        from fatbox.host import lab as labmod
        pub = labmod.key_path(ctl.s).with_suffix(".pub")
        return {"lab": {"layout": ctl.s.lab.layout, "address": ctl.s.lab.address, "login": ctl.s.lab.login,
                        "port": ctl.s.lab.port},
                "vm": ctl.s.vm, "guest_user": ctl.s.guest_user, "guest_python": ctl.s.guest_python,
                "has_key": pub.exists(),
                "public_key": pub.read_text(encoding="ascii").strip() if pub.exists() else "",
                "pinned": labmod.is_pinned(ctl.s),
                "results": [{"status": st, "text": tx} for st, tx in (ctl.lab_results or [])],
                "checked": ctl.lab_results is not None}

    def lab_idle() -> None:
        if job.running() or vm.action:
            raise ValueError("wait: a fetch, update or VM action is running")
    page = PAGE.read_bytes()
    csp = page_csp(page)

    class Handler(BaseHTTPRequestHandler):
        server_version = "fatbox-host"

        def log_message(self, fmt, *args):
            log.debug(fmt, *args)

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", csp)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _has_token(self) -> bool:
            try:
                c = SimpleCookie(self.headers.get("Cookie") or "").get("fbx")
            except CookieError:
                return False
            return c is not None and hmac.compare_digest(c.value.encode(), token.encode())

        def _guard(self) -> bool:
            # Host check blocks DNS rebinding; the custom header blocks cross-site POSTs; the token keeps out
            # anything that did not get the console URL (including the VM via NAT loopback).
            if self.headers.get("Host") not in allowed_hosts:
                self._json({"error": "bad host"}, 403)
                return False
            u = urlparse(self.path)
            given = parse_qs(u.query).get("t", [""])[0]
            if self.command == "GET" and u.path == "/" and given:
                if not hmac.compare_digest(given.encode(), token.encode()):
                    self._json({"error": "bad token"}, 403)
                    return False
                self.send_response(303)
                self.send_header("Set-Cookie", f"fbx={token}; HttpOnly; SameSite=Strict; Path=/")
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return False
            if not self._has_token():
                self._json({"error": "open the URL printed in the console (it carries the access token)"}, 403)
                return False
            if self.command == "POST" and self.headers.get("X-FatBox") != "1":
                self._json({"error": "missing X-FatBox header"}, 403)
                return False
            return True

        def _errors(self, fn) -> None:
            try:
                fn()
            except (GuestError, Invalid) as e:
                self._json({"error": str(e), "detail": getattr(e, "detail", "")}, 502)
            except ValueError as e:
                self._json({"error": str(e)}, 400)
            except Exception as e:
                log.exception("%s %s", self.command, self.path)
                self._json({"error": f"{type(e).__name__}: {e}"}, 500)

        def do_GET(self):
            if not self._guard():
                return
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/":
                return self._send(200, page, "text/html; charset=utf-8")
            if u.path in ASSETS:
                name, ctype = ASSETS[u.path]
                return self._send(200, (PAGE.parent / "assets" / name).read_bytes(), ctype)
            routes = {
                "/api/vm": lambda: self._json(vm_info()),
                "/api/snapshots": lambda: self._json({**ctl.snapshot_view(), "notes": ctl.snaps.take_notes()}),
                "/api/library": lambda: self._json({"rows": ctl.library.rows(), "notes": ctl.library.take_notes()}),
                "/api/report": lambda: self._json(report_view(ctl.report(q.get("sha256", ""), q.get("refresh") == "1"))),
                "/api/job": lambda: self._json(job.snapshot(int(q.get("since", 0)))),
                "/api/version": lambda: self._json(ctl.version_check()),
                # 0.29.0: samples waiting for triage (Fetch tab step 3); not while a job uses the VM
                "/api/pending": lambda: self._json({"busy": True, "rows": []} if job.running()
                                                   else {"busy": False, "rows": ctl.pending()}),
                "/api/prefs": lambda: self._json({"prefs": ctl.prefs.load(), "notes": ctl.prefs.take_notes()}),
                "/api/lab": lambda: self._json(lab_view()),
                "/api/labmap": lambda: self._json(lab_map()),
            }
            if u.path not in routes:
                return self._json({"error": "not found"}, 404)
            self._errors(routes[u.path])

        def do_POST(self):
            if not self._guard():
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if not 0 <= length <= 64 * 1024:  # a negative length would read until the client hangs up
                return self._json({"error": "bad Content-Length"}, 400)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            if self.path in ("/api/fetch", "/api/triage", "/api/update-vm", "/api/browse", "/api/sync", "/api/clean-snapshot"):
                def start():
                    problem = ctl.lab_problem() if self.path != "/api/sync" else None
                    if problem:  # 0.37.0: a failed lab check blocks every job that uses the VM
                        raise ValueError(f"Lab check failed: {problem} Fix it in Settings → Lab layout, then Test connection.")
                    if not vm.action_lock.acquire(blocking=False):  # 0.19.2: same lock as the VM buttons
                        raise ValueError(f"wait: '{vm.action or 'another action'}' is still in progress")
                    try:
                        job.start(body, {"/api/fetch": "fetch", "/api/triage": "triage", "/api/browse": "browse", "/api/sync": "sync",
                                         "/api/clean-snapshot": "clean"}.get(self.path, "update"))
                    finally:
                        vm.action_lock.release()
                    self._json({"ok": True})
                self._errors(start)
            elif self.path == "/api/snapshots/default":
                self._errors(lambda: self._json({"default": ctl.set_default_snapshot(body.get("uuid"))}))
            elif self.path == "/api/settings":
                def settings():
                    ctl.set_auto_revert(body.get("auto_revert"))
                    self._json({"ok": True})
                self._errors(settings)
            elif self.path == "/api/prefs":  # 0.23.0 Settings tab: checked in prefs.check, saved on the host only
                def prefs():
                    if body.get("reset") is True:
                        return self._json({"prefs": ctl.prefs.reset()})
                    if job.running():
                        raise ValueError("wait: a fetch is running; save Settings after it ends")
                    self._json({"prefs": ctl.prefs.save(body.get("prefs"))})
                self._errors(prefs)
            elif self.path in ("/api/library/save", "/api/library/discard"):  # 0.26.0: the New view's buttons
                def keep():
                    if self.path.endswith("/save"):
                        return self._json({"saved": ctl.library.save(body.get("sha256"))})
                    if body.get("confirm") is not True:
                        raise ValueError("confirmation required")
                    self._json({"discarded": ctl.library.discard(body.get("sha256"))})
                self._errors(keep)
            elif self.path == "/api/library/delete":
                def delete():
                    if body.get("confirm") is not True:
                        raise ValueError("confirmation required")
                    self._json({"deleted": ctl.library.delete(body.get("sha256"))})
                self._errors(delete)
            elif self.path == "/api/lab/save":  # 0.37.0: Settings → Lab layout
                def lab_save():
                    from fatbox.host.settings import save_lab
                    lab_idle()
                    ctl.s.lab = save_lab(ctl.s.home, body.get("lab"))
                    ctl.lab_reset()
                    self._json(lab_view())
                self._errors(lab_save)
            elif self.path == "/api/lab/pair":
                def lab_pair():
                    from fatbox.host.lab import make_key
                    make_key(ctl.s)
                    self._json(lab_view())
                self._errors(lab_pair)
            elif self.path == "/api/lab/check":
                def lab_check():
                    lab_idle()
                    ctl.lab_check()
                    self._json(lab_view())
                self._errors(lab_check)
            elif self.path == "/api/lab/forget-key":  # the test PC was reinstalled: pin its new key on the next check
                def lab_forget():
                    from fatbox.host.lab import known_hosts
                    if body.get("confirm") is not True:
                        raise ValueError("confirmation required")
                    lab_idle()
                    known_hosts(ctl.s).unlink(missing_ok=True)
                    ctl.lab_reset()
                    self._json(lab_view())
                self._errors(lab_forget)
            elif self.path == "/api/cancel":
                running = job.running()
                if running:
                    ctl.cancel()
                self._json({"cancelled": running})
            elif self.path == "/api/quit":
                # 0.20.0: the only way to stop a host started without a console window (pythonw shortcut)
                def quit_():
                    if job.running() or vm.action:
                        raise ValueError("wait: a fetch, update or VM action is still running (cancel it first)")
                    if on_quit is None:
                        raise ValueError("quit is not available here")
                    self._json({"ok": True})
                    threading.Thread(target=on_quit, daemon=True).start()
                self._errors(quit_)
            elif self.path.startswith("/api/vm/"):
                action = self.path[len("/api/vm/"):]

                def act():
                    try:
                        vm_action(vm, job, action, body)
                    except LookupError:
                        return self._json({"error": "not found"}, 404)
                    except Unsaved as e:
                        return self._json({"error": str(e), "unsaved": True}, 409)
                    self._json({"ok": True})
                self._errors(act)
            else:
                self._json({"error": "not found"}, 404)

    return Handler


URL_FILE = "gui-url.txt"  # in the host home: lets a second shortcut click open the running GUI


def _running_url(home: Path, port: int) -> str | None:
    """The URL of a FatBox host already serving on this port (from a second shortcut click), else None."""
    try:
        url = (home / URL_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not re.fullmatch(rf"http://127\.0\.0\.1:{port}/\?t=[A-Za-z0-9_-]{{20,100}}", url):
        return None
    import http.client
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/api/version", headers={"Host": f"127.0.0.1:{port}"})
        server = conn.getresponse().getheader("Server") or ""
        conn.close()
    except OSError:
        return None
    return url if server.startswith("fatbox-host") else None


def serve(ctl: Controller, open_browser: bool = True) -> None:
    port = ctl.s.port
    running = _running_url(ctl.s.home, port)
    if running:  # already open (e.g. the shortcut clicked twice): show it instead of failing on the busy port
        print(f"FatBox host is already running: {running}")
        if open_browser:
            webbrowser.open(running)
        return
    token = secrets.token_urlsafe(32)
    job = Job(ctl)
    try:
        notice = ctl.startup_check()
    except (GuestError, subprocess.SubprocessError, OSError) as e:  # VirtualBox not reachable yet, or VBoxManage
        # or ssh missing (0.39.3): say so, the GUI still starts and Settings > Lab layout can explain
        notice = f"could not check the VM's network at start: {e}"
    if notice:
        print("WARNING: " + notice)
        job.add("--- ⚠ " + notice)
    # 0.37.0: check the lab in the background (an unreachable test PC must not delay the GUI)
    threading.Thread(target=ctl.lab_check, daemon=True).start()
    branch = ctl.branch()
    if branch and branch != "main":
        note = (f"this host runs FatBox from git branch '{branch}', not main. Normal use: "
                "git checkout main, then git pull (Update VM only installs what is on main).")
        print("NOTE: " + note)
        job.add("--- note: " + note)
    holder: list[ThreadingHTTPServer] = []
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port),
                                    make_handler(ctl, job, port, token, on_quit=lambda: holder[0].shutdown()))
    except OSError as e:
        raise ValueError(f"port {port} on 127.0.0.1 is busy ({e}). Another program uses it, "
                         "or FatBox is still stopping: try again, or set another port in host.toml") from e
    holder.append(httpd)
    url = f"http://127.0.0.1:{port}/?t={token}"
    url_file = ctl.s.home / URL_FILE
    try:
        url_file.write_text(url + "\n", encoding="utf-8")
    except OSError:
        log.warning("could not write %s; a second shortcut click won't find this GUI", url_file)
    print(f"FatBox host GUI on {url}  (VM: {ctl.s.vm}; stop with Quit in the page, or Ctrl+C here)", flush=True)
    log.info("GUI started on 127.0.0.1:%d", port)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        try:
            if url_file.read_text(encoding="utf-8").strip() == url:
                url_file.unlink()
        except OSError:
            pass
        log.info("GUI stopped")
