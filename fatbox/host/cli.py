"""python -m fatbox.host  {init,check,gui,list,report,fetch,update-vm,shortcut,lab}  (runs on the HOST)."""
from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import subprocess
import sys
from pathlib import Path

from fatbox.host.controller import Controller
from fatbox.host.settings import load_settings, write_example
from fatbox.host.validate import Invalid
from fatbox.host.vbox import GuestError


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fatbox.host", description="Control fatbox in the VM from the host")
    p.add_argument("--settings", help=r"default: %%APPDATA%%\fatbox-host\host.toml")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="write an example host.toml to fill in")
    sub.add_parser("check", help="VM state + compare FatBox versions in VM and host")
    g = sub.add_parser("gui", help="host browser UI on 127.0.0.1")
    g.add_argument("--no-browser", action="store_true")
    sub.add_parser("list", help="list samples in the VM")
    r = sub.add_parser("report", help="get one validated report from the VM")
    r.add_argument("sha256")
    f = sub.add_parser("fetch", help="fetch in the VM (network on only while downloading), then triage offline")
    f.add_argument("--mode", default="recent")
    f.add_argument("--value", default="")
    f.add_argument("--max", type=int, default=3, help="samples, 1..30")
    f.add_argument("--max-size-mb", type=int, default=5, help="download limit in MB, 1..100")
    f.add_argument("--no-size-limit", action="store_true", help="no download limit (the 100 MB unpacked cap stays)")
    f.add_argument("--budget", type=int, default=400, help="time budget for the whole fetch, 60..1800 s")
    f.add_argument("--small-first", action="store_true")
    sub.add_parser("update-vm", help="update FatBox in the VM (network on only while it runs)")
    lb = sub.add_parser("lab", help="two-machine lab (T-19): pair = make this PC's key, check = test the link")
    lb.add_argument("action", choices=["pair", "check"])
    sub.add_parser("shortcut", help="put a 'FatBox Host' shortcut on the desktop that opens the GUI with no console window")
    windowless = sys.stdout is None or sys.stderr is None  # started by pythonw.exe (the desktop shortcut)
    try:
        args = p.parse_args(argv)
    except SystemExit:
        if windowless:
            _message_box("FatBox host: bad command line in the shortcut. Run 'python -m fatbox.host shortcut' again.")
        raise
    level = logging.DEBUG if args.verbose else logging.INFO
    if windowless:
        try:
            _log_to_file(args.settings, level)
        except OSError as e:
            _message_box(f"FatBox host could not open its log file:\n\n{e}")
            return 2
    else:
        logging.basicConfig(level=level, format="%(levelname)-7s %(message)s")

    if args.cmd == "shortcut":
        return make_shortcut()
    if args.cmd == "init":
        try:
            print(f"wrote {write_example(args.settings)}  -> edit it, then create the password_file it names")
            return 0
        except FileExistsError as e:
            print(e, file=sys.stderr)
            return 1
    try:
        if args.cmd == "lab":
            return lab_cmd(args.action, load_settings(args.settings))
        ctl = Controller(load_settings(args.settings))
        if args.cmd == "check":
            print(f"VM '{ctl.s.vm}': {ctl.vbox.vm_state()}")
            v = ctl.version_check()
            print(f"guest: FatBox {v['vm'] or '(unknown version)'}, host: FatBox {v['host']}")
            if not v["ok"]:
                print(v["message"], file=sys.stderr)
                return 1
            print("versions match")
        elif args.cmd == "gui":
            from fatbox.host.server import serve
            serve(ctl, open_browser=not args.no_browser)
        elif args.cmd == "list":
            for r in ctl.list_samples():
                print(f"{r['status']:<12} {r['priority'] or '-':>6} {r['score'] if r['score'] is not None else '-':>3}  "
                      f"{r['sha256'][:16]}  {r['signature'] or '-':<20} {r['file_type'] or '-'}")
        elif args.cmd == "report":
            print(json.dumps(ctl.report(args.sha256), indent=1))
        elif args.cmd == "fetch":
            opts = {"mode": args.mode, "value": args.value, "max": args.max, "max_size_mb": args.max_size_mb,
                    "size_limit": not args.no_size_limit, "budget": args.budget, "small_first": args.small_first}
            return ctl.fetch(opts, print)
        elif args.cmd == "update-vm":
            return ctl.update_vm(print)
        return 0
    except (FileNotFoundError, ValueError, GuestError, Invalid) as e:
        print(f"error: {e}", file=sys.stderr)
        if windowless:
            _message_box(f"FatBox host could not start:\n\n{e}")
        return 2
    except Exception as e:  # no console to show a traceback in: log it and say so
        if not windowless:
            raise
        logging.getLogger("fatbox.host").exception("unexpected error")
        _message_box(f"FatBox host stopped with an error:\n\n{type(e).__name__}: {e}\n\nDetails: {LOG_NAME} in the host folder.")
        return 3


def lab_cmd(action: str, s) -> int:
    from fatbox.host import lab
    if action == "pair":
        made, pub = lab.make_key(s)
        print(("made" if made else "kept") + f" this PC's lab key: {lab.key_path(s)}")
        print("\nOn the test PC (the one whose VirtualBox holds the test VM), in PowerShell 'Run as administrator',")
        print("in the FatBox folder's scripts\\lab, run (HOST_IP = this PC's IP on the link to the test PC):\n")
        print(f'  powershell -ExecutionPolicy Bypass -File .\\lab-setup.ps1 -HostAddress HOST_IP -PublicKey "{pub}"\n')
        print("Then here: set [lab] in host.toml (python -m fatbox.host init shows it) and run:  python -m fatbox.host lab check")
        return 0
    results = lab.run_checks(s, Controller(s).version_check)
    for status, text in results:
        print({"ok": "  ok  ", "warn": " warn ", "bad": " FAIL "}[status] + text)
    return 1 if any(st == "bad" for st, _ in results) else 0


LOG_NAME = "host.log"


def _log_to_file(settings: str | None, level: int) -> None:
    """pythonw has no console: send logging and print() to <host home>/host.log (2 x 1 MB, rotated)."""
    from fatbox.host.settings import default_home
    home = Path(settings).parent if settings else default_home()
    home.mkdir(parents=True, exist_ok=True)
    h = logging.handlers.RotatingFileHandler(home / LOG_NAME, maxBytes=1024 * 1024, backupCount=1, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    logging.basicConfig(level=level, handlers=[h], force=True)
    sys.stdout = sys.stderr = _PrintToLog()  # print() lands in the same file (survives log rotation)


class _PrintToLog:
    """A stand-in stdout/stderr for pythonw: each printed line becomes one log line."""
    def write(self, text: str) -> int:
        for line in str(text).splitlines():
            if line.strip():
                logging.getLogger("fatbox.host").info(line)
        return len(text)

    def flush(self) -> None:
        pass


def _message_box(text: str) -> None:
    """A Windows message box, the only way a windowless start can show an error. Silent elsewhere."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, text, "FatBox host", 0x10)  # MB_ICONERROR
    except (AttributeError, OSError):
        pass


def shortcut_target() -> tuple[str, str, str]:
    """(pythonw.exe, arguments, working folder) for the desktop shortcut: this Python, no console window."""
    exe = Path(sys.executable)
    pyw = exe.with_name("pythonw.exe")
    if not pyw.exists():
        raise FileNotFoundError(f"{pyw} not found (it comes with every Windows Python next to python.exe)")
    return str(pyw), "-m fatbox.host gui", str(Path(__file__).resolve().parents[2])


def make_shortcut() -> int:
    if os.name != "nt":
        print("error: the shortcut is for Windows only", file=sys.stderr)
        return 2
    try:
        target, arguments, folder = shortcut_target()
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    # WScript.Shell writes the .lnk; the values go in as environment variables, so no path is ever
    # pasted into the PowerShell code itself.
    ps = ("$d=[Environment]::GetFolderPath('Desktop');"
          "$l=(New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $d 'FatBox Host.lnk'));"
          "$l.TargetPath=$env:FBX_T;$l.Arguments=$env:FBX_A;$l.WorkingDirectory=$env:FBX_W;"
          "$l.IconLocation=$env:FBX_I+',0';$l.Description='FatBox host GUI';$l.Save();"
          "Join-Path $d 'FatBox Host.lnk'")
    icon = Path(__file__).with_name("assets") / "fatbox.ico"   # 0.27.0: the FatBox rune icon
    env = {**os.environ, "FBX_T": target, "FBX_A": arguments, "FBX_W": folder,
           "FBX_I": str(icon) if icon.exists() else target}
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                       capture_output=True, text=True, env=env, timeout=60)
    if r.returncode != 0:
        print(f"error: could not make the shortcut: {r.stderr.strip()}", file=sys.stderr)
        return 2
    print(f"made {r.stdout.strip()}  ->  {target} {arguments}  (in {folder})")
    print("Double-click it: the GUI opens in your browser, no console window. Stop it with Quit in the page.")
    print(f"Errors show in a message box; the log is {LOG_NAME} in the host folder (next to host.toml).")
    return 0
