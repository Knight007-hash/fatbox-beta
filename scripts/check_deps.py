"""CI guard for requirements.txt (T-4). Fails (exit 1) and says why when:

  1. a library is not pinned to one exact version (==) with at least one sha256 hash,
  2. a library named in requirements.in is missing from requirements.txt,
  3. --only-binary :all: is gone (installs could run a package's own setup code),
  4. [--online] a pinned release is younger than COOLDOWN_DAYS on PyPI,
  5. [--wheels DIR] a downloaded Windows wheel holds a native module the VM's Python can't load (T-9:
     die-python 0.5.0's "cp313" wheel holds a module built for Python 3.14).

    python scripts/check_deps.py            # 1-3, offline
    python scripts/check_deps.py --online   # 1-4, asks pypi.org for upload dates
    python scripts/check_deps.py --wheels DIR   # 1-3 and 5, DIR from `pip download --platform win_amd64 ...`
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

COOLDOWN_DAYS = 7
VM_PYTHON = "cp313"   # the analysis VM's Python (C:\Python313); Windows only loads <name>.cp313-win_amd64.pyd or <name>.pyd
ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.+!_-]+)$")
HASH = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def logical_lines(text: str) -> list[str]:
    """requirements.txt lines with comments dropped and backslash continuations joined."""
    out, cur = [], ""
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        cur += line
        if cur.strip():
            out.append(cur.strip())
        cur = ""
    if cur.strip():
        out.append(cur.strip())
    return out


def parse(text: str) -> tuple[dict[str, str], list[str], list[str]]:
    """-> ({name: version}, [option lines], [problems])"""
    pins, options, problems = {}, [], []
    for line in logical_lines(text):
        if line.startswith("-"):
            options.append(line)
            continue
        req, *hashes = line.split()
        m = PIN.match(req)
        if not m:
            problems.append(f"not pinned to one exact version: {req}")
            continue
        if not hashes or not all(HASH.match(h) for h in hashes):
            problems.append(f"missing or malformed --hash for {req}")
        name = norm(m.group(1))
        if name in pins:
            problems.append(f"listed twice: {name}")
        pins[name] = m.group(2)
    return pins, options, problems


def check_offline(req_txt: str, req_in: str) -> tuple[dict[str, str], list[str]]:
    pins, options, problems = parse(req_txt)
    if "--only-binary :all:" not in options:
        problems.append("--only-binary :all: is missing; regenerate with scripts/pin_deps.py")
    if not pins:
        problems.append("no libraries pinned")
    for line in req_in.splitlines():
        name = re.split(r"[<>=!~;\[ ]", line.split("#", 1)[0].strip())[0]  # "die-python==0.4.0" -> die-python
        if name and norm(name) not in pins:
            problems.append(f"{name} is in requirements.in but not pinned in requirements.txt")
    return pins, problems


def uploaded(name: str, version: str) -> dt.datetime:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as r:
        files = json.load(r)["urls"]
    if not files:
        raise ValueError(f"{name}=={version} has no files on PyPI")
    return min(dt.datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")) for f in files)


def check_cooldown(pins: dict[str, str], now: dt.datetime | None = None) -> list[str]:
    now = now or dt.datetime.now(dt.timezone.utc)
    problems = []
    for name, version in sorted(pins.items()):
        age = now - uploaded(name, version)
        print(f"  {name}=={version}: {age.days} days old")
        if age < dt.timedelta(days=COOLDOWN_DAYS):
            problems.append(f"{name}=={version} is only {age.days} days old (cooldown {COOLDOWN_DAYS} days); "
                            "wait, or pin the previous version")
    return problems


def check_wheels(folder: Path) -> list[str]:
    """Every native module in a Windows wheel must carry a name the VM's Python looks for."""
    problems, wheels = [], sorted(folder.glob("*.whl"))
    if not wheels:
        return [f"no wheels in {folder}"]
    for w in wheels:
        with zipfile.ZipFile(w) as z:
            for n in z.namelist():
                if n.lower().endswith(".pyd"):
                    tag = n.rsplit("/", 1)[-1].split(".")[1:-1]  # _die.cp314-win_amd64.pyd -> ["cp314-win_amd64"]
                    if tag and tag != [f"{VM_PYTHON}-win_amd64"]:
                        problems.append(f"{w.name}: {n} is built for {tag[0]}, the VM runs {VM_PYTHON}; "
                                        "pin a version whose wheel fits (requirements.in)")
    return problems


def main(argv: list[str]) -> int:
    pins, problems = check_offline((ROOT / "requirements.txt").read_text(encoding="utf-8"),
                                   (ROOT / "requirements.in").read_text(encoding="utf-8"))
    if "--online" in argv and not problems:
        problems += check_cooldown(pins)
    if "--wheels" in argv and not problems:
        problems += check_wheels(Path(argv[argv.index("--wheels") + 1]))
    for p in problems:
        print("FAIL:", p)
    if not problems:
        print(f"OK: {len(pins)} libraries pinned with hashes" + (", all past the cooldown" if "--online" in argv else ""))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
