"""Regenerate requirements.txt from requirements.in (T-4).

Every library, including the ones pulled in indirectly, gets an exact version and the sha256 of every file
PyPI has for it. Releases younger than COOLDOWN_DAYS are skipped: hijacked releases are usually caught and
pulled within days. Run it on a dev machine with internet, never in the VM:

    python -m pip install pip-tools==7.6.2
    python scripts/pin_deps.py

Then open a PR; CI (deps.yml) re-checks the result before anything reaches the VM.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

COOLDOWN_DAYS = 7
ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    cmd = [sys.executable, "-m", "piptools", "compile", "--quiet", "--generate-hashes", "--strip-extras",
           "--allow-unsafe", "--upgrade",
           # --only-binary is written into requirements.txt itself, so every install of it refuses to build
           # from source (no setup.py of a downloaded package ever runs).
           "--pip-args", f"--uploaded-prior-to P{COOLDOWN_DAYS}D --only-binary :all:",
           "--output-file", str(ROOT / "requirements.txt"), str(ROOT / "requirements.in")]
    env = {**os.environ, "CUSTOM_COMPILE_COMMAND": "python scripts/pin_deps.py"}  # shown in the file header
    r = subprocess.run(cmd, cwd=ROOT, env=env)
    if r.returncode == 0:
        print("requirements.txt regenerated. Next: python scripts/check_deps.py, then open a PR.")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
