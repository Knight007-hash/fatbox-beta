"""T-4: requirements.txt is fully pinned with hashes, and the CI guard catches every way it can go wrong."""
import datetime as dt
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_deps", ROOT / "scripts" / "check_deps.py")
cd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cd)

H = "    --hash=sha256:" + "0" * 64


def test_repo_requirements_pass():
    pins, problems = cd.check_offline((ROOT / "requirements.txt").read_text(), (ROOT / "requirements.in").read_text())
    assert problems == []
    # the 4 we use plus the 5 they pull in
    assert {"requests", "pyzipper", "pefile", "yara-python", "urllib3", "idna", "certifi",
            "charset-normalizer", "pycryptodomex"} <= set(pins)


@pytest.mark.parametrize("txt, problem", [
    (f"--only-binary :all:\nrequests>=2.31 \\\n{H}\n", "not pinned to one exact version"),
    ("--only-binary :all:\nrequests==2.34.2\n", "missing or malformed --hash"),
    ("--only-binary :all:\nrequests==2.34.2 \\\n    --hash=sha256:xyz\n", "missing or malformed --hash"),
    (f"requests==2.34.2 \\\n{H}\n", "--only-binary :all: is missing"),
    (f"--only-binary :all:\nrequests==2.34.2 \\\n{H}\nRequests==2.0 \\\n{H}\n", "listed twice"),
    (f"--only-binary :all:\nidna==3.20 \\\n{H}\n", "requests is in requirements.in but not pinned"),
])
def test_guard_catches(txt, problem):
    _, problems = cd.check_offline(txt, "# names\nrequests\n")
    assert any(problem in p for p in problems), problems


def test_cooldown(monkeypatch):
    now = dt.datetime(2026, 11, 5, tzinfo=dt.timezone.utc)
    ages = {"old": 30, "fresh": 0}
    monkeypatch.setattr(cd, "uploaded", lambda name, v: now - dt.timedelta(days=ages[name], hours=4))
    problems = cd.check_cooldown({"old": "1.0", "fresh": "2.0"}, now)
    assert len(problems) == 1 and "fresh==2.0 is only 0 days old" in problems[0]


def test_pin_script_keeps_the_safety_flags():
    src = (ROOT / "scripts" / "pin_deps.py").read_text()
    assert "--generate-hashes" in src and "--uploaded-prior-to P{COOLDOWN_DAYS}D" in src and "--only-binary :all:" in src


def test_a_pinned_name_in_requirements_in_is_understood():
    _, problems = cd.check_offline(f"--only-binary :all:\ndie-python==0.4.0 \\\n{H}\n", "die-python==0.4.0  # why\n")
    assert problems == []


def test_windows_wheel_built_for_another_python_is_caught(tmp_path):
    import zipfile

    def wheel(name, pyd):
        with zipfile.ZipFile(tmp_path / name, "w") as z:
            z.writestr(pyd, b"MZ")
    wheel("die_python-0.5.0-cp313-abi3-win_amd64.whl", "die/_die.cp314-win_amd64.pyd")   # what PyPI really has
    wheel("good-1.0-cp313-cp313-win_amd64.whl", "good/_x.cp313-win_amd64.pyd")
    wheel("plain-1.0-cp37-abi3-win_amd64.whl", "plain/_y.pyd")
    problems = cd.check_wheels(tmp_path)
    assert len(problems) == 1 and "_die.cp314-win_amd64.pyd is built for cp314" in problems[0]
    assert cd.check_wheels(tmp_path / "nothing") == [f"no wheels in {tmp_path / 'nothing'}"]
