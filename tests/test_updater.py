"""Updater against real local git repos (bare origin + dev clone + 'VM' clone). No network."""
import shutil
import subprocess

import pytest

from fatbox.updater import UpdateError, update

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git not installed")


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True,
                   capture_output=True)


@pytest.fixture
def repos(tmp_path):
    origin, dev, vm = tmp_path / "origin.git", tmp_path / "dev", tmp_path / "vm"
    git(tmp_path, "init", "--bare", "-b", "main", str(origin))
    git(tmp_path, "clone", str(origin), str(dev))
    (dev / "fatbox").mkdir()
    (dev / "fatbox" / "__init__.py").write_text('__version__ = "1.0"\n')
    (dev / "fatbox" / "__main__.py").write_text("from fatbox import __version__\nprint('FatBox', __version__)\n")
    (dev / "requirements.txt").write_text("")
    (dev / ".gitignore").write_text("config.toml\ndata/\n")
    git(dev, "add", "-A"); git(dev, "commit", "-m", "v1"); git(dev, "push", "-u", "origin", "main")
    git(tmp_path, "clone", str(origin), str(vm))
    (vm / "config.toml").write_text("secret = 'keep me'\n")
    (vm / "data").mkdir(); (vm / "data" / "index.db").write_text("db")
    return dev, vm


def push_change(dev, version="2.0", req=None):
    (dev / "fatbox" / "__init__.py").write_text(f'__version__ = "{version}"\n')
    if req is not None:
        (dev / "requirements.txt").write_text(req)
    git(dev, "commit", "-am", f"v{version}"); git(dev, "push")


def test_up_to_date(repos, capsys):
    _, vm = repos
    assert update(vm, install=False) == 0
    assert "already up to date" in capsys.readouterr().out


def test_fast_forward_keeps_local_files(repos, capsys):
    dev, vm = repos
    push_change(dev, "2.0", req="requests\n")
    assert update(vm, install=False) == 0
    out = capsys.readouterr().out
    assert "FatBox 2.0" in out and "libraries not checked" in out
    assert (vm / "config.toml").read_text() == "secret = 'keep me'\n"
    assert (vm / "data" / "index.db").exists()


def test_dirty_tracked_file_aborts(repos):
    dev, vm = repos
    push_change(dev, "2.0")
    (vm / "fatbox" / "__init__.py").write_text("# my local hack\n")
    with pytest.raises(UpdateError, match="local edits"):
        update(vm, install=False)
    assert (vm / "fatbox" / "__init__.py").read_text() == "# my local hack\n"


def test_diverged_aborts(repos):
    dev, vm = repos
    push_change(dev, "2.0")
    (vm / "notes.txt").write_text("x"); git(vm, "add", "notes.txt"); git(vm, "commit", "-m", "local")
    with pytest.raises(UpdateError, match="diverge"):
        update(vm, install=False)


def test_not_a_checkout(tmp_path):
    with pytest.raises(UpdateError, match="not a git checkout"):
        update(tmp_path, install=False)


def test_auth_failure_points_to_the_hosts_update_vm(repos, monkeypatch):
    _, vm = repos
    import fatbox.updater as up
    real = up.subprocess.run

    def fake(cmd, **kw):
        if cmd[:2] == ["git", "fetch"]:
            return subprocess.CompletedProcess(cmd, 128, "", "fatal: Authentication failed for 'https://github.com/x/y.git/'")
        return real(cmd, **kw)

    monkeypatch.setattr(up.subprocess, "run", fake)
    with pytest.raises(UpdateError, match="click Update VM in the host's GUI") as e:
        update(vm, install=False)
    assert "set-token" not in str(e.value) and "cmdkey" not in str(e.value)   # 0.42.0: nothing to do in the VM


def test_no_fetch_never_contacts_github(repos, monkeypatch, capsys):
    """0.42.0: the host already put its code in; `update --no-fetch` only trims and checks."""
    _, vm = repos
    import fatbox.updater as up
    real = up.subprocess.run

    def fake(cmd, **kw):
        assert "fetch" not in cmd and "merge" not in cmd, cmd
        return real(cmd, **kw)

    monkeypatch.setattr(up.subprocess, "run", fake)
    assert update(vm, install=False, fetch=False) == 0
    assert "code from the host:" in capsys.readouterr().out


def test_token_file_is_sent_by_git_not_credential_manager(repos, tmp_path, monkeypatch):
    import base64
    import fatbox.updater as up
    _, vm = repos
    tok = tmp_path / "home" / ".fatbox" / "github-token"
    monkeypatch.setattr(up, "TOKEN_FILE", tok)
    assert up._token_args() == []                     # no file: Credential Manager as before
    for bad in ("short", "ghp_" + "a" * 30 + "\r\nX-Evil: 1", "a b" * 10):
        with pytest.raises(UpdateError, match="doesn't look like"):
            up.save_token(bad)
    assert up.save_token("  github_pat_" + "A1_b" * 10 + "\n") == tok
    args = up._token_args()
    assert args[:2] == ["-c", "credential.helper="] and args[3].startswith("http.https://github.com/.extraheader=")
    assert base64.b64decode(args[3].split()[-1]).decode() == "x-access-token:github_pat_" + "A1_b" * 10
    # git really sees it (helper switched off) and a normal update still works with it
    assert up._git("config", "--get", "http.https://github.com/.extraheader", cwd=vm).startswith("Authorization: Basic ")
    assert update(vm, install=False) == 0
    tok.write_text("not a token!\n")
    with pytest.raises(UpdateError, match="set-token"):
        update(vm, install=False)


def test_set_token_command(tmp_path, monkeypatch, capsys):
    import fatbox.updater as up
    from fatbox.cli import main
    monkeypatch.setattr(up, "TOKEN_FILE", tmp_path / ".fatbox" / "github-token")
    monkeypatch.setattr(up, "token_from_credential_manager", lambda: None)
    monkeypatch.setattr("getpass.getpass", lambda prompt: "github_pat_" + "x" * 30)
    assert main(["set-token"]) == 0 and "snapshot" in capsys.readouterr().out
    assert (tmp_path / ".fatbox" / "github-token").read_text().strip() == "github_pat_" + "x" * 30
    monkeypatch.setattr("getpass.getpass", lambda prompt: "nope")
    assert main(["set-token"]) == 3


def test_set_token_copies_from_credential_manager(tmp_path, monkeypatch, capsys):
    import fatbox.updater as up
    from fatbox.cli import main
    monkeypatch.setattr(up, "TOKEN_FILE", tmp_path / ".fatbox" / "github-token")
    real = up.subprocess.run

    def fake(cmd, **kw):
        if cmd[:3] == ["git", "credential", "fill"]:
            assert kw["env"]["GCM_INTERACTIVE"] == "Never"
            return subprocess.CompletedProcess(cmd, 0, "protocol=https\nhost=github.com\nusername=me\n"
                                                       "password=github_pat_" + "z" * 30 + "\n", "")
        return real(cmd, **kw)
    monkeypatch.setattr(up.subprocess, "run", fake)
    monkeypatch.setattr("getpass.getpass", lambda prompt: pytest.fail("must not prompt"))
    assert main(["set-token"]) == 0 and "Credential Manager" in capsys.readouterr().out
    assert (tmp_path / ".fatbox" / "github-token").read_text().strip() == "github_pat_" + "z" * 30


# --- T-4: pinned libraries are checked on EVERY update -------------------------------------------------------
PINNED = "--only-binary :all:\nfoo==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\nbar==2.0 \\\n    --hash=sha256:" + "b" * 64 + "\n"


def fake_python(tmp_path, pip_says: str, rc: int = 0):
    """A stand-in for the VM's python.exe: records its argv; `-m pip` prints pip_says and exits with rc."""
    log = tmp_path / "argv.log"
    exe = tmp_path / "python"
    exe.write_text(f"""#!/bin/sh
echo "$@" >> "{log}"
if [ "$2" = "pip" ]; then printf '%s\\n' "{pip_says}"; exit {rc}; fi
echo "FatBox 2.0"
""")
    exe.chmod(0o755)
    return str(exe), log


posix_only = pytest.mark.skipif(not shutil.which("sh"), reason="needs sh")


@posix_only
def test_libraries_checked_even_when_up_to_date(repos, tmp_path, capsys):
    dev, vm = repos
    push_change(dev, "2.0", req=PINNED)
    exe, log = fake_python(tmp_path, "Requirement already satisfied: foo==1.0")
    assert update(vm, python=exe) == 0
    capsys.readouterr()
    assert update(vm, python=exe) == 0  # nothing new on GitHub: libraries are still checked
    out = capsys.readouterr().out
    assert "already up to date" in out
    assert "checking libraries (pinned + hashed)" in out and "libraries OK: 2 pinned" in out
    assert "Requirement already satisfied" not in out  # noise kept out of the GUI log
    argv = log.read_text()
    assert argv.count("-m pip install") == 2
    assert "--require-hashes" in argv and "--only-binary :all:" in argv


@posix_only
def test_hash_mismatch_fails_in_plain_words(repos, tmp_path):
    _, vm = repos
    exe, _ = fake_python(tmp_path, "ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE.", rc=1)
    with pytest.raises(UpdateError, match="did NOT match its fingerprint"):
        update(vm, python=exe)


@posix_only
def test_no_wheel_fails_in_plain_words(repos, tmp_path):
    _, vm = repos
    exe, _ = fake_python(tmp_path, "ERROR: No matching distribution found for foo==1.0", rc=1)
    with pytest.raises(UpdateError, match="no ready-made file"):
        update(vm, python=exe)


@posix_only
def test_failed_install_is_retried_by_next_update(repos, tmp_path, capsys):
    dev, vm = repos
    push_change(dev, "2.0", req=PINNED)
    (tmp_path / "bad").mkdir()
    bad, _ = fake_python(tmp_path / "bad", "ERROR: connection reset", rc=1)
    with pytest.raises(UpdateError, match="run Update VM again"):
        update(vm, python=bad)
    good, log = fake_python(tmp_path, "Successfully installed foo-1.0")
    assert update(vm, python=good) == 0  # code already pulled: up to date, but libraries still get installed
    out = capsys.readouterr().out
    assert "already up to date" in out and "libraries OK: 2 pinned" in out


@posix_only
def test_pip_user_site_notice_is_not_shown(repos, tmp_path, capsys):
    _, vm = repos
    exe, _ = fake_python(tmp_path, "Defaulting to user installation because normal site-packages is not writeable")
    assert update(vm, python=exe) == 0
    out = capsys.readouterr().out
    assert "Defaulting to user installation" not in out and "libraries OK" in out


def test_vm_folder_keeps_only_what_the_vm_runs(repos, capsys):
    """T-6: host code, tests, scripts and design docs never land in the VM's folder (sparse checkout)."""
    dev, vm = repos
    for rel in ("fatbox/host/server.py", "fatbox/cli.py", "tests/test_x.py", "scripts/pin_deps.py",
                ".github/workflows/tests.yml", "SPEC.md", "rules/yara/a.yar", "README.md", "requirements.in"):
        (dev / rel).parent.mkdir(parents=True, exist_ok=True)
        (dev / rel).write_text("x\n")
    git(dev, "add", "-A"); git(dev, "commit", "-m", "more files"); git(dev, "push")
    assert update(vm, install=False) == 0
    assert "VM folder trimmed" in capsys.readouterr().out
    for gone in ("fatbox/host", "tests", "scripts", ".github", "SPEC.md", "requirements.in"):
        assert not (vm / gone).exists(), gone
    for kept in ("fatbox/__init__.py", "fatbox/cli.py", "rules/yara/a.yar", "README.md", "requirements.txt",
                 "config.toml", "data/index.db"):
        assert (vm / kept).exists(), kept
    # later updates: still trimmed, no repeat notice, and the tree counts as clean (no "local edits" refusal)
    (dev / "fatbox" / "host" / "server.py").write_text("y\n")
    push_change(dev, "3.0.0")  # other length than 1.0: same-second .pyc caching
    assert update(vm, install=False) == 0
    out = capsys.readouterr().out
    assert "FatBox 3.0.0" in out and "trimmed" not in out and not (vm / "fatbox" / "host").exists()
