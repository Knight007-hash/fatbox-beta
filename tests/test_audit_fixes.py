"""0.19.2: fixes from the full audit of 0.19.0 (snapshot names, missing config, MalShare key, button race, ...)."""
import json
import threading

import pytest
import requests

from fatbox import cli
from fatbox.host import validate
from fatbox.host.settings import load_settings
from fatbox.host.snapshots import SnapshotPrefs

UUID = "12345678-1234-1234-1234-123456789abc"


# ---- #2 a default snapshot keeps any VirtualBox name -------------------------------------------------------
@pytest.mark.parametrize("name", ["Snapshot 1", "clean (before update)", "nettoyé"])
def test_default_snapshot_with_any_name_is_kept(tmp_path, name):
    p = SnapshotPrefs(tmp_path)
    p.update(default={"name": name, "uuid": UUID})
    assert p.load()["default"] == {"name": name, "uuid": UUID}
    view = p.view([{"name": name, "uuid": UUID}], UUID, "0.19.2")
    assert view["default"]["uuid"] == UUID


@pytest.mark.parametrize("name", ["", "a\nb", "esc\x1b[2J", "x" * 201])
def test_snapshot_names_with_control_characters_are_still_refused(tmp_path, name):
    p = SnapshotPrefs(tmp_path)
    p.update(default={"name": name, "uuid": UUID})
    assert p.load()["default"] is None


# ---- #3 a named config.toml that is missing stops with a clear error ------------------------------------------
def test_missing_named_config_is_an_error(tmp_path, capsys):
    rc = cli.main(["-c", str(tmp_path / "config.toml"), "list"])
    assert rc == 2
    assert "not found" in capsys.readouterr().err
    assert not (tmp_path / "data").exists()


def test_no_config_flag_still_uses_defaults(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["list"]) == 0
    assert (tmp_path / "data").is_dir()


@pytest.mark.parametrize("limit", ["0", "-1", "1001"])
def test_list_limit_is_bounded(limit, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        cli.main(["list", "--limit", limit])


# ---- #4 the MalShare key never shows up in an error -------------------------------------------------------
class _Boom:
    headers: dict = {}

    def get(self, url, params=None, **kw):
        raise requests.ConnectionError(f"Max retries exceeded with url: /api.php?api_key={params['api_key']}&action=x")


class _Err:
    headers: dict = {}

    def get(self, url, params=None, **kw):
        r = requests.Response()
        r.status_code, r.url = 500, f"{url}?api_key={params['api_key']}&action={params['action']}"
        return r


@pytest.mark.parametrize("session", [_Boom(), _Err()])
def test_malshare_errors_hide_the_key(session):
    from fatbox.fetch.common import FetchError
    from fatbox.fetch.malshare import MalShareSource
    key = "S3CRETKEY1234567890abcdef"
    src = MalShareSource(key, session=session)
    with pytest.raises(FetchError) as e:
        src.list_candidates()
    assert key not in str(e.value) and "<api_key>" in str(e.value)


# ---- bazaar: a wrong vault password is refused before anything is downloaded --------------------------------
def test_bazaar_password_checked_before_download():
    from fatbox.fetch.bazaar import BazaarSource
    from fatbox.fetch.common import FetchError

    class NoNet:
        headers: dict = {}

        def post(self, *a, **kw):
            raise AssertionError("downloaded anyway")
    with pytest.raises(FetchError, match="infected"):
        BazaarSource("key", session=NoNet()).download_zip("a" * 64, "other", 1024)


# ---- host settings: an old host.toml with fetch_timeout_s still loads --------------------------------------
def test_old_host_toml_key_is_skipped(tmp_path):
    pw = tmp_path / "guest.pw"
    pw.write_text("x")
    f = tmp_path / "host.toml"
    f.write_text(f"password_file = '{pw}'\nfetch_timeout_s = 3600\n", encoding="utf-8")
    s = load_settings(f)
    assert not hasattr(s, "fetch_timeout_s") and s.clean_snapshot == ""
    f.write_text(f"password_file = '{pw}'\nno_such_key = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown keys"):
        load_settings(f)


# ---- #10 report shapes: a hacked VM can't break the report view ------------------------------------------
SHA = "a" * 64
GOOD = {"hashes": {"sha256": SHA}, "priority": "low", "score": 1, "reasons": [], "behaviour": [], "yara": [],
        "source_meta": {"tags": ["x"]},
        "pe": {"suspicious_imports": [{"api": "A"}], "packer_hints": ["UPX"], "sections": [{"name": ".text"}],
               "dotnet": {"pinvoke": ["VirtualAlloc"], "error": None}}}


def test_report_with_the_right_shapes_passes():
    assert validate.report(json.dumps(GOOD).encode(), SHA)["pe"]["dotnet"]["pinvoke"] == ["VirtualAlloc"]
    assert validate.report(json.dumps({**GOOD, "pe": None}).encode(), SHA)["pe"] is None


@pytest.mark.parametrize("bad", [
    {"behaviour": ["x"]}, {"yara": "x"}, {"source_meta": {"tags": "abc"}},
    {"pe": {"suspicious_imports": "abc"}}, {"pe": {"packer_hints": [1]}}, {"pe": {"sections": {}}},
    {"pe": {"dotnet": "x"}}, {"pe": {"dotnet": {"pinvoke": "VirtualAlloc"}}},
])
def test_report_with_wrong_shapes_is_refused(bad):
    with pytest.raises(validate.Invalid):
        validate.report(json.dumps({**GOOD, **bad}).encode(), SHA)


# ---- button race: a job and a VM action can't both start ---------------------------------------------------
def test_vm_action_waits_for_a_job_that_is_starting():
    from fatbox.host.server import vm_action

    class VM:
        action = None
        action_lock = threading.Lock()

        def state(self):
            raise AssertionError("the action ran while a job was starting")

    class StartingJob:
        kind = "fetch"

        def running(self):
            return True
    vm = VM()
    with pytest.raises(ValueError, match="fetch is running"):
        vm_action(vm, StartingJob(), "start", {})
    assert not vm.action_lock.locked()
    vm.action_lock.acquire()  # a job being started holds the same lock
    try:
        with pytest.raises(ValueError, match="still in progress"):
            vm_action(vm, StartingJob(), "start", {})
    finally:
        vm.action_lock.release()


def test_malshare_key_hidden_in_urllib3_retry_warnings(caplog):
    import logging
    from fatbox.fetch.malshare import MalShareSource
    key = "fc3cKEYfromTHEscreenshot0123456789"
    MalShareSource(key, session=_Boom())
    with caplog.at_level(logging.WARNING):
        logging.getLogger("urllib3.connectionpool").warning(
            "Retrying (%r) after connection broken by '%r': %s", "Retry(total=2)", "NameResolutionError",
            f"/api.php?api_key={key}&action=getlimit")
    assert key not in caplog.text and "api_key=<api_key>" in caplog.text
