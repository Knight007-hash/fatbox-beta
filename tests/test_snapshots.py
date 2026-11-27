"""T-8: a very clean default snapshot, a Snapshots tab to manage it, and auto-revert after each fetch."""
import json

import pytest

from fatbox import __version__, cli
from fatbox.host.snapshots import SnapshotPrefs
from fatbox.store import Store, make_sample_zip, sha256_bytes

U1, U2 = "11111111-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


# ---- VM side: wipe-data ------------------------------------------------------------------------------
def test_wipe_data_empties_only_the_sample_store(tmp_path, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[paths]\ndata_dir = "./data"\n')
    store = Store(tmp_path / "data")
    for i in range(2):
        body = f"sample {i}".encode() * 50
        sha = sha256_bytes(body)
        store.add(sha, make_sample_zip("s.bin", body, "infected"), {}, "manual")
        (store.report_dir_for(sha) / "static.json").write_text("{}")
    keep = tmp_path / "data" / "notes.txt"
    keep.write_text("not FatBox's")
    store.db.close()
    assert cli.main(["-c", str(cfg), "wipe-data"]) == 2          # never without --yes
    assert "refusing" in capsys.readouterr().err and (tmp_path / "data" / "index.db").exists()
    assert cli.main(["-c", str(cfg), "wipe-data", "--yes"]) == 0
    assert json.loads(capsys.readouterr().out) == {"samples_removed": 2, "reports_removed": 2}
    assert not (tmp_path / "data" / "vault").exists() and not (tmp_path / "data" / "index.db").exists()
    assert keep.exists() and cfg.exists()                         # nothing else touched
    assert cli.main(["-c", str(cfg), "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"rows": []}


# ---- host side: what FatBox remembers ----------------------------------------------------------------
def test_prefs_follow_uuids_and_warn(tmp_path):
    p = SnapshotPrefs(tmp_path, fallback_name="old-clean")
    rows = [{"name": "old-clean", "uuid": U1}, {"name": "clean-fatbox", "uuid": U2}]
    v = p.view(rows, U1, __version__)
    assert v["default"]["name"] == "old-clean" and "not checked by FatBox" in v["warning"]  # host.toml fallback
    p.add_checked("clean-fatbox", U2, __version__, "2026-11-09T00:10:00+00:00")
    p.update(auto_revert=True)
    renamed = [{"name": "old-clean", "uuid": U1}, {"name": "renamed-in-virtualbox", "uuid": U2}]
    v = p.view(renamed, U2, __version__)
    assert v["default"]["uuid"] == U2 and v["warning"] is None and v["auto_revert"]
    row = next(r for r in v["rows"] if r["uuid"] == U2)
    assert row["checked"] and row["default"] and row["current"] and row["version"] == __version__
    reused = [{"name": "clean-fatbox", "uuid": U1}]                   # same name, different snapshot
    assert not p.view(reused, None, __version__)["rows"][0]["checked"]
    assert p.view(renamed, None, "99.0.0")["warning"] == (f"The default snapshot has FatBox {__version__}, the host "
                                                         "99.0.0: make a new clean snapshot.")
    v = p.view([{"name": "old-clean", "uuid": U1}], None, __version__)  # default deleted in VirtualBox
    assert v["default"] is None and "is gone" in v["warning"] and not v["auto_revert"]
    assert p.load()["auto_revert"] is False and "auto-revert turned OFF" in p.take_notes()[0]


@pytest.mark.parametrize("junk", ['{"version": 1, "default": {"name": "x;calc", "uuid": "nope"}, "checked": "x", '
                                  '"auto_revert": "yes"}', "[[[", '{"version": 2}', "x" * 300_000])
def test_damaged_prefs_mean_no_default_and_auto_revert_off(tmp_path, junk):
    (tmp_path / "snapshots.json").write_text(junk)
    p = SnapshotPrefs(tmp_path)
    got = p.load()
    assert got["default"] is None and got["checked"] == [] and got["auto_revert"] is False


# ---- through the fake VBoxManage ---------------------------------------------------------------------
@pytest.fixture
def lab(tmp_path, monkeypatch):
    import test_host
    ctl, sha, home = test_host.lab.__wrapped__(tmp_path, monkeypatch)
    ctl.poll_s = ctl.settle_s = 0
    return ctl, sha, test_host


def test_make_clean_snapshot(lab):
    ctl, sha, th = lab
    lines = []
    assert ctl.make_clean_snapshot(lines.append) == 0
    log = th.guest_log()
    assert log[:3] == ["--version cable=off", "list cable=off", "report cable=off"]   # reports saved first
    assert "wipe-data cable=off" in log and log.index("report cable=off") < log.index("wipe-data cable=off")
    assert ctl.library.report(sha) is not None and not ctl.library.rows()[0]["in_vm"]
    assert ctl.list_samples() == []
    vmlog = open(th.os.environ["FAKE_VM_FILE"] + ".log").read()
    take = vmlog.index(" take ")                                                      # 0.18.1: photographed while off
    assert "acpipowerbutton" in vmlog[:take] and "startvm" in vmlog[take:]
    assert "startvm" not in vmlog[:take]            # 0.42.2: no extra restart before the photo (one boot, after it)
    v = ctl.snapshot_view()
    name = f"clean-fatbox-{__version__}-"
    assert v["default"]["name"].startswith(name) and v["warning"] is None
    assert v["rows"][0]["checked"] and v["rows"][0]["version"] == __version__
    assert ctl.vm.state() == "running" and ctl.vm.cable() == "off"
    steps = [ln for ln in lines if "clean snapshot" in ln]
    assert "taken (VM shut down), checked, and set" in steps[-2]
    assert steps[-1] == "--- clean snapshot 6/6: the VM booted from it, FatBox answers, 0 samples"
    ctl.make_clean_snapshot(lambda _: None)                                           # same day: a new name
    assert sorted(r["name"] for r in ctl.snapshot_view()["rows"])[1].endswith("-2")


def test_clean_snapshot_stops_before_wiping_when_a_report_is_missing(lab, monkeypatch):
    ctl, sha, th = lab
    monkeypatch.setattr(ctl.library, "sync", lambda *a, **k: {"saved": 0, "missing": 1, "total": 0})
    from fatbox.host.vbox import GuestError
    with pytest.raises(GuestError, match="nothing was wiped, no snapshot taken"):
        ctl.make_clean_snapshot(lambda _: None)
    assert "wipe-data cable=off" not in th.guest_log() and ctl.vm.snapshots()[0] == []
    assert [r["sha256"] for r in ctl.list_samples()] == [sha]


def test_auto_revert_after_fetch(lab):
    ctl, _, th = lab
    ctl.make_clean_snapshot(lambda _: None)
    ctl.set_auto_revert(True)
    lines = []
    assert ctl.fetch({"mode": "recent", "max": 1}, lines.append) == 0
    vmlog = open(th.os.environ["FAKE_VM_FILE"] + ".log").read().splitlines()
    restore = [i for i, ln in enumerate(vmlog) if " restore " in ln]
    assert restore and vmlog[restore[-1] - 1].endswith("poweroff")                    # off, then restore
    assert ctl.vm.state() == "running" and ctl.vm.cable() == "off"                    # resumed, cable out
    i = lines.index
    assert i("--- network OFF (checked)") < i("--- starting analysis (network is off)")
    assert any(ln.startswith("--- library:") for ln in lines)
    assert any(ln.startswith("--- auto-revert: going back to clean-fatbox-") for ln in lines)
    assert f"--- VM back and running; network OFF (checked); FatBox {__version__} ✓" in lines


def test_no_auto_revert_when_a_report_was_not_saved(lab, monkeypatch):
    ctl, _, _ = lab
    ctl.make_clean_snapshot(lambda _: None)
    ctl.set_auto_revert(True)
    monkeypatch.setattr(ctl.library, "sync", lambda *a, **k: {"saved": 0, "missing": 2, "total": 0})
    lines = []
    ctl.fetch({"mode": "recent", "max": 1}, lines.append)
    assert "--- auto-revert skipped: not every report was saved. Click Refresh, then Revert" in lines
    assert not any("going back" in ln for ln in lines)


def test_snapshot_settings_and_delete_rules(lab):
    from fatbox.host.server import Job, vm_action
    ctl, _, _ = lab
    with pytest.raises(ValueError, match="pick a default snapshot first"):
        ctl.set_auto_revert(True)
    for bad in ("yes", 1, None):
        with pytest.raises(ValueError):
            ctl.set_auto_revert(bad)
    ctl.make_clean_snapshot(lambda _: None)
    ctl.vm.take("manual-one")
    rows = {r["name"]: r for r in ctl.snapshot_view()["rows"]}
    default = ctl.snapshot_view()["default"]
    job = Job(ctl)
    with pytest.raises(ValueError, match="confirmation"):
        vm_action(ctl.vm, job, "delete-snapshot", {"uuid": rows["manual-one"]["uuid"]})
    with pytest.raises(ValueError, match="default snapshot"):
        vm_action(ctl.vm, job, "delete-snapshot", {"uuid": default["uuid"], "confirm": True})
    with pytest.raises(ValueError):
        ctl.set_default_snapshot("not-a-uuid")
    ctl.set_default_snapshot(rows["manual-one"]["uuid"].upper())
    v = ctl.snapshot_view()
    assert v["default"]["name"] == "manual-one" and "not checked by FatBox" in v["warning"]
    vm_action(ctl.vm, job, "delete-snapshot", {"uuid": default["uuid"], "confirm": True})
    assert [r["name"] for r in ctl.snapshot_view()["rows"]] == ["manual-one"]


def test_browse_marks_samples_already_in_the_library(lab):
    ctl, _, _ = lab
    ctl.library.sync([{"sha256": "a" * 64, "status": "fetched"}], lambda s: None, lambda _: None)
    rows = ctl.browse({"mode": "tag", "value": "ransomware"}, lambda _: None)
    assert {r["sha256"][0]: r["in_library"] for r in rows} == {"a": True, "b": False}


def test_gui_snapshot_endpoints(lab):
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer

    from fatbox.host.server import Job, make_handler
    ctl, _, _ = lab
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(ctl, Job(ctl), port, "tok")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base, hdr = f"http://127.0.0.1:{port}", {"Cookie": "fbx=tok", "X-FatBox": "1"}

    def call(path, body=None):
        data = None if body is None else json.dumps(body).encode()
        return json.loads(urllib.request.urlopen(urllib.request.Request(base + path, data, headers=hdr)).read())
    try:
        v = call("/api/snapshots")
        assert v["rows"] == [] and "No default snapshot" in v["warning"] and v["auto_revert"] is False
        with pytest.raises(urllib.error.HTTPError) as e:
            call("/api/settings", {"auto_revert": True})
        assert e.value.code == 400
        assert call("/api/clean-snapshot", {})["ok"]
        for _ in range(400):
            j = call("/api/job?since=0")
            if j["state"] != "running":
                break
            threading.Event().wait(0.05)
        assert (j["kind"], j["state"]) == ("clean", "done"), j
        v = call("/api/snapshots")
        assert v["default"] and v["rows"][0]["checked"]
        assert call("/api/vm")["clean_snapshot"] == v["default"]["name"]
        assert call("/api/settings", {"auto_revert": True}) == {"ok": True}
        assert call("/api/snapshots")["auto_revert"] is True
    finally:
        httpd.shutdown()


# ---- 0.18.1: Hyper-V (VirtualBox NEM) can't resume saved memory: FatBox always boots fresh ----------------
def test_clean_snapshot_holds_no_memory_and_revert_boots_fresh(lab, monkeypatch):
    ctl, _, th = lab
    monkeypatch.setenv("FAKE_NEM", "1")
    ctl.make_clean_snapshot(lambda _: None)
    d = ctl.snapshot_view()["default"]
    ctl.vm.revert(d["uuid"])
    assert ctl.vm.state() == "poweroff"                     # nothing to resume: Start boots Windows from the disk
    ctl.vm.start(headless=True)
    assert ctl.vm.state() == "running" and ctl.vm.cable() == "off"


def test_an_old_live_snapshot_still_works_booted_fresh(lab, monkeypatch):
    ctl, _, th = lab
    monkeypatch.setenv("FAKE_NEM", "1")
    ctl.vm.take("clean-old-live")                           # taken while running, like FatBox before 0.18.1
    lines = []
    ctl.snaps.update(default={"name": "clean-old-live", "uuid": ctl.vm.snapshot_list()[0][0]["uuid"]})
    ctl.auto_revert(lines.append)
    vmlog = open(th.os.environ["FAKE_VM_FILE"] + ".log").read()
    assert "discardstate" in vmlog and ctl.vm.state() == "running"
    assert any("auto-revert done" in ln for ln in lines)


@pytest.mark.parametrize("state", ["saved", "abortedsaved"])
def test_start_drops_saved_memory_first(lab, monkeypatch, state):
    ctl, _, th = lab
    monkeypatch.setenv("FAKE_NEM", "1")
    import json as j
    f = th.os.environ["FAKE_VM_FILE"]
    vm = j.load(open(f))
    vm["state"] = state
    j.dump(vm, open(f, "w"))
    ctl.vm.start(headless=True)                             # the 0.18.0 live test failed exactly here
    assert ctl.vm.state() == "running" and ctl.vm.cable() == "off"


def test_windows_ignoring_the_power_button_is_shut_down_from_inside(lab, monkeypatch):
    ctl, _, th = lab
    ctl.acpi_wait_s = 0
    monkeypatch.setenv("FAKE_ACPI_IGNORED", "1")           # the 0.18.1 live test: power button set to do nothing
    lines = []
    assert ctl.make_clean_snapshot(lines.append) == 0
    assert th.guest_log().count("shutdown cable=off") == 1  # 0.42.2: one shutdown (no restart), network off
    assert lines.count("--- Windows ignored the power button; asking Windows itself to shut down") == 1
    assert not any("powering off" in ln for ln in lines)
    vmlog = open(th.os.environ["FAKE_VM_FILE"] + ".log").read()
    take = vmlog.index(" take ")
    assert "shutdown --yes" in vmlog[vmlog.rindex("acpipowerbutton", 0, take):take]
    assert ctl.snapshot_view()["default"]["name"].startswith(f"clean-fatbox-{__version__}-")


def test_no_guest_shutdown_when_the_power_button_works(lab):
    ctl, _, th = lab
    ctl.make_clean_snapshot(lambda _: None)
    assert "shutdown cable=off" not in th.guest_log()


def test_guest_shutdown_refused_without_yes(tmp_path, capsys):
    from fatbox import cli
    assert cli.main(["shutdown"]) == 2
    assert "Add --yes" in capsys.readouterr().err


def test_windows_ignoring_every_shutdown_is_powered_off_and_still_snapshotted(lab, monkeypatch):
    # 0.28.0 (live test 2026-11-19): Windows ignored the power button AND shutdown.exe; the clean snapshot used to
    # fail after 180 s. Now the idle, empty, offline VM is powered off and photographed, and step 7 boots from it.
    ctl, _, th = lab
    ctl.shutdown_timeout_s = ctl.acpi_wait_s = 0
    monkeypatch.setenv("FAKE_ACPI_IGNORED", "1")
    monkeypatch.setenv("FAKE_GUEST_SHUTDOWN_IGNORED", "1")
    lines = []
    assert ctl.make_clean_snapshot(lines.append) == 0
    assert "--- Windows did not shut down in time: powering off (the VM is idle, empty and offline)" in lines
    assert any("taken (VM powered off)" in ln for ln in lines) and lines[-1].startswith("--- clean snapshot 6/6")
    vmlog = open(th.os.environ["FAKE_VM_FILE"] + ".log").read()
    take = vmlog.index(" take ")
    assert "poweroff" in vmlog[vmlog.rindex("shutdown --yes", 0, take):take]   # off before the photo, never live
    assert "powered off after Windows ignored shutdown" in vmlog[take:]
    assert ctl.snapshot_view()["default"]["name"].startswith(f"clean-fatbox-{__version__}-")


def test_guest_session_cut_by_shutdown_is_not_called_a_failure(lab, monkeypatch):
    ctl, _, th = lab
    ctl.shutdown_timeout_s = ctl.acpi_wait_s = 0
    monkeypatch.setenv("FAKE_ACPI_IGNORED", "1")
    monkeypatch.setenv("FAKE_GUEST_SHUTDOWN_IGNORED", "1")
    run = ctl.vbox.run
    monkeypatch.setattr(ctl.vbox, "run", lambda *a, **k: (1, b"", "") if a[0][0] == "shutdown" else run(*a, **k))
    lines = []
    ctl._shut_down(lines.append)
    assert "--- the VM's shutdown command: no answer (Windows was going down)" in lines
    assert not any("failed" in ln for ln in lines)


def test_clean_snapshot_waits_when_guest_additions_restart_after_boot(lab):
    """0.42.0 live (win 2): FatBox answered once after the restart, then the Guest Additions restarted while
    Windows finished starting up; the check at step 6 waits them out instead of failing the clean snapshot."""
    from fatbox.host.vbox import GuestError
    ctl, sha, th = lab
    ctl.not_ready_wait_s = 10
    real, calls = ctl.ping, []
    starting = "VBoxManage.exe: error: Error starting guest session (current status is: starting)"

    def flappy():
        calls.append(1)
        if len(calls) in (3, 4):   # 1: before the wipe, 2: wait_ready after the boot from the photo, 3-4: the flap
            raise GuestError("Windows in the VM is not ready for FatBox yet", starting)
        return real()
    ctl.ping = flappy
    lines = []
    assert ctl.make_clean_snapshot(lines.append) == 0
    assert any(ln.startswith("--- waiting for Windows in the VM to get ready") for ln in lines)
    assert "--- Windows in the VM is ready" in lines


def test_clean_snapshot_that_boots_with_samples_is_reported(lab, monkeypatch):
    """0.42.2: with no restart before the photo, step 6 (boot from it) checks it is still empty."""
    from fatbox.host.vbox import GuestError
    ctl, _, _ = lab
    real, calls = ctl.list_samples, []

    def later_dirty():
        calls.append(1)
        return [{"sha256": "a" * 64}] if len(calls) >= 3 else real()   # 1: sync, 2: after wipe, 3: after the boot
    monkeypatch.setattr(ctl, "list_samples", later_dirty)
    with pytest.raises(GuestError, match="boots, but is not clean"):
        ctl.make_clean_snapshot(lambda _: None)
