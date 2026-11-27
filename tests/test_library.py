"""T-7: the host keeps its own report library, so reports outlive a revert of the VM."""
import json

import pytest

from fatbox.host import library as libmod
from fatbox.host import validate
from fatbox.host.library import Library
from fatbox.host.vbox import GuestError

A, B, C = "a" * 64, "b" * 64, "c" * 64


def rep(sha, score=40, prio="medium", **kw):
    return {"hashes": {"sha256": sha}, "priority": prio, "score": score, "analyzed_at": "2026-11-08T21:24:00+00:00",
            "source_meta": {"signature": "Fam", "tags": ["t"]}, **kw}


def vmrow(sha, status="static_done", score=40, prio="medium", **kw):
    return {"sha256": sha, "status": status, "score": score, "priority": prio, "signature": "Fam", "file_type": "exe",
            "file_name": "x.exe", "tags": ["t"], "fetched_at": "2026-11-08 21:23:00", "error": None, **kw}


class VmReports:
    def __init__(self, **reports):
        self.reports, self.asked = reports, []

    def __call__(self, sha):
        self.asked.append(sha)
        raw = json.dumps(self.reports[sha]).encode()
        return validate.report(raw, sha)  # same check the controller does on VM output


def test_sync_copies_only_new_or_changed_reports(tmp_path):
    lib, vm, lines = Library(tmp_path), VmReports(**{A: rep(A), B: rep(B)}), []
    assert lib.sync([vmrow(A), vmrow(B), vmrow(C, "timeout", None, None, error="took too long")], vm, lines.append) \
        == {"saved": 2, "missing": 0, "total": 3}
    assert "--- library: 2 new report(s) saved (3 total)" in lines and vm.asked == [A, B]
    rows = {r["sha256"]: r for r in lib.rows()}
    assert rows[A]["has_report"] and rows[A]["in_vm"] and rows[A]["analyzed_at"].startswith("2026-11-08")
    assert rows[C]["status"] == "timeout" and not rows[C]["has_report"]  # kept, even without a report
    assert lib.report(A)["score"] == 40
    vm.asked.clear()
    lib.sync([vmrow(A), vmrow(B)], vm, lines.append)
    assert vm.asked == []                                   # nothing new: no report fetched again
    vm.reports[A] = rep(A, 80, "high")
    lib.sync([vmrow(A, score=80, prio="high")], vm, lines.append)
    assert vm.asked == [A] and lib.report(A)["priority"] == "high"   # changed: fetched again
    rows = {r["sha256"]: r for r in lib.rows()}
    assert rows[A]["in_vm"] and not rows[B]["in_vm"] and not rows[C]["in_vm"]  # reverted away: report stays
    assert lib.report(B) is not None
    assert not list((tmp_path / "library").rglob("*.tmp"))  # every write swapped in whole


def test_capped_vm_list_does_not_mark_rows_gone(tmp_path):
    lib = Library(tmp_path)
    lib.sync([vmrow(A), vmrow(B)], VmReports(**{A: rep(A), B: rep(B)}), lambda _: None)
    lib.sync([vmrow(A)], VmReports(), lambda _: None, complete=False)
    assert all(r["in_vm"] for r in lib.rows())


def test_hostile_or_failing_reports_are_not_saved(tmp_path):
    lib, lines = Library(tmp_path), []

    def get(sha):
        if sha == A:
            return validate.report(json.dumps(rep(B)).encode(), A)  # report for another sample
        raise GuestError("the VM is still starting")
    assert lib.sync([vmrow(A), vmrow(B)], get, lines.append)["missing"] == 2
    assert lib.report(A) is None and not any(r["has_report"] for r in lib.rows())
    assert any("not saved: report sha256 does not match" in ln for ln in lines)
    assert "--- library: 2 report(s) could not be saved; Refresh tries again" in lines


def test_everything_is_checked_again_when_read_from_disk(tmp_path):
    lib = Library(tmp_path)
    lib.sync([vmrow(A), vmrow(B)], VmReports(**{A: rep(A), B: rep(B)}), lambda _: None)
    (lib.reports / f"{A}.json").write_text(json.dumps(rep(A, prio="critical")))  # changed on disk
    with pytest.raises(validate.Invalid):
        lib.report(A)
    idx = json.loads(lib.index_path.read_text())
    idx["rows"][0]["signature"] = "Evil‮gpj.exe"
    idx["rows"][1]["sha256"] = "..\\..\\x"
    idx["rows"].append({"sha256": C, "in_vm": "yes", "has_report": True})
    lib.index_path.write_text(json.dumps(idx))
    rows = lib.rows()
    assert [r["sha256"] for r in rows] == [A] and "‮" not in rows[0]["signature"]
    assert lib.take_notes() == ["library: 2 damaged row(s) in index.json ignored"]
    with pytest.raises(validate.Invalid):
        lib.report("../" + "a" * 61)


def test_damaged_index_is_kept_aside_and_rebuilt(tmp_path):
    lib = Library(tmp_path)
    lib.sync([vmrow(A)], VmReports(**{A: rep(A)}), lambda _: None)
    (lib.reports / "not-a-sha.json").write_text("{}")
    (lib.reports / f"{B}.json").write_text("x" * 100)          # junk report: skipped
    lib.index_path.write_text('{"rows": [[[[')
    rows = lib.rows()
    assert [r["sha256"] for r in rows] == [A] and rows[0]["has_report"] and rows[0]["priority"] == "medium"
    assert (lib.dir / "index.json.bad").read_text() == '{"rows": [[[['
    assert lib.take_notes()[0].startswith("library: the library index was damaged")


def test_reports_cached_before_t7_join_the_library(tmp_path):
    old = tmp_path / "reports"
    old.mkdir()
    (old / f"{A}.json").write_text(json.dumps(rep(A)))
    (old / f"{B}.json").write_text(json.dumps(rep(C)))          # wrong sample inside: skipped
    lib = Library(tmp_path)
    assert [r["sha256"] for r in lib.rows()] == [A] and not lib.rows()[0]["in_vm"]
    assert (lib.reports / f"{A}.json").exists()
    assert lib.take_notes() == ["library: built the index from 1 saved report(s)"]


def test_limits_never_delete_anything(tmp_path, monkeypatch):
    lib, lines = Library(tmp_path), []
    monkeypatch.setattr(libmod, "MAX_ROWS", 2)
    got = lib.sync([vmrow(A), vmrow(B), vmrow(C)], VmReports(**{A: rep(A), B: rep(B), C: rep(C)}), lines.append)
    assert got == {"saved": 2, "missing": 1, "total": 2}
    assert any("library is full (2 reports)" in ln for ln in lines)
    monkeypatch.setattr(libmod, "MAX_ROWS", 5000)
    monkeypatch.setattr(lib, "free_bytes", lambda: 100 * 1024 * 1024)
    lines.clear()
    assert lib.sync([vmrow(A), vmrow(B), vmrow(C)], VmReports(), lines.append)["missing"] == 1
    assert any("less than 500 MB free" in ln for ln in lines)
    assert {r["sha256"] for r in lib.rows()} == {A, B, C} and lib.report(A) is not None


def test_delete_only_what_is_no_longer_in_the_vm(tmp_path):
    lib = Library(tmp_path)
    lib.sync([vmrow(A), vmrow(B)], VmReports(**{A: rep(A), B: rep(B)}), lambda _: None)
    with pytest.raises(ValueError, match="no longer in the VM"):
        lib.delete([A])
    lib.mark_all_gone()
    for bad in ([], "a" * 64, ["../x"], [None]):
        with pytest.raises(ValueError):
            lib.delete(bad)
    assert lib.delete([A, A]) == 1
    assert [r["sha256"] for r in lib.rows()] == [B] and not (lib.reports / f"{A}.json").exists()


# ---- through the controller and the fake VBoxManage ---------------------------------------------------
@pytest.fixture
def lab(tmp_path, monkeypatch):
    import test_host
    ctl, sha, home = test_host.lab.__wrapped__(tmp_path, monkeypatch)
    vmfile = tmp_path / "lab-vm.json"
    vmfile.write_text(json.dumps({"state": "running", "cable": "off", "snaps": ["clean"], "current": "clean"}))
    return ctl, sha, test_host


def test_revert_saves_reports_first(lab):
    from fatbox.host.server import Job, vm_action
    ctl, sha, th = lab
    job = Job(ctl)
    vm_action(ctl.vm, job, "revert", {"name": "clean", "confirm": True})
    assert th.guest_log() == ["list cable=off", "report cable=off"]   # copied before the VM was wiped
    assert ctl.vm.state() == "poweroff"
    rows = ctl.library.rows()
    assert [r["sha256"] for r in rows] == [sha] and not rows[0]["in_vm"]
    assert ctl.report(sha)["hashes"]["sha256"] == sha                  # VM off: read from the library
    assert any("1 new report(s) saved" in t for _, t in job.lines)


def test_revert_waits_when_reports_could_not_be_saved(lab, monkeypatch):
    from fatbox.host.server import Job, Unsaved, vm_action
    ctl, sha, _ = lab
    monkeypatch.setenv("FAKE_GUEST", "noadditions")
    with pytest.raises(Unsaved, match="The library could not be updated"):
        vm_action(ctl.vm, Job(ctl), "revert", {"name": "clean", "confirm": True})
    assert ctl.vm.state() == "running"                                 # nothing wiped yet
    vm_action(ctl.vm, Job(ctl), "revert", {"name": "clean", "confirm": True, "unsaved_ok": True})
    assert ctl.vm.state() == "poweroff"


def test_gui_library_sync_and_delete(lab):
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer

    from fatbox.host.server import Job, make_handler
    ctl, sha, _ = lab
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(ctl, Job(ctl), port, "tok")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base, hdr = f"http://127.0.0.1:{port}", {"Cookie": "fbx=tok", "X-FatBox": "1"}

    def call(path, body=None):
        data = None if body is None else json.dumps(body).encode()
        return json.loads(urllib.request.urlopen(urllib.request.Request(base + path, data, headers=hdr)).read())
    try:
        assert call("/api/library")["rows"] == []
        assert call("/api/sync", {})["ok"]
        for _ in range(200):
            j = call("/api/job?since=0")
            if j["state"] != "running":
                break
            threading.Event().wait(0.05)
        assert (j["kind"], j["state"]) == ("sync", "done")
        assert [r["sha256"] for r in call("/api/library")["rows"]] == [sha]
        for body, code in (({"sha256": [sha]}, 400), ({"sha256": [sha], "confirm": True}, 400)):
            with pytest.raises(urllib.error.HTTPError) as e:  # no confirm; then: still in the VM
                call("/api/library/delete", body)
            assert e.value.code == code
        ctl.library.mark_all_gone()
        assert call("/api/library/delete", {"sha256": [sha], "confirm": True}) == {"deleted": 1}
        assert call("/api/library")["rows"] == []
    finally:
        httpd.shutdown()
