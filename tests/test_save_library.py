"""0.26.0: reports are still copied off the VM automatically, but wait as "not saved" until you Save or Discard
them in the New view. Library shows saved ones only. A revert never loses a not-saved report."""
import json

import pytest

from fatbox.host.library import Library
from test_library import A, B, C, VmReports, rep, vmrow


def sync(lib, *shas, complete=True):
    return lib.sync([vmrow(s) for s in shas], VmReports(**{s: rep(s) for s in shas}), lambda _: None, complete=complete)


def by_sha(lib):
    return {r["sha256"]: r for r in lib.rows()}


def test_copied_reports_start_not_saved_and_save_keeps_them(tmp_path):
    lib = Library(tmp_path)
    sync(lib, A, B)
    assert not any(r["saved"] for r in lib.rows())
    assert lib.save([A, A]) == 1 and lib.save([A]) == 0          # twice is harmless
    rows = by_sha(lib)
    assert rows[A]["saved"] and not rows[B]["saved"]
    sync(lib, A, B)                                                # a later Refresh keeps the choice
    assert by_sha(lib)[A]["saved"]


def test_revert_never_loses_a_not_saved_report(tmp_path):
    lib = Library(tmp_path)
    sync(lib, A)
    lib.mark_all_gone()
    r = by_sha(lib)[A]
    assert not r["in_vm"] and not r["saved"] and lib.report(A) is not None


def test_discard_drops_it_and_refresh_does_not_copy_it_back(tmp_path):
    lib = Library(tmp_path)
    sync(lib, A, B)
    lib.mark_all_gone()
    sync(lib, A)                                                   # A back in the VM, B not
    assert lib.discard([A, B]) == 2
    assert lib.rows() == [] and not list(lib.reports.glob("*.json"))
    vm = VmReports(**{A: rep(A)})
    lib.sync([vmrow(A)], vm, lambda _: None)
    assert vm.asked == [] and lib.rows() == []                     # A still in the VM: stays discarded
    lib.sync([], VmReports(), lambda _: None)                      # A left the VM: the mark goes
    assert json.loads(lib.index_path.read_text())["rows"] == []
    sync(lib, A)                                                   # fetched again later: new, not saved
    assert not by_sha(lib)[A]["saved"]


def test_discard_mark_goes_on_revert_and_capped_list_keeps_it(tmp_path):
    lib = Library(tmp_path)
    sync(lib, A)
    lib.discard([A])
    sync(lib, B, complete=False)                                   # capped list: A may still be there
    assert len(json.loads(lib.index_path.read_text())["rows"]) == 2
    lib.mark_all_gone()
    assert [r["sha256"] for r in json.loads(lib.index_path.read_text())["rows"]] == [B]


def test_saved_reports_cannot_be_discarded_and_bad_input_is_refused(tmp_path):
    lib = Library(tmp_path)
    sync(lib, A)
    lib.save([A])
    with pytest.raises(ValueError, match="already saved"):
        lib.discard([A])
    for bad in ([], "a" * 64, ["../x"], [None], [A] * 5001):
        for fn in (lib.save, lib.discard):
            with pytest.raises(ValueError):
                fn(bad)
    assert lib.save([C]) == 0 and lib.discard([C]) == 0            # unknown sha: nothing happens


def test_old_index_rows_count_as_saved_and_bad_flags_are_dropped(tmp_path):
    lib = Library(tmp_path)
    sync(lib, A, B)
    idx = json.loads(lib.index_path.read_text())
    for r in idx["rows"]:
        r.pop("saved"), r.pop("discarded")                         # an index written before 0.26.0
    idx["rows"][1]["saved"] = "yes"                                # changed on disk: not a bool
    lib.index_path.write_text(json.dumps(idx))
    rows = lib.rows()
    assert len(rows) == 1 and rows[0]["saved"] and not rows[0]["discarded"]
    assert "1 damaged row(s)" in lib.take_notes()[0]


def test_opening_a_discarded_report_does_not_keep_it(tmp_path):
    lib = Library(tmp_path)
    sync(lib, A)
    lib.discard([A])
    lib.put_report(A, VmReports(**{A: rep(A)})(A))
    assert lib.report(A) is None and lib.rows() == []


def test_report_opened_from_the_vm_is_not_saved(tmp_path):
    lib = Library(tmp_path)
    lib.put_report(A, VmReports(**{A: rep(A)})(A))
    assert not by_sha(lib)[A]["saved"]


def test_rebuilt_index_counts_reports_as_saved(tmp_path):
    lib = Library(tmp_path)
    sync(lib, A)
    lib.index_path.unlink()
    assert by_sha(lib)[A]["saved"]                                 # nothing on disk can say otherwise: keep it


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="fake VBoxManage is a POSIX shell wrapper")
def test_save_and_discard_api(lab):  # noqa: F811
    import urllib.error
    import urllib.request
    from test_windowless import _serve
    ctl, _, _ = lab
    sync(ctl.library, A, B)
    httpd, port, _ = _serve(ctl)

    def call(path, body):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", json.dumps(body).encode(), method="POST",
                                     headers={"Cookie": "fbx=tok123", "X-FatBox": "1", "Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(req).read())

    try:
        assert call("/api/library/save", {"sha256": [A]}) == {"saved": 1}
        for path, body, msg in (("/api/library/discard", {"sha256": [B]}, "confirmation"),
                                ("/api/library/discard", {"sha256": [A], "confirm": True}, "already saved"),
                                ("/api/library/save", {"sha256": ["x"]}, "sha256")):
            with pytest.raises(urllib.error.HTTPError) as e:
                call(path, body)
            assert e.value.code == 400 and msg in json.loads(e.value.read())["error"]
        assert call("/api/library/discard", {"sha256": [B], "confirm": True}) == {"discarded": 1}
        assert [(r["sha256"], r["saved"]) for r in ctl.library.rows()] == [(A, True)]
    finally:
        httpd.shutdown()
        httpd.server_close()


from test_host import lab  # noqa: E402,F401  (fixture)
