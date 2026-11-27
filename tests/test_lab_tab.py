"""0.41.0 Lab tab (T-24 part 1): the home screen's numbers and the page that shows them."""
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from fatbox.host.labmap import RESERVE_MB, as_int, fits, host_memory
from test_host import lab  # noqa: F401  (fixture)
from test_lab import pytestmark_posix

PAGE = (Path(__file__).resolve().parents[1] / "fatbox" / "host" / "page.html").read_text(encoding="utf-8")


def test_fits_keeps_room_for_windows():
    assert fits(8192 + RESERVE_MB, 8192) and not fits(8192 + RESERVE_MB - 1, 8192) and not fits(99999, 0)


def test_virtualbox_numbers_are_checked():
    assert as_int("8192") == 8192 and as_int(None) is None and as_int("-1") is None and as_int("9" * 20) is None


def test_host_memory_is_sane_or_unknown():
    m = host_memory()
    assert m is None or (m[0] > 0 and 0 <= m[1] <= m[0])


def test_lab_is_the_home_tab_and_shows_text_only():
    assert 'id="tab-lab" role="tab" aria-selected="true"' in PAGE and '<section class="pane" id="pane-fetch" role="tabpanel" hidden>' in PAGE
    js = PAGE.split("function labMapRender", 1)[1].split("async function labMap", 1)[0]
    assert "innerHTML" not in js


@pytestmark_posix
def test_labmap_endpoint(lab):  # noqa: F811
    from fatbox.host.server import Job, make_handler
    ctl, sha, home = lab
    home.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(ctl, Job(ctl), port, "tok")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/labmap", headers={"Cookie": "fbx=tok"})
        m = json.loads(urllib.request.urlopen(req).read())
        assert m["layout"] == "one-pc" and len(m["vms"]) == 1
        v = m["vms"][0]
        assert v["active"] and v["name"] == ctl.s.vm and v["memory_mb"] == 8192 and v["cpus"] == 4
        assert m["host"] is None or m["another_fits"] in (True, False)
    finally:
        httpd.shutdown()
