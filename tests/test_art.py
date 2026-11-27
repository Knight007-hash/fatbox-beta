"""0.43.0: Kittelsen art in the host GUI. Fixed files shipped with FatBox, served by the host behind the token like
the favicon, so the page's CSP keeps img-src 'self'. Decoration only: no data is drawn over by the art."""
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from fatbox.host import server
from test_host import lab  # noqa: F401  (fixture)

ART = Path(server.__file__).with_name("assets") / "art"
FILES = ("pesta.jpg", "forest.jpg", "ravens.jpg")
PAGE = server.PAGE.read_text(encoding="utf-8")


def test_art_files_are_small_jpegs_with_credits():
    for name in FILES:
        raw = (ART / name).read_bytes()
        assert raw[:3] == b"\xff\xd8\xff" and len(raw) < 400_000, name
        assert server.ASSETS[f"/assets/art/{name}"] == (f"art/{name}", "image/jpeg")
    credits = (ART / "CREDITS.txt").read_text(encoding="utf-8")
    assert "Theodor Kittelsen" in credits and "public domain" in credits.lower()


def test_page_uses_only_host_art():
    for name in FILES:
        assert f"url(/assets/art/{name})" in PAGE
    assert "https://" not in PAGE.split("<script>")[0]
    assert "public domain" not in PAGE.split("<style>", 1)[1].split("</style>", 1)[1]  # beta: no credit line on screen (CREDITS.txt keeps it)
    assert "pesta-wide" not in PAGE and not (ART / "pesta-wide.jpg").exists()   # 0.43.1: one Pesta file
    assert 'id="ambient" type="checkbox"' in PAGE and 'store("fbx-ambient")' in PAGE   # B can be turned off


def test_wait_screen_never_covers_the_vm_buttons():
    # it lives inside the tab area; the header (Start, Power off, Revert...) stays usable while Windows boots
    head, rest = PAGE.split('<div class="content" id="content">', 1)
    assert 'id="wait"' not in head and 'id="wait"' in rest.split('<nav class="tabs"', 1)[0]
    js = PAGE.split("function waitScreen", 1)[1].split("function setAmbient", 1)[0]
    assert "innerHTML" not in js


@pytest.mark.skipif(sys.platform == "win32", reason="fake VBoxManage is a POSIX shell wrapper")
def test_art_is_served_behind_the_token(lab):  # noqa: F811
    from test_windowless import _serve
    ctl, _, _ = lab
    httpd, port, _ = _serve(ctl)

    def get(path, cookie="fbx=tok123"):
        return urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Cookie": cookie}))

    try:
        r = get("/assets/art/pesta.jpg")
        assert r.headers["Content-Type"] == "image/jpeg" and r.read() == (ART / "pesta.jpg").read_bytes()
        assert "img-src 'self'" in r.headers["Content-Security-Policy"]
        for path, cookie in (("/assets/art/pesta.jpg", "fbx=wrong"), ("/assets/art/CREDITS.txt", "fbx=tok123"),
                             ("/assets/art/../page.html", "fbx=tok123")):
            with pytest.raises(urllib.error.HTTPError):
                get(path, cookie)
    finally:
        httpd.shutdown()
