"""0.27.0: the FatBox rune icon (desktop shortcut + browser tab) and the runic wordmark (inline SVG, our own
drawing). One fixed asset file is served, behind the same token as everything else; nothing is loaded from the
internet, and the page's own CSP allows images from the host only."""
import json
import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from fatbox.host import server

ASSETS = Path(server.__file__).with_name("assets")


def test_shipped_files_and_their_licenses():
    for name in ("fatbox.ico", "favicon.png", "icon.svg", "OFL-NotoSansRunic.txt"):
        assert (ASSETS / name).is_file(), name
    assert "SIL Open Font License" in (ASSETS / "OFL-NotoSansRunic.txt").read_text(encoding="utf-8")
    assert not list(ASSETS.glob("*.woff*"))              # no font files: the wordmark is drawn
    assert (ASSETS / "favicon.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_the_icon_is_a_real_windows_ico_with_every_size():
    raw = (ASSETS / "fatbox.ico").read_bytes()
    reserved, kind, count = struct.unpack_from("<HHH", raw)
    assert (reserved, kind) == (0, 1)
    sizes = set()
    for i in range(count):
        w, h, _, _, _, _, size, off = struct.unpack_from("<BBBBHHII", raw, 6 + 16 * i)
        assert raw[off:off + 8] == b"\x89PNG\r\n\x1a\n" and off + size <= len(raw)
        sizes.add(w or 256)
    assert {16, 24, 32, 48, 256} <= sizes


def test_the_wordmark_is_an_inline_drawing_and_no_font_changes():
    page = server.PAGE.read_text(encoding="utf-8")
    assert '<h1 aria-label="FatBox"' in page and page.count('class="wordmark"') == 1
    assert "@font-face" not in page
    assert "https://" not in page.split("<script>")[0]    # no CDN: everything comes from the host


@pytest.mark.skipif(sys.platform == "win32", reason="fake VBoxManage is a POSIX shell wrapper")
def test_assets_are_served_behind_the_token(lab):  # noqa: F811
    from test_windowless import _serve
    ctl, _, _ = lab
    httpd, port, _ = _serve(ctl)

    def get(path, cookie="fbx=tok123"):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Cookie": cookie})
        return urllib.request.urlopen(req)

    try:
        r = get("/assets/favicon.png")
        assert r.headers["Content-Type"] == "image/png" and r.read() == (ASSETS / "favicon.png").read_bytes()
        csp = r.headers["Content-Security-Policy"]
        assert "img-src 'self'" in csp and "font-src" not in csp and "script-src 'sha256-" in csp
        for path in ("/assets/fatbox.ico", "/assets/../page.html", "/assets/icon.svg", "/assets/x.woff2"):
            with pytest.raises(urllib.error.HTTPError) as e:
                get(path)
            assert e.value.code == 404
        with pytest.raises(urllib.error.HTTPError) as e:
            get("/assets/favicon.png", cookie="fbx=wrong")
        assert e.value.code == 403 and "token" in json.loads(e.value.read())["error"]
    finally:
        httpd.shutdown()
        httpd.server_close()


from test_host import lab  # noqa: E402,F401  (fixture)
