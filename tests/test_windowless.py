"""0.20.0: the host GUI started from a desktop shortcut with pythonw (no console window)."""
import json
import logging
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from fatbox.host import cli, server
from fatbox.host.server import Job, make_handler
from test_host import lab  # noqa: F401  (fixture)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="fake VBoxManage is a POSIX shell wrapper")


def _serve(ctl, token="tok123", on_quit=None):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    job = Job(ctl)
    httpd.RequestHandlerClass = make_handler(ctl, job, port, token, on_quit=on_quit)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port, job


def _post(port, path, token="tok123"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", b"{}", method="POST",
                                 headers={"Cookie": f"fbx={token}", "X-FatBox": "1"})
    return json.loads(urllib.request.urlopen(req).read())


def test_quit_stops_the_server(lab):  # noqa: F811
    ctl, _, _ = lab
    stopped = threading.Event()
    httpd, port, job = _serve(ctl, on_quit=stopped.set)
    try:
        job.state = "running"  # a running fetch or update blocks Quit
        with pytest.raises(urllib.error.HTTPError) as e:
            _post(port, "/api/quit")
        assert e.value.code == 400 and "still running" in json.loads(e.value.read())["error"]
        job.state = "done"
        assert _post(port, "/api/quit")["ok"] and stopped.wait(5)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_quit_needs_token_and_a_quit_hook(lab):  # noqa: F811
    ctl, _, _ = lab
    httpd, port, _ = _serve(ctl)
    try:
        with pytest.raises(urllib.error.HTTPError) as e:
            _post(port, "/api/quit", token="wrong")
        assert e.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as e:
            _post(port, "/api/quit")  # tests and embedders without a hook: refused, not crashed
        assert e.value.code == 400
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_second_click_opens_the_running_gui(lab, monkeypatch):  # noqa: F811
    ctl, _, home = lab
    home.mkdir(parents=True, exist_ok=True)
    httpd, port, _ = _serve(ctl)
    try:
        assert server._running_url(home, port) is None  # no file yet
        url = f"http://127.0.0.1:{port}/?t=" + "A" * 43
        (home / server.URL_FILE).write_text("javascript:alert(1)\n")
        assert server._running_url(home, port) is None  # only our own URL shape is ever opened
        (home / server.URL_FILE).write_text(url + "\n")
        assert server._running_url(home, port) == url
        opened = []
        monkeypatch.setattr(server.webbrowser, "open", opened.append)
        ctl.s.port = port
        server.serve(ctl)  # returns at once: the port is ours already
        assert opened == [url]
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert server._running_url(home, port) is None  # stale file, nothing listening


def test_busy_port_is_a_plain_error(lab):  # noqa: F811
    ctl, _, home = lab
    home.mkdir(parents=True, exist_ok=True)
    blocker = ThreadingHTTPServer(("127.0.0.1", 0), None)  # someone else's server, no URL file
    try:
        ctl.s.port = blocker.server_address[1]
        with pytest.raises(ValueError, match="busy"):
            server.serve(ctl, open_browser=False)
    finally:
        blocker.server_close()


def test_windowless_errors_go_to_a_message_box_and_the_log(tmp_path, monkeypatch):
    boxes = []
    monkeypatch.setattr(cli, "_message_box", boxes.append)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    root = logging.getLogger()
    saved = root.handlers[:]
    try:
        rc = cli.main(["--settings", str(tmp_path / "host.toml"), "gui"])  # no host.toml there
        print("printed line")
        for h in logging.getLogger().handlers:
            h.flush()
    finally:
        for h in root.handlers:
            h.close()
        root.handlers[:] = saved
    assert rc == 2 and len(boxes) == 1 and "could not start" in boxes[0]
    log = (tmp_path / cli.LOG_NAME).read_text(encoding="utf-8")
    assert "error:" in log and "printed line" in log


def test_shortcut_target_uses_pythonw_next_to_this_python(tmp_path, monkeypatch):
    exe = tmp_path / "python.exe"
    exe.write_text("")
    monkeypatch.setattr(sys, "executable", str(exe))
    with pytest.raises(FileNotFoundError, match="pythonw.exe"):
        cli.shortcut_target()
    (tmp_path / "pythonw.exe").write_text("")
    target, args, folder = cli.shortcut_target()
    assert target == str(tmp_path / "pythonw.exe") and args == "-m fatbox.host gui"
    assert (__import__("pathlib").Path(folder) / "fatbox" / "host" / "cli.py").exists()
