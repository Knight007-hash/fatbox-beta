"""Offline tests: no network, no live malware. Uses synthetic bytes and a benign PE if available."""
import glob
import json
import sys
from pathlib import Path

import pytest

import secrets

import requests

from fatbox.fetch.bazaar import BazaarSource
from fatbox.fetch.common import AuthError, FetchError, Filters, run_fetch
from fatbox.fetch.malshare import MalShareSource
from fatbox.static.basics import local_file_type
from fatbox.report import write_reports
from fatbox.static.strings_iocs import behaviour_hits, defang, extract_iocs, extract_strings
from fatbox.static.triage import triage
from fatbox.static.yara_scan import YaraScanner
from fatbox.store import SampleTooLarge, Store, make_sample_zip, read_sample_from_zip, sha256_bytes

RULES = Path(__file__).resolve().parents[1] / "rules" / "yara"

# Benign text that *looks* like a ransomware/stealer to exercise indicators. Not executable.
FAKE = (
    b"MZfake\x00\x00 cmd.exe /c vssadmin delete shadows /all /quiet\x00"
    b"Your files have been encrypted. Buy the decryption key with bitcoin at http://examplebad.top/pay\x00"
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00 https://api.telegram.org/bot123:abc/sendMessage\x00"
    b"8.8.4.4\x00 10.1.2.3\x00 kernel32.dll\x00 evil-c2.ru\x00\x00\x00"
    + "C:\\Users\\Public\\payload.exe".encode("utf-16le")
)


def test_zip_roundtrip_and_limit():
    z = make_sample_zip("a.bin", b"x" * 1000, "infected")
    name, data = read_sample_from_zip(z, "infected", 2000)
    assert name == "a.bin" and data == b"x" * 1000
    with pytest.raises(SampleTooLarge):
        read_sample_from_zip(z, "infected", 500)


def test_iocs_and_noise_filter():
    iocs = extract_iocs(extract_strings(FAKE))
    assert "8.8.4.4" in iocs["ipv4"] and "10.1.2.3" in iocs["ipv4_private"]
    assert "evil-c2.ru" in iocs["domains"] and "kernel32.dll" not in iocs["domains"]
    assert any("examplebad.top" in u for u in iocs["urls"])
    assert any("payload.exe" in p for p in iocs["paths"])  # UTF-16 string
    assert defang("http://a.b") == "hxxp[://]a[.]b"


def test_hostile_strings_do_not_hang_triage():
    import time
    # Each took minutes to hours with the old unbounded patterns; a sample stuck in triage blocks every later run.
    for data in (b"a." * 100_000 + b"1", b"powershell " * 50_000, b"bcdedit " * 60_000):
        t0 = time.monotonic()
        strings = extract_strings(data)
        extract_iocs(strings)
        behaviour_hits(strings)
        assert time.monotonic() - t0 < 5, data[:12]
    hits = {h["indicator"] for h in behaviour_hits(["powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A",
                                                    "bcdedit /set {default} recoveryenabled No"])}
    assert {"encoded PowerShell", "recovery disabled"} <= hits


def test_triage_non_pe_scores_and_yara():
    r = triage(FAKE, "fake.bin", YaraScanner(RULES))
    rules = {y["rule"] for y in r["yara"]}
    if YaraScanner(RULES).rules:
        assert {"FB_Shadow_Copy_Wipe", "FB_Ransom_Note_Language", "FB_Telegram_Discord_Exfil"} <= rules
    techniques = {b["attack"] for b in r["behaviour"]}
    assert {"T1490", "T1547.001", "T1567"} <= techniques
    assert r["priority"] in ("medium", "high")
    assert r["errors"]  # "MZfake" is not a valid PE -> recorded, not raised


def _benign_pe():
    cands = glob.glob(str(Path(sys.prefix) / "lib" / "*" / "site-packages" / "**" / "distlib" / "*.exe"), recursive=True)
    cands += glob.glob(str(Path(sys.prefix) / "Lib" / "site-packages" / "**" / "distlib" / "*.exe"), recursive=True)
    cands += glob.glob(str(Path.home() / ".cache" / "**" / "distlib" / "t32.exe"), recursive=True)
    return Path(cands[0]) if cands else None


def test_triage_real_pe(tmp_path):
    pe_path = _benign_pe()
    if not pe_path:
        pytest.skip("no benign PE available")
    r = triage(pe_path.read_bytes(), pe_path.name)
    assert r["kind"] == "pe" and r["pe"] and r["pe"]["sections"]
    assert r["pe"]["machine"].startswith("IMAGE_FILE_MACHINE")
    assert r["pe"]["pdb_path"] and r["pe"]["pdb_path"].endswith(".pdb")
    j, m = write_reports(r, tmp_path)
    assert json.loads(j.read_text())["hashes"]["sha256"] == r["hashes"]["sha256"]
    assert "## PE" in m.read_text()


# ---- fetch layer -------------------------------------------------------------

def _pe(dll=False) -> bytes:
    """Minimal MZ/PE header (not runnable) so local_file_type has something real to parse."""
    b = bytearray(b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little"))
    b += b"PE\x00\x00" + b"\x00" * 18 + (0x2102 if dll else 0x0102).to_bytes(2, "little") + b"\x00" * 64
    return bytes(b) + secrets.token_bytes(16)  # unique hash per call


class FakeSource:
    name = "fake"

    def __init__(self, samples):
        self.samples = samples  # sha -> (meta, bytes)

    def list_candidates(self):
        return [m for m, _ in self.samples.values()]

    def download_zip(self, sha, pw, max_bytes, deadline_s=300, progress=None):
        meta, data = self.samples[sha]
        return make_sample_zip("x", data, pw)


FILTERS = Filters(file_types=["exe"], delay_seconds=0)


def test_fetch_filters_dedups_and_verifies(tmp_path):
    exe, dll, unlabeled_dll = _pe(), _pe(dll=True), _pe(dll=True)
    s_exe, s_dll, s_unl = sha256_bytes(exe), sha256_bytes(dll), sha256_bytes(unlabeled_dll)
    s_liar = "0" * 64
    samples = {
        s_exe: ({"sha256": s_exe, "file_type": "exe", "signature": "AgentTesla"}, exe),
        s_dll: ({"sha256": s_dll, "file_type": "dll"}, dll),             # filtered on metadata
        s_unl: ({"sha256": s_unl}, unlabeled_dll),                        # filtered on real bytes
        s_liar: ({"sha256": s_liar, "file_type": "exe"}, b"tampered"),    # hash mismatch
    }
    store = Store(tmp_path)
    added = run_fetch(store, FakeSource(samples), FILTERS, "infected", 1 << 20)
    assert added == [s_exe]
    assert store.get(s_exe)["file_type"] == "exe" and store.get(s_exe)["source"] == "fake"
    assert store.zip_path_for(s_exe).suffix == ".quarantine"
    assert run_fetch(store, FakeSource(samples), FILTERS, "infected", 1 << 20) == []  # dedup


def test_local_file_type():
    assert local_file_type(_pe()) == "exe" and local_file_type(_pe(dll=True)) == "dll"
    assert local_file_type(b"\x7fELF....") == "elf"


class FakeResp:
    def __init__(self, status=200, content=b"", js=None):
        self.status_code, self.content, self._js = status, content, js
        self.headers = {"Content-Length": str(len(content))} if content else {}
        self.text = content.decode("latin-1")

    def json(self):
        if self._js is None:
            raise ValueError("no json")
        return self._js

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def iter_content(self, n):
        for i in range(0, len(self.content), n):
            yield self.content[i:i + n]

    def close(self):
        pass


class FakeSession:
    def __init__(self, handler):
        self.headers, self.handler, self.calls = {}, handler, []

    def post(self, url, data=None, timeout=None, stream=False):
        self.calls.append(("POST", data))
        return self.handler("POST", data)

    def get(self, url, params=None, timeout=None, stream=False):
        self.calls.append(("GET", params))
        return self.handler("GET", params)


def test_bazaar_source_end_to_end(tmp_path):
    exe = _pe()
    sha = sha256_bytes(exe)

    def handler(method, data):
        if data["query"] == "get_recent":
            return FakeResp(js={"query_status": "ok", "data": [
                {"sha256_hash": sha, "file_type": "exe", "file_size": len(exe), "signature": "Remcos",
                 "tags": ["exe", "RAT"]}]})
        return FakeResp(content=make_sample_zip(f"{sha}.exe", exe, "infected"))

    sess = FakeSession(handler)
    src = BazaarSource("KEY", session=sess)
    assert sess.headers["Auth-Key"] == "KEY"
    store = Store(tmp_path)
    assert run_fetch(store, src, FILTERS, "infected", 1 << 20) == [sha]
    assert store.get(sha)["signature"] == "Remcos"


def test_bazaar_auth_errors():
    with pytest.raises(AuthError):
        BazaarSource("")
    src = BazaarSource("BAD", session=FakeSession(lambda m, d: FakeResp(js={"query_status": "unknown_auth_key"})))
    with pytest.raises(AuthError):
        src.list_candidates()
    src = BazaarSource("BAD", session=FakeSession(lambda m, d: FakeResp(status=401)))
    with pytest.raises(AuthError):
        src.list_candidates()


def test_malshare_wraps_raw_download_in_zip(tmp_path):
    exe = _pe()
    sha = sha256_bytes(exe)

    def handler(method, params):
        if params["action"] == "getlist":
            return FakeResp(js=[{"md5": "x", "sha1": "y", "sha256": sha}])
        if params["action"] == "getfile":
            return FakeResp(content=exe)
        raise AssertionError(params)

    store = Store(tmp_path)
    added = run_fetch(store, MalShareSource("KEY", session=FakeSession(handler)), FILTERS, "infected", 1 << 20)
    assert added == [sha]
    zip_bytes = store.zip_path_for(sha).read_bytes()
    assert zip_bytes.startswith(b"PK") and exe not in zip_bytes  # stored encrypted, never plaintext
    assert read_sample_from_zip(zip_bytes, "infected", 1 << 20)[1] == exe


def test_malshare_size_cap_and_quota():
    big = FakeSession(lambda m, p: FakeResp(content=b"A" * 5000))
    with pytest.raises(FetchError):
        MalShareSource("KEY", session=big).download_zip("a" * 64, "infected", 1000)
    with pytest.raises(AuthError):
        MalShareSource("KEY", session=FakeSession(lambda m, p: FakeResp(status=429))).list_candidates()


def test_one_bad_source_does_not_stop_others(tmp_path, monkeypatch, capsys):
    from fatbox import cli
    monkeypatch.delenv("MB_API_KEY", raising=False)
    monkeypatch.delenv("MALSHARE_API_KEY", raising=False)
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text(f'[paths]\ndata_dir = "{(tmp_path / "d").as_posix()}"\n[fetch]\nsources = ["bazaar", "malshare"]\n')
    rc = cli.main(["-c", str(cfg_file), "fetch"])
    out = capsys.readouterr()
    assert rc == 2 and "bazaar: fetch failed" in out.err and "malshare: fetch failed" in out.err


class StallingResp(FakeResp):
    def iter_content(self, n):
        yield b"PK\x03\x04partial"
        raise requests.exceptions.ConnectionError("Read timed out.")


def test_stall_surfaces_as_clear_error():
    src = BazaarSource("KEY", session=FakeSession(lambda m, d: StallingResp(content=b"x" * 10)))
    with pytest.raises(FetchError, match="stalled"):
        src.download_zip("a" * 64, "infected", 1 << 20)


def test_content_length_over_cap_rejected_before_download():
    r = FakeResp(content=b"A" * 10)
    r.headers["Content-Length"] = str(50 << 20)
    src = MalShareSource("KEY", session=FakeSession(lambda m, p: r))
    with pytest.raises(FetchError, match="exceeds cap"):
        src.download_zip("a" * 64, "infected", 1 << 20)


def test_small_first_and_progress_logging(tmp_path, caplog):
    big, small = _pe() + b"B" * 5000, _pe()
    samples = {
        sha256_bytes(big): ({"sha256": sha256_bytes(big), "file_type": "exe", "file_size": len(big)}, big),
        sha256_bytes(small): ({"sha256": sha256_bytes(small), "file_type": "exe", "file_size": len(small)}, small),
    }
    f = Filters(file_types=["exe"], delay_seconds=0, small_first=True, max_per_run=1)
    caplog.set_level("INFO")
    added = run_fetch(Store(tmp_path), FakeSource(samples), f, "infected", 1 << 20)
    assert added == [sha256_bytes(small)]
    assert "2 pass filters" in caplog.text and "[1/1]" in caplog.text and "stored" in caplog.text


def test_yara_error_keeps_the_report():
    """0.39.3: a YARA timeout or scan error goes into the report's errors instead of failing the sample."""
    import yara
    scanner = YaraScanner(RULES)

    class Boom:
        def match(self, **kw):
            raise yara.TimeoutError("scan timed out")
    scanner.rules = Boom()
    r = triage(FAKE, "s.bin", scanner)
    assert r["yara"] == [] and any(e.startswith("yara: ") for e in r["errors"]) and r["score"] >= 0
