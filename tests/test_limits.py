"""T-2 fetch limits: 1-30 in the VM too, two size limits, one shared time budget, the summary line."""
import secrets
import time

import pytest

from fatbox.cli import build_parser, main
from fatbox.config import load_config
from fatbox.fetch import common
from fatbox.fetch.common import FetchError, FetchStats, Filters, run_fetch
from fatbox.store import UNPACKED_CAP, Store, make_sample_zip, sha256_bytes


def pe() -> bytes:
    b = bytearray(b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little"))
    b += b"PE\x00\x00" + b"\x00" * 18 + (0x0102).to_bytes(2, "little") + b"\x00" * 64
    return bytes(b) + secrets.token_bytes(16)


class Src:
    name = "fake"

    def __init__(self, blobs, listed_size=None, slow=None):
        self.blobs = {sha256_bytes(b): b for b in blobs}
        self.listed_size, self.slow, self.deadlines = listed_size, slow, []

    def list_candidates(self):
        return [{"sha256": s, "file_type": "exe", "file_size": self.listed_size or len(b)} for s, b in self.blobs.items()]

    def download_zip(self, sha, pw, max_bytes, deadline_s=300, progress=None):
        self.deadlines.append(deadline_s)
        if self.slow:  # behaves like stream_body on a dead-slow link: gives up when its deadline passes
            time.sleep(deadline_s)
            raise FetchError(f"{sha[:16]}: gave up after {deadline_s:.0f}s")
        return make_sample_zip("x", self.blobs[sha], pw)


F = dict(file_types=["exe"], delay_seconds=0)


# --- Part 1: 1..30 (and the other ranges) are checked inside the VM too -------------------------------------
@pytest.mark.parametrize("argv", [["fetch", "--max", "0"], ["fetch", "--max", "31"], ["fetch", "--max", "x"],
                                  ["fetch", "--max-size-mb", "101"], ["fetch", "--budget", "59"],
                                  ["fetch", "--budget", "1801"]])
def test_cli_rejects_out_of_range(argv, capsys):
    with pytest.raises(SystemExit) as e:
        build_parser().parse_args(argv)
    err = capsys.readouterr().err
    assert e.value.code == 2 and ("must be" in err or "not a whole number" in err)


def test_cli_accepts_edges():
    a = build_parser().parse_args(["fetch", "--max", "30", "--max-size-mb", "100", "--budget", "60", "--no-size-limit"])
    assert (a.max, a.max_size_mb, a.budget, a.no_size_limit) == (30, 100, 60, True)


@pytest.mark.parametrize("toml, msg", [
    ("[filters]\nmax_per_run = 50\n", "max_per_run must be 1..30"),
    ("[fetch]\nbudget_s = 5000\n", "fetch_budget_s must be 60..1800"),
    ("[fetch]\ndownload_limit_mb = 0\n", "download_limit_mb must be 1..100"),
    ("[fetch]\ndownload_limit_on = \"no\"\n", "download_limit_on must be true or false"),
])
def test_config_out_of_range_stops_at_start(tmp_path, toml, msg, capsys):
    (tmp_path / "config.toml").write_text(toml)
    with pytest.raises(ValueError, match=msg):
        load_config(tmp_path / "config.toml")
    assert main(["-c", str(tmp_path / "config.toml"), "list"]) == 2
    assert msg in capsys.readouterr().err


def test_config_defaults_and_old_name(tmp_path):
    cfg = load_config(None)
    assert (cfg.download_limit_mb, cfg.download_limit_on, cfg.fetch_budget_s) == (5, True, 400)
    assert cfg.max_bytes == 5 * 1024 * 1024
    (tmp_path / "c.toml").write_text("[vault]\nmax_sample_mb = 20\n")  # pre-0.11 config keeps working
    assert load_config(tmp_path / "c.toml").download_limit_mb == 20
    cfg.download_limit_on = False
    assert cfg.max_bytes == UNPACKED_CAP  # limit off: downloads still stop at 100 MB


# --- Part 2: unpacked cap is separate from the download limit, and "too big" is skipped and reported ---------
def test_unpacked_cap_is_separate_from_download_limit(tmp_path, monkeypatch):
    """A 5 MB download limit no longer means a 5 MB unpack limit: a sample bigger than the download cap
    (but within the unpacked cap) unpacks fine as long as its zip fits."""
    blob = pe() + b"\x00" * 50_000  # compresses to far less than it unpacks to
    added = run_fetch(Store(tmp_path), Src([blob], listed_size=1), Filters(**F), "infected", 20_000)
    assert added == [sha256_bytes(blob)]


def test_too_big_to_analyze_is_skipped_and_counted(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(common, "UNPACKED_CAP", 10_000)
    caplog.set_level("INFO")
    stats, blob = FetchStats(), pe() + b"\x00" * 20_000
    store = Store(tmp_path)
    assert run_fetch(store, Src([blob], listed_size=1), Filters(**F), "infected", 1 << 20, stats=stats) == []
    assert stats.too_big == 1 and stats.failed == 0 and not store.has(sha256_bytes(blob))
    assert "too big to analyze (unpacks past" in caplog.text and "limit for this lab): skipped" in caplog.text


def test_listed_size_past_cap_is_counted_without_downloading(tmp_path):
    stats, src = FetchStats(), Src([pe()], listed_size=UNPACKED_CAP + 1)
    assert run_fetch(Store(tmp_path), src, Filters(**F), "infected", UNPACKED_CAP, stats=stats) == []
    assert stats.too_big == 1 and src.deadlines == []


# --- Part 3: one shared time budget ---------------------------------------------------------------------------
def test_budget_used_up_skips_the_rest(tmp_path, caplog):
    caplog.set_level("INFO")
    stats, src = FetchStats(), Src([pe(), pe(), pe()])
    added = run_fetch(Store(tmp_path), src, Filters(max_per_run=2, **F), "infected", 1 << 20,
                      deadline=time.monotonic() + 5, stats=stats)  # under MIN_START_S: not worth starting
    assert added == [] and src.deadlines == [] and stats.skipped_budget == 2
    assert "time budget used up: 0 stored, 2 skipped" in caplog.text


def test_download_never_outlives_the_budget_and_is_cut_off(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "MIN_START_S", 0.05)
    stats, src = FetchStats(), Src([pe(), pe()], slow=True)
    t0 = time.monotonic()
    added = run_fetch(Store(tmp_path), src, Filters(**F), "infected", 1 << 20, deadline=t0 + 0.4, stats=stats)
    assert added == [] and stats.cut_off == 1 and stats.failed == 0
    assert src.deadlines[0] <= 0.4 and time.monotonic() - t0 < 1.5
    assert stats.skipped_budget == 1  # the second sample was never started


def test_finished_samples_are_kept_when_time_runs_out(tmp_path):
    stats = FetchStats()
    added = run_fetch(Store(tmp_path), Src([pe(), pe()]), Filters(**F), "infected", 1 << 20,
                      deadline=time.monotonic() + 60, stats=stats)
    assert len(added) == 2 and stats.stored == 2 and stats.skipped_budget == 0


def test_summary_line():
    s = FetchStats(stored=2, too_big=1, skipped_budget=3)
    assert s.summary(107.4) == ("summary: 2 stored, 1 too big, 0 wrong type, 0 failed, 0 cut off, "
                                "3 skipped (budget), 107 s used")


def test_a_silent_connection_cannot_outlive_the_budget():
    from fatbox.fetch.http import STALL_SECONDS, stall_within
    assert stall_within(400) == STALL_SECONDS  # normal: the 45 s stall rule
    assert stall_within(12.5) == 12.5          # near the end of the budget: the socket gives up in time
    assert stall_within(0.2) == 1.0            # never below 1 s
