"""0.18.4: a reproducible build (debug entry type REPRO) has a hash, not a date, in TimeDateStamp.

The PE here is built in code (not runnable, one empty .text section, a debug directory), never a real sample.
"""
from __future__ import annotations

import struct

from fatbox.report import _compiled
from fatbox.static.pe import DEBUG_TYPE_REPRO, analyze_pe
from fatbox.static.triage import triage

FUTURE = 0xB0000000   # year 2063: what a Roslyn /deterministic hash often looks like as a date
PAST = 0x5F5E1000     # 2020-09-13: an ordinary date

REASON = "zero/future compile timestamp"


def build_pe(timestamp: int, debug_types: tuple[int, ...] = ()) -> bytes:
    """PE32 with a .text section at RVA/offset 0x200 that holds the debug directory entries."""
    lfanew = 0x40
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", lfanew)
    n_dbg = len(debug_types)
    fh = struct.pack("<HHIIIHH", 0x14C, 1, timestamp, 0, 0, 0xE0, 0x0102)
    dirs = [(0, 0)] * 16
    if n_dbg:
        dirs[6] = (0x200, 28 * n_dbg)  # IMAGE_DIRECTORY_ENTRY_DEBUG
    oh = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
                     0x10B, 14, 0, 0x200, 0, 0, 0x200, 0x200, 0x200, 0x400000, 0x200, 0x200,
                     6, 0, 0, 0, 6, 0, 0, 0x400, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    oh += b"".join(struct.pack("<II", *d) for d in dirs)
    sec = struct.pack("<8sIIIIIIHHI", b".text", 0x200, 0x200, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    head = (dos + b"PE\x00\x00" + fh + oh + sec).ljust(0x200, b"\x00")
    body = b"".join(struct.pack("<IIHHIIII", 0, timestamp, 0, 0, t, 0, 0, 0) for t in debug_types)
    return head + body.ljust(0x200, b"\x00")


def test_reproducible_build_future_date_is_not_flagged():
    pe = analyze_pe(build_pe(FUTURE, (2, DEBUG_TYPE_REPRO)))  # CODEVIEW + REPRO, like a Roslyn build
    assert pe["reproducible_build"] is True
    assert pe["compile_time_anomaly"] is False
    assert _compiled(pe) == "not a real date (reproducible build)"


def test_reproducible_build_zero_date_is_not_flagged():
    pe = analyze_pe(build_pe(0, (DEBUG_TYPE_REPRO,)))
    assert pe["reproducible_build"] is True and pe["compile_time_anomaly"] is False


def test_future_date_without_repro_still_flagged():
    pe = analyze_pe(build_pe(FUTURE, (2,)))
    assert pe["reproducible_build"] is False and pe["compile_time_anomaly"] is True
    assert "anomalous" in _compiled(pe)
    assert analyze_pe(build_pe(0))["compile_time_anomaly"] is True


def test_ordinary_date_not_flagged():
    pe = analyze_pe(build_pe(PAST))
    assert pe["reproducible_build"] is False and pe["compile_time_anomaly"] is False
    assert pe["compile_time"].startswith("2020-09-13")


def test_score_drops_the_5_points_only_for_reproducible_builds():
    repro = triage(build_pe(FUTURE, (DEBUG_TYPE_REPRO,)), "a.exe")
    plain = triage(build_pe(FUTURE), "b.exe")
    assert not any(REASON in x for x in repro["reasons"])
    assert any(REASON in x for x in plain["reasons"])


def test_old_reports_without_the_field_still_render():
    old = {"compile_time": "2063-01-01T00:00:00+00:00", "compile_time_anomaly": True}
    assert _compiled(old).endswith("⚠ anomalous")
