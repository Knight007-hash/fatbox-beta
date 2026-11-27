from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path

from fatbox import __version__
from fatbox.config import (MAX_CAPA_S, MAX_PARALLEL, MAX_SAMPLE_S, MAX_SHARE, MIN_CAPA_S, MIN_SAMPLE_S,
                           RAM_RESERVE_GB, SAMPLE_RAM_GB, STAGGER_S, TRIAGE_PER_RUN, auto_parallel, cpu_share,
                           free_ram_gb, load_config, room_for_one_more)
from fatbox.report import write_reports
from fatbox.static.triage import priority, score, triage
from fatbox.static.yara_scan import YaraScanner
from fatbox.store import UNPACKED_CAP, Store, make_sample_zip, read_sample_from_zip, sha256_bytes

log = logging.getLogger("fatbox")
MAX_PICKS = 30      # picked sha256s per fetch (same 1..30 rule as --max)
BROWSE_MAX = 1000   # rows in a browse list


def bounded(lo: int, hi: int):
    """argparse type: an int in lo..hi, else a clear error (the VM checks limits itself, SPEC F-1)."""
    def parse(text: str) -> int:
        try:
            n = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"not a whole number: {text!r}")
        if not lo <= n <= hi:
            raise argparse.ArgumentTypeError(f"must be {lo}..{hi}")
        return n
    return parse


def sha256_arg(text: str) -> str:
    """argparse type: exactly 64 hex characters (T-13 picks come from the host; the VM checks them too)."""
    s = text.strip().lower()
    if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
        raise argparse.ArgumentTypeError(f"not a sha256: {text[:70]!r}")
    return s


NAME_RE = re.compile(r"^[A-Za-z0-9._\- ]{1,40}$")
MAX_NAMES = 20


def name_list(text: str) -> list[str]:
    """argparse type: comma-separated tags or family names (0.23.0 Settings), each 1..40 of A-Z a-z 0-9 . _ - space."""
    names = [n.strip() for n in text.split(",") if n.strip()]
    if len(names) > MAX_NAMES:
        raise argparse.ArgumentTypeError(f"at most {MAX_NAMES} names")
    for n in names:
        if not NAME_RE.match(n):
            raise argparse.ArgumentTypeError(f"bad name {n[:50]!r}: letters, digits, . _ - and space only (max 40)")
    return names


def type_list(text: str) -> list[str]:
    """argparse type: comma-separated file-type choices from TYPE_GROUPS (exe, dll, office, lnk, elf, pdf, ps1)."""
    from fatbox.fetch.common import TYPE_GROUPS
    picks = [t.strip().lower() for t in text.split(",") if t.strip()]
    bad = [t for t in picks if t not in TYPE_GROUPS]
    if not picks or bad:
        raise argparse.ArgumentTypeError(f"choose from {', '.join(TYPE_GROUPS)}")
    return list(dict.fromkeys(picks))


def make_source(cfg, name: str, args):
    if name == "bazaar":
        from fatbox.fetch.bazaar import BazaarSource, PickedSource
        b = cfg.bazaar
        if getattr(args, "sha256", None):
            return PickedSource(BazaarSource(b.api_key, "recent", "", b.limit), args.sha256)
        limit = getattr(args, "limit", None) if getattr(args, "cmd", None) == "browse" else None
        return BazaarSource(b.api_key, args.mode or b.mode, args.value or b.query_value, limit or b.limit)
    if name == "malshare":
        from fatbox.fetch.malshare import MalShareSource
        return MalShareSource(cfg.malshare.api_key, cfg.malshare.type_filter)
    raise ValueError(f"unknown source: {name}")


def cmd_fetch(cfg, store, args) -> int:
    import time

    from fatbox.fetch.common import AuthError, FetchError, FetchStats, run_fetch
    if args.max is not None:
        cfg.filters.max_per_run = args.max
    if args.max_size_mb is not None:
        cfg.download_limit_mb = args.max_size_mb
    if args.no_size_limit:
        cfg.download_limit_on = False
    if args.budget is not None:
        cfg.fetch_budget_s = args.budget
    if args.small_first:
        cfg.filters.small_first = True
    # 0.23.0: the host's Settings tab. Every value is checked again here (bounded/name_list/type_list + cfg.check)
    from fatbox.fetch.common import TYPE_GROUPS
    if args.types is not None:
        cfg.filters.file_types = [label for t in args.types for label in TYPE_GROUPS[t]]
    if args.tags is not None:
        cfg.filters.tags_any = args.tags
    if args.skip_families is not None:
        cfg.filters.signatures_none = args.skip_families
    if args.min_size_kb is not None:
        cfg.filters.min_size_kb = args.min_size_kb
    if args.unpack_limit_mb is not None:
        cfg.unpack_limit_mb = args.unpack_limit_mb
    if args.too_big is not None:
        cfg.too_big = args.too_big
    if args.sha256:
        # T-13 picks: exactly these, no list query. The type filter is a preference, and the user chose these
        # on purpose; every safety rule (sha256 match, limits, cap, budget) stays.
        if len(args.sha256) > MAX_PICKS:
            print(f"at most {MAX_PICKS} sha256s per fetch", file=sys.stderr)
            return 2
        picks = list(dict.fromkeys(args.sha256))
        have = [s for s in picks if store.has(s)]
        for s in have:
            print(f"{s[:16]} already in the VM: skipped")
        args.sha256 = [s for s in picks if s not in have]
        if args.source not in (None, "bazaar"):
            print("picked samples come from bazaar only", file=sys.stderr)
            return 2
        args.source = "bazaar"
        cfg.filters.file_types, cfg.filters.tags_any, cfg.filters.signatures_any = [], [], []
        cfg.filters.signatures_none, cfg.filters.min_size_kb = [], 0
        cfg.filters.max_per_run = max(1, len(args.sha256))
        cfg.filters.small_first = False
        print(f"picked: {len(picks)} sample(s), {len(have)} already in the VM", flush=True)
        if not args.sha256:
            print("total: 0")
            return 0
    cfg.check()
    cap_mb = cfg.cap // (1024 * 1024)
    print(f"limits: {cfg.filters.max_per_run} samples, download limit "
          + (f"{min(cfg.download_limit_mb, cap_mb)} MB" if cfg.download_limit_on else f"off (stops at {cap_mb} MB)")
          + f", unpack limit {cap_mb} MB (bigger: {'metadata kept' if cfg.too_big == 'info' else 'skipped'})"
          + f", time budget {cfg.fetch_budget_s} s", flush=True)
    f = cfg.filters
    if not args.sha256 and (f.file_types or f.tags_any or f.signatures_none or f.min_size_kb):
        print("filters: types " + (", ".join(f.file_types) or "any")
              + (f"; tags {', '.join(f.tags_any)}" if f.tags_any else "")
              + (f"; never {', '.join(f.signatures_none)}" if f.signatures_none else "")
              + (f"; at least {f.min_size_kb} KB" if f.min_size_kb else ""), flush=True)
    start = time.monotonic()
    deadline, stats = start + cfg.fetch_budget_s, FetchStats()
    sources = [args.source] if args.source else cfg.sources
    total, rc = 0, 0
    for name in sources:
        try:
            added = run_fetch(store, make_source(cfg, name, args), cfg.filters, cfg.zip_password, cfg.max_bytes,
                              deadline, stats, cap=cfg.cap, keep_info=cfg.too_big == "info")
            print(f"{name}: {len(added)} new sample(s)")
            total += len(added)
        except (AuthError, FetchError) as e:
            print(f"{name}: fetch failed: {e}", file=sys.stderr)
            rc = 2
        except Exception as e:  # network down etc.: one source failing must not stop the others
            log.exception("%s: unexpected error", name)
            print(f"{name}: fetch failed: {type(e).__name__}: {e}", file=sys.stderr)
            rc = 2
    print(f"total: {total}")
    print(stats.summary(time.monotonic() - start))
    return rc


def cmd_browse(cfg, store, args) -> int:
    """T-13: the candidate list only (metadata, no files), as JSON for the host GUI. Downloads nothing."""
    from fatbox.fetch.common import AuthError, FetchError
    try:
        rows = make_source(cfg, "bazaar", args).list_candidates()
    except (AuthError, FetchError, ValueError) as e:
        print(f"browse failed: {e}", file=sys.stderr)
        return 2
    rows = [r for r in rows if isinstance(r.get("sha256"), str)][:BROWSE_MAX]
    for r in rows:
        r["in_vm"] = store.has(r["sha256"].lower())
    print(json.dumps({"rows": rows}))
    return 0


def cmd_sources(cfg, store, args) -> int:
    """Check keys/quotas without downloading anything."""
    from fatbox.fetch.common import AuthError, FetchError
    for name in ("bazaar", "malshare"):
        try:
            src = make_source(cfg, name, argparse.Namespace(mode=None, value=None))
            if name == "malshare":
                info = src.limits()
                if args.malshare_types:
                    info = {"limits": info, "types_24h": src._get("gettypes").json()}
                print(f"malshare: OK {info}")
            else:
                print(f"bazaar: OK, {len(src.list_candidates())} samples in current '{src.mode}' window")
        except (AuthError, FetchError, ValueError) as e:
            print(f"{name}: {e}")
        except Exception as e:
            print(f"{name}: {type(e).__name__}: {e}")
    return 0


def cmd_import(cfg, store, args) -> int:
    """Import a local sample. Prefer an already password-zipped file."""
    p = Path(args.path)
    raw = p.read_bytes()
    if raw.startswith(b"PK"):
        name, data = read_sample_from_zip(raw, args.password or cfg.zip_password, UNPACKED_CAP)
        zip_bytes = raw if not args.password else make_sample_zip(name, data, cfg.zip_password)
    else:
        log.warning("importing a plaintext file: delete the original once imported")
        name, data = p.name, raw
        zip_bytes = make_sample_zip(name, data, cfg.zip_password)
    sha = sha256_bytes(data)
    store.add(sha, zip_bytes, {"file_name": name, "tags": args.tag or []}, source="manual")
    print(sha)
    return 0


def triage_one(cfg, store, scanner, row, config_path: str | None = None, limit_s: int | None = None,
               capa_s: int | None = None, capa_packed: str | None = None, share: int = 1) -> dict | None:
    """share (0.32.0): how many samples share one CPU right now; the sub-helpers' limits are stretched by it."""
    from fatbox.static import code_analysis as ca
    from fatbox.static import file_analysis as fa
    sha, engines, capa = row["sha256"], None, None
    config_path = config_path or "config.toml"
    try:
        # T-9: the engines start first, in their own sub-helper, with half the sample limit (min 5 s)
        engines = fa.Run(sha, config_path, max(5, (limit_s or cfg.sample_time_s) // 2) * share)
        name, data = read_sample_from_zip(Path(row["zip_path"]), cfg.zip_password, UNPACKED_CAP)
        engine_result = engines.result()  # Detect It Easy takes a second or two
        # 0.21.0: capa starts once DIE has answered, so a packed native program can skip it (only the unpacking
        # stub would be analysed). It still runs side by side with the rest of triage, with its own limit (T-14).
        # 0.23.0: Settings "capa on packed programs: run anyway" turns this skip off
        skip = None if (capa_packed or cfg.capa_packed) == "run" else ca.skip_reason(fa.build(*engine_result, data, None), data)
        if not skip:
            capa = fa.Run(sha, config_path, (capa_s or cfg.capa_time_s) * share, command="capa-one", label="code analysis",
                          extra=("--lib-skip",) if cfg.capa_lib_skip else (),
                          statuses=ca.STATUSES)
        report = triage(data, name, scanner)
        report["file_analysis"] = fa.build(*engine_result, data, report.get("pe"))
        report["code_analysis"] = ca.build("skipped", skip, None) if skip else ca.build(*capa.result())
        report["score"], report["reasons"] = score(report)
        report["priority"] = priority(report["score"])
        del data
        meta = {k: row[k] for k in ("source", "first_seen", "file_name", "file_type", "signature")}
        meta["tags"] = json.loads(row["tags"] or "[]")
        jpath, _ = write_reports(report, store.report_dir_for(sha), meta)
        store.set_result(sha, "static_done", report["score"], report["priority"])
        print(f"{report['priority']:>6} {report['score']:>3}  {sha[:16]}  {meta['signature'] or '-':<20} {jpath}")
        return report
    except Exception as e:
        for helper in (engines, capa):
            if helper is not None:
                helper.stop()
        log.exception("triage failed for %s", sha)
        store.set_result(sha, "error", error=f"{type(e).__name__}: {e}")
        return None


TIMEOUT_REASON = "analysis took longer than {} s: stopped"


def kill_tree(p) -> None:
    """Stop a helper and every process it started. Windows: taskkill /T; elsewhere: its own process group."""
    import os
    import signal
    import subprocess
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True, timeout=30)
        else:
            os.killpg(p.pid, signal.SIGKILL)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        p.kill()
    except OSError:
        pass
    p.wait()


def triage_isolated(cfg, store, row, limit_s: int, config_path: str, capa_s: int | None = None,
                    capa_packed: str | None = None, share: int = 1) -> str:
    """Triage one sample in its own helper process with a stopwatch (T-5). A file built to hang a parser
    can only cost limit_s + capa_s: the helper is killed, the sample is marked "timeout" and never picked again.
    capa (T-14) has its own limit inside that; when only capa runs over, the report is still made.
    0.32.0: when samples share CPUs (more at once than the VM has CPUs), every limit is stretched by `share`,
    so each sample still gets the CPU time it would have had alone."""
    import os
    import shutil
    import subprocess
    sha = row["sha256"]
    root = str(Path(__file__).resolve().parents[1])
    env = {**os.environ, "PYTHONPATH": root + os.pathsep + os.environ.get("PYTHONPATH", "")}
    capa_s = capa_s or cfg.capa_time_s
    total = (limit_s + capa_s) * share
    cmd = [sys.executable, "-m", "fatbox", "-c", config_path, "triage-one", sha, "--sample-time", str(limit_s),
           "--capa-time", str(capa_s), "--capa-packed", capa_packed or cfg.capa_packed, "--share", str(share)]
    try:
        p = subprocess.Popen(cmd, env=env, cwd=root, start_new_session=os.name != "nt")
    except OSError as e:
        store.set_result(sha, "error", error=f"could not start the analysis helper: {e}")
        return "error"
    try:
        rc = p.wait(timeout=total)
    except subprocess.TimeoutExpired:
        kill_tree(p)  # the helper and its sub-helpers (T-9 file analysis, T-14 capa)
        shutil.rmtree(store.report_dir_for(sha), ignore_errors=True)  # a half-written report is no report
        store.set_result(sha, "timeout", error=TIMEOUT_REASON.format(total))
        print(f"TIMEOUT      {sha[:16]}  {TIMEOUT_REASON.format(total)}", flush=True)
        return "timeout"
    status = (store.get(sha) or {"status": "error"})["status"]
    if status == "fetched":  # the helper died without a word (crash, out of memory)
        store.set_result(sha, "error", error=f"analysis helper crashed (exit {rc})")
        status = "error"
    return "done" if status == "static_done" else "error"


def warm_capa_rules(cfg) -> None:
    """Compile the capa rules once before the helpers start. capa keeps the compiled set in its own cache
    (%LOCALAPPDATA%\\flare\\capa\\cache), so every capa-one helper loads it in a fraction of a second instead of
    parsing 1,000+ rule files; without this, parallel helpers right after an update would all compile at once."""
    import time
    from fatbox.static.code_analysis import rule_set
    start = time.monotonic()
    try:
        rule_set(Path(cfg.capa_dir))
    except Exception as e:  # capa missing or broken: each helper reports it in its own report
        log.warning("capa rules not prepared: %s: %s", type(e).__name__, e)
        return
    if time.monotonic() - start > 2:
        print(f"capa rules compiled and cached ({time.monotonic() - start:.0f} s, once per update)", flush=True)


def cmd_triage(cfg, store, args) -> int:
    import os
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor
    if args.sample_time is not None:
        cfg.sample_time_s = args.sample_time
    if args.capa_time is not None:
        cfg.capa_time_s = args.capa_time
    if args.parallel is not None:
        cfg.parallel = args.parallel
    if args.capa_packed is not None:
        cfg.capa_packed = args.capa_packed
    cfg.check()
    if args.sha256:
        row = store.get(args.sha256.lower())
        if not row:
            print("unknown sha256", file=sys.stderr)
            return 1
        if row["status"] == "too_big":
            print("too big: only its metadata was kept, there is no file to analyse", file=sys.stderr)
            return 1
        rows = [row]
    else:
        rows = store.by_status("fetched") + (store.by_status("error") if args.retry_errors else [])
    if not rows:
        print("nothing to triage")
        return 0
    now = rows[:TRIAGE_PER_RUN]
    later = f", {len(rows) - len(now)} left for the next run" if len(rows) > len(now) else ""
    cpus = os.cpu_count() or 1
    free = free_ram_gb()
    workers = min(cfg.parallel or auto_parallel(cpus), len(now))
    share = cpu_share(workers, cpus)
    per = cfg.sample_time_s + cfg.capa_time_s
    ram = (f", {free:.1f} GB free RAM; each start needs {RAM_RESERVE_GB + SAMPLE_RAM_GB:.1f} GB free"
           if free is not None else "")
    stretch = f", limits x{share} (samples share CPUs)" if share > 1 else ""
    print(f"triage: {len(rows)} waiting, limit {cfg.sample_time_s} s per sample + {cfg.capa_time_s} s for capa, "
          f"up to {workers} at a time ({cpus} CPUs{ram}){stretch}{later}", flush=True)
    config_path = str(Path(args.config).resolve())
    counts = {"done": 0, "timeout": 0, "error": 0, "later": 0}
    start = time.monotonic()
    # 0.32.0: the whole run stays inside TRIAGE_PER_RUN x (limit + capa limit), the host's own stopwatch for this
    # step (minus its margin), however many run at once and however long the RAM guard waits. A sample that could
    # not finish inside what is left is not started: it stays waiting for the next run.
    run_end = start + TRIAGE_PER_RUN * per
    warm_capa_rules(cfg)
    gate = threading.Condition()
    running, most, ram_wait = [0], [0], [0.0]
    young: list[float] = []  # start times of running helpers younger than STAGGER_S (their RAM may still rise)

    def held() -> float:
        """0.39.0: free RAM as a new start may count it: what Windows shows minus SAMPLE_RAM_GB for each helper
        started in the last STAGGER_S seconds, whose RAM may not show yet. Unknown free RAM stays unknown."""
        free = free_ram_gb()
        now_t = time.monotonic()
        young[:] = [t for t in young if now_t - t < STAGGER_S]
        return None if free is None else free - SAMPLE_RAM_GB * len(young)

    def one(row) -> str:
        # Each sample has its own helper and its own stopwatch (limit + capa limit, x share). The stopwatch starts
        # when the helper starts, so waiting in the queue never counts against a sample. SQLite connections can't
        # cross threads, so each worker opens its own.
        with gate:
            # Live RAM gate (0.34.0; 0.39.0 reserves instead of waiting). Beside running samples, a new one starts
            # only while the VM really has room for one more (room_for_one_more), counting each helper started in
            # the last STAGGER_S as already holding SAMPLE_RAM_GB, because its RAM (mostly capa's library
            # signatures) may not show yet. Up to 0.38.0 every start waited STAGGER_S after the last one instead:
            # on runs of small samples that gap was most of the time. The first sample always may run. So Windows
            # never pages sample bytes out to its pagefile on disk (INV-2), and the VM doesn't run out of memory.
            while running[0] > 0 and not room_for_one_more(held()):
                t = time.monotonic()
                gate.wait(timeout=1.0)  # a finished helper notifies at once; otherwise poll free RAM
                ram_wait[0] += time.monotonic() - t  # 0.38.0: time held back by RAM, for the timers
            if run_end - time.monotonic() < per * share:
                return "later"
            running[0] += 1
            most[0] = max(most[0], running[0])
            born = time.monotonic()
            young.append(born)
        own = Store(cfg.data_dir)
        t0 = time.monotonic()
        try:
            result = triage_isolated(cfg, own, row, cfg.sample_time_s, config_path, cfg.capa_time_s, share=share)
            print(f"time   {row['sha256'][:16]}  {time.monotonic() - t0:.0f} s  {result}", flush=True)  # 0.38.0
            return result
        finally:
            with gate:  # first: the helper has exited, so its RAM is free and a waiting sample may go
                running[0] -= 1
                if born in young:
                    young.remove(born)  # its RAM is back: no longer held for it
                gate.notify_all()
            own.db.close()

    def tally(result: str) -> None:
        counts[result] += 1
        # 0.31.0: the host's VM badge shows "analysing done/total" from this exact line
        print(f"progress: {sum(counts.values())}/{len(now)}", flush=True)

    print(f"progress: 0/{len(now)}", flush=True)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(one, now):
            tally(result)
    left = f", {counts['later']} left for the next run (out of time)" if counts["later"] else ""
    print(f"summary: {counts['done']} done, {counts['timeout']} timeout, {counts['error']} error{left}, "
          f"{time.monotonic() - start:.0f} s used, at most {most[0]} at once"
          + (f", {ram_wait[0]:.0f} s held back by RAM (added up)" if ram_wait[0] >= 1 else ""), flush=True)
    return 0


def cmd_triage_one(cfg, store, args) -> int:
    """The helper's side: analyse exactly one sample in this process (started by cmd_triage, not by people)."""
    row = store.get(args.sha256.lower())
    if not row:
        print("unknown sha256", file=sys.stderr)
        return 1
    scanner = YaraScanner(cfg.yara_dir)
    limit = args.sample_time if args.sample_time is not None else cfg.sample_time_s
    capa_s = args.capa_time if args.capa_time is not None else cfg.capa_time_s
    return 0 if triage_one(cfg, store, scanner, row, str(Path(args.config).resolve()), limit, capa_s,
                           args.capa_packed, args.share) else 1


def cmd_file_analysis_one(cfg, store, args) -> int:
    from fatbox.static.file_analysis import cmd_file_analysis_one as run
    return run(cfg, store, args)


def cmd_capa_one(cfg, store, args) -> int:
    from fatbox.static.code_analysis import cmd_capa_one as run
    return run(cfg, store, args)


def cmd_capa_compare(cfg, store, args) -> int:
    from fatbox.static.code_analysis import cmd_capa_compare as run
    return run(cfg, store, args)


def cmd_baseline(cfg, store, args) -> int:
    from fatbox.baseline import cmd_baseline as run
    return run(cfg, store, args)


def cmd_baseline_one(cfg, store, args) -> int:
    from fatbox.baseline import cmd_baseline_one as run
    return run(cfg, store, args)


def cmd_run(cfg, store, args) -> int:
    cmd_fetch(cfg, store, args)
    args.sha256, args.retry_errors, args.sample_time, args.capa_time, args.parallel = None, False, None, None, None
    args.capa_packed = None
    return cmd_triage(cfg, store, args)


LIST_FIELDS = ("sha256", "source", "first_seen", "file_name", "file_type", "signature", "fetched_at",
               "status", "score", "priority", "error")


def cmd_list(cfg, store, args) -> int:
    if args.json:  # machine-readable, consumed by the host controller (fatbox.host)
        rows = [{**{k: r[k] for k in LIST_FIELDS}, "tags": json.loads(r["tags"] or "[]")} for r in store.all(args.limit)]
        print(json.dumps({"rows": rows}))
        return 0
    for r in store.all(args.limit):
        print(f"{r['status']:<12} {r['priority'] or '-':>6} {r['score'] if r['score'] is not None else '-':>3}  "
              f"{r['sha256'][:16]}  {r['signature'] or '-':<20} {r['file_type'] or '-':<5} {r['fetched_at']}")
    return 0


def cmd_report(cfg, store, args) -> int:
    """Print one static.json to stdout (the host controller reads reports this way, never the sample)."""
    sha = args.sha256.lower()
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        print("bad sha256", file=sys.stderr)
        return 1
    p = cfg.data_dir / "reports" / sha / "static.json"
    if not p.exists():
        print("no report", file=sys.stderr)
        return 1
    sys.stdout.write(p.read_text(encoding="utf-8"))
    return 0


def cmd_update(cfg, store, args) -> int:
    from fatbox.updater import UpdateError, update
    try:
        return update(install=not args.no_install, fetch=not args.no_fetch)
    except UpdateError as e:
        print(f"update failed: {e}", file=sys.stderr)
        return 3


def cmd_set_token(cfg, store, args) -> int:
    import getpass
    from fatbox.updater import UpdateError, save_token, token_from_credential_manager
    token = token_from_credential_manager()
    if token:
        print("copied the token Windows Credential Manager already has for github.com")
    else:
        token = getpass.getpass("GitHub token (read-only, this repo only). Paste with RIGHT-CLICK, not Ctrl+V; "
                                "typing is hidden: ")
    try:
        path = save_token(token)
    except UpdateError as e:
        print(f"{e}. Got {len(token.strip())} characters: paste with right-click, not Ctrl+V.", file=sys.stderr)
        return 3
    print(f"saved to {path}. Take a new clean snapshot so a revert keeps it.")
    return 0


def cmd_wipe_data(cfg, args) -> int:
    """T-8: empty the VM's sample store (vault, index, reports) before the host takes a clean snapshot. Only
    these three, under data_dir from the config; nothing else is touched. The host sends this only after
    every report was copied to its library, then checks that `list` shows 0 samples."""
    if not args.yes:
        print("refusing: this deletes every sample and report in the VM. Add --yes", file=sys.stderr)
        return 2
    import shutil
    d = cfg.data_dir
    samples = sum(1 for _ in (d / "vault").rglob("*.zip.quarantine")) if (d / "vault").is_dir() else 0
    reports = sum(1 for p in (d / "reports").iterdir() if p.is_dir()) if (d / "reports").is_dir() else 0
    for name in ("vault", "reports"):
        p = d / name
        if p.is_symlink():  # never follow a link out of data_dir
            p.unlink()
        elif p.exists():
            shutil.rmtree(p)
    for name in ("index.db", "index.db-journal", "index.db-wal", "index.db-shm"):
        (d / name).unlink(missing_ok=True)
    print(json.dumps({"samples_removed": samples, "reports_removed": reports}))
    return 0


def cmd_shutdown(args) -> int:
    """0.18.2: shut Windows down from inside, for Make clean snapshot when Windows ignores VirtualBox's ACPI
    power button (power button set to "do nothing" or "sleep"). A normal, clean Windows shutdown: running
    programs are closed (/f) and the disk is flushed. The host sends it only after the power button had no effect."""
    if not args.yes:
        print("refusing: this shuts the VM down. Add --yes", file=sys.stderr)
        return 2
    import os
    import subprocess
    if os.name != "nt":
        print("shutdown: only inside the Windows VM", file=sys.stderr)
        return 2
    exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "shutdown.exe"
    r = subprocess.run([str(exe), "/s", "/f", "/t", "0"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        print(f"shutdown.exe failed (exit {r.returncode}): {(r.stderr or r.stdout).strip()[:300]}", file=sys.stderr)
        return 1
    print("Windows is shutting down")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fatbox", description="FatBox: fetch + static triage in the analysis VM")
    p.add_argument("-c", "--config", default=None, help="config file (default: config.toml in the current folder)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"FatBox {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def fetch_args(sp):
        sp.add_argument("--source", choices=["bazaar", "malshare"], help="default: [fetch].sources")
        sp.add_argument("--mode", choices=["recent", "latest", "tag", "signature", "file_type"],
                        help="MalwareBazaar query mode")
        sp.add_argument("--value", help="tag / signature / file_type value")
        sp.add_argument("--max", type=bounded(1, 30), help="samples to store this run, 1..30")
        sp.add_argument("--max-size-mb", type=bounded(1, 100), help="download limit in MB, 1..100 (slow links: 2-5)")
        sp.add_argument("--no-size-limit", action="store_true", help="no download limit (unpacked cap 100 MB stays)")
        sp.add_argument("--budget", type=bounded(60, 1800), help="time budget for the whole fetch, seconds (60..1800)")
        sp.add_argument("--small-first", action="store_true", help="download smallest candidates first")
        sp.add_argument("--sha256", nargs="+", type=sha256_arg, metavar="SHA256",
                        help=f"fetch exactly these samples (1..{MAX_PICKS}, from the host's Browse list)")
        sp.add_argument("--types", type=type_list, help="file types, comma list: exe,dll,office,lnk,elf,pdf,ps1")
        sp.add_argument("--tags", type=name_list, help="only samples with one of these tags (comma list)")
        sp.add_argument("--skip-families", type=name_list, help="never these families (comma list)")
        sp.add_argument("--min-size-kb", type=bounded(0, 10240), help="skip candidates smaller than this, 0..10240 KB")
        sp.add_argument("--unpack-limit-mb", type=int, choices=(25, 50, 100),
                        help="zip-bomb guard: 25, 50 or 100 MB (never higher)")
        sp.add_argument("--too-big", choices=("skip", "info"),
                        help="past the unpack limit: skip, or keep a metadata row only (info)")

    fetch_args(sub.add_parser("fetch", help="download new samples from MalwareBazaar"))
    br = sub.add_parser("browse", help="list MalwareBazaar candidates as JSON (metadata only, for the host GUI)")
    br.add_argument("--mode", choices=["recent", "latest", "tag", "signature", "file_type"], default="recent")
    br.add_argument("--value", help="tag / signature / file_type value")
    br.add_argument("--limit", type=bounded(1, BROWSE_MAX), default=100, help=f"rows for tag/signature/file_type (1..{BROWSE_MAX})")
    t = sub.add_parser("triage", help="static triage of pending samples")
    t.add_argument("--sha256")
    t.add_argument("--retry-errors", action="store_true", help="also retry samples whose triage failed (not timeouts)")
    t.add_argument("--sample-time", type=bounded(MIN_SAMPLE_S, MAX_SAMPLE_S),
                   help="time limit per sample, seconds (10..300, default [triage] sample_time_s = 60)")
    t.add_argument("--capa-time", type=bounded(MIN_CAPA_S, MAX_CAPA_S),
                   help="extra time for code analysis (capa), seconds (30..600, default [triage] capa_time_s = 120)")
    t.add_argument("--parallel", type=bounded(1, MAX_PARALLEL),
                   help=f"samples analysed at the same time, 1..{MAX_PARALLEL} (default [triage] parallel = 0: auto, "
                        "one per CPU as far as free RAM allows)")
    t.add_argument("--capa-packed", choices=("skip", "run"),
                   help="capa on packed native programs: skip (default) or run anyway")
    one = sub.add_parser("triage-one", help=argparse.SUPPRESS)  # internal: the helper process of `triage`
    one.add_argument("sha256")
    one.add_argument("--sample-time", type=bounded(MIN_SAMPLE_S, MAX_SAMPLE_S))
    one.add_argument("--capa-time", type=bounded(MIN_CAPA_S, MAX_CAPA_S))
    one.add_argument("--capa-packed", choices=("skip", "run"))
    one.add_argument("--share", type=bounded(1, MAX_SHARE), default=1)
    fa = sub.add_parser("file-analysis-one", help=argparse.SUPPRESS)  # internal: T-9 engines' sub-helper
    fa.add_argument("sha256", type=sha256_arg)
    co = sub.add_parser("capa-one", help=argparse.SUPPRESS)  # internal: T-14 capa's sub-helper
    co.add_argument("sha256", type=sha256_arg)
    co.add_argument("--lib-skip", action="store_true")
    cc = sub.add_parser("capa-compare", help="run capa twice per sample (full / library emulation skipped) and "
                                             "compare the findings and the time (reads in memory, never runs)")
    cc.add_argument("--max", type=bounded(1, 100), default=10, help="samples to compare, 1..100 (default 10)")
    bl = sub.add_parser("baseline", help="score clean Windows files to measure false positives (reads, never runs)")
    bl.add_argument("--dir", default=r"C:\Windows\System32", help=r"folder of clean files (default C:\Windows\System32)")
    bl.add_argument("--max", type=bounded(1, 1000), default=50, help="files to score, 1..1000 (default 50)")
    bl.add_argument("--no-capa", action="store_true", help="skip code analysis (capa): much faster")
    blo = sub.add_parser("baseline-one", help=argparse.SUPPRESS)  # internal: the helper of `baseline`
    blo.add_argument("path")
    blo.add_argument("--no-capa", action="store_true")
    fetch_args(sub.add_parser("run", help="fetch then triage"))
    i = sub.add_parser("import", help="import a local sample (zip preferred)")
    i.add_argument("path")
    i.add_argument("--password", help="password of the input zip if not the vault password")
    i.add_argument("--tag", action="append")
    sc = sub.add_parser("sources", help="verify API keys / quotas (downloads nothing)")
    sc.add_argument("--malshare-types", action="store_true", help="also list MalShare type names (24h)")
    u = sub.add_parser("update", help="pull the latest code from GitHub (keeps config.toml and data/)")
    u.add_argument("--no-install", action="store_true", help="don't check or install the pinned libraries")
    u.add_argument("--no-fetch", action="store_true",
                   help="don't contact GitHub: the host's Update VM already copied its code in (0.42.0)")
    sub.add_parser("set-token", help="save the read-only GitHub token for updates (also from the host's Update VM)")
    ls = sub.add_parser("list", help="show indexed samples")
    ls.add_argument("--limit", type=bounded(1, 1000), default=50, help="rows, 1..1000 (the host asks for 1000)")
    ls.add_argument("--json", action="store_true", help="JSON output (for the host controller)")
    r = sub.add_parser("report", help="print a sample's static.json (for the host controller)")
    r.add_argument("sha256")
    w = sub.add_parser("wipe-data", help="delete every sample and report in this VM (before a clean snapshot)")
    w.add_argument("--yes", action="store_true", help="really delete")
    sd = sub.add_parser("shutdown", help="shut Windows down cleanly (the host's Make clean snapshot uses it)")
    sd.add_argument("--yes", action="store_true", help="really shut down")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    if args.cmd == "shutdown":
        return cmd_shutdown(args)
    if args.cmd in ("update", "set-token"):
        return {"update": cmd_update, "set-token": cmd_set_token}[args.cmd](None, None, args)
    explicit = args.config is not None
    args.config = args.config or "config.toml"
    helper = args.cmd in ("triage-one", "file-analysis-one", "capa-one", "baseline-one")  # get the parent's -c as is
    if explicit and not helper and not Path(args.config).is_file():
        # 0.19.2: the host always names the VM's config.toml. Without it FatBox used to fall back to defaults and
        # keep data\ in whatever folder the command started in, so the host saw 0 samples with no reason given.
        print(f"config error: {args.config} not found. In the VM: copy config.example.toml to config.toml "
              "in the FatBox folder (and check guest_dir in host.toml)", file=sys.stderr)
        return 2
    try:
        cfg = load_config(args.config)
    except ValueError as e:
        print(f"config error ({args.config}): {e}", file=sys.stderr)
        return 2
    if args.cmd == "wipe-data":  # before Store() opens index.db: Windows can't delete an open file
        return cmd_wipe_data(cfg, args)
    store = Store(cfg.data_dir)
    handler = {"browse": cmd_browse, "fetch": cmd_fetch, "triage": cmd_triage, "triage-one": cmd_triage_one,
               "file-analysis-one": cmd_file_analysis_one, "capa-one": cmd_capa_one, "capa-compare": cmd_capa_compare,
               "baseline": cmd_baseline, "baseline-one": cmd_baseline_one, "run": cmd_run, "import": cmd_import, "list": cmd_list,
               "sources": cmd_sources, "report": cmd_report}
    return handler[args.cmd](cfg, store, args)
