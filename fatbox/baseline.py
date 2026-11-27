"""Clean-file baseline (0.18.5): score known-good Windows files to measure false positives.

`python -m fatbox baseline` picks up to --max .exe/.dll files from one folder (default C:\\Windows\\System32),
scores each one with the same triage, File Analysis (DIE) and Code Analysis (capa) that samples get, and writes
a summary to data\\baseline\\. The files are only read, never run (INV-3). Nothing goes into the vault, the index
or the library, and nothing needs the network.

Each file is scored in its own helper (`baseline-one <path>`, internal) with the sample time limit plus the capa
limit, like triage-one: a file that hangs a parser costs that time and is listed as "timeout".
"""
from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fatbox import __version__

DEFAULT_DIR = r"C:\Windows\System32"
MAX_FILES = 1000
MAX_BYTES = 20 * 1024 * 1024    # bigger clean files are skipped: they say little and cost minutes in capa
NOISY_SHARE = 0.10              # a rule that fires on more than this share of clean files is noise
EXTENSIONS = (".exe", ".dll")
TOP = 15                        # highest-scoring clean files listed in the summary
_POINTS = re.compile(r"^\+(\d+) ")


def pick_files(folder: Path, max_n: int, max_bytes: int = MAX_BYTES) -> list[Path]:
    """Up to max_n .exe/.dll files directly in folder, spread evenly over the name-sorted list (same pick
    every run on the same Windows)."""
    files = []
    for p in folder.iterdir():
        try:
            if p.suffix.lower() in EXTENSIONS and p.is_file() and 0 < p.stat().st_size <= max_bytes:
                files.append(p)
        except OSError:
            continue  # files Windows won't let us look at
    files.sort(key=lambda p: p.name.lower())
    if len(files) <= max_n:
        return files
    step = len(files) / max_n
    return [files[int(i * step)] for i in range(max_n)]


def rule_key(reason: str) -> tuple[str, int] | None:
    """'+10 high-entropy sections: .rsrc' -> ('high-entropy sections', 10). Reasons worth 0 points -> None."""
    m = _POINTS.match(reason)
    if not m or m.group(1) == "0":
        return None
    text = reason[m.end():]
    for cut in (":", " ("):
        if cut in text:
            text = text[:text.index(cut)]
    return text.strip(), int(m.group(1))


# ---- the helper's side ----------------------------------------------------------------------------------------
def score_file(data: bytes, name: str, cfg, capa: bool) -> dict:
    """Everything a sample gets, in this process: triage, File Analysis, Code Analysis, score."""
    from fatbox.static import code_analysis as ca
    from fatbox.static import file_analysis as fa
    from fatbox.static.triage import priority, score, triage
    from fatbox.static.yara_scan import YaraScanner
    report = triage(data, name, YaraScanner(cfg.yara_dir))
    try:
        sub = fa.scan(data)
    except Exception as e:
        sub = {"status": "error", "error": f"{type(e).__name__}: {e}"}
    st = sub.get("status") if sub.get("status") in fa.STATUSES else "error"
    report["file_analysis"] = fa.build(st, sub.get("error"), sub if st == "ok" else None, data, report.get("pe"))
    if capa:
        try:
            with ca.quiet_stdout():
                sub = ca.analyze(data, Path(cfg.capa_dir))
        except Exception as e:
            sub = {"status": "error", "error": f"{type(e).__name__}: {e}"}
        st = sub.get("status") if sub.get("status") in ca.STATUSES else "error"
        report["code_analysis"] = ca.build(st, sub.get("error"), sub if st == "ok" else None)
    report["score"], report["reasons"] = score(report)
    report["priority"] = priority(report["score"])
    code = report.get("code_analysis") or {}
    return {
        "status": "ok", "name": name, "size": len(data), "score": report["score"],
        "priority": report["priority"], "reasons": report["reasons"],
        "file_analysis": (report.get("file_analysis") or {}).get("status"),
        "code_analysis": code.get("status") if capa else "off",
        "capa_scored": [c["name"] for c in code.get("capabilities") or [] if c.get("scored")],
    }


def cmd_baseline_one(cfg, store, args) -> int:
    """`fatbox baseline-one <path>` (internal): score one clean file, one JSON object on stdout."""
    p = Path(args.path)
    try:
        data = p.read_bytes()[:MAX_BYTES + 1]
        if len(data) > MAX_BYTES:
            raise ValueError(f"bigger than {MAX_BYTES} bytes")
        out = score_file(data, p.name, cfg, not args.no_capa)
    except Exception as e:
        out = {"status": "error", "error": f"{type(e).__name__}: {e}"[:300]}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    return 0


# ---- the parent's side ----------------------------------------------------------------------------------------
def summarize(results: list[dict], folder: str, capa: bool, seconds: float) -> dict:
    ok = [r for r in results if r.get("status") == "ok"]
    n = len(ok)
    rules: Counter = Counter()
    points: dict[str, int] = {}
    capa_rules: Counter = Counter()
    for r in ok:
        for key in {k for k in (rule_key(x) for x in r["reasons"]) if k}:
            rules[key[0]] += 1
            points[key[0]] = key[1]
        capa_rules.update(set(r.get("capa_scored") or []))
    return {
        "tool": f"FatBox {__version__}",
        "made_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "folder": folder, "capa": capa, "seconds": round(seconds),
        "files": len(results), "scored": n,
        "not_scored": [{"name": r.get("name"), "status": r.get("status"), "error": r.get("error")}
                       for r in results if r.get("status") != "ok"],
        "priority": {p: sum(1 for r in ok if r["priority"] == p) for p in ("low", "medium", "high")},
        "average_score": round(sum(r["score"] for r in ok) / n, 1) if n else 0,
        "rules": [{"rule": k, "points": points[k], "files": c, "share": round(c / n, 3),
                   "noisy": c / n > NOISY_SHARE} for k, c in rules.most_common()],
        "capa_rules": [{"rule": k, "files": c, "share": round(c / n, 3)} for k, c in capa_rules.most_common()],
        "top": [{"name": r["name"], "score": r["score"], "priority": r["priority"], "reasons": r["reasons"]}
                for r in sorted(ok, key=lambda r: -r["score"])[:TOP]],
        "results": results,
    }


def to_markdown(s: dict) -> str:
    pr = s["priority"]
    L = [f"# Clean-file baseline ({s['tool']})", "",
         f"- Folder: `{s['folder']}`, {s['files']} files, {s['scored']} scored, capa {'on' if s['capa'] else 'off'}, "
         f"{s['seconds']} s",
         f"- Priority: low {pr['low']}, medium {pr['medium']}, high {pr['high']} (clean files should all be low)",
         f"- Average score: {s['average_score']}", "",
         f"## Rules that fired on clean files (noisy = more than {NOISY_SHARE:.0%})", "",
         "| Rule | Points | Files | Share | |", "|---|---|---|---|---|"]
    L += [f"| {r['rule']} | +{r['points']} | {r['files']} | {r['share']:.0%} | {'NOISY' if r['noisy'] else ''} |"
          for r in s["rules"]] or ["| none | | | | |"]
    if s["capa_rules"]:
        L += ["", "## capa rules that scored on clean files", "", "| capa rule | Files | Share |", "|---|---|---|"]
        L += [f"| {r['rule']} | {r['files']} | {r['share']:.0%} |" for r in s["capa_rules"]]
    L += ["", "## Highest-scoring clean files", "", "| File | Score | Why |", "|---|---|---|"]
    L += [f"| `{t['name']}` | {t['score']} ({t['priority']}) | "
          f"{'; '.join(x for x in t['reasons'] if not x.startswith('+0')) or '-'} |" for t in s["top"]]
    if s["not_scored"]:
        L += ["", "## Not scored", ""] + [f"- `{x['name']}`: {x['status']} {x['error'] or ''}" for x in s["not_scored"]]
    return "\n".join(L) + "\n"


def cmd_baseline(cfg, store, args) -> int:
    from fatbox.static.file_analysis import Run
    folder = Path(args.dir).resolve()
    if not folder.is_dir():
        print(f"not a folder: {folder}", file=sys.stderr)
        return 1
    files = pick_files(folder, args.max)
    if not files:
        print(f"no .exe/.dll files in {folder}")
        return 0
    capa = not args.no_capa
    budget = cfg.sample_time_s + (cfg.capa_time_s if capa else 0)
    print(f"baseline: {len(files)} clean files from {folder}, capa {'on' if capa else 'off'}, "
          f"limit {budget} s per file", flush=True)
    config_path = str(Path(args.config).resolve())
    results, start = [], time.monotonic()
    for i, p in enumerate(files, 1):
        extra = ("--no-capa",) if not capa else ()
        st, err, obj = Run(str(p), config_path, budget, command="baseline-one", label="baseline",
                           extra=extra).result()
        r = obj if st == "ok" and obj else {"status": st, "name": p.name, "error": err}
        r["name"] = p.name
        results.append(r)
        shown = f"{r['priority']:>6} {r['score']:>3}" if r["status"] == "ok" else f"{r['status']:>10}"
        print(f"{i:>4}/{len(files)} {shown}  {p.name}", flush=True)
    s = summarize(results, str(folder), capa, time.monotonic() - start)
    out = Path(cfg.data_dir) / "baseline"
    out.mkdir(parents=True, exist_ok=True)
    stem = "baseline-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    (out / f"{stem}.json").write_text(json.dumps(s, indent=1), encoding="utf-8")
    (out / f"{stem}.md").write_text(to_markdown(s), encoding="utf-8")
    pr = s["priority"]
    noisy = [r["rule"] for r in s["rules"] if r["noisy"]]
    print(f"summary: low {pr['low']}, medium {pr['medium']}, high {pr['high']}; noisy rules: "
          f"{', '.join(noisy) or 'none'}", flush=True)
    print(f"written: {out / (stem + '.md')}", flush=True)
    return 0
