"""T-14 Code Analysis (F-10): what the code does, found by capa (Mandiant, Apache-2.0) in the sample's own code.

capa disassembles the program (vivisect for native PE, dnfile for .NET) and matches about 1,000 community
rules against what it finds: "inject a thread", "check for a debugger", "encrypt data using AES". It never
runs the sample (INV-3). It is a disassembler reading hostile bytes, so it runs in its own sub-helper,
exactly like the T-9 file analysis engines:

    triage-one <sha>          waits at most capa_time_s (default 120 s) for:
      capa-one <sha>          opens the .zip.quarantine itself, in memory (INV-2), prints one JSON object

The sample is never written to disk in plain form: vivisect loads it from a BytesIO and dnfile from bytes.
The only file capa writes is its rule cache (the rules, not the sample).

Rules and library signatures are vendored in rules/capa/ at a pinned version (see rules/capa/README.md):
they reach the VM through Update VM like the YARA rules, so capa needs no network of its own (INV-7).
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
from pathlib import Path

STATUSES = ("ok", "timeout", "crashed", "not_installed", "error", "skipped")
FORMATS = ("pe", "dotnet")
MAX_CAPS = 200               # capabilities kept per report
MAX_NAME = 120               # characters per rule name / namespace
MAX_ATTACK = 10              # ATT&CK ids per capability
ATTACK_RE = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")

# capa namespace prefix -> FatBox topic (first match wins). Everything else (compiler, encoding, linking,
# runtime, data-manipulation other than encryption, host-interaction other than injection, ...) is "other".
TOPICS = (
    ("malware-family", "malware-family"),
    ("host-interaction/process/inject", "injection"),
    ("anti-analysis", "anti-analysis"),
    ("persistence", "persistence"),
    ("collection", "collection"),
    ("load-code", "load-code"),
    ("communication", "communication"),
    ("impact", "impact"),
    ("data-manipulation/encryption", "encryption"),
)
TOPIC_NAMES = tuple(t for _, t in TOPICS) + ("other",)
# 0.18.3: load-code rules that only mean "this program reads a PE file". Packers, installers, launchers and the
# Rust/Go runtimes do it too, so they are shown with 0 points. Hiding tricks in the same namespace (resolve
# functions by parsing PE exports, rebuild import table, reflective DLL injection) still count.
EVERYDAY_RULES = frozenset({"parse PE header", "access PE header", "enumerate PE sections",
                            "inspect section memory permissions"})


def _s(v, n: int = MAX_NAME) -> str:
    return v[:n] if isinstance(v, str) else ""


def topic(namespace: str) -> str:
    for prefix, name in TOPICS:
        if namespace == prefix or namespace.startswith(prefix + "/"):
            return name
    return "other"


# ---- the sub-helper's side ------------------------------------------------------------------------------
class InMemory:
    """capa's extractors call path.read_bytes() on the file they analyse: this hands them the bytes in RAM."""

    def __init__(self, data: bytes):
        self.data = data

    def read_bytes(self) -> bytes:
        return self.data


def is_dotnet(data: bytes) -> bool:
    """A .NET assembly has a CLR header (the COM descriptor data directory, index 14)."""
    import pefile
    pe = pefile.PE(data=data, fast_load=True)
    try:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return bool(d.VirtualAddress and d.Size)
    except (AttributeError, IndexError):
        return False
    finally:
        pe.close()


def rule_set(capa_dir: Path):
    """(rules, signature paths, rules version). Raises FileNotFoundError when rules/capa is missing."""
    import capa.rules
    rules_dir = capa_dir / "rules"
    if not rules_dir.is_dir():
        raise FileNotFoundError(f"{rules_dir} not found")
    version = (capa_dir / "VERSION").read_text(encoding="utf-8").strip() if (capa_dir / "VERSION").is_file() else ""
    sigs = sorted(str(p) for p in (capa_dir / "sigs").glob("*.sig"))
    return capa.rules.get_rules([rules_dir]), sigs, version


# 0.32.0: vivisect's per-function emulation that guesses how arguments are passed; ~70-80% of capa's time
EMULATION_MODULES = ("vivisect.analysis.i386.calling", "vivisect.analysis.amd64.emulation")


class _SkipLibrary:
    """Stands in for one emulation module in one workspace: runs it, except on functions the FLIRT signatures
    named as library code (C runtime, MFC, zlib, ...). capa ignores library functions anyway, so their
    emulation only costs time. Real code is still emulated in full."""

    def __init__(self, mod, counts: dict):
        self.mod, self.counts, self.__name__ = mod, counts, mod.__name__

    def analyzeFunction(self, vw, fva):  # noqa: N802 (vivisect's name)
        import viv_utils.flirt
        if viv_utils.flirt.is_library_function(vw, fva):
            self.counts["skipped"] += 1
            return None
        self.counts["emulated"] += 1
        return self.mod.analyzeFunction(vw, fva)


def skip_library_emulation(vw) -> dict:
    """Run the FLIRT signatures first, then skip emulation of what they named. -> live counts of both."""
    from viv_utils.flirt import FlirtFunctionAnalyzer
    counts = {"skipped": 0, "emulated": 0}
    flirt = [k for k in vw.fmodlist if isinstance(vw.fmods.get(k), FlirtFunctionAnalyzer)]
    vw.fmodlist[:] = flirt + [k for k in vw.fmodlist if k not in flirt]
    for name in EMULATION_MODULES:
        if name in vw.fmods:
            vw.fmods[name] = _SkipLibrary(vw.fmods[name], counts)
    return counts


def extractor(data: bytes, fmt: str, sigs: list[str], lib_skip: bool = False):
    import capa.features.common
    if fmt == "dotnet":
        import dnfile
        import capa.features.extractors.dnfile.extractor as dx
        dx.load_dotnet_image = lambda p: dnfile.dnPE(data=p.read_bytes())  # capa's own loader opens a path
        return dx.DnfileFeatureExtractor(InMemory(data))
    import vivisect
    import viv_utils.flirt
    import capa.features.extractors.viv.extractor as vx
    vw = vivisect.VivWorkspace()
    vw.config.viv.parsers.pe.nx = True
    vw.loadFromFd(io.BytesIO(data), fmtname="pe")  # not viv_utils.getWorkspaceFromBytes: that one writes a file
    if sigs:  # library code (MSVC runtime, zlib, ...) is named and skipped, so its tricks don't count
        viv_utils.flirt.register_flirt_signature_analyzers(vw, sigs)
        if lib_skip:
            skip_library_emulation(vw)
    vw.analyze()
    return vx.VivisectFeatureExtractor(vw, InMemory(data), capa.features.common.OS_WINDOWS)


def analyze(data: bytes, capa_dir: Path, lib_skip: bool = False) -> dict:
    """Run capa on bytes in memory. Returns the sub-helper's JSON object."""
    if data[:2] != b"MZ":
        return {"status": "skipped", "error": "not a Windows program: capa runs on PE and .NET files"}
    try:
        import capa.capabilities.common
        import capa.version
    except Exception as e:
        return {"status": "not_installed", "error": _s(f"flare-capa: {type(e).__name__}: {e}; run Update VM "
                                                       "(it installs the pinned libraries)", 300)}
    try:
        rules, sigs, version = rule_set(capa_dir)
    except FileNotFoundError as e:
        return {"status": "not_installed", "error": _s(f"capa rules: {e}; run Update VM", 300)}
    engine = {"capa": _s(capa.version.__version__, 40), "rules": _s(version, 40)}
    fmt = "dotnet" if is_dotnet(data) else "pe"
    caps = capa.capabilities.common.find_capabilities(rules, extractor(data, fmt, sigs, lib_skip),
                                                  disable_progress=True)
    found = []
    for name in sorted(caps.matches):
        r = rules[name]
        ns = r.meta.get("namespace") or ""
        if r.meta.get("lib") or r.is_subscope_rule() or ns.startswith("internal"):
            continue  # building blocks of other rules, not capabilities
        scope = getattr(r.scopes.static, "value", "")
        attack = [m.group(1) for a in r.meta.get("att&ck") or [] for m in [ATTACK_RE.search(str(a))] if m]
        found.append({"name": _s(name), "namespace": _s(ns), "attack": attack[:MAX_ATTACK],
                      "scope": "file" if scope == "file" else "code", "nursery": bool(r.meta.get("capa/nursery"))})
        if len(found) >= MAX_CAPS:
            break
    return {"status": "ok", "engine": engine, "format": fmt, "matches": found}


class quiet_stdout:
    """vivisect prints progress to stdout; the parent reads stdout as JSON, so park fd 1 on devnull meanwhile."""

    def __enter__(self):
        sys.stdout.flush()
        self.saved, self.stdout = os.dup(1), sys.stdout
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, 1)          # native code and anything that writes to fd 1
        os.close(null)
        sys.stdout = open(os.devnull, "w")   # Python's print()

    def __exit__(self, *exc):
        sys.stdout.close()
        sys.stdout = self.stdout
        os.dup2(self.saved, 1)
        os.close(self.saved)
        return False


def cmd_capa_one(cfg, store, args) -> int:
    """`fatbox capa-one <sha>` (internal): the sub-helper. One JSON object on stdout."""
    from fatbox.store import UNPACKED_CAP, read_sample_from_zip
    row = store.get(args.sha256.lower())
    if not row:
        print(json.dumps({"status": "error", "error": "unknown sha256"}))
        return 1
    _, data = read_sample_from_zip(Path(row["zip_path"]), cfg.zip_password, UNPACKED_CAP)
    try:
        with quiet_stdout():
            out = analyze(data, Path(cfg.capa_dir), lib_skip=getattr(args, "lib_skip", False))
    except Exception as e:  # e.g. an unsupported architecture, or a file vivisect can't parse
        out = {"status": "error", "error": _s(f"{type(e).__name__}: {e}", 300)}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    return 0


# ---- the helper's side ------------------------------------------------------------------------------------
def skip_reason(fa: dict, data: bytes) -> str | None:
    """0.21.0: why capa is not worth running, or None. A native program that Detect It Easy says is packed or
    protected shows capa only its unpacking stub: minutes of disassembly for (almost) nothing, and the packer
    itself is already scored by File Analysis. .NET is cheap for capa (metadata, no disassembly) and an
    obfuscator still leaves the API calls readable, so .NET always runs. A DIE failure or a mere entropy
    guess never skips capa."""
    if fa.get("status") != "ok":
        return None
    for field, word in (("protector", "protected"), ("packer", "packed")):
        if fa.get(field):
            try:
                if is_dotnet(data):
                    return None
            except Exception:  # headers pefile can't read: not .NET as far as we can tell
                pass
            return _s(f"{word} ({fa[field][0]}): capa would only see the unpacking stub, so it was not run. "
                      "File Analysis scores the packer", 300)
    return None


def scored(c: dict) -> bool:
    """Only code findings from stable rules in a named topic count: file-wide string matches, nursery (draft)
    rules, everyday topics ("other": read a file, parse arguments) and everyday PE reading (EVERYDAY_RULES) are
    shown with 0 points. A malware family match always counts."""
    if c["topic"] == "malware-family":
        return True
    return c["topic"] != "other" and c["scope"] == "code" and not c["nursery"] and c["name"] not in EVERYDAY_RULES


def build(status: str, error: str | None, sub: dict | None) -> dict:
    """The report's "code_analysis" object, rebuilt from the sub-helper's answer with every cap applied."""
    ca: dict = {"status": status, "error": _s(error, 300) or None, "engine": {}, "format": None, "capabilities": []}
    if not sub:
        return ca
    eng = sub.get("engine") if isinstance(sub.get("engine"), dict) else {}
    ca["engine"] = {k: _s(eng.get(k), 40) for k in ("capa", "rules") if _s(eng.get(k), 40)}
    ca["format"] = sub.get("format") if sub.get("format") in FORMATS else None
    caps = []
    for m in (sub.get("matches") or [])[:MAX_CAPS]:
        if not isinstance(m, dict) or not _s(m.get("name")):
            continue
        ns = _s(m.get("namespace"))
        attack = [a for a in (m.get("attack") or []) if isinstance(a, str) and re.fullmatch(r"T\d{4}(\.\d{3})?", a)]
        c = {"name": _s(m.get("name")), "topic": topic(ns), "namespace": ns, "attack": attack[:MAX_ATTACK],
             "scope": "file" if m.get("scope") == "file" else "code", "nursery": m.get("nursery") is True}
        c["scored"] = scored(c)
        caps.append(c)
    order = {t: i for i, t in enumerate(TOPIC_NAMES)}
    caps.sort(key=lambda c: (not c["scored"], order[c["topic"]], c["name"]))
    ca["capabilities"] = caps
    return ca


def families(ca: dict | None) -> list[str]:
    """Malware families capa named (namespace malware-family/<family>), as "plugx"."""
    if not ca or ca.get("status") != "ok":
        return []
    out = []
    for c in ca.get("capabilities") or []:
        name = c["namespace"].partition("malware-family/")[2].split("/")[0]
        if c["topic"] == "malware-family" and name and name not in out:
            out.append(name)
    return out


# ---- 0.32.0: check that skipping library emulation loses nothing, on the samples in this VM ---------------
def compare_findings(full: dict, fast: dict) -> tuple[list[str], list[str]]:
    """-> (lost, gained): capability names only the full run found, and only the fast run found."""
    a = {m.get("name") for m in full.get("matches") or []}
    b = {m.get("name") for m in fast.get("matches") or []}
    return sorted(a - b), sorted(b - a)


def cmd_capa_compare(cfg, store, args) -> int:
    """`fatbox capa-compare [--max 10]`: run capa on each sample twice, one run after the other, in its own
    capa-one helper as in triage (zip read in memory, INV-2; nothing is run, INV-3): full emulation, then with
    library emulation skipped. Prints the findings each mode lost or gained and both times. Only native
    programs count: .NET has no emulation, and skipped or failed runs say so."""
    import time
    from fatbox.static.file_analysis import Run
    rows = [r for r in store.by_status("static_done") + store.by_status("fetched")
            if r["zip_path"] and Path(r["zip_path"]).is_file()][:args.max]
    if not rows:
        print("nothing to compare: no samples in this VM")
        return 0
    config_path = str(Path(args.config).resolve())
    budget = cfg.capa_time_s
    print(f"capa-compare: {len(rows)} samples, full vs library emulation skipped, limit {budget} s per run",
          flush=True)
    same = differ = other = 0
    t_full = t_fast = 0.0
    for i, row in enumerate(rows, 1):
        sha, runs = row["sha256"], []
        for extra in ((), ("--lib-skip",)):
            t0 = time.monotonic()
            st, err, obj = Run(sha, config_path, budget, command="capa-one", label="code analysis",
                               statuses=STATUSES, extra=extra).result()
            runs.append((st, err, obj, time.monotonic() - t0))
        (s1, e1, full, d1), (s2, e2, fast, d2) = runs
        head = f"{i:>3}/{len(rows)} {sha[:16]}"
        if s1 != "ok" or s2 != "ok" or full.get("format") != "pe":
            other += 1
            why = "a .NET program (no emulation to skip)" if s1 == "ok" and full.get("format") == "dotnet" \
                else f"full: {s1}{' (' + e1 + ')' if e1 else ''}; fast: {s2}{' (' + e2 + ')' if e2 else ''}"
            print(f"{head}  not compared: {_s(why, 200)}", flush=True)
            continue
        t_full, t_fast = t_full + d1, t_fast + d2
        lost, gained = compare_findings(full, fast)
        n = len(full.get("matches") or [])
        if lost or gained:
            differ += 1
            print(f"{head}  DIFFERENT  {d1:.0f} s -> {d2:.0f} s  lost: {', '.join(lost) or '-'}  "
                  f"gained: {', '.join(gained) or '-'}", flush=True)
        else:
            same += 1
            print(f"{head}  same {n} findings  {d1:.0f} s -> {d2:.0f} s", flush=True)
    speed = f", {t_full:.0f} s -> {t_fast:.0f} s in total" if same + differ else ""
    print(f"RESULT: {same} same, {differ} different, {other} not compared{speed}", flush=True)
    if differ:
        print("keep [triage] capa_lib_skip = false: skipping library emulation changed findings", flush=True)
    elif same:
        print("findings identical on every native program compared", flush=True)
    return 0
