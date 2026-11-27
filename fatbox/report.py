from __future__ import annotations

import json
from pathlib import Path

from fatbox.static.strings_iocs import defang


def _compiled(pe: dict) -> str:
    if pe.get("reproducible_build"):
        return "not a real date (reproducible build)"
    return f"{pe['compile_time']}{'  ⚠ anomalous' if pe['compile_time_anomaly'] else ''}"


def write_reports(report: dict, out_dir: Path, meta: dict | None = None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jpath = out_dir / "static.json"
    jpath.write_text(json.dumps({"source_meta": meta or {}, **report}, indent=2, default=str), encoding="utf-8")
    mpath = out_dir / "static.md"
    mpath.write_text(render_markdown(report, meta or {}), encoding="utf-8")
    return jpath, mpath


def render_markdown(r: dict, meta: dict) -> str:
    h = r["hashes"]
    L = [
        f"# Static triage: `{h['sha256']}`",
        "",
        f"**Priority:** {r['priority'].upper()} ({r['score']}/100)  ",
        f"**Family (source label):** {meta.get('signature') or 'unknown'}  ",
        f"**Tags:** {', '.join(meta.get('tags') or []) or '-'}  ",
        f"**Kind:** {r['kind']} | **Size:** {r['size']:,} B | **Entropy:** {r['entropy']}",
        "",
        "| Hash | Value |", "|---|---|",
        *[f"| {k} | `{v}` |" for k, v in h.items() if v],
        "",
        "## Why this score",
        *([f"- {x}" for x in r["reasons"]] or ["- nothing notable"]),
    ]
    pe = r.get("pe")
    if pe:
        L += [
            "", "## PE",
            f"- {pe['machine']} {'DLL' if pe['is_dll'] else 'EXE'}{' (.NET)' if pe['is_dotnet'] else ''}, "
            f"subsystem {pe['subsystem']}",
            f"- Compiled: {_compiled(pe)}",
            f"- PDB: `{pe['pdb_path'] or '-'}`",
            *([f"- .NET P/Invoke: {', '.join(pe['dotnet']['pinvoke'][:40]) or '-'}"] if pe.get("dotnet") else []),
            f"- EP {pe['entrypoint']} in `{pe['entrypoint_section']}` | imphash `{pe['imphash']}`",
            f"- Signature blob: {'yes' if pe['has_signature_blob'] else 'no'} | TLS: {pe['tls_callbacks']} "
            f"| Packer hints: {', '.join(pe['packer_hints']) or '-'}",
            "", "| Section | Perms | Raw | Virtual | Entropy |", "|---|---|---|---|---|",
            *[f"| `{s['name']}` | {s['perms']} | {s['raw_size']} | {s['vsize']} | {s['entropy']} |"
              for s in pe["sections"]],
        ]
        if pe["suspicious_imports"]:
            L += ["", "### Suspicious imports", "| API | Category | ATT&CK |", "|---|---|---|",
                  *[f"| {i['api']} | {i['category']} | {i['attack']} |" for i in pe["suspicious_imports"]]]
    if r["behaviour"]:
        L += ["", "## String-level behaviour indicators (unconfirmed until dynamic)",
              "| Indicator | ATT&CK | Evidence |", "|---|---|---|",
              *[f"| {b['indicator']} | {b['attack']} | `{defang(b['evidence'])}` |" for b in r["behaviour"]]]
    if r["yara"]:
        L += ["", "## YARA", *[f"- **{y['rule']}** {y['meta'].get('description', '')}" for y in r["yara"]]]
    iocs = {k: v for k, v in r["iocs"].items() if v}
    if iocs:
        L += ["", "## IOCs (defanged)"]
        for k, vals in iocs.items():
            L += [f"**{k}** ({len(vals)})", *[f"- `{defang(v)}`" for v in vals[:40]]]
            if len(vals) > 40:
                L.append(f"- … {len(vals) - 40} more in static.json")
    if r["errors"]:
        L += ["", "## Errors", *[f"- {e}" for e in r["errors"]]]
    return "\n".join(L) + "\n"
