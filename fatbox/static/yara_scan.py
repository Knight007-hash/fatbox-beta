from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)

try:
    import yara
except ImportError:  # yara-python is optional
    yara = None


class YaraScanner:
    """Compiles every *.yar / *.yara under rules_dir once; scans in-memory bytes."""

    def __init__(self, rules_dir: Path):
        self.rules = None
        self.last_error: str | None = None
        self.status = "disabled"
        if yara is None:
            self.status = "yara-python not installed"
            return
        files = sorted(p for p in Path(rules_dir).rglob("*") if p.suffix.lower() in (".yar", ".yara"))
        if not files:
            self.status = f"no rules in {rules_dir}"
            return
        sources = {}
        for i, f in enumerate(files):
            try:  # compile individually first so one broken community rule doesn't kill the set
                yara.compile(filepath=str(f))
                sources[f"ns{i}_{f.stem}"] = str(f)
            except yara.Error as e:
                log.warning("skipping broken YARA file %s: %s", f, e)
        if sources:
            self.rules = yara.compile(filepaths=sources)
            self.status = f"{len(sources)} rule files"

    def scan(self, data: bytes) -> list[dict]:
        if not self.rules:
            return []
        hits = []
        self.last_error = None
        try:
            matches = self.rules.match(data=data, timeout=60)
        except yara.Error as e:  # 0.39.3: a timeout or scan error loses the YARA part, not the whole report
            log.warning("YARA scan failed: %s", e)
            self.last_error = f"yara: {type(e).__name__}: {str(e)[:200]}"
            return []
        for m in matches:
            hits.append({
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": list(m.tags),
                "meta": {k: v for k, v in m.meta.items() if isinstance(v, (str, int, bool))},
            })
        return hits
