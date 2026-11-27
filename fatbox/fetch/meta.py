"""Pre-download hints and filters computed from source metadata only (no file needed). Standard library only:
the host imports this module too (0.29.0: Browse applies the same filters as a fetch)."""
from __future__ import annotations

from dataclasses import dataclass, field

TYPE_GROUPS = {
    "exe": ["exe"], "dll": ["dll"], "office": ["doc", "xls", "ppt", "msi"], "lnk": ["lnk"], "elf": ["elf"],
    "pdf": ["pdf"], "ps1": ["ps1"],
}


@dataclass
class Filters:
    file_types: list[str] = field(default_factory=lambda: ["exe", "dll"])
    tags_any: list[str] = field(default_factory=list)
    signatures_any: list[str] = field(default_factory=list)
    max_per_run: int = 20
    max_attempts: int = 100      # downloads attempted per run, incl. ones rejected after download
    delay_seconds: float = 2.0
    small_first: bool = False    # slow links: try the smallest candidates first
    download_timeout: int = 300  # per-sample ceiling in seconds; the shared fetch budget usually ends it first
    signatures_none: list[str] = field(default_factory=list)  # 0.23.0: never these families
    min_size_kb: int = 0         # 0.23.0: skip candidates smaller than this (tiny stubs); 0 = no minimum


def prefilter(item: dict, f: Filters, max_bytes: int, cap: int) -> str | None:
    """Filter on metadata the source gave us. Returns a skip reason or None. Unknown fields pass."""
    ftype = (item.get("file_type") or "").lower()
    if f.file_types and ftype and ftype not in {t.lower() for t in f.file_types}:
        return f"file_type={ftype}"
    size = item.get("file_size") or 0
    if size > cap:
        return "too big to analyze"
    if size > max_bytes:
        return "too large"
    if f.min_size_kb and size and size < f.min_size_kb * 1024:
        return "too small"
    tags = {t.lower() for t in (item.get("tags") or [])}
    if f.tags_any and not tags & {t.lower() for t in f.tags_any}:
        return "tags"
    sig = (item.get("signature") or "").lower()
    if f.signatures_any and sig not in {s.lower() for s in f.signatures_any}:
        return "signature"
    if sig and sig in {s.lower() for s in f.signatures_none}:
        return "family skipped"
    return None


# Family presets. Matched case-insensitively against the signature and tags.
FAMILY_PRESETS: dict[str, list[str]] = {
    "stealer": ["agenttesla", "formbook", "xloader", "redline", "lumma", "lummastealer", "vidar", "stealc",
                "raccoon", "raccoonstealer", "snakekeylogger", "snake keylogger", "risepro", "metastealer",
                "amadey-stealer", "rhadamanthys", "phemedrone", "wardenstealer", "stealer", "infostealer",
                "masslogger", "404keylogger", "vipkeylogger", "acr stealer", "acrstealer"],
    "rat": ["asyncrat", "remcos", "remcosrat", "xworm", "njrat", "dcrat", "quasarrat", "quasar", "nanocore",
            "venomrat", "warzonerat", "avemaria", "netwire", "orcus", "dark crystal rat", "rat", "sectoprat",
            "arechclient2", "netsupport"],
    "ransomware": ["lockbit", "blackcat", "alphv", "conti", "stopransomware", "stop", "djvu", "phobos", "makop",
                   "medusalocker", "babuk", "akira", "play", "blackbasta", "mallox", "ransomware", "chaos"],
    "loader": ["guloader", "cloudeye", "smokeloader", "amadey", "privateloader", "emotet", "icedid", "qakbot",
               "qbot", "darkgate", "latrodectus", "pikabot", "bumblebee", "hijackloader", "idatloader",
               "socgholish", "modiloader", "dbatloader", "loader", "dropper", "downloader"],
    # 0.29.0
    "banker": ["trickbot", "zloader", "dridex", "ursnif", "gozi", "isfb", "danabot", "grandoreiro", "mekotio",
               "casbaneiro", "coper", "anatsa", "banker", "bankbot"],
    "backdoor": ["cobaltstrike", "cobalt strike", "sliver", "bruteratel", "brute ratel", "havoc", "metasploit",
                 "meterpreter", "plugx", "shadowpad", "mythic", "backdoor"],
    "wiper": ["wiper", "hermeticwiper", "whispergate", "caddywiper", "acidrain", "isaacwiper", "zerocleare"],
    "worm": ["worm", "phorpiex", "mirai", "gafgyt", "mozi", "ramnit", "dorkbot", "vobfus", "conficker"],
    "miner": ["miner", "coinminer", "xmrig", "cryptominer", "silentcryptominer", "lemonduck"],
}

# Higher = more interesting to study first (rough, editable).
CATEGORY_WEIGHT = {"ransomware": 35, "wiper": 35, "rat": 30, "stealer": 30, "banker": 30, "backdoor": 30,
                   "loader": 25, "worm": 20, "miner": 15}


def categories(item: dict) -> list[str]:
    names = {(item.get("signature") or "").lower()} | {t.lower() for t in (item.get("tags") or [])}
    names.discard("")
    return [cat for cat, fams in FAMILY_PRESETS.items() if names & set(fams)]


def prescore(item: dict) -> tuple[int, list[str]]:
    """Metadata-only interest score 0-100. NOT a static-analysis result."""
    pts, why = 0, []
    cats = categories(item)
    if item.get("signature"):
        pts += 25
        why.append(f"+25 known family: {item['signature']}")
    if cats:
        w = max(CATEGORY_WEIGHT[c] for c in cats)
        pts += w
        why.append(f"+{w} category: {', '.join(cats)}")
    if (item.get("file_type") or "").lower() in ("exe", "dll"):
        pts += 15
        why.append("+15 Windows PE")
    ntags = len(item.get("tags") or [])
    if ntags >= 3:
        pts += 10
        why.append(f"+10 well tagged ({ntags} tags)")
    if not item.get("signature") and not cats:
        why.append("unlabeled: unknown family")
    return min(pts, 100), why
