from __future__ import annotations

import hashlib
import math
from collections import Counter

MAGIC = [
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"Rar!", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"{\\rtf", "rtf"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
]


def hashes(data: bytes) -> dict:
    out = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    try:  # fuzzy hashes are optional
        import tlsh
        out["tlsh"] = tlsh.hash(data) or None
    except ImportError:
        pass
    try:
        import ppdeep
        out["ssdeep"] = ppdeep.hash(data)
    except ImportError:
        pass
    return out


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 3)


def file_kind(data: bytes) -> str:
    for magic, kind in MAGIC:
        if data.startswith(magic):
            return kind
    head = data[:512].lower()
    if head.startswith(b"#!"):
        return "script-shebang"
    for marker, kind in ((b"<script", "html/js"), (b"powershell", "script-ps"), (b"wscript", "script-vbs/js"),
                         (b"@echo off", "script-bat"), (b"<?xml", "xml"), (b"<html", "html")):
        if marker in head:
            return kind
    return "unknown"


def local_file_type(data: bytes) -> str:
    """Coarse type label in MalwareBazaar's vocabulary (exe, dll, elf, zip, ...) derived from bytes."""
    kind = file_kind(data)
    if kind == "pe":
        try:
            e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
            if data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                characteristics = int.from_bytes(data[e_lfanew + 22:e_lfanew + 24], "little")
                return "dll" if characteristics & 0x2000 else "exe"
        except (IndexError, ValueError):
            pass
        return "pe-malformed"
    return {"ole": "doc", "script-ps": "ps1", "script-bat": "bat"}.get(kind, kind)
