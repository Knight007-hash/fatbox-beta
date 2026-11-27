"""Sample vault + SQLite index.

Safety invariant: samples are only ever stored as AES-encrypted zips.
Plaintext sample bytes exist in memory during triage and are never written to disk here.
"""
from __future__ import annotations

import hashlib
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pyzipper

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256      TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    first_seen  TEXT,
    file_name   TEXT,
    file_type   TEXT,
    signature   TEXT,
    tags        TEXT,            -- JSON list
    zip_path    TEXT NOT NULL,
    fetched_at  TEXT NOT NULL,
    status      TEXT NOT NULL,   -- fetched | static_done | dynamic_done | error | timeout | too_big
    score       INTEGER,
    priority    TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_status ON samples(status);
"""


# Zip-bomb guard (SPEC Limits): a sample is never unpacked past this, whatever any setting says. Not a
# verdict on the file: a padded binary can be real malware, it is just more than this lab analyses safely.
UNPACKED_CAP = 100 * 1024 * 1024


class SampleTooLarge(Exception):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.vault_dir = data_dir / "vault"
        self.reports_dir = data_dir / "reports"
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(data_dir / "index.db")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---- vault -------------------------------------------------------------
    def zip_path_for(self, sha256: str) -> Path:
        # .zip.quarantine: never double-clickable, never auto-extracted by Explorer
        return self.vault_dir / sha256[:2] / f"{sha256}.zip.quarantine"

    def report_dir_for(self, sha256: str) -> Path:
        d = self.reports_dir / sha256
        d.mkdir(parents=True, exist_ok=True)
        return d

    def has(self, sha256: str) -> bool:
        return self.db.execute("SELECT 1 FROM samples WHERE sha256=?", (sha256,)).fetchone() is not None

    def add(self, sha256: str, zip_bytes: bytes, meta: dict, source: str) -> Path:
        path = self.zip_path_for(sha256)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zip_bytes)
        self.db.execute(
            "INSERT OR REPLACE INTO samples (sha256, source, first_seen, file_name, file_type, signature, tags,"
            " zip_path, fetched_at, status) VALUES (?,?,?,?,?,?,?,?,?, 'fetched')",
            (
                sha256,
                source,
                meta.get("first_seen"),
                meta.get("file_name"),
                meta.get("file_type"),
                meta.get("signature"),
                json.dumps(meta.get("tags") or []),
                str(path),
                utcnow(),
            ),
        )
        self.db.commit()
        return path

    def add_info(self, sha256: str, meta: dict, source: str, reason: str) -> None:
        """0.23.0: a sample past the unpack limit, kept as metadata only (status too_big, no file, no zip_path).
        Never triaged; `has` is true, so the next fetch doesn't download it again."""
        self.db.execute(
            "INSERT OR IGNORE INTO samples (sha256, source, first_seen, file_name, file_type, signature, tags,"
            " zip_path, fetched_at, status, error) VALUES (?,?,?,?,?,?,?, '', ?, 'too_big', ?)",
            (sha256, source, meta.get("first_seen"), meta.get("file_name"), meta.get("file_type"),
             meta.get("signature"), json.dumps(meta.get("tags") or []), utcnow(), reason[:300]),
        )
        self.db.commit()

    def set_result(self, sha256: str, status: str, score: int | None = None,
                   priority: str | None = None, error: str | None = None) -> None:
        self.db.execute(
            "UPDATE samples SET status=?, score=?, priority=?, error=? WHERE sha256=?",
            (status, score, priority, error, sha256),
        )
        self.db.commit()

    def get(self, sha256: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM samples WHERE sha256=?", (sha256,)).fetchone()

    def by_status(self, status: str) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM samples WHERE status=? ORDER BY fetched_at", (status,)).fetchall()

    def all(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM samples ORDER BY fetched_at DESC LIMIT ?", (limit,)).fetchall()


def read_sample_from_zip(zip_source: Path | bytes, password: str, max_bytes: int) -> tuple[str, bytes]:
    """Decrypt the single member of a sample zip into memory. Returns (member_name, data)."""
    fh = io.BytesIO(zip_source) if isinstance(zip_source, (bytes, bytearray)) else open(zip_source, "rb")
    with fh, pyzipper.AESZipFile(fh) as zf:
        members = [i for i in zf.infolist() if not i.is_dir()]
        if len(members) != 1:
            raise ValueError(f"expected 1 member in sample zip, found {len(members)}")
        info = members[0]
        if info.file_size > max_bytes:
            raise SampleTooLarge(f"{info.filename}: {info.file_size} bytes > limit {max_bytes}")
        zf.setpassword(password.encode())
        with zf.open(info) as member:
            data = member.read(max_bytes + 1)  # bounded read even if the header lies
        if len(data) > max_bytes:
            raise SampleTooLarge(f"{info.filename}: decompressed past limit {max_bytes}")
        return info.filename, data


def make_sample_zip(name: str, data: bytes, password: str) -> bytes:
    """Wrap bytes in an AES zip (used for manual imports and tests)."""
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        zf.writestr(name, data)
    return buf.getvalue()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
