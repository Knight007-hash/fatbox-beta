from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

from fatbox.fetch.common import MAX_BUDGET_S, MAX_SAMPLES, MIN_BUDGET_S, UNPACK_LIMITS_MB, Filters
from fatbox.store import UNPACKED_CAP

MIN_SAMPLE_S, MAX_SAMPLE_S = 10, 300   # triage time limit per sample (T-5)
MIN_CAPA_S, MAX_CAPA_S = 30, 600       # code analysis (capa) time limit per sample, on top of the above (T-14)
TRIAGE_PER_RUN = 30                    # samples triaged per run, oldest first; the rest wait for the next run
MAX_PARALLEL = 10                      # 0.32.0: samples analysed at the same time, 1..10 (0.21.0: 1..4)
SAMPLE_RAM_GB = 1.1                    # 0.32.0: one sample in flight, measured on Linux (capa ~0.9 GB, mostly its
#                                        library signatures, + the triage and file-analysis helpers). 0.34.0: only the
#                                        headroom a NEW sample needs; what running ones use is read live
STAGGER_S = 10                         # 0.34.0: a helper's RAM may still rise this long after its start; 0.39.0:
#                                        such a young helper counts as holding SAMPLE_RAM_GB (no fixed gap)
RAM_RESERVE_GB = 1.5                   # 0.32.0: never start a sample below this much free RAM (no paging, INV-2)
MAX_SHARE = 3                          # 0.32.0: at most 3x the time limits when samples share a CPU


def free_ram_gb() -> float | None:
    """Free (available) RAM in GB, or None when unknown. Windows: GlobalMemoryStatusEx; Linux: /proc/meminfo."""
    try:
        if os.name == "nt":
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            st = MemoryStatus()
            st.dwLength = ctypes.sizeof(MemoryStatus)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return None
            return st.ullAvailPhys / 1024 ** 3
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024 ** 2
    except (OSError, ValueError, AttributeError):
        return None
    return None


def auto_parallel(cpus: int | None = None) -> int:
    """parallel = 0 (auto): one sample per CPU (0.32.0; was half), 1..10. capa keeps one CPU busy per sample; the
    triage and file-analysis helpers mostly wait for it. 0.34.0: RAM no longer caps this number up front: the
    live RAM gate in `triage` starts each sample only when the VM really has room for it."""
    cpus = cpus if cpus is not None else (os.cpu_count() or 1)
    return max(1, min(MAX_PARALLEL, cpus))


def room_for_one_more(free_gb: float | None) -> bool:
    """0.34.0 live RAM gate: a new sample may start beside running ones only while the VM has its headroom
    (SAMPLE_RAM_GB) on top of the reserve (RAM_RESERVE_GB) free right now. Unknown free RAM: yes."""
    return free_gb is None or free_gb >= RAM_RESERVE_GB + SAMPLE_RAM_GB


def cpu_share(workers: int, cpus: int | None = None) -> int:
    """How many samples share one CPU (1..MAX_SHARE). The time limits are stretched by this, so a sample that gets
    a third of a CPU also gets three times the time: the same CPU time it would have alone."""
    cpus = cpus if cpus is not None else (os.cpu_count() or 1)
    return max(1, min(MAX_SHARE, -(-workers // max(1, cpus))))

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib


@dataclass
class BazaarConfig:
    api_key: str = ""
    mode: str = "recent"        # recent | latest | tag | signature | file_type
    query_value: str = ""
    limit: int = 100


@dataclass
class MalShareConfig:
    api_key: str = ""
    type_filter: str = ""       # server-side type (see `fatbox sources --types`), e.g. "PE32"; "" = all


@dataclass
class Config:
    data_dir: Path = Path("./data")
    yara_dir: Path = Path("./rules/yara")
    capa_dir: Path = Path("./rules/capa")   # capa rules + library signatures, pinned (T-14)
    zip_password: str = "infected"
    download_limit_mb: int = 5      # skip samples bigger than this (slow link); 1..100
    download_limit_on: bool = True  # off: downloads stop only at the unpacked cap (100 MB)
    fetch_budget_s: int = 400       # one time budget for the whole fetch, all samples together; 60..1800
    sample_time_s: int = 60         # triage time limit per sample; past it the analysis is stopped; 10..300
    capa_time_s: int = 120          # extra time for code analysis (capa) per sample; past it capa is stopped; 30..600
    parallel: int = 0               # samples analysed at once; 0 = auto (CPUs and free RAM, 1..10); 1..10
    capa_lib_skip: bool = True      # 0.32.0: skip emulation of library functions FLIRT named (capa ignores them).
    #                                 0.34.0: on by default (capa-compare: identical findings on real samples)
    capa_packed: str = "skip"       # 0.23.0: capa on packed native programs: skip (only the stub) | run
    unpack_limit_mb: int = 100      # 0.23.0: zip-bomb guard, 25 | 50 | 100; can go lower, never higher or off
    too_big: str = "skip"           # 0.23.0: a sample past the unpack limit: skip | info (metadata row only)
    sources: list[str] = field(default_factory=lambda: ["bazaar"])
    filters: Filters = field(default_factory=Filters)
    bazaar: BazaarConfig = field(default_factory=BazaarConfig)
    malshare: MalShareConfig = field(default_factory=MalShareConfig)

    @property
    def max_bytes(self) -> int:
        """Download cap in bytes: the download limit when it is on, else the unpacked cap."""
        return min(self.download_limit_mb * 1024 * 1024 if self.download_limit_on else UNPACKED_CAP, self.cap)

    @property
    def cap(self) -> int:
        """The unpack limit in bytes: never above UNPACKED_CAP (100 MB), whatever any setting says."""
        return min(self.unpack_limit_mb * 1024 * 1024, UNPACKED_CAP)

    def check(self) -> "Config":
        if not isinstance(self.download_limit_on, bool):
            raise ValueError(f"download_limit_on must be true or false (config.toml says {self.download_limit_on!r})")
        for name, value, lo, hi in (("download_limit_mb", self.download_limit_mb, 1, 100),
                                    ("fetch_budget_s", self.fetch_budget_s, MIN_BUDGET_S, MAX_BUDGET_S),
                                    ("max_per_run", self.filters.max_per_run, 1, MAX_SAMPLES),
                                    ("sample_time_s", self.sample_time_s, MIN_SAMPLE_S, MAX_SAMPLE_S),
                                    ("capa_time_s", self.capa_time_s, MIN_CAPA_S, MAX_CAPA_S),
                                    ("parallel", self.parallel, 0, MAX_PARALLEL)):
            if not lo <= value <= hi:
                raise ValueError(f"{name} must be {lo}..{hi} (config.toml says {value})")
        if self.unpack_limit_mb not in UNPACK_LIMITS_MB:
            raise ValueError(f"unpack_limit_mb must be one of {UNPACK_LIMITS_MB} (config.toml says {self.unpack_limit_mb})")
        if not isinstance(self.capa_lib_skip, bool):
            raise ValueError(f"capa_lib_skip must be true or false (config.toml says {self.capa_lib_skip!r})")
        if self.capa_packed not in ("skip", "run"):
            raise ValueError(f"capa_packed must be skip or run (config.toml says {self.capa_packed!r})")
        if self.too_big not in ("skip", "info"):
            raise ValueError(f"too_big must be skip or info (config.toml says {self.too_big!r})")
        if not 0 <= self.filters.min_size_kb <= 10240:
            raise ValueError(f"min_size_kb must be 0..10240 (config.toml says {self.filters.min_size_kb})")
        return self


def _build(cls, raw: dict):
    names = {f.name for f in fields(cls)}
    unknown = set(raw) - names
    if unknown:
        raise ValueError(f"unknown keys for {cls.__name__}: {sorted(unknown)}")
    return cls(**raw)


def load_config(path: str | os.PathLike | None) -> Config:
    raw: dict = {}
    base = Path(".")
    if path and Path(path).exists():
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
        # relative paths follow the config file, not the cwd (the host runs us via guestcontrol from System32)
        base = Path(path).resolve().parent

    paths, vault, fetch = raw.get("paths", {}), raw.get("vault", {}), raw.get("fetch", {})
    cfg = Config(
        data_dir=base / paths.get("data_dir", "./data"),
        yara_dir=base / paths.get("yara_dir", "./rules/yara"),
        capa_dir=base / paths.get("capa_dir", "./rules/capa"),
        zip_password=vault.get("zip_password", "infected"),
        # [vault] max_sample_mb is the pre-0.11 name of the download limit; still read when the new key is absent
        download_limit_mb=int(fetch.get("download_limit_mb", vault.get("max_sample_mb", 5))),
        download_limit_on=fetch.get("download_limit_on", True),
        fetch_budget_s=int(fetch.get("budget_s", 400)),
        sample_time_s=int(raw.get("triage", {}).get("sample_time_s", 60)),
        capa_time_s=int(raw.get("triage", {}).get("capa_time_s", 120)),
        parallel=int(raw.get("triage", {}).get("parallel", 0)),
        capa_packed=str(raw.get("triage", {}).get("capa_packed", "skip")),
        capa_lib_skip=raw.get("triage", {}).get("capa_lib_skip", True),
        unpack_limit_mb=int(fetch.get("unpack_limit_mb", 100)),
        too_big=str(fetch.get("too_big", "skip")),
        sources=list(fetch.get("sources", ["bazaar"])),
        filters=_build(Filters, raw.get("filters", {})),
        bazaar=_build(BazaarConfig, raw.get("bazaar", {})),
        malshare=_build(MalShareConfig, raw.get("malshare", {})),
    )
    cfg.bazaar.api_key = os.environ.get("MB_API_KEY", cfg.bazaar.api_key)
    cfg.malshare.api_key = os.environ.get("MALSHARE_API_KEY", cfg.malshare.api_key)
    return cfg.check()
