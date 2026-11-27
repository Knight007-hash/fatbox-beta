"""0.41.0 Lab tab (T-24 part 1): this PC's memory and the RAM check for test VMs. Host-side numbers only."""
from __future__ import annotations

import ctypes
import sys
from pathlib import Path

RESERVE_MB = 2048   # left for Windows and FatBox itself when deciding whether another VM fits


def host_memory() -> tuple[int, int] | None:
    """(total MB, free MB) of this PC, or None when the OS won't say."""
    try:
        if sys.platform == "win32":
            class MemStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            st = MemStatus()
            st.dwLength = ctypes.sizeof(MemStatus)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return None
            return st.ullTotalPhys // 2**20, st.ullAvailPhys // 2**20
        kv = {}
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            k, _, v = line.partition(":")
            kv[k] = int(v.split()[0]) // 1024
        return kv["MemTotal"], kv.get("MemAvailable", kv.get("MemFree", 0))
    except (OSError, KeyError, ValueError, AttributeError):
        return None


def fits(free_mb: int, vm_mb: int) -> bool:
    """Can a VM of vm_mb start now without squeezing this PC?"""
    return vm_mb > 0 and free_mb - RESERVE_MB >= vm_mb


def as_int(raw: str | None) -> int | None:
    """A VirtualBox number (memory, cpus), or None if it isn't one."""
    return int(raw) if raw and raw.isdigit() and len(raw) <= 7 else None
