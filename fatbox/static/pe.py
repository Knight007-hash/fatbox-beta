"""PE structural analysis with pefile. Parse only, never load/execute."""
from __future__ import annotations

from datetime import datetime, timezone

import pefile

from fatbox.static.basics import entropy

# API -> (category, ATT&CK technique)
SUSPICIOUS_APIS: dict[str, tuple[str, str]] = {
    "VirtualAllocEx": ("injection", "T1055"),
    "WriteProcessMemory": ("injection", "T1055"),
    "CreateRemoteThread": ("injection", "T1055"),
    "NtCreateThreadEx": ("injection", "T1055"),
    "QueueUserAPC": ("injection", "T1055.004"),
    "SetThreadContext": ("injection", "T1055.012"),
    "NtUnmapViewOfSection": ("injection", "T1055.012"),
    "ZwUnmapViewOfSection": ("injection", "T1055.012"),
    "IsDebuggerPresent": ("anti-analysis", "T1622"),
    "CheckRemoteDebuggerPresent": ("anti-analysis", "T1622"),
    "NtQueryInformationProcess": ("anti-analysis", "T1622"),
    "OutputDebugStringA": ("anti-analysis", "T1622"),
    "SetWindowsHookExA": ("collection", "T1056.001"),
    "SetWindowsHookExW": ("collection", "T1056.001"),
    "GetAsyncKeyState": ("collection", "T1056.001"),
    "GetClipboardData": ("collection", "T1115"),
    "BitBlt": ("collection", "T1113"),
    "URLDownloadToFileA": ("network", "T1105"),
    "URLDownloadToFileW": ("network", "T1105"),
    "InternetOpenA": ("network", "T1071.001"),
    "InternetOpenW": ("network", "T1071.001"),
    "InternetOpenUrlA": ("network", "T1071.001"),
    "HttpSendRequestA": ("network", "T1071.001"),
    "WinHttpOpen": ("network", "T1071.001"),
    "WSAStartup": ("network", "T1095"),
    "RegSetValueExA": ("persistence", "T1547.001"),
    "RegSetValueExW": ("persistence", "T1547.001"),
    "CreateServiceA": ("persistence", "T1543.003"),
    "CreateServiceW": ("persistence", "T1543.003"),
    "CryptEncrypt": ("crypto", "T1486"),
    "BCryptEncrypt": ("crypto", "T1486"),
    "CryptAcquireContextA": ("crypto", ""),
    "CryptAcquireContextW": ("crypto", ""),
    "AdjustTokenPrivileges": ("privilege", "T1134"),
    "OpenProcessToken": ("privilege", "T1134"),
    "CreateToolhelp32Snapshot": ("discovery", "T1057"),
    "Process32First": ("discovery", "T1057"),
    "Process32FirstW": ("discovery", "T1057"),
    "ShellExecuteA": ("execution", "T1106"),
    "ShellExecuteW": ("execution", "T1106"),
    "WinExec": ("execution", "T1106"),
    "CreateProcessA": ("execution", "T1106"),
    "CreateProcessW": ("execution", "T1106"),
    "LoadLibraryA": ("dynamic-resolve", "T1129"),
    "LoadLibraryW": ("dynamic-resolve", "T1129"),
    "GetProcAddress": ("dynamic-resolve", "T1129"),
}

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect",
    ".vmp1": "VMProtect", ".enigma1": "Enigma", ".petite": "Petite", "pec2": "PECompact", ".nsp0": "NsPack",
}


# 0.18.4: debug directory entry type IMAGE_DEBUG_TYPE_REPRO. Compilers that build "reproducibly" (.NET
# Roslyn /deterministic, MSVC /Brepro, many Windows system files) add it and put a hash in TimeDateStamp.
DEBUG_TYPE_REPRO = 16


def _section_name(sec) -> str:
    return sec.Name.rstrip(b"\x00").decode("latin-1", "replace")


def analyze_pe(data: bytes) -> dict:
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
    ])
    try:
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        ts = fh.TimeDateStamp
        compiled = datetime.fromtimestamp(ts, timezone.utc) if ts else None
        now = datetime.now(timezone.utc)

        ep = oh.AddressOfEntryPoint
        ep_section = None
        sections = []
        for s in pe.sections:
            name = _section_name(s)
            raw = s.get_data()
            chars = s.Characteristics
            perms = ("R" if chars & 0x40000000 else "-") + ("W" if chars & 0x80000000 else "-") + \
                    ("X" if chars & 0x20000000 else "-")
            if s.contains_rva(ep):
                ep_section = name
            sections.append({
                "name": name, "vaddr": hex(s.VirtualAddress), "vsize": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData, "entropy": entropy(raw), "perms": perms,
            })

        imports: dict[str, list[str]] = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode("latin-1", "replace").lower()
            imports[dll] = [
                (i.name.decode("latin-1", "replace") if i.name else f"ord_{i.ordinal}") for i in entry.imports
            ]
        flat_imports = {fn for fns in imports.values() for fn in fns}
        suspicious = sorted(
            ({"api": a, "category": c, "attack": t} for a, (c, t) in SUSPICIOUS_APIS.items() if a in flat_imports),
            key=lambda x: (x["category"], x["api"]),
        )

        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            exports = [e.name.decode("latin-1", "replace") for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name][:200]

        resources = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                tname = str(rtype.name) if rtype.name else pefile.RESOURCE_TYPE.get(rtype.id, str(rtype.id))
                for rid in (rtype.directory.entries if hasattr(rtype, "directory") else []):
                    for lang in (rid.directory.entries if hasattr(rid, "directory") else []):
                        if not hasattr(lang, "data") or len(resources) >= 200:
                            continue
                        d = lang.data.struct
                        blob = pe.get_data(d.OffsetToData, d.Size)
                        resources.append({"type": tname, "size": d.Size, "entropy": entropy(blob)})

        pdb = None
        reproducible = False
        for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            if getattr(dbg.struct, "Type", None) == DEBUG_TYPE_REPRO:
                reproducible = True
            name = getattr(dbg.entry, "PdbFileName", None) if dbg.entry else None
            if name and pdb is None:
                pdb = name.rstrip(b"\x00").decode("utf-8", "replace")  # build-path leaks help attribution

        overlay_off = pe.get_overlay_data_start_offset()
        overlay = data[overlay_off:] if overlay_off else b""

        sec_dir = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        clr_dir = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]

        is_dotnet = clr_dir.VirtualAddress != 0
        dotnet = None
        if is_dotnet:  # 0.19.0: a .NET program's real imports are in its metadata
            from fatbox.static.dotnet import references
            dotnet = references(data, SUSPICIOUS_APIS)
            suspicious = sorted(suspicious + dotnet.pop("suspicious"), key=lambda x: (x["category"], x["api"]))

        packers = sorted({PACKER_SECTIONS[s["name"].lower()] for s in sections if s["name"].lower() in PACKER_SECTIONS})

        return {
            "machine": pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine)),
            "is_dll": bool(fh.Characteristics & 0x2000),
            "is_dotnet": is_dotnet,
            "subsystem": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem)),
            "compile_time": compiled.isoformat() if compiled else None,
            # 0.18.4: a reproducible build stores a hash in the date field, so its "date" says nothing
            "reproducible_build": reproducible,
            "compile_time_anomaly": not reproducible and ((ts == 0) or (compiled is not None and compiled > now)),
            "entrypoint": hex(ep),
            "entrypoint_section": ep_section,
            "imphash": pe.get_imphash() or None,
            "pdb_path": pdb,
            "has_signature_blob": sec_dir.VirtualAddress != 0 and sec_dir.Size > 0,
            # T-9: the certificate table's file offset, so File Analysis can tell it apart from an overlay
            "signature_blob": {"offset": sec_dir.VirtualAddress, "size": sec_dir.Size}
            if sec_dir.VirtualAddress != 0 and sec_dir.Size > 0 else None,
            "tls_callbacks": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
            "sections": sections,
            "import_count": len(flat_imports),
            "imports": imports,
            "suspicious_imports": suspicious,
            "dotnet": dotnet,   # 0.19.0: {"pinvoke": [names], "error": ...} for .NET, else None
            "exports": exports,
            "resources": resources,
            "overlay": {"offset": overlay_off, "size": len(overlay), "entropy": entropy(overlay)} if overlay else None,
            "packer_hints": packers,
            "pefile_warnings": pe.get_warnings()[:20],
        }
    finally:
        pe.close()
