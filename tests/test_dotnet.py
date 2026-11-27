"""0.19.0: .NET metadata references. dnfile is replaced by a fake here: no .NET binary is in the repo."""
from __future__ import annotations

import struct
import sys
import types

from fatbox.static import dotnet
from fatbox.static.dotnet import first_param_is_bytes, native_match, references
from fatbox.static.pe import SUSPICIOUS_APIS, analyze_pe
from fatbox.static.triage import score
from test_compile_time import PAST, build_pe

LOAD_BYTES = bytes.fromhex("000112651d05")       # static Assembly Load(byte[])
LOAD_BYTES_PDB = bytes.fromhex("000212651d051d05")  # Load(byte[], byte[])
LOAD_NAME = bytes.fromhex("0001126512808d")      # Load(AssemblyName): plugin hosts
LOAD_STRING = bytes.fromhex("000112650e")        # Load(string)
APPDOMAIN_NAME = bytes.fromhex("200112351280a5")  # instance AppDomain.Load(AssemblyName)


def test_signature_decoder():
    assert first_param_is_bytes(LOAD_BYTES) and first_param_is_bytes(LOAD_BYTES_PDB)
    assert not first_param_is_bytes(LOAD_NAME) and not first_param_is_bytes(LOAD_STRING)
    assert not first_param_is_bytes(APPDOMAIN_NAME)
    for broken in (b"", b"\x00", b"\x00\x01", b"\x00\x01\x12", b"\x00\x01\x99\x1d\x05", b"\x00\x00\x12\x65"):
        assert not first_param_is_bytes(broken)


def test_native_match_adds_charset_suffix():
    assert native_match("SetWindowsHookEx", SUSPICIOUS_APIS) == "SetWindowsHookExW"
    assert native_match("VirtualAllocEx", SUSPICIOUS_APIS) == "VirtualAllocEx"
    assert native_match("MessageBox", SUSPICIOUS_APIS) is None


# ---- fake dnfile ---------------------------------------------------------------------------------------------
class Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def ref(ns, typ, name, sig=b"\x20\x00\x01"):
    return Row(Class=Row(row=Row(TypeNamespace=ns, TypeName=typ)), Name=name, Signature=Row(value=sig))


def fake_dnfile(monkeypatch, implmap=(), memberref=(), fail=False):
    class DnPE:
        def __init__(self, data=None):
            if fail:
                raise ValueError("bad CLR header")
            self.net = Row(mdtables=Row(ImplMap=[Row(ImportName=n) for n in implmap], MemberRef=list(memberref)))

        def close(self):
            pass
    monkeypatch.setitem(sys.modules, "dnfile", types.SimpleNamespace(dnPE=DnPE))


def test_references_map_pinvoke_and_dotnet_apis(monkeypatch):
    fake_dnfile(monkeypatch, implmap=["VirtualAllocEx", "WriteProcessMemory", "SetWindowsHookEx", "MessageBox"],
                memberref=[ref("System.Reflection", "Assembly", "Load", LOAD_BYTES),
                           ref("System.Diagnostics", "Debugger", "get_IsAttached"),
                           ref("System.Net", "WebClient", "DownloadData"),
                           ref("System.Security.Cryptography", "RijndaelManaged", ".ctor"),
                           ref("System", "Console", "WriteLine"),
                           Row(Class=Row(row=None), Name="x", Signature=None)])   # TypeSpec parent: skipped
    out = references(b"MZ", SUSPICIOUS_APIS)
    assert out["error"] is None
    assert out["pinvoke"] == ["VirtualAllocEx", "WriteProcessMemory", "SetWindowsHookEx", "MessageBox"]
    got = {r["api"]: r["category"] for r in out["suspicious"]}
    assert got == {"P/Invoke VirtualAllocEx": "injection", "P/Invoke WriteProcessMemory": "injection",
                   "P/Invoke SetWindowsHookExW": "collection", ".NET Assembly::Load": "load-code",
                   ".NET Debugger::get_IsAttached": "anti-analysis", ".NET WebClient::DownloadData": "network",
                   ".NET RijndaelManaged::.ctor": "crypto"}


def test_load_by_name_is_not_code_loading(monkeypatch):
    fake_dnfile(monkeypatch, memberref=[ref("System.Reflection", "Assembly", "Load", LOAD_NAME),
                                        ref("System.Reflection", "Assembly", "Load", LOAD_STRING),
                                        ref("System", "AppDomain", "Load", APPDOMAIN_NAME)])
    assert references(b"MZ", SUSPICIOUS_APIS)["suspicious"] == []


def test_broken_metadata_is_no_facts_not_a_crash(monkeypatch):
    fake_dnfile(monkeypatch, fail=True)
    out = references(b"MZ", SUSPICIOUS_APIS)
    assert out["suspicious"] == [] and out["pinvoke"] == [] and "bad CLR header" in out["error"]


def test_pinvoke_list_is_capped(monkeypatch):
    fake_dnfile(monkeypatch, implmap=[f"f{i}" for i in range(dotnet.MAX_PINVOKE + 50)])
    assert len(references(b"MZ", SUSPICIOUS_APIS)["pinvoke"]) == dotnet.MAX_PINVOKE


def dotnet_pe() -> bytes:
    """The synthetic PE with a CLR (COM descriptor, index 14) data directory pointing into .text."""
    b = bytearray(build_pe(PAST))
    dirs = 0x40 + 4 + 20 + 96          # e_lfanew + PE sig + file header + PE32 optional header fields
    struct.pack_into("<II", b, dirs + 14 * 8, 0x200, 0x48)
    return bytes(b)


def test_dotnet_pe_gets_scored_like_native_imports(monkeypatch):
    fake_dnfile(monkeypatch, implmap=["VirtualAllocEx"],
                memberref=[ref("System.Reflection", "Assembly", "Load", LOAD_BYTES)])
    pe = analyze_pe(dotnet_pe())
    assert pe["is_dotnet"] and pe["dotnet"] == {"pinvoke": ["VirtualAllocEx"], "error": None}
    r = {"pe": pe, "behaviour": [], "yara": [], "iocs": {}, "entropy": 1.0}
    reasons = score(r)[1]
    assert "+15 injection APIs imported" in reasons and "+10 load-code APIs imported" in reasons
    assert not any("very few imports" in x for x in reasons)


def test_native_pe_has_no_dotnet_block():
    assert analyze_pe(build_pe(PAST))["dotnet"] is None
