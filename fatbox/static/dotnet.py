""".NET metadata references (0.19.0): what a .NET program calls, read from memory with dnfile. Parse only.

A .NET program imports one native function (_CorExeMain), so the native import rules never see it. Its real
"imports" are in the metadata: P/Invoke declarations ([DllImport] VirtualAllocEx, ...) and references to .NET
APIs (System.Net.WebClient::DownloadData, ...). Both are turned into the same {"api", "category", "attack"}
rows as native suspicious imports, so triage scores them with the same points.
"""
from __future__ import annotations

MAX_PINVOKE = 200      # P/Invoke names kept in the report
MAX_STR = 120

# "Namespace.Type::Method" -> (category, ATT&CK). Kept to calls that say something; Process.Start, File.* and
# plain reflection are everyday .NET. Measured against clean .NET files with `fatbox baseline`.
DOTNET_APIS: dict[str, tuple[str, str]] = {
    # code loaded from bytes at run time: the classic .NET loader / crypter stub. Only the Load(byte[], ...)
    # overloads count (BYTES_FIRST); Load(string) / Load(AssemblyName) is how plugin hosts load a named DLL.
    "System.Reflection.Assembly::Load": ("load-code", "T1620"),
    "System.AppDomain::Load": ("load-code", "T1620"),
    # anti-analysis
    "System.Diagnostics.Debugger::get_IsAttached": ("anti-analysis", "T1622"),
    "System.Diagnostics.Debugger::IsLogging": ("anti-analysis", "T1622"),
    # collection
    "System.Windows.Forms.Clipboard::GetText": ("collection", "T1115"),
    "System.Windows.Forms.Clipboard::GetDataObject": ("collection", "T1115"),
    "System.Drawing.Graphics::CopyFromScreen": ("collection", "T1113"),
    # network
    "System.Net.WebClient::DownloadData": ("network", "T1105"),
    "System.Net.WebClient::DownloadFile": ("network", "T1105"),
    "System.Net.WebClient::DownloadString": ("network", "T1105"),
    "System.Net.WebClient::UploadData": ("network", "T1041"),
    "System.Net.WebClient::UploadValues": ("network", "T1041"),
    "System.Net.Sockets.TcpClient::Connect": ("network", "T1095"),
    "System.Net.Sockets.Socket::Connect": ("network", "T1095"),
    # persistence
    "Microsoft.Win32.RegistryKey::SetValue": ("persistence", "T1547.001"),
    # crypto (often used to decrypt the hidden payload)
    "System.Security.Cryptography.RijndaelManaged::.ctor": ("crypto", ""),
    "System.Security.Cryptography.TripleDESCryptoServiceProvider::.ctor": ("crypto", ""),
    "System.Security.Cryptography.DESCryptoServiceProvider::.ctor": ("crypto", ""),
}


BYTES_FIRST = {"System.Reflection.Assembly::Load", "System.AppDomain::Load"}
_PRIMITIVES = set(range(0x01, 0x0F)) | {0x18, 0x19, 0x1C}


def _cint(b: bytes, i: int) -> tuple[int, int]:
    """ECMA-335 compressed unsigned int at b[i] -> (value, next index)."""
    x = b[i]
    if x < 0x80:
        return x, i + 1
    if x & 0xC0 == 0x80:
        return ((x & 0x3F) << 8) | b[i + 1], i + 2
    return ((x & 0x1F) << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3], i + 4


def _skip_type(b: bytes, i: int) -> int:
    t = b[i]
    if t in _PRIMITIVES:
        return i + 1
    if t in (0x11, 0x12):          # VALUETYPE / CLASS + TypeDefOrRef token
        return _cint(b, i + 1)[1]
    if t == 0x1D:                  # SZARRAY of a type
        return _skip_type(b, i + 1)
    raise ValueError("type not handled")


def first_param_is_bytes(sig: bytes) -> bool:
    """Method signature blob: is the first parameter byte[] (SZARRAY U1)?"""
    try:
        i = 1
        if sig[0] & 0x10:          # GENERIC: number of generic parameters
            i = _cint(sig, i)[1]
        n, i = _cint(sig, i)
        if n < 1:
            return False
        i = _skip_type(sig, i)     # return type
        return sig[i:i + 2] == b"\x1d\x05"
    except (IndexError, ValueError):
        return False


def _s(v) -> str:
    return str(v)[:MAX_STR] if v is not None else ""


def native_match(name: str, table: dict) -> str | None:
    """A P/Invoke name against the native API table; .NET often drops the A/W suffix (CharSet picks it)."""
    for n in (name, name + "W", name + "A"):
        if n in table:
            return n
    return None


def references(data: bytes, native_apis: dict[str, tuple[str, str]]) -> dict:
    """-> {"pinvoke": [...], "suspicious": [rows], "error": None}. Never raises: a broken .NET header is
    normal in this domain and only means "no .NET facts"."""
    out: dict = {"pinvoke": [], "suspicious": [], "error": None}
    try:
        import dnfile
        pe = dnfile.dnPE(data=data)
    except Exception as e:
        out["error"] = _s(f"{type(e).__name__}: {e}")
        return out
    try:
        t = pe.net.mdtables if pe.net else None
        found: dict[str, tuple[str, str]] = {}
        names: list[str] = []
        for r in (getattr(t, "ImplMap", None) or []) if t else []:
            name = _s(getattr(r, "ImportName", ""))
            if name and name not in names and len(names) < MAX_PINVOKE:
                names.append(name)
            hit = native_match(name, native_apis) if name else None
            if hit:
                found[f"P/Invoke {hit}"] = native_apis[hit]
        for r in (getattr(t, "MemberRef", None) or []) if t else []:
            try:
                cls = r.Class.row
                key = f"{_s(cls.TypeNamespace)}.{_s(cls.TypeName)}::{_s(r.Name)}"
            except Exception:
                continue  # parent is not a TypeRef (TypeSpec, MethodDef ...)
            if key in BYTES_FIRST:
                sig = getattr(r.Signature, "value", r.Signature)
                if not first_param_is_bytes(bytes(sig or b"")):
                    continue
            if key in DOTNET_APIS:
                found[f".NET {_s(cls.TypeName)}::{_s(r.Name)}"] = DOTNET_APIS[key]
        out["pinvoke"] = names
        out["suspicious"] = sorted(({"api": a, "category": c, "attack": k} for a, (c, k) in found.items()),
                                   key=lambda x: (x["category"], x["api"]))
    except Exception as e:
        out["error"] = _s(f"{type(e).__name__}: {e}")
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return out
