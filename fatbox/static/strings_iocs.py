"""String extraction, IOC extraction and string-level behaviour indicators."""
from __future__ import annotations

import ipaddress
import re

ASCII_TMPL = rb"[\x20-\x7e]{%d,}"
UTF16_TMPL = rb"(?:[\x20-\x7e]\x00){%d,}"

URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\^`{|}]{4,}", re.I)
# Not inside a longer dotted number: "1.3.6.1.4.1.311.61.1.1" (an OID) or "2.16.840.1.101.3.4.1" is no IP.
IPV4_RE = re.compile(r"(?<![\d.])\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\.\d)")
EMAIL_RE = re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+\b")
# Every repeat is bounded: an unbounded one made "a.a.a..." runs quadratic (1 MB of it ran for hours).
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}([a-z]{2,24})\b", re.I)
REG_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s\"']{3,}", re.I)
WINPATH_RE = re.compile(r"\b[a-z]:\\[^\s\"'<>|*?]{3,}|%[a-z]+%\\[^\s\"'<>|*?]{2,}", re.I)
BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")

# Restrict domain hits to real TLDs that malware actually uses; avoids "kernel32.dll"-style noise.
TLDS = set("""com net org info biz io co ru su cn top xyz online site club live pw tk ml ga cf gq me us uk de fr nl
br in ir ua kz by pl it es tr vn kr jp tw hk sg id th my ph pk bd ng za eg sa ae il ca au nz mx ar cl
cc ws to su onion app dev cloud shop store tech space fun icu cyou buzz rest bar sbs lol quest monster""".split())

PRIVATE_NOISE = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}

# Network IOCs that almost every normal program carries. Still listed in the report, but they give no score.
# XML schemas, certificate chains (CRL/OCSP/CA pages), runtime boilerplate links.
BENIGN_HOSTS = ("w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org", "xmlsoap.org", "purl.org",
                "microsoft.com", "windowsupdate.com", "aka.ms", "globalsign.com", "globalsign.net", "verisign.com",
                "digicert.com", "sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "symantec.com",
                "symcb.com", "symcd.com", "symauth.com", "thawte.com", "geotrust.com", "entrust.net",
                "godaddy.com", "starfieldtech.com", "letsencrypt.org", "identrust.com", "certum.pl")
CERT_PREFIXES = ("crl.", "crl3.", "crl4.", "ocsp.", "cacerts.")
# Public DNS resolvers: malware uses them, but so does every network program.
PUBLIC_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222",
              "208.67.220.220", "114.114.114.114"}
OID_PREFIXES = ("1.2.", "1.3.", "2.5.", "2.16.")

# (regex, label, ATT&CK) — string-level hints for purple-team mapping; confirm dynamically.
BEHAVIOUR_PATTERNS = [
    (r"vssadmin(\.exe)?\s+delete\s+shadows", "shadow copy deletion", "T1490"),
    (r"wmic\s+shadowcopy\s+delete", "shadow copy deletion", "T1490"),
    (r"bcdedit.{0,200}recoveryenabled\s+no", "recovery disabled", "T1490"),
    (r"wevtutil(\.exe)?\s+cl", "event log clearing", "T1070.001"),
    (r"schtasks(\.exe)?\s+/create", "scheduled task", "T1053.005"),
    (r"\\CurrentVersion\\Run", "Run key persistence", "T1547.001"),
    (r"powershell.{0,200}-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", "encoded PowerShell", "T1059.001"),
    (r"powershell", "PowerShell reference", "T1059.001"),
    (r"cmd(\.exe)?\s+/c", "cmd execution", "T1059.003"),
    (r"Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring", "Defender tampering", "T1562.001"),
    (r"netsh\s+advfirewall", "firewall modification", "T1562.004"),
    (r"VBoxService|VBoxTray|vmtoolsd|vmware|qemu-ga|SbieDll|wireshark|procmon|x64dbg|ollydbg", "VM/sandbox/tool check", "T1497.001"),
    (r"\\Google\\Chrome\\User Data|\\Mozilla\\Firefox\\Profiles|Login Data|logins\.json", "browser credential theft", "T1555.003"),
    (r"wallet\.dat|\\Exodus\\|\\Electrum\\|MetaMask", "crypto wallet theft", "T1005"),
    (r"api\.telegram\.org|discord(app)?\.com/api/webhooks", "chat-app exfil channel", "T1567"),
    (r"ipinfo\.io|ip-api\.com|api\.ipify\.org|checkip\.", "external IP discovery", "T1016"),
    (r"YOUR FILES (HAVE BEEN|ARE) ENCRYPTED|decrypt(ion)? (key|tool)|bitcoin", "ransom note language", "T1486"),
    (r"mimikatz|sekurlsa|lsass", "credential dumping reference", "T1003.001"),
    (r"rundll32(\.exe)?\s", "rundll32 proxy execution", "T1218.011"),
    (r"regsvr32|mshta|certutil.{0,200}-urlcache", "LOLBin proxy/download", "T1218"),
]
_BEHAVIOUR = [(re.compile(p, re.I), label, t) for p, label, t in BEHAVIOUR_PATTERNS]


def extract_strings(data: bytes, min_len: int = 6, cap: int = 20000) -> list[str]:
    out: list[str] = []
    for m in re.finditer(ASCII_TMPL % min_len, data):
        out.append(m.group().decode("ascii"))
        if len(out) >= cap:
            return out
    for m in re.finditer(UTF16_TMPL % min_len, data):
        out.append(m.group().decode("utf-16le"))
        if len(out) >= cap:
            break
    return out


def _valid_ip(s: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return False
    return not (s in PRIVATE_NOISE or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _host(url: str) -> str:
    m = re.match(r"(?i)[a-z]+://(?:[^/@\s]*@)?([^/:?#\s]*)", url)
    host = re.split(r"[^a-z0-9.-]", (m.group(1) if m else "").lower())[0].strip(".")
    return re.sub(r"(?<=[a-z])\d+$", "", host)  # ASN.1 length byte glued to the TLD: "verisign.com0"


def url_noise(url: str) -> str | None:
    """Why this URL is not evidence (schema, certificate, template), or None when it counts."""
    host = _host(url)
    if not host or "." not in host:
        return "template"  # http://%s/..., http://localhost
    if host.startswith(CERT_PREFIXES):
        return "certificate"
    if IPV4_RE.fullmatch(host):
        return ip_noise(host)
    if any(host == d or host.endswith("." + d) for d in BENIGN_HOSTS):
        return "schema/certificate"
    return None


def ip_noise(ip: str) -> str | None:
    """Why this dotted quad is not evidence (version number, OID, public DNS), or None when it counts."""
    parts = [int(x) for x in ip.split(".")]
    if parts[3] == 0 or max(parts) <= 20:
        return "version number"  # 1.0.0.0, 6.0.0.0, 3.0.0.4, 5.3.1.9
    if ip.startswith(OID_PREFIXES):
        return "OID"  # 1.3.101.110 (X25519)
    if ip in PUBLIC_DNS:
        return "public DNS"
    return None


def network_iocs(iocs: dict) -> tuple[list[str], int]:
    """URLs and public IPs that count as evidence, and how many were ignored as noise."""
    urls, ips = iocs.get("urls") or [], iocs.get("ipv4") or []
    counted = [u for u in urls if url_noise(u) is None] + [i for i in ips if ip_noise(i) is None]
    return counted, len(urls) + len(ips) - len(counted)


def extract_iocs(strings: list[str]) -> dict:
    blob = "\n".join(strings)
    urls = sorted(set(URL_RE.findall(blob)))
    all_ips = {ip for ip in IPV4_RE.findall(blob) if _valid_ip(ip)}
    private = {ip for ip in all_ips if ipaddress.IPv4Address(ip).is_private}
    emails = sorted(set(EMAIL_RE.findall(blob)))
    domains = sorted({m.group(0).lower() for m in DOMAIN_RE.finditer(blob) if m.group(1).lower() in TLDS})
    return {
        "urls": urls[:500],
        "ipv4": sorted(all_ips - private)[:500],
        "ipv4_private": sorted(private)[:100],
        "domains": domains[:500],
        "emails": emails[:200],
        "registry": sorted(set(REG_RE.findall(blob)))[:300],
        "paths": sorted(set(WINPATH_RE.findall(blob)))[:300],
        "btc_addresses": sorted(set(BTC_RE.findall(blob)))[:50],
    }


def behaviour_hits(strings: list[str]) -> list[dict]:
    blob = "\n".join(strings)
    hits = []
    for rx, label, technique in _BEHAVIOUR:
        m = rx.search(blob)
        if m:
            hits.append({"indicator": label, "attack": technique, "evidence": m.group(0)[:160]})
    return hits


def defang(s: str) -> str:
    return s.replace("http", "hxxp").replace("://", "[://]").replace(".", "[.]")
