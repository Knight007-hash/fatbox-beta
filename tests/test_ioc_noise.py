"""0.17.2: network IOCs that every normal program carries give no score (found in a review of real reports)."""
from fatbox.static.strings_iocs import extract_iocs, ip_noise, network_iocs, url_noise
from fatbox.static.triage import score


def _report(urls=(), ips=()):
    return {"pe": None, "entropy": 5.0, "behaviour": [], "yara": [], "file_analysis": None,
            "iocs": {"urls": list(urls), "ipv4": list(ips)}}


def test_benign_urls_are_noise():
    for u in ("http://www.w3.org/2001/XMLSchema", "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
              "http://crl.globalsign.net/Root.crl0", "http://ocsp.verisign.com0",
              "http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt0", "http://sf.symcd.com0&",
              "http://%s/cgi-bin/p.cgi", "http://%s%s", "https://aka.ms/dotnet-warnings/"):
        assert url_noise(u), u


def test_real_urls_count():
    for u in ("https://discord.com/api/webhooks/1/abc", "http://backdoor.evil-c2.ru", "https://api.ipify.org/",
              "http://203.0.113.50/cgi-bin/p.cgi", "http://user@evil.top:8080/x", "http://microsoft.com.evil.ru/"):
        assert url_noise(u) is None, u


def test_lookalike_host_is_not_noise():
    assert url_noise("http://evilw3.org/x") is None  # only w3.org itself or its subdomains
    assert url_noise("http://notmicrosoft.com/x") is None


def test_version_oid_dns_ips_are_noise():
    for ip in ("1.0.0.0", "6.0.0.0", "3.0.0.4", "5.3.1.9", "23.32.0.0", "1.3.101.110", "8.8.8.8", "114.114.114.114"):
        assert ip_noise(ip), ip
    for ip in ("203.0.113.50", "177.221.180.26", "45.67.89.123"):
        assert ip_noise(ip) is None, ip


def test_ip_not_cut_out_of_longer_dotted_number():
    iocs = extract_iocs(["1.3.6.1.4.1.311.61.1.1", "2.16.840.1.101.3.4.1", "v 45.67.89.123.", "45.67.89.124"])
    assert iocs["ipv4"] == ["45.67.89.123", "45.67.89.124"]


def test_score_ignores_noise_only():
    pts, why = score(_report(["http://www.w3.org/2001/XMLSchema"], ["1.0.0.0", "6.0.0.0"]))
    assert pts == 0
    assert any(w.startswith("+0 network IOCs: 3 found, all noise") for w in why)


def test_score_counts_real_and_says_what_was_ignored():
    pts, why = score(_report(["http://www.w3.org/2001/XMLSchema", "http://c2.evil.top/gate"], ["1.0.0.0"]))
    assert pts == 5
    assert "+5 embedded network IOCs (1 counted, 2 ignored as noise)" in why


def test_score_without_iocs_says_nothing():
    pts, why = score(_report())
    assert pts == 0 and not any("network" in w for w in why)


def test_network_iocs_handles_missing_lists():
    assert network_iocs({}) == ([], 0)
