"""0.30.0: the report opens with a verdict, findings and a score bar; details are folded. Host side only."""
from pathlib import Path

from fatbox.host.server import report_view

PAGE = (Path(__file__).resolve().parents[1] / "fatbox" / "host" / "page.html").read_text(encoding="utf-8")


def test_report_view_adds_host_categories_only():
    rep = {"source_meta": {"signature": "AgentTesla", "tags": ["exe"]}, "score": 80}
    out = report_view(rep)
    assert out["host_view"] == {"categories": ["stealer"]} and out["score"] == 80 and "host_view" not in rep
    # a hacked VM sending odd types never breaks the view
    for meta in ({"signature": 7, "tags": ["CobaltStrike", 3]}, None, "x", {"tags": None}):
        v = report_view({"source_meta": meta})["host_view"]["categories"]
        assert isinstance(v, list)
    assert report_view({"source_meta": {"signature": 7, "tags": ["CobaltStrike", 3]}})["host_view"]["categories"] == ["backdoor"]


def test_page_report_is_text_only_and_defanged():
    script = PAGE.split("<script>")[1]
    assert "innerHTML" not in script.replace("Never innerHTML", "")
    assert "const defang" in script and 'el("details")' in script and "navigator.clipboard.writeText" in script
    assert "static analysis only, the sample was never run" in script
    assert "delete r.host_view" in script   # the host's words never show up as part of the report's raw JSON
    for title in ("Key findings", "Network indicators", "Hashes and PE details", "Every score line", "Raw JSON"):
        assert title in script
