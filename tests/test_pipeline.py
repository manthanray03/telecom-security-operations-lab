"""End-to-end: the committed data produces the numbers quoted in the README."""
from datetime import date, datetime

from secops import access_review, compliance, detections, incidents, metrics
from secops.data import load
from tests.helpers import DATA

AS_OF = datetime(2026, 11, 20)


def build():
    d = load(DATA)
    alerts = detections.run_all(d)
    incs = incidents.build(alerts)
    incidents.apply_updates(incs, d.updates, AS_OF)
    findings = access_review.review(d, AS_OF.date())
    results = compliance.run(d, findings, alerts, incs, AS_OF.date())
    return d, alerts, incs, findings, results


def test_readme_numbers():
    d, alerts, incs, findings, results = build()
    assert len(alerts) == 11 and len(incs) == 10
    assert sum(i["severity"] == "Critical" for i in incs) == 3
    assert len(findings) == 20
    assert sum(r["result"] == "Pass" for r in results) == 4 and len(results) == 12
    m = metrics.run(metrics.database(alerts, incs, findings, results))
    assert m["median_minutes"] == {"detect": 9, "ack": 27, "contain": 171}


def test_log_gap_is_found():
    _, _, _, _, results = build()
    gap = next(r for r in results if r["check_id"] == "CC-08")
    assert gap["result"] == "Fail" and "2026-11-13 02:00" in gap["evidence"]


def test_run_lab_writes_reports(tmp_path):
    import run_lab
    assert run_lab.main(["--as-of", "2026-11-20", "--strict", "--out", str(tmp_path)]) == 0
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["access_review.csv", "alerts.csv", "compliance_results.csv", "dashboard.html", "incidents.csv",
                     "security_summary.md"]
