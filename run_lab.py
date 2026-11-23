#!/usr/bin/env python3
"""Run the whole lab: check the data, review access, run detections, build the
incident register, check compliance and write the reports.

    python3 run_lab.py --as-of 2026-11-20          # the date the committed reports use
    python3 run_lab.py --strict                    # exit 1 if the data checks find problems
    python3 run_lab.py --out build/reports         # write somewhere else
"""
from __future__ import annotations

import argparse
import sys
from datetime import date, datetime
from pathlib import Path

from secops import access_review, checks, compliance, detections, incidents, metrics, reports
from secops.data import load
from secops.util import fmt_ts

ROOT = Path(__file__).resolve().parent


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Telecom security operations lab")
    parser.add_argument("--data", default=str(ROOT / "data"), help="Folder with the input CSV files")
    parser.add_argument("--out", default=str(ROOT / "reports"), help="Folder for the reports")
    parser.add_argument("--as-of", default=None, help="Report date YYYY-MM-DD (default: today)")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if any data check fails")
    args = parser.parse_args(argv)

    as_of_date = date.fromisoformat(args.as_of) if args.as_of else date.today()
    as_of = datetime.combine(as_of_date, datetime.min.time())
    ds = load(Path(args.data))

    problems = checks.check_inputs(ds)
    if problems and any("missing" in p for p in problems):
        print("\n".join(problems), file=sys.stderr)
        return 1

    alerts = detections.run_all(ds)
    incs = incidents.build(alerts)
    problems += checks.check_updates(ds.updates, incs, as_of)
    incidents.apply_updates(incs, ds.updates, as_of)
    findings = access_review.review(ds, as_of_date)
    results = compliance.run(ds, findings, alerts, incs, as_of_date)
    m = metrics.run(metrics.database(alerts, incs, findings, results))

    times = sorted(e["_ts"] for e in ds.auth + ds.firewall if e["_ts"])
    period = (fmt_ts(times[0])[:10], fmt_ts(times[-1])[:10]) if times else ("", "")
    written = reports.write_all(Path(args.out), as_of, alerts, incs, findings, results, m, period)

    h = reports.headline(alerts, incs, findings, results, m)
    print(f"Data checks: {'OK' if not problems else f'{len(problems)} problem(s)'}")
    for p in problems[:20]:
        print(f"  - {p}")
    print(f"Alerts: {h['alerts']}  Incidents: {h['incidents']} ({h['critical']} Critical, {h['overdue']} overdue)")
    print(f"Access review findings: {h['findings']} ({h['high_findings']} High)")
    print(f"Compliance checks passed: {h['passed']} of {h['checks']}")
    print(f"Wrote {len(written)} files to {args.out}/")
    return 1 if (problems and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())
