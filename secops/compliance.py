"""Compliance checks against the access management standard, mapped to NIST CSF 2.0.

Each check returns a measured value, the target, Pass/Fail and the evidence, so a
reviewer can see why it failed without re-running anything.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, timedelta

from . import config
from .access_review import mfa_coverage, privileged_users
from .data import Dataset

FIELDS = ["check_id", "csf", "requirement", "control", "measured", "target", "result", "evidence"]


def run(ds: Dataset, findings: list[dict], alerts: list[dict], incidents: list[dict], as_of: date) -> list[dict]:
    by_check = defaultdict(list)
    for f in findings:
        by_check[f["requirement"]].append(f["username"])
    results = []

    def add(check_id, csf, req, control, measured, target, ok, evidence):
        results.append({"check_id": check_id, "csf": csf, "requirement": req, "control": control,
                        "measured": measured, "target": target, "result": "Pass" if ok else "Fail",
                        "evidence": evidence})

    def names(req):
        return ", ".join(sorted(set(by_check[req]))) or "none"

    leavers = by_check["AM-02"]
    add("CC-01", "PR.AA-01", "AM-02", "Leavers' accounts disabled within 1 business day",
        f"{len(leavers)} enabled", "0", not leavers, f"Still enabled: {names('AM-02')}")
    orphans = by_check["AM-01"]
    add("CC-02", "PR.AA-01", "AM-01", "Every enabled human account has an HR record",
        f"{len(orphans)} orphaned", "0", not orphans, f"No HR record: {names('AM-01')}")
    service_logins = sorted({e["username"] for e in ds.auth if e["result"] == "SUCCESS"
                             and e["username"] in {u["username"] for u in ds.users if u["account_type"] == "service"}})
    add("CC-03", "PR.AA-01", "AM-07", "Service accounts are not used for interactive sign-in",
        f"{len(service_logins)} accounts", "0", not service_logins,
        f"Interactive sign-ins by: {', '.join(service_logins) or 'none'}")
    priv = privileged_users(ds)
    enabled = {u["username"]: u for u in ds.users if u["account_status"] == "Enabled" and u["account_type"] == "human"}
    priv_enabled = [p for p in priv if p in enabled]
    priv_mfa = [p for p in priv_enabled if enabled[p]["mfa_enrolled"] == "Y"]
    pct = 100 * len(priv_mfa) / len(priv_enabled) if priv_enabled else 100
    add("CC-04", "PR.AA-03", "AM-04", "MFA on every privileged account",
        f"{pct:.0f}% ({len(priv_mfa)} of {len(priv_enabled)})", "100%", pct == 100, f"No MFA: {names('AM-04')}")
    enrolled, total = mfa_coverage(ds)
    pct_all = 100 * enrolled / total if total else 100
    add("CC-05", "PR.AA-03", "AM-03", "MFA coverage, all enabled human accounts",
        f"{pct_all:.1f}% ({enrolled} of {total})", f">= {config.MFA_COVERAGE_TARGET:.0f}%",
        pct_all >= config.MFA_COVERAGE_TARGET, f"Not enrolled: {total - enrolled}")
    dormant = by_check["AM-05"]
    add("CC-06", "PR.AA-05", "AM-05", f"No enabled account unused for {config.DORMANT_DAYS}+ days",
        f"{len(dormant)} dormant", "0", not dormant, f"Dormant: {names('AM-05')}")
    sod = by_check["AM-06"]
    add("CC-07", "PR.AA-05", "AM-06", "No separation-of-duties conflicts",
        f"{len(sod)} conflicts", "0", not sod, f"Conflicts: {names('AM-06')}")
    gaps = log_gaps(ds)
    add("CC-08", "DE.CM-01", "AM-08", "Firewall logs reach the SIEM every hour",
        f"{sum(len(v) for v in gaps.values())} missing hours", "0", not any(gaps.values()),
        "; ".join(f"{src}: {_ranges(hours)}" for src, hours in gaps.items() if hours) or "no gaps")
    linked = [a for a in alerts if a.get("incident_id")]
    add("CC-09", "DE.AE-02", "IR-01", "Every alert is reviewed as part of an incident",
        f"{len(linked)} of {len(alerts)}", "100%", len(linked) == len(alerts), "Alerts are grouped by entity")
    categorized = [i for i in incidents if i.get("category") and i.get("severity")]
    add("CC-10", "RS.MA-03", "IR-02", "Every incident is categorized and prioritized",
        f"{len(categorized)} of {len(incidents)}", "100%", len(categorized) == len(incidents),
        "Severity from the rule, raised for privileged accounts and confirmed fraud")
    acked = [i for i in incidents if i["ack_met"] == "Yes"]
    missed = [i["incident_id"] for i in incidents if i["ack_met"] != "Yes"]
    pct_ack = 100 * len(acked) / len(incidents) if incidents else 100
    add("CC-11", "RS.MA-02", "IR-03", "Incidents acknowledged within target",
        f"{pct_ack:.0f}% ({len(acked)} of {len(incidents)})", "100%", pct_ack == 100,
        f"Missed: {', '.join(missed) or 'none'}")
    cont = [i for i in incidents if i["contain_met"] == "Yes"]
    missed = [i["incident_id"] for i in incidents if i["contain_met"] not in ("Yes", "Pending")]
    pct_c = 100 * len(cont) / len(incidents) if incidents else 100
    add("CC-12", "RS.MI-01", "IR-04", "Incidents contained within SLA",
        f"{pct_c:.0f}% ({len(cont)} of {len(incidents)})", ">= 90%", pct_c >= 90,
        f"Missed or overdue: {', '.join(missed) or 'none'}")
    return results


def log_gaps(ds: Dataset) -> dict:
    """Hours with no events for sources that log around the clock (the firewall).

    Sign-ins and calls are quiet overnight by nature, so an empty hour there is normal.
    """
    hours = sorted({e["_ts"].replace(minute=0, second=0) for e in ds.firewall if e["_ts"]})
    missing = []
    if hours:
        h = hours[0]
        present = set(hours)
        while h <= hours[-1]:
            if h not in present:
                missing.append(h)
            h += timedelta(hours=1)
    return {"firewall_log": missing}


def _ranges(hours) -> str:
    if not hours:
        return "none"
    spans, start, prev = [], hours[0], hours[0]
    for h in hours[1:] + [None]:
        if h is None or h - prev > timedelta(hours=1):
            spans.append(f"{start:%Y-%m-%d %H:00} to {prev + timedelta(hours=1):%H:00}")
            start = h
        prev = h if h else prev
    return ", ".join(spans)
