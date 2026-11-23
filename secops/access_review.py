"""User access review: compares the directory with HR and the entitlement list.

Each check maps to a requirement in docs/access-management-standard.md.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta

from . import config
from .data import Dataset
from .util import parse_ts

FIELDS = ["finding_id", "check", "requirement", "severity", "username", "department", "detail", "action"]


def _human_enabled(ds: Dataset) -> list:
    return [u for u in ds.users if u["account_type"] == "human" and u["account_status"] == "Enabled"]


def privileged_users(ds: Dataset) -> set:
    return {user for user, perms in ds.permissions().items() if perms & config.PRIVILEGED_PERMISSIONS}


def review(ds: Dataset, as_of: date) -> list[dict]:
    findings: list[dict] = []
    hr = {h["employee_id"]: h for h in ds.hr}
    perms = ds.permissions()
    privileged = privileged_users(ds)

    def add(check, req, sev, user, detail, action):
        findings.append({"check": check, "requirement": req, "severity": sev, "username": user["username"],
                         "department": user["department"], "detail": detail, "action": action})

    for u in _human_enabled(ds):
        rec = hr.get(u["employee_id"]) if u["employee_id"] else None
        # Leavers whose account is still on.
        if rec and rec["status"] == "Terminated" and rec["termination_date"]:
            left = date.fromisoformat(rec["termination_date"])
            days = (as_of - left).days
            if days > config.TERMINATION_GRACE_DAYS:
                add("Terminated employee, account enabled", "AM-02", "High", u,
                    f"Left on {left.isoformat()} ({days} days ago); account still enabled",
                    "Disable the account today and confirm with HR")
        # Accounts with no HR record behind them.
        if not rec:
            add("Orphaned account (no HR record)", "AM-01", "High" if u["username"] in privileged else "Medium", u,
                "Enabled human account with no matching employee record",
                "Find an owner and a contract end date, or disable it")
        # Not used for 90+ days.
        last = parse_ts(u["last_logon"]) if u["last_logon"] else None
        if last is None or (datetime.combine(as_of, datetime.min.time()) - last) > timedelta(days=config.DORMANT_DAYS):
            seen = last.date().isoformat() if last else "never"
            add("Dormant account", "AM-05", "Medium", u, f"Last sign-in {seen}",
                "Confirm with the manager; disable if not needed")
        # MFA.
        if u["mfa_enrolled"] != "Y":
            if u["username"] in privileged:
                held = ", ".join(sorted(perms.get(u["username"], set()) & config.PRIVILEGED_PERMISSIONS))
                add("Privileged account without MFA", "AM-04", "High", u, f"Holds {held}; MFA not enrolled",
                    "Enrol MFA before the next sign-in; block privileged access until then")
            else:
                add("Account without MFA", "AM-03", "Low", u, "MFA not enrolled", "Enrol MFA")
    # Separation of duties.
    enabled = {u["username"]: u for u in _human_enabled(ds)}
    for rule in ds.sod_rules:
        for user, held in sorted(perms.items()):
            if user in enabled and rule["permission_a"] in held and rule["permission_b"] in held:
                add(f"Separation of duties conflict ({rule['rule_id']})", "AM-06", "High", enabled[user],
                    f"Holds {rule['permission_a']} and {rule['permission_b']}: {rule['risk']}",
                    "Remove one permission or add a second approver")
    order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["check"], f["username"]))
    for i, f in enumerate(findings, 1):
        f["finding_id"] = f"AR-{i:03d}"
    return findings


def mfa_coverage(ds: Dataset) -> tuple[int, int]:
    """(enrolled, total) for enabled human accounts."""
    users = _human_enabled(ds)
    return sum(1 for u in users if u["mfa_enrolled"] == "Y"), len(users)
