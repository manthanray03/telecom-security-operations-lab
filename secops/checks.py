"""Data quality checks. Run before anything else so a bad export can't produce a wrong report."""
from __future__ import annotations

import ipaddress
from datetime import date, datetime

from . import config
from .data import Dataset
from .util import parse_ts

EVENT_TYPES = {"LOGIN", "PLAN_CHANGE", "BILL_PAYMENT", "PASSWORD_RESET", "DEVICE_ORDER", "ADDRESS_CHANGE",
               "EMAIL_CHANGE", "PORT_OUT_REQUEST", "SIM_SWAP"}


def check_inputs(ds: Dataset) -> list[str]:
    errors = [f"{name}: missing columns {', '.join(cols)}" for name, cols in ds.missing_columns.items()]
    for key in ("users", "hr", "entitlements", "auth", "firewall", "cdr", "customer"):
        if not getattr(ds, key):
            errors.append(f"{key}: file missing or empty")
    if errors:
        return errors

    names = [u["username"] for u in ds.users]
    errors += [f"users.csv: duplicate username {n}" for n in sorted({n for n in names if names.count(n) > 1})]
    for u in ds.users:
        where = f"users.csv {u['username']}"
        if u["account_type"] not in ("human", "service"):
            errors.append(f"{where}: account_type must be human or service")
        if u["account_status"] not in ("Enabled", "Disabled"):
            errors.append(f"{where}: account_status must be Enabled or Disabled")
        if u["account_type"] == "human" and u["mfa_enrolled"] not in ("Y", "N"):
            errors.append(f"{where}: mfa_enrolled must be Y or N for a person")
        errors += _date(where, "created_date", u["created_date"])
        if u["last_logon"]:
            errors += _ts(where, "last_logon", u["last_logon"])
    ids = [h["employee_id"] for h in ds.hr]
    errors += [f"hr_roster.csv: duplicate employee_id {i}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    for h in ds.hr:
        where = f"hr_roster.csv {h['employee_id']}"
        if h["status"] not in ("Active", "Terminated"):
            errors.append(f"{where}: status must be Active or Terminated")
        if h["status"] == "Terminated":
            if not h["termination_date"]:
                errors.append(f"{where}: terminated with no termination_date")
            else:
                errors += _date(where, "termination_date", h["termination_date"])
    known = set(names)
    for e in ds.entitlements:
        if e["username"] not in known:
            errors.append(f"entitlements.csv: {e['username']} is not in users.csv")
    perms = {e["permission"] for e in ds.entitlements}
    for r in ds.sod_rules:
        for p in (r["permission_a"], r["permission_b"]):
            if p not in perms:
                errors.append(f"sod_rules.csv {r['rule_id']}: permission {p} is never granted (typo?)")

    last_success = {}
    for i, e in enumerate(ds.auth, 2):
        where = f"auth_log.csv line {i}"
        if e["_ts"] is None:
            errors.append(f"{where}: bad timestamp {e['timestamp']!r}")
        errors += _ip(where, e["src_ip"])
        if e["result"] not in ("SUCCESS", "FAILURE"):
            errors.append(f"{where}: result must be SUCCESS or FAILURE")
        if e["_lat"] is None or e["_lon"] is None or not (-90 <= e["_lat"] <= 90 and -180 <= e["_lon"] <= 180):
            errors.append(f"{where}: bad lat/lon")
        if e["result"] == "SUCCESS" and e["_ts"]:
            last_success[e["username"]] = max(last_success.get(e["username"], e["_ts"]), e["_ts"])
    for u in ds.users:
        seen = last_success.get(u["username"])
        if seen and u["last_logon"] and parse_ts(u["last_logon"]) < seen:
            errors.append(f"users.csv {u['username']}: last_logon is older than a sign-in in auth_log.csv "
                          "(directory export out of date?)")
    for i, e in enumerate(ds.firewall, 2):
        where = f"firewall_log.csv line {i}"
        if e["_ts"] is None:
            errors.append(f"{where}: bad timestamp")
        errors += _ip(where, e["src_ip"]) + _ip(where, e["dst_ip"])
        if e["_port"] is None or not 0 <= e["_port"] <= 65535:
            errors.append(f"{where}: bad dst_port")
        if e["action"] not in ("ALLOW", "DENY"):
            errors.append(f"{where}: action must be ALLOW or DENY")
    exts = {x["extension"] for x in ds.extensions}
    for c in ds.cdr:
        where = f"voip_cdr.csv {c['call_id']}"
        if c["_ts"] is None:
            errors.append(f"{where}: bad start_time")
        if c["_dur"] is None or c["_dur"] < 0:
            errors.append(f"{where}: bad duration_sec")
        if exts and c["extension"] not in exts:
            errors.append(f"{where}: extension {c['extension']} is not in extensions.csv")
        if not c["dialled_number"].startswith("+"):
            errors.append(f"{where}: dialled_number must be E.164 (+country code)")
    for e in ds.customer:
        where = f"customer_events.csv {e['event_id']}"
        if e["_ts"] is None:
            errors.append(f"{where}: bad timestamp")
        if e["event_type"] not in EVENT_TYPES:
            errors.append(f"{where}: unknown event_type {e['event_type']}")
    return errors


def check_updates(updates: list[dict], incidents: list[dict], as_of: datetime) -> list[str]:
    """Analyst updates must point at a real incident and move forward in time and status."""
    errors = []
    opened = {i["incident_id"]: i["_opened"] for i in incidents}
    order = {s: n for n, s in enumerate(config.INCIDENT_STATUSES)}
    last = {}
    for u in sorted(updates, key=lambda x: (x["incident_id"], x["_ts"] or datetime.min)):
        where = f"incident_updates.csv {u['incident_id']} {u['timestamp']}"
        if u["incident_id"] not in opened:
            errors.append(f"{where}: no such incident (data regenerated? update the file)")
            continue
        if u["status"] not in order:
            errors.append(f"{where}: status must be one of {', '.join(config.INCIDENT_STATUSES)}")
            continue
        if u["_ts"] is None:
            errors.append(f"{where}: bad timestamp")
            continue
        if u["_ts"] < opened[u["incident_id"]]:
            errors.append(f"{where}: update is earlier than the incident opened")
        if u["_ts"] > as_of:
            errors.append(f"{where}: update is after the report date")
        prev = last.get(u["incident_id"])
        if prev is not None and order[u["status"]] < prev:
            errors.append(f"{where}: status goes backwards")
        last[u["incident_id"]] = order[u["status"]]
    return errors


def _ip(where, value):
    try:
        ipaddress.ip_address(value)
        return []
    except ValueError:
        return [f"{where}: bad IP address {value!r}"]


def _date(where, field, value):
    try:
        date.fromisoformat(value)
        return []
    except ValueError:
        return [f"{where}: bad {field} {value!r}"]


def _ts(where, field, value):
    try:
        parse_ts(value)
        return []
    except ValueError:
        return [f"{where}: bad {field} {value!r}"]
