"""Incident register: groups alerts into incidents and tracks response against SLAs.

Alerts about the same entity (user, IP, extension or customer) within 24 hours of
an incident opening are merged into that incident. Analyst actions come from
data/incident_updates.csv, the lab's stand-in for a ticketing system.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from . import config
from .util import fmt_ts, max_severity

FIELDS = ["incident_id", "title", "category", "severity", "entity_type", "entity", "opened_at", "alert_ids",
          "rules", "status", "acknowledged_at", "contained_at", "closed_at", "ack_target_h", "contain_sla_h",
          "contain_due", "ack_met", "contain_met", "minutes_to_detect", "minutes_to_ack", "minutes_to_contain",
          "last_note"]


def build(alerts: list[dict]) -> list[dict]:
    incidents: list[dict] = []
    merge = timedelta(hours=config.INCIDENT_MERGE_HOURS)
    for a in sorted(alerts, key=lambda x: (x["_detected"], x["alert_id"])):
        key = (a["entity_type"], a["entity"])
        match = next((i for i in incidents if i["_key"] == key and a["_detected"] - i["_opened"] <= merge), None)
        if match:
            match["_alerts"].append(a)
            match["severity"] = max_severity(match["severity"], a["severity"])
            continue
        incidents.append({"_key": key, "_opened": a["_detected"], "_alerts": [a], "severity": a["severity"],
                          "entity_type": a["entity_type"], "entity": a["entity"],
                          "category": config.RULES[a["rule_id"]]["category"]})
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-{n:04d}"
        inc["opened_at"] = fmt_ts(inc["_opened"])
        inc["alert_ids"] = " ".join(a["alert_id"] for a in inc["_alerts"])
        inc["rules"] = " ".join(sorted({a["rule_id"] for a in inc["_alerts"]}))
        inc["title"] = f"{inc['category']}: {inc['entity']}"
        first = min(a["_first"] for a in inc["_alerts"])
        inc["minutes_to_detect"] = round((inc["_opened"] - first).total_seconds() / 60)
        for a in inc["_alerts"]:
            a["incident_id"] = inc["incident_id"]
            if a.get("_agent"):
                inc["_agent"] = a["_agent"]
    return incidents


def apply_updates(incidents: list[dict], updates: list[dict], as_of: datetime) -> None:
    """Fill in status, response times and SLA results from the analyst updates."""
    by_id = {}
    for u in sorted(updates, key=lambda x: (x["_ts"] is None, x["_ts"])):
        if u["_ts"] and u["_ts"] <= as_of:
            by_id.setdefault(u["incident_id"], []).append(u)
    for inc in incidents:
        ups = by_id.get(inc["incident_id"], [])
        sev = inc["severity"]
        ack_h, sla_h = config.ACK_TARGET_HOURS[sev], config.CONTAIN_SLA_HOURS[sev]
        opened = inc["_opened"]
        ack = next((u["_ts"] for u in ups if u["status"] in ("Acknowledged", "Contained", "Closed")), None)
        contained = next((u["_ts"] for u in ups if u["status"] in ("Contained", "Closed")), None)
        closed = next((u["_ts"] for u in ups if u["status"] == "Closed"), None)
        inc.update({
            "status": ups[-1]["status"] if ups else "Open",
            "_ack": ack, "_contained": contained, "_closed": closed,
            "acknowledged_at": fmt_ts(ack), "contained_at": fmt_ts(contained), "closed_at": fmt_ts(closed),
            "ack_target_h": ack_h, "contain_sla_h": sla_h,
            "contain_due": fmt_ts(opened + timedelta(hours=sla_h)),
            "ack_met": _met(opened, ack, ack_h, as_of),
            "contain_met": _met(opened, contained, sla_h, as_of),
            "minutes_to_ack": _minutes(opened, ack),
            "minutes_to_contain": _minutes(opened, contained),
            "last_note": ups[-1]["note"] if ups else "",
        })


def _met(opened, done, hours, as_of) -> str:
    due = opened + timedelta(hours=hours)
    if done:
        return "Yes" if done <= due else "No"
    return "Overdue" if as_of > due else "Pending"


def _minutes(start, end):
    return round((end - start).total_seconds() / 60) if end else ""
