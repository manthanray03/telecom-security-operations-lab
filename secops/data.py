"""Load the CSV files into plain Python structures."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .util import parse_ts, read_csv

FILES = {
    "users": "users.csv",
    "hr": "hr_roster.csv",
    "entitlements": "entitlements.csv",
    "sod_rules": "sod_rules.csv",
    "auth": "auth_log.csv",
    "firewall": "firewall_log.csv",
    "extensions": "extensions.csv",
    "cdr": "voip_cdr.csv",
    "customer": "customer_events.csv",
    "updates": "incident_updates.csv",
}

REQUIRED = {
    "users": ["username", "display_name", "employee_id", "department", "account_type", "account_status",
              "mfa_enrolled", "created_date", "last_logon"],
    "hr": ["employee_id", "full_name", "department", "status", "termination_date"],
    "entitlements": ["username", "system", "permission"],
    "sod_rules": ["rule_id", "permission_a", "permission_b", "risk"],
    "auth": ["timestamp", "username", "src_ip", "city", "country", "lat", "lon", "result", "app", "mfa"],
    "firewall": ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "action", "rule_name",
                 "bytes"],
    "extensions": ["extension", "label", "department"],
    "cdr": ["call_id", "start_time", "extension", "dialled_number", "duration_sec", "disposition", "trunk"],
    "customer": ["event_id", "timestamp", "customer_id", "event_type", "channel", "agent", "verification"],
    "updates": ["incident_id", "timestamp", "status", "actor", "note"],
}


@dataclass
class Dataset:
    users: list = field(default_factory=list)
    hr: list = field(default_factory=list)
    entitlements: list = field(default_factory=list)
    sod_rules: list = field(default_factory=list)
    auth: list = field(default_factory=list)
    firewall: list = field(default_factory=list)
    extensions: list = field(default_factory=list)
    cdr: list = field(default_factory=list)
    customer: list = field(default_factory=list)
    updates: list = field(default_factory=list)
    missing_columns: dict = field(default_factory=dict)

    def permissions(self) -> dict:
        """username -> set of permission names."""
        out: dict = {}
        for row in self.entitlements:
            out.setdefault(row["username"], set()).add(row["permission"])
        return out


def load(folder: Path) -> Dataset:
    folder = Path(folder)
    ds = Dataset()
    for key, name in FILES.items():
        path = folder / name
        rows = read_csv(path) if path.exists() else []
        if rows:
            missing = [c for c in REQUIRED[key] if c not in rows[0]]
            if missing:
                ds.missing_columns[name] = missing
        setattr(ds, key, rows)
    typed(ds)
    return ds


def typed(ds: Dataset) -> None:
    """Add parsed copies of the fields the rules use. Bad values are left for checks.py."""
    for e in ds.auth:
        e["_ts"] = _try(parse_ts, e.get("timestamp"))
        e["_lat"] = _try(float, e.get("lat"))
        e["_lon"] = _try(float, e.get("lon"))
    for e in ds.firewall:
        e["_ts"] = _try(parse_ts, e.get("timestamp"))
        e["_port"] = _try(int, e.get("dst_port"))
    for c in ds.cdr:
        c["_ts"] = _try(parse_ts, c.get("start_time"))
        c["_dur"] = _try(int, c.get("duration_sec"))
    for e in ds.customer:
        e["_ts"] = _try(parse_ts, e.get("timestamp"))
    for u in ds.updates:
        u["_ts"] = _try(parse_ts, u.get("timestamp"))


def _try(fn, value):
    try:
        return fn(value)
    except (TypeError, ValueError):
        return None
