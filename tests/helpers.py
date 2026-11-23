"""Builders for small hand-made data sets, so each test shows exactly what it feeds the rule."""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from secops.data import Dataset, typed
from secops.util import fmt_ts

CITY = {
    "Regina": ("CA", 50.4452, -104.6189),
    "Saskatoon": ("CA", 52.1332, -106.6700),
    "Toronto": ("CA", 43.6532, -79.3832),
    "Singapore": ("SG", 1.3521, 103.8198),
}
DATA = Path(__file__).resolve().parent.parent / "data"
T0 = datetime(2026, 11, 10, 2, 0, 0)  # a Tuesday, 02:00


def user(name, *, emp="", status="Enabled", mfa="Y", kind="human", last="2026-11-15 09:00:00", dept="Sales"):
    return {"username": name, "display_name": name, "employee_id": emp, "department": dept, "account_type": kind,
            "account_status": status, "mfa_enrolled": mfa, "created_date": "2024-01-01", "last_logon": last}


def hr(emp, status="Active", left=""):
    return {"employee_id": emp, "full_name": emp, "department": "Sales", "status": status, "termination_date": left}


def auth(ts, name, result="SUCCESS", ip="10.20.10.5", city="Regina", app="SSO", mfa="Y"):
    country, lat, lon = CITY[city]
    return {"timestamp": fmt_ts(ts), "username": name, "src_ip": ip, "city": city, "country": country,
            "lat": str(lat), "lon": str(lon), "result": result, "app": app, "mfa": mfa}


def fw(ts, src, dst, port, action="DENY"):
    return {"timestamp": fmt_ts(ts), "src_ip": src, "src_port": "50000", "dst_ip": dst, "dst_port": str(port),
            "protocol": "TCP", "action": action, "rule_name": "TEST", "bytes": "0"}


def call(n, ts, ext, number, dur=300):
    return {"call_id": f"C{n:04d}", "start_time": fmt_ts(ts), "extension": ext, "dialled_number": number,
            "duration_sec": str(dur), "disposition": "ANSWERED", "trunk": "T1"}


def cust(n, ts, customer, event, channel="Online", agent="", verification="PASSWORD"):
    return {"event_id": f"EV{n:04d}", "timestamp": fmt_ts(ts), "customer_id": customer, "event_type": event,
            "channel": channel, "agent": agent, "verification": verification}


def update(inc, ts, status, note="test"):
    return {"incident_id": inc, "timestamp": fmt_ts(ts), "status": status, "actor": "Analyst", "note": note}


def ds(**parts) -> Dataset:
    d = Dataset(**{k: v for k, v in parts.items()})
    typed(d)
    return d


def minutes(n):
    return timedelta(minutes=n)
