"""Load results into an in-memory SQLite database and run the named queries in sql/metrics.sql."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .util import median

ROOT = Path(__file__).resolve().parent.parent


def load_queries(path: Path = ROOT / "sql" / "metrics.sql") -> dict:
    queries, name, buf = {}, None, []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("-- name:"):
            if name:
                queries[name] = "\n".join(buf).strip()
            name, buf = line.split(":", 1)[1].strip(), []
        elif name and not line.startswith("--"):
            buf.append(line)
    if name:
        queries[name] = "\n".join(buf).strip()
    return queries


def database(alerts, incidents, findings, compliance) -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript((ROOT / "sql" / "schema.sql").read_text(encoding="utf-8"))
    db.executemany("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)", [
        (a["alert_id"], a["incident_id"], a["rule_id"], a["rule_name"], a["severity"], a["technique"],
         a["entity_type"], a["entity"], a["first_seen"], a["detected_at"], a["event_count"]) for a in alerts])
    db.executemany("INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", [
        (i["incident_id"], i["title"], i["category"], i["severity"], i["status"], i["opened_at"], i["contain_due"],
         i["ack_met"], i["contain_met"], i["minutes_to_detect"], _int(i["minutes_to_ack"]),
         _int(i["minutes_to_contain"])) for i in incidents])
    db.executemany("INSERT INTO findings VALUES (?,?,?,?,?,?)", [
        (f["finding_id"], f["check"], f["requirement"], f["severity"], f["username"], f["department"])
        for f in findings])
    db.executemany("INSERT INTO compliance VALUES (?,?,?,?)", [
        (c["check_id"], c["csf"], c["control"], c["result"]) for c in compliance])
    return db


def run(db: sqlite3.Connection) -> dict:
    out = {name: [dict(r) for r in db.execute(sql)] for name, sql in load_queries().items()}
    times = out.pop("response_times")
    out["median_minutes"] = {
        "detect": median([t["minutes_to_detect"] for t in times]),
        "ack": median([t["minutes_to_ack"] for t in times]),
        "contain": median([t["minutes_to_contain"] for t in times]),
    }
    return out


def _int(v):
    return None if v in ("", None) else int(v)
