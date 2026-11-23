"""Detection rules. Each rule reads the logs and returns alerts.

An alert is raised at the first scheduled run after the event that crossed the
threshold (see util.next_run). The rule list, thresholds and ATT&CK mappings are
documented in docs/detection-catalogue.md.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, timedelta

from . import config
from .access_review import privileged_users
from .data import Dataset
from .util import bump, country_for, fmt_ts, haversine_km, is_business_hours, next_run

FIELDS = ["alert_id", "rule_id", "rule_name", "severity", "technique", "entity_type", "entity",
          "first_seen", "trigger_time", "detected_at", "last_seen", "event_count", "evidence", "playbook"]


def _alert(rule_id, severity, entity, first, trigger, last, count, evidence):
    meta = config.RULES[rule_id]
    return {"rule_id": rule_id, "rule_name": meta["name"], "severity": severity, "technique": meta["technique"],
            "entity_type": meta["entity_type"], "entity": entity, "_first": first, "_trigger": trigger,
            "_detected": next_run(trigger), "_last": last, "event_count": count, "evidence": evidence,
            "playbook": meta["playbook"]}


def password_spraying(ds: Dataset) -> list[dict]:
    """DET-01: one source IP fails against many different accounts in a short window."""
    alerts = []
    by_ip = defaultdict(list)
    for e in ds.auth:
        if e["_ts"]:
            by_ip[e["src_ip"]].append(e)
    window = timedelta(minutes=config.SPRAY_WINDOW_MIN)
    for ip, events in sorted(by_ip.items()):
        events.sort(key=lambda e: e["_ts"])
        fails = [e for e in events if e["result"] == "FAILURE"]
        start = 0
        for i, e in enumerate(fails):
            while e["_ts"] - fails[start]["_ts"] > window:
                start += 1
            accounts = {f["username"] for f in fails[start:i + 1]}
            if len(accounts) >= config.SPRAY_MIN_ACCOUNTS:
                burst = [f for f in fails if fails[start]["_ts"] <= f["_ts"] <= fails[start]["_ts"] + window * 2]
                all_accounts = {f["username"] for f in burst}
                successes = [s for s in events if s["result"] == "SUCCESS"
                             and burst[0]["_ts"] <= s["_ts"] <= burst[-1]["_ts"] + timedelta(hours=24)]
                known = {u["username"] for u in ds.users}
                invalid = sorted(a for a in all_accounts if a not in known)
                sev = "High" if successes else "Medium"
                evidence = (f"{len(burst)} failed sign-ins against {len(all_accounts)} accounts from {ip} "
                            f"({e['city']}, {e['country']}) to {e['app']}; {len(invalid)} usernames don't exist "
                            f"({', '.join(invalid)}); {len(successes)} successful sign-ins from this IP")
                alerts.append(_alert("DET-01", sev, ip, burst[0]["_ts"], e["_ts"], burst[-1]["_ts"],
                                     len(burst), evidence))
                break
    return alerts


def brute_force_success(ds: Dataset) -> list[dict]:
    """DET-02: many failures on one account, then a success soon after."""
    alerts = []
    privileged = privileged_users(ds)
    mfa = {u["username"]: u["mfa_enrolled"] for u in ds.users}
    by_user = defaultdict(list)
    for e in ds.auth:
        if e["_ts"]:
            by_user[e["username"]].append(e)
    window = timedelta(minutes=config.BRUTE_WINDOW_MIN)
    after = timedelta(minutes=config.BRUTE_SUCCESS_WITHIN_MIN)
    for user, events in sorted(by_user.items()):
        events.sort(key=lambda e: e["_ts"])
        fails = [e for e in events if e["result"] == "FAILURE"]
        start, fired = 0, None
        for i, f in enumerate(fails):
            while f["_ts"] - fails[start]["_ts"] > window:
                start += 1
            if i - start + 1 >= config.BRUTE_MIN_FAILURES:
                fired = (fails[start], f)
                break
        if not fired:
            continue
        first, threshold = fired
        burst = [f for f in fails if first["_ts"] <= f["_ts"] <= threshold["_ts"] + after]
        success = next((s for s in events if s["result"] == "SUCCESS"
                        and threshold["_ts"] <= s["_ts"] <= burst[-1]["_ts"] + after), None)
        if not success:
            continue
        sev = "High"
        notes = []
        if user in privileged:
            sev = bump(sev)
            notes.append("privileged account")
        if mfa.get(user) != "Y":
            notes.append("no MFA enrolled")
        evidence = (f"{len(burst)} failed sign-ins in {int((burst[-1]['_ts'] - burst[0]['_ts']).total_seconds() // 60)} "
                    f"minutes from {success['src_ip']} ({success['city']}, {success['country']}), then a successful "
                    f"{success['app']} sign-in at {fmt_ts(success['_ts'])}" + (f"; {', '.join(notes)}" if notes else ""))
        alerts.append(_alert("DET-02", sev, user, first["_ts"], success["_ts"], success["_ts"], len(burst) + 1, evidence))
    return alerts


def impossible_travel(ds: Dataset) -> list[dict]:
    """DET-03: two successful sign-ins too far apart to travel between, the second from a new place."""
    alerts = []
    privileged = privileged_users(ds)
    by_user = defaultdict(list)
    for e in ds.auth:
        if e["_ts"] and e["result"] == "SUCCESS" and e["_lat"] is not None:
            by_user[e["username"]].append(e)
    for user, events in sorted(by_user.items()):
        events.sort(key=lambda e: e["_ts"])
        seen = set()
        for prev, cur in zip(events, events[1:]):
            seen.add(prev["city"])
            km = haversine_km(prev["_lat"], prev["_lon"], cur["_lat"], cur["_lon"])
            hours = max((cur["_ts"] - prev["_ts"]).total_seconds() / 3600, 1 / 60)
            speed = km / hours
            if km >= config.TRAVEL_MIN_KM and speed > config.TRAVEL_MAX_KMH and cur["city"] not in seen:
                sev = "Critical" if user in privileged else "High"
                evidence = (f"{prev['city']} ({prev['src_ip']}) at {fmt_ts(prev['_ts'])}, then {cur['city']}, "
                            f"{cur['country']} ({cur['src_ip']}) at {fmt_ts(cur['_ts'])}: {km:,.0f} km in "
                            f"{hours * 60:,.0f} minutes ({speed:,.0f} km/h); MFA on second sign-in: {cur['mfa']}")
                # The suspicious event is the second sign-in, so the activity starts there.
                alerts.append(_alert("DET-03", sev, user, cur["_ts"], cur["_ts"], cur["_ts"], 2, evidence))
    return alerts


def terminated_account_signin(ds: Dataset) -> list[dict]:
    """DET-04: a successful sign-in by an account whose owner has left."""
    alerts = []
    hr = {h["employee_id"]: h for h in ds.hr}
    owner = {u["username"]: hr.get(u["employee_id"]) for u in ds.users if u["employee_id"]}
    for e in sorted(ds.auth, key=lambda x: (x["_ts"] is None, x["_ts"])):
        rec = owner.get(e["username"])
        if not (e["_ts"] and e["result"] == "SUCCESS" and rec and rec["status"] == "Terminated"
                and rec["termination_date"]):
            continue
        left = date.fromisoformat(rec["termination_date"])
        if e["_ts"].date() > left:
            evidence = (f"{rec['full_name']} left on {left.isoformat()}; account signed in to {e['app']} from "
                        f"{e['src_ip']} ({e['city']}) at {fmt_ts(e['_ts'])}, {(e['_ts'].date() - left).days} days later")
            alerts.append(_alert("DET-04", "High", e["username"], e["_ts"], e["_ts"], e["_ts"], 1, evidence))
    return alerts


def port_scan(ds: Dataset) -> list[dict]:
    """DET-05: one source touches many ports on one host within minutes."""
    alerts = []
    pairs = defaultdict(list)
    for e in ds.firewall:
        if e["_ts"] and e["_port"] is not None:
            pairs[(e["src_ip"], e["dst_ip"])].append(e)
    window = timedelta(minutes=config.SCAN_WINDOW_MIN)
    for (src, dst), events in sorted(pairs.items()):
        events.sort(key=lambda e: e["_ts"])
        start = 0
        for i, e in enumerate(events):
            while e["_ts"] - events[start]["_ts"] > window:
                start += 1
            ports = {x["_port"] for x in events[start:i + 1]}
            if len(ports) >= config.SCAN_MIN_PORTS:
                scan = [x for x in events if events[start]["_ts"] <= x["_ts"] <= events[start]["_ts"] + window]
                allowed = sorted({x["_port"] for x in scan if x["action"] == "ALLOW"})
                internal = src.startswith("10.")
                sev = "High" if internal else "Medium"
                evidence = (f"{'Internal' if internal else 'External'} host {src} probed "
                            f"{len({x['_port'] for x in scan})} ports on {dst} in "
                            f"{int((scan[-1]['_ts'] - scan[0]['_ts']).total_seconds())} seconds; "
                            f"allowed: {', '.join(map(str, allowed)) or 'none'}")
                alerts.append(_alert("DET-05", sev, src, scan[0]["_ts"], e["_ts"], scan[-1]["_ts"], len(scan), evidence))
                break
    return alerts


def toll_fraud(ds: Dataset) -> list[dict]:
    """DET-06: bursts of international calls from one extension outside business hours."""
    alerts = []
    labels = {x["extension"]: x["label"] for x in ds.extensions}
    by_ext = defaultdict(list)
    for c in ds.cdr:
        if c["_ts"] is None or c["_dur"] is None or not c["dialled_number"].startswith("+"):
            continue
        code, country, rate, high = country_for(c["dialled_number"])
        if code == "+1" or is_business_hours(c["_ts"]):
            continue
        by_ext[c["extension"]].append(dict(c, _country=country, _rate=rate, _high=high))
    window = timedelta(minutes=config.TOLL_WINDOW_MIN)
    for ext, calls in sorted(by_ext.items()):
        calls.sort(key=lambda c: c["_ts"])
        start, trigger = 0, None
        for i, c in enumerate(calls):
            while c["_ts"] - calls[start]["_ts"] > window:
                start += 1
            in_window = calls[start:i + 1]
            high_minutes = sum(x["_dur"] for x in in_window if x["_high"]) / 60
            if len(in_window) >= config.TOLL_MIN_CALLS or high_minutes >= config.TOLL_MIN_HIGH_RISK_MINUTES:
                trigger = c
                break
        if not trigger:
            continue
        # Everything from the same extension in that after-hours run of calls.
        run = [c for c in calls if calls[start]["_ts"] <= c["_ts"] <= calls[start]["_ts"] + timedelta(hours=12)]
        minutes = sum(c["_dur"] for c in run) / 60
        cost = sum(c["_dur"] / 60 * c["_rate"] for c in run)
        countries = sorted({c["_country"] for c in run})
        sev = "Critical" if cost >= config.TOLL_CRITICAL_COST else "High"
        evidence = (f"Extension {ext} ({labels.get(ext, 'unknown')}): {len(run)} international calls, "
                    f"{minutes:,.0f} minutes, {fmt_ts(run[0]['_ts'])} to {fmt_ts(run[-1]['_ts'])}, to "
                    f"{', '.join(countries)}; estimated cost ${cost:,.2f}")
        alerts.append(_alert("DET-06", sev, ext, run[0]["_ts"], trigger["_ts"], run[-1]["_ts"], len(run), evidence))
    return alerts


def sim_swap_takeover(ds: Dataset) -> list[dict]:
    """DET-07: SIM swap, then a password reset and other risky changes within 24 hours."""
    alerts = []
    by_cust = defaultdict(list)
    for e in ds.customer:
        if e["_ts"]:
            by_cust[e["customer_id"]].append(e)
    window = timedelta(hours=config.SIM_TAKEOVER_WINDOW_HOURS)
    for cust, events in sorted(by_cust.items()):
        events.sort(key=lambda e: e["_ts"])
        for swap in (e for e in events if e["event_type"] == "SIM_SWAP"):
            after = [e for e in events if swap["_ts"] < e["_ts"] <= swap["_ts"] + window
                     and e["event_type"] in config.SIM_RISKY_EVENTS]
            reset = next((e for e in after if e["event_type"] == "PASSWORD_RESET"), None)
            if not reset:
                continue
            types = [e["event_type"] for e in after]
            sev = "Critical" if any(t in config.SIM_CRITICAL_EVENTS for t in types) else "High"
            minutes = int((reset["_ts"] - swap["_ts"]).total_seconds() // 60)
            evidence = (f"SIM swap via {swap['channel']} (agent {swap['agent'] or 'n/a'}, verification "
                        f"{swap['verification']}) at {fmt_ts(swap['_ts'])}; password reset {minutes} minutes later, "
                        f"then {', '.join(t for t in types if t != 'PASSWORD_RESET') or 'nothing else'}")
            alert = _alert("DET-07", sev, cust, swap["_ts"], reset["_ts"], after[-1]["_ts"], len(after) + 1, evidence)
            alert["_agent"] = swap["agent"]
            alerts.append(alert)
    return alerts


ALL_RULES = [password_spraying, brute_force_success, impossible_travel, terminated_account_signin,
             port_scan, toll_fraud, sim_swap_takeover]


def run_all(ds: Dataset) -> list[dict]:
    alerts = [a for rule in ALL_RULES for a in rule(ds)]
    alerts.sort(key=lambda a: (a["_detected"], a["rule_id"], a["entity"]))
    for i, a in enumerate(alerts, 1):
        a["alert_id"] = f"ALR-{i:04d}"
        a["first_seen"] = fmt_ts(a["_first"])
        a["trigger_time"] = fmt_ts(a["_trigger"])
        a["detected_at"] = fmt_ts(a["_detected"])
        a["last_seen"] = fmt_ts(a["_last"])
    return alerts
