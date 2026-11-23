#!/usr/bin/env python3
"""Generate the synthetic data set for the lab.

Everything is made up: a fictional Saskatchewan telecom ("Prairie Lynx Telecom"),
its staff directory, one week of sign-in, firewall, call detail and customer account
logs (Monday 2026-11-09 to Sunday 2026-11-15), and a handful of planted attacks.
IP addresses come from private (RFC 1918) and documentation (RFC 5737) ranges.

The random seed is fixed, so running this again gives the same files.

    python3 generate_data.py            # writes data/*.csv
    python3 generate_data.py --out tmp  # somewhere else
"""
from __future__ import annotations

import argparse
import random
from datetime import date, datetime, timedelta
from pathlib import Path

from secops.util import fmt_ts, write_csv

SEED = 435
START = datetime(2026, 11, 9)            # Monday
DAYS = 7
EXPORT_AT = datetime(2026, 11, 16, 8, 0)  # directory export time

CITIES = {
    "Regina": ("CA", 50.4452, -104.6189),
    "Saskatoon": ("CA", 52.1332, -106.6700),
    "Moose Jaw": ("CA", 50.3934, -105.5519),
    "Prince Albert": ("CA", 53.2033, -105.7531),
    "Swift Current": ("CA", 50.2881, -107.7939),
    "Yorkton": ("CA", 51.2139, -102.4628),
    "Toronto": ("CA", 43.6532, -79.3832),
    "Amsterdam": ("NL", 52.3676, 4.9041),
    "Sao Paulo": ("BR", -23.5505, -46.6333),
    "Singapore": ("SG", 1.3521, 103.8198),
}

FIRST = """Aiden Amelia Ava Ben Carla Chloe Colin Dana Derek Elena Ethan Faith Gavin Grace Hannah
Isaac Jade Jason Kara Kevin Leah Liam Maya Megan Nathan Nora Owen Paige Quinn Rachel Ryan Sara
Sean Tara Tessa Victor Wade Willow Zoe Adam Brooke Caleb Diana Eric Fiona Gabe Holly Ian Jenna
Kyle Lena Mason Naomi Olivia Peter Riley Shane Trent Uma Vince""".split()
LAST = """Anderson Baker Bell Brooks Carter Clarke Cole Dubois Ellis Evans Foster Friesen Gill Gray
Hart Hayes Hughes Jensen Kaur King Klassen Lambert Lavoie Lewis Mackay Martel Miller Mitchell
Moore Nelson Olsen Patel Pelletier Price Reid Ross Ryan Schmidt Scott Shaw Stewart Tran Turner
Walker Ward Watson Webb Wiebe Wong Young Zhang Bauer Chartrand Dyck Fehr""".split()

DEPARTMENTS = [
    ("Customer Care", 35, ["CRM:customer_view", "CRM:customer_edit", "CRM:sim_swap_perform"]),
    ("Billing", 15, ["BILLING:billing_view", "BILLING:billing_adjust"]),
    ("Network Operations", 18, ["NETWORK:read_only"]),
    ("IT Service Desk", 12, ["IAM:password_reset", "CRM:customer_view"]),
    ("Corporate Security", 6, ["SIEM:alert_triage"]),
    ("Field Services", 18, ["CRM:customer_view", "WORKORDER:workorder_edit"]),
    ("Finance", 10, ["BILLING:billing_view", "FIN:gl_post"]),
    ("Human Resources", 6, ["HR:hr_admin"]),
    ("Sales", 8, ["CRM:customer_view", "CRM:customer_edit"]),
]

# Named people the planted scenarios need. Everyone else is generated.
SCENARIO_PEOPLE = [
    # username, name, department, extra permissions, mfa, home city
    ("dmorin", "Daniel Morin", "Network Operations", ["NETWORK:firewall_change"], "N", "Regina"),
    ("lbennett", "Laura Bennett", "Sales", [], "Y", "Regina"),
    ("mgagnon", "Marc Gagnon", "Sales", [], "Y", "Regina"),
    ("tcampbell", "Tyler Campbell", "Customer Care", [], "Y", "Saskatoon"),
    ("skowalski", "Sam Kowalski", "Customer Care", ["CRM:sim_swap_approve"], "Y", "Regina"),
    ("nfraser", "Nina Fraser", "Customer Care", [], "Y", "Saskatoon"),
    ("ehall", "Emma Hall", "Billing", ["BILLING:billing_approve"], "Y", "Regina"),
    ("bthompson", "Brian Thompson", "Network Operations",
     ["NETWORK:firewall_change", "NETWORK:change_approve"], "Y", "Regina"),
    ("aparker", "Alex Parker", "Network Operations", ["PBX:pbx_admin"], "N", "Regina"),
    ("jwilson", "Jordan Wilson", "IT Service Desk", ["IAM:user_admin"], "N", "Regina"),
    ("gmartin", "Grace Martin", "Billing", [], "Y", "Regina"),
    ("hlee", "Holly Lee", "Field Services", [], "Y", "Saskatoon"),
]

TERMINATED_ENABLED = {"tcampbell": date(2026, 10, 31), "gmartin": date(2026, 11, 6), "hlee": date(2026, 11, 13)}
INVALID_SPRAY_NAMES = ["admin", "administrator", "test", "helpdesk", "backup", "scanner"]


class IpPool:
    """Hands out unique addresses from the RFC 5737 documentation ranges."""

    RESERVED = {"203.0.113.10", "203.0.113.20", "203.0.113.45", "198.51.100.77", "198.51.100.5",
                "192.0.2.77", "192.0.2.140", "203.0.113.201", "198.51.100.150"}

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.free = [f"{net}.{h}" for net in ("198.51.100", "203.0.113", "192.0.2")
                     for h in range(2, 255) if f"{net}.{h}" not in self.RESERVED]
        rng.shuffle(self.free)

    def take(self) -> str:
        return self.free.pop()

    def any(self) -> str:
        return self.rng.choice(self.free)


def build_people(rng: random.Random):
    used = {p[0] for p in SCENARIO_PEOPLE}
    people = []
    emp = 1000

    def add(username, name, dept, perms, mfa, city):
        nonlocal emp
        emp += 1
        base = next(d[2] for d in DEPARTMENTS if d[0] == dept)
        people.append({"username": username, "name": name, "department": dept, "employee_id": f"E{emp}",
                       "perms": list(dict.fromkeys(base + perms)), "mfa": mfa, "home": city})

    for p in SCENARIO_PEOPLE:
        add(*p)
    counts = {d[0]: d[1] for d in DEPARTMENTS}
    for p in SCENARIO_PEOPLE:
        counts[p[2]] -= 1
    for dept, n, _ in DEPARTMENTS:
        for _ in range(counts[dept]):
            while True:
                first, last = rng.choice(FIRST), rng.choice(LAST)
                username = (first[0] + last).lower()
                if username not in used:
                    break
            used.add(username)
            city = rng.choices(["Regina", "Saskatoon", "Moose Jaw", "Prince Albert", "Swift Current", "Yorkton"],
                               [55, 30, 5, 4, 3, 3])[0]
            add(username, f"{first} {last}", dept, [], "Y", city)

    by_dept = {}
    for p in people:
        by_dept.setdefault(p["department"], []).append(p)
    generated = lambda dept: [p for p in by_dept[dept] if p["username"] not in {s[0] for s in SCENARIO_PEOPLE}]
    # Ordinary role grants (no conflicts).
    for p in generated("Billing")[:1]:
        p["perms"] = [x for x in p["perms"] if x != "BILLING:billing_adjust"] + ["BILLING:billing_approve"]
    for p in generated("Network Operations")[:4]:
        p["perms"].append("NETWORK:firewall_change")
    for p in generated("Network Operations")[4:6]:
        p["perms"].append("NETWORK:change_approve")
    for p in generated("Network Operations")[6:7]:
        p["perms"].append("PBX:pbx_admin")
    for p in generated("IT Service Desk")[:1]:
        p["perms"].append("IAM:user_admin")
    for p in generated("Corporate Security")[:1]:
        p["perms"].append("IAM:audit_log_admin")
    for p in generated("Customer Care")[:2]:      # team leads approve, they don't perform
        p["perms"] = [x for x in p["perms"] if x != "CRM:sim_swap_perform"] + ["CRM:sim_swap_approve"]
    # Two ordinary staff who never enrolled in MFA.
    for p in rng.sample(generated("Field Services") + generated("Finance"), 2):
        p["mfa"] = "N"
    # Eight accounts nobody has used for months.
    pool = [p for p in people if p["username"] not in {s[0] for s in SCENARIO_PEOPLE}
            and not any(x.split(":")[1] in {"firewall_change", "pbx_admin", "user_admin", "audit_log_admin",
                                                "sim_swap_approve", "billing_approve", "change_approve"}
                        for x in p["perms"]) and p["mfa"] == "Y"]
    for p in rng.sample(pool, 8):
        p["dormant"] = True
    for p in people:
        p["office"] = "Saskatoon" if p["home"] in ("Saskatoon", "Prince Albert") else "Regina"
    return people


def office_ip(rng, office):
    return f"10.{20 if office == 'Regina' else 30}.{rng.choice([10, 20, 30])}.{rng.randint(20, 240)}"


def auth_event(ts, user, ip, city, result, app, mfa):
    country, lat, lon = CITIES[city]
    return {"timestamp": fmt_ts(ts), "username": user, "src_ip": ip, "city": city, "country": country,
            "lat": lat, "lon": lon, "result": result, "app": app, "mfa": mfa}


def build_auth(rng, people, pools):
    events = []
    remote_ip = {p["username"]: pools.take() for p in people}
    scripted_days = {("mgagnon", date(2026, 11, 12)), ("mgagnon", date(2026, 11, 13)),
                     ("dmorin", date(2026, 11, 13)), ("lbennett", date(2026, 11, 13))}
    skip = {p["username"] for p in people if p.get("dormant")} | set(TERMINATED_ENABLED)
    for p in people:
        if p["username"] in skip:
            continue
        mfa = p["mfa"]
        for d in range(DAYS):
            day = START + timedelta(days=d)
            if (p["username"], day.date()) in scripted_days:
                continue
            weekday = day.weekday() < 5
            if weekday and rng.random() < 0.9:
                slots = [(7, 30, 9, 30)] + ([(12, 30, 14, 0)] if rng.random() < 0.5 else [])
            elif not weekday and rng.random() < 0.12:
                slots = [(10, 0, 20, 0)]
            else:
                continue
            for h1, m1, h2, m2 in slots:
                start = day + timedelta(hours=h1, minutes=m1)
                span = int(((h2 * 60 + m2) - (h1 * 60 + m1)) * 60)
                ts = start + timedelta(seconds=rng.randint(0, span))
                remote = (not weekday) or rng.random() < 0.3
                ip, city = (remote_ip[p["username"]], p["home"]) if remote else (office_ip(rng, p["office"]), p["office"])
                app = "VPN" if remote else rng.choice(["SSO", "SSO", "CRM", "BILLING"])
                fails = 1 if rng.random() < 0.05 else 0
                fails += rng.randint(1, 2) if rng.random() < 0.01 else 0
                for i in range(fails):
                    events.append(auth_event(ts - timedelta(seconds=40 * (fails - i)), p["username"], ip, city,
                                             "FAILURE", app, "NA"))
                events.append(auth_event(ts, p["username"], ip, city, "SUCCESS", app, mfa))

    # Benign trip: Regina in the morning, Toronto that afternoon and the next day.
    events += [
        auth_event(datetime(2026, 11, 12, 8, 31, 12), "mgagnon", office_ip(rng, "Regina"), "Regina", "SUCCESS", "SSO", "Y"),
        auth_event(datetime(2026, 11, 12, 14, 2, 40), "mgagnon", "198.51.100.150", "Toronto", "SUCCESS", "VPN", "Y"),
        auth_event(datetime(2026, 11, 13, 8, 15, 5), "mgagnon", "198.51.100.150", "Toronto", "SUCCESS", "VPN", "Y"),
    ]
    # Planted: password spraying from one address, 28 accounts, 1 try each.
    names = [p["username"] for p in people if not p.get("dormant")]
    targets = rng.sample(names, 22) + INVALID_SPRAY_NAMES
    rng.shuffle(targets)
    t = datetime(2026, 11, 10, 2, 14, 3)
    for name in targets:
        events.append(auth_event(t, name, "203.0.113.45", "Amsterdam", "FAILURE", "VPN", "NA"))
        t += timedelta(seconds=rng.randint(28, 44))
    # Planted: brute force against a privileged account with no MFA, then a success.
    events.append(auth_event(datetime(2026, 11, 12, 16, 34, 9), "dmorin", office_ip(rng, "Regina"), "Regina",
                             "SUCCESS", "SSO", "N"))
    t = datetime(2026, 11, 12, 23, 38, 5)
    for _ in range(16):
        events.append(auth_event(t, "dmorin", "198.51.100.77", "Sao Paulo", "FAILURE", "VPN", "NA"))
        t += timedelta(seconds=rng.randint(35, 48))
    events.append(auth_event(t + timedelta(seconds=20), "dmorin", "198.51.100.77", "Sao Paulo", "SUCCESS", "VPN", "N"))
    # Planted: impossible travel, Regina then Singapore 47 minutes later (MFA push approved).
    events.append(auth_event(datetime(2026, 11, 13, 8, 5, 22), "lbennett", office_ip(rng, "Regina"), "Regina",
                             "SUCCESS", "SSO", "Y"))
    events.append(auth_event(datetime(2026, 11, 13, 8, 52, 47), "lbennett", "203.0.113.201", "Singapore",
                             "SUCCESS", "VPN", "Y"))
    # The real users sign back in after the service desk resets their passwords.
    events.append(auth_event(datetime(2026, 11, 13, 9, 41, 15), "dmorin", office_ip(rng, "Regina"), "Regina",
                             "SUCCESS", "SSO", "N"))
    events.append(auth_event(datetime(2026, 11, 13, 11, 20, 40), "lbennett", office_ip(rng, "Regina"), "Regina",
                             "SUCCESS", "SSO", "Y"))
    # Planted: a terminated employee's account, never disabled, signs in to the CRM.
    events.append(auth_event(datetime(2026, 11, 14, 19, 22, 31), "tcampbell", "192.0.2.140", "Saskatoon",
                             "SUCCESS", "CRM", "Y"))
    events.sort(key=lambda e: (e["timestamp"], e["username"]))
    return events


def build_directory(rng, people, auth):
    last = {}
    for e in auth:
        if e["result"] == "SUCCESS":
            last[e["username"]] = max(last.get(e["username"], ""), e["timestamp"])
    users, hr, ents = [], [], []
    for p in people:
        u = p["username"]
        created = date(2019, 1, 1) + timedelta(days=rng.randint(0, 2300))
        if p.get("dormant"):
            ll = datetime(2026, 3, 1) + timedelta(days=rng.randint(0, 160), hours=rng.randint(8, 16))
            last_logon = fmt_ts(ll)
        elif u in TERMINATED_ENABLED and u not in last:
            last_logon = fmt_ts(datetime.combine(TERMINATED_ENABLED[u], datetime.min.time()) - timedelta(hours=7))
        else:
            last_logon = last.get(u, "")
        users.append({"username": u, "display_name": p["name"], "employee_id": p["employee_id"],
                      "department": p["department"], "account_type": "human", "account_status": "Enabled",
                      "mfa_enrolled": p["mfa"], "created_date": created.isoformat(), "last_logon": last_logon})
        term = TERMINATED_ENABLED.get(u)
        hr.append({"employee_id": p["employee_id"], "full_name": p["name"], "department": p["department"],
                   "status": "Terminated" if term else "Active",
                   "termination_date": term.isoformat() if term else ""})
        for perm in p["perms"]:
            system, permission = perm.split(":")
            ents.append({"username": u, "system": system, "permission": permission})
    # Leavers handled correctly: disabled the day they left.
    emp = 1000 + len(people)
    for i, (name, dept, left) in enumerate([("Wade Klassen", "Field Services", date(2026, 10, 20)),
                                            ("Paige Lambert", "Sales", date(2026, 10, 28))]):
        emp += 1
        u = (name.split()[0][0] + name.split()[1]).lower()
        users.append({"username": u, "display_name": name, "employee_id": f"E{emp}", "department": dept,
                      "account_type": "human", "account_status": "Disabled", "mfa_enrolled": "Y",
                      "created_date": "2021-05-03",
                      "last_logon": fmt_ts(datetime.combine(left, datetime.min.time()) - timedelta(hours=8))})
        hr.append({"employee_id": f"E{emp}", "full_name": name, "department": dept, "status": "Terminated",
                   "termination_date": left.isoformat()})
    # A contractor account with no HR record behind it.
    users.append({"username": "contractor.fw", "display_name": "Firewall Contractor", "employee_id": "",
                  "department": "Network Operations", "account_type": "human", "account_status": "Enabled",
                  "mfa_enrolled": "Y", "created_date": "2026-06-15", "last_logon": "2026-09-30 14:12:44"})
    ents += [{"username": "contractor.fw", "system": "NETWORK", "permission": "read_only"},
             {"username": "contractor.fw", "system": "NETWORK", "permission": "firewall_change"}]
    for svc, perm in [("svc_backup", "BACKUP:backup_operator"), ("svc_billing_batch", "BILLING:billing_view"),
                      ("svc_siem_collector", "SIEM:log_read"), ("svc_pbx_cdr", "PBX:cdr_export")]:
        users.append({"username": svc, "display_name": svc, "employee_id": "", "department": "IT Infrastructure",
                      "account_type": "service", "account_status": "Enabled", "mfa_enrolled": "NA",
                      "created_date": "2020-02-10", "last_logon": ""})
        system, permission = perm.split(":")
        ents.append({"username": svc, "system": system, "permission": permission})
    return users, hr, ents


def build_firewall(rng, people, pools):
    events = []
    internal = [office_ip(rng, "Regina") for _ in range(60)] + [office_ip(rng, "Saskatoon") for _ in range(30)]
    web = [pools.take() for _ in range(40)]
    gap_start, gap_end = datetime(2026, 11, 13, 2), datetime(2026, 11, 13, 6)
    for h in range(DAYS * 24):
        hour = START + timedelta(hours=h)
        if gap_start <= hour < gap_end:
            continue  # log forwarder outage: no firewall events reached the SIEM
        busy = 8 <= hour.hour < 18 and hour.weekday() < 5
        for _ in range(rng.randint(45, 70) if busy else rng.randint(18, 32)):
            ts = hour + timedelta(seconds=rng.randint(0, 3599))
            r = rng.random()
            if r < 0.62:
                ev = (rng.choice(internal), rng.choice(web), rng.choice([443] * 8 + [80, 53]), "TCP", "ALLOW", "OUT-WEB")
            elif r < 0.78:
                ev = (pools.any(), "203.0.113.10", 443, "TCP", "ALLOW", "IN-PORTAL")
            elif r < 0.83:
                ev = ("198.51.100.5", "203.0.113.20", 5060, "UDP", "ALLOW", "IN-SIP-TRUNK")
            elif r < 0.93:
                ev = (pools.any(), rng.choice(["203.0.113.10", "203.0.113.20"]),
                      rng.choice([22, 23, 445, 3389, 1433, 8080, 5060]), "TCP", "DENY", "DEFAULT-DENY")
            else:
                ev = (rng.choice(internal), "10.10.100.20", rng.choice([443, 443, 1433]), "TCP", "ALLOW", "INT-APP")
            events.append(fw(ts, *ev, rng))
    # Planted: external scan of the customer portal, all denied.
    ports = rng.sample([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 587, 631,
                        873, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2222, 3000, 3128, 3306, 3389, 4443,
                        5060, 5432, 5900, 5985, 6379, 7001, 8000, 8008, 8080, 8443, 8888, 9000, 9090, 9200, 10000], 45)
    t = datetime(2026, 11, 11, 3, 2, 10)
    for port in ports:
        events.append(fw(t, "192.0.2.77", "203.0.113.10", port, "TCP", "DENY", "DEFAULT-DENY", rng))
        t += timedelta(seconds=rng.randint(3, 5))
    # Planted: a workstation scanning the billing database server from inside.
    ports = [22, 443, 1433] + rng.sample([21, 23, 25, 80, 110, 135, 139, 445, 1521, 2049, 3306, 3389, 5432, 5900,
                                          5985, 6379, 8000, 8080, 8443, 9000, 9200, 1434, 161, 389, 636, 873, 111,
                                          514, 631], 29)
    rng.shuffle(ports)
    t = datetime(2026, 11, 14, 15, 10, 30)
    for port in ports:
        allowed = port in (443, 1433)
        events.append(fw(t, "10.20.20.55", "10.10.100.20", port, "TCP", "ALLOW" if allowed else "DENY",
                         "INT-APP" if allowed else "INT-DENY", rng))
        t += timedelta(seconds=rng.randint(2, 4))
    events.sort(key=lambda e: e["timestamp"])
    return events


def fw(ts, src, dst, port, proto, action, rule, rng):
    return {"timestamp": fmt_ts(ts), "src_ip": src, "src_port": rng.randint(1024, 65535), "dst_ip": dst,
            "dst_port": port, "protocol": proto, "action": action, "rule_name": rule,
            "bytes": rng.randint(400, 90000) if action == "ALLOW" else 0}


def build_voice(rng):
    exts = [{"extension": str(4000 + i), "label": f"Desk phone {4000 + i}",
             "department": rng.choice([d[0] for d in DEPARTMENTS])} for i in range(1, 121)]
    exts.append({"extension": "4471", "label": "Boardroom B conference phone", "department": "Facilities"})
    calls, n = [], 0

    def number(kind):
        if kind == "local":
            return f"+1306555{rng.randint(0, 9999):04d}"
        if kind == "canada":
            return f"+1{rng.choice(['403', '416', '604', '780', '204'])}555{rng.randint(0, 9999):04d}"
        if kind == "us":
            return f"+1{rng.choice(['212', '312', '701', '406'])}555{rng.randint(0, 9999):04d}"
        code = rng.choice(["+44", "+91", "+86", "+63"])
        return f"{code}{'2079460' if code == '+44' else ''}{rng.randint(100000, 999999)}"

    def add(ts, ext, dialled, dur, disposition="ANSWERED"):
        nonlocal n
        n += 1
        calls.append({"call_id": f"C{n:06d}", "start_time": fmt_ts(ts), "extension": ext,
                      "dialled_number": dialled, "duration_sec": dur if disposition == "ANSWERED" else 0,
                      "disposition": disposition, "trunk": "SIP-TRUNK-1"})

    for d in range(DAYS):
        day = START + timedelta(days=d)
        count = rng.randint(230, 290) if day.weekday() < 5 else rng.randint(10, 20)
        for _ in range(count):
            if day.weekday() < 5:
                ts = day + timedelta(hours=8, seconds=rng.randint(0, int(9.5 * 3600)))
            else:
                ts = day + timedelta(hours=10, seconds=rng.randint(0, 6 * 3600))
            kind = rng.choices(["local", "canada", "us", "intl"], [82, 10, 4, 4])[0]
            disp = rng.choices(["ANSWERED", "NO ANSWER", "BUSY"], [85, 10, 5])[0]
            add(ts, rng.choice(exts[:-1])["extension"], number(kind), rng.randint(25, 900), disp)
        # A few evening calls (domestic) from the network operations desk.
        for _ in range(rng.randint(2, 5)):
            add(day + timedelta(hours=19, seconds=rng.randint(0, 3 * 3600)), "4015", number("local"),
                rng.randint(60, 600))
    # Legitimate: one weekend call to the UK, 20 minutes.
    add(datetime(2026, 11, 14, 10, 15, 2), "4012", "+442079460718", 1210)
    # Planted: toll fraud through the boardroom phone, early Sunday morning.
    t = datetime(2026, 11, 15, 1, 12, 0)
    high_risk = ["+53", "+371", "+232", "+252", "+224"]
    for _ in range(54):
        code = rng.choice(high_risk)
        add(t, "4471", f"{code}{rng.randint(1000000, 9999999)}", rng.randint(180, 560))
        t += timedelta(seconds=rng.randint(150, 330))
    calls.sort(key=lambda c: (c["start_time"], c["call_id"]))
    return exts, calls


def build_customer_events(rng, people):
    events = []
    agents = [p["username"] for p in people if p["department"] == "Customer Care"
              and p["username"] not in TERMINATED_ENABLED and not p.get("dormant")
              and "CRM:sim_swap_perform" in p["perms"]]
    customers = [f"CUST-{100000 + i}" for i in range(1, 1201)]
    fraud = {"CUST-100417", "CUST-100823", "CUST-100296"}
    benign = "CUST-100777"
    reserved = fraud | {benign}
    types = ["LOGIN", "PLAN_CHANGE", "BILL_PAYMENT", "PASSWORD_RESET", "DEVICE_ORDER", "ADDRESS_CHANGE",
             "EMAIL_CHANGE", "PORT_OUT_REQUEST"]
    weights = [50, 15, 11, 8, 6, 5, 4, 1]
    touched = set()
    for d in range(DAYS):
        day = START + timedelta(days=d)
        for _ in range(rng.randint(190, 250)):
            cust = rng.choice(customers)
            if cust in reserved:
                continue
            touched.add(cust)
            et = rng.choices(types, weights)[0]
            ts = day + timedelta(hours=7, seconds=rng.randint(0, 15 * 3600))
            if et in ("LOGIN", "PASSWORD_RESET", "EMAIL_CHANGE", "BILL_PAYMENT"):
                channel, agent, verif = rng.choice(["Online", "App"]), "", "SMS_OTP" if et == "PASSWORD_RESET" else "PASSWORD"
            else:
                channel = rng.choice(["Online", "App", "Call Centre", "Store"])
                agent = rng.choice(agents) if channel in ("Call Centre", "Store") else ""
                verif = {"Call Centre": "KBA", "Store": "ID_CHECK"}.get(channel, "PASSWORD")
            events.append(cust_ev(ts, cust, et, channel, agent, verif))
    # Legitimate SIM swaps on customers with no other activity that week.
    quiet = [c for c in customers if c not in touched and c not in reserved]
    for cust in rng.sample(quiet, 25):
        day = START + timedelta(days=rng.randint(0, DAYS - 1))
        channel = rng.choices(["Store", "Call Centre"], [70, 30])[0]
        events.append(cust_ev(day + timedelta(hours=9, seconds=rng.randint(0, 9 * 3600)), cust, "SIM_SWAP",
                              channel, rng.choice(agents), "ID_CHECK" if channel == "Store" else "KBA"))
    # Benign: SIM swap in store, password reset three days later (outside the window).
    events.append(cust_ev(datetime(2026, 11, 10, 11, 15, 40), benign, "SIM_SWAP", "Store", "nfraser", "ID_CHECK"))
    events.append(cust_ev(datetime(2026, 11, 13, 9, 2, 11), benign, "PASSWORD_RESET", "Online", "", "SMS_OTP"))
    # Planted: three SIM swap account takeovers.
    plan = [
        ("CUST-100417", datetime(2026, 11, 10, 13, 42, 18), "Call Centre", "skowalski", "KBA",
         [(16, "PASSWORD_RESET"), (21, "EMAIL_CHANGE"), (38, "PORT_OUT_REQUEST")]),
        ("CUST-100823", datetime(2026, 11, 12, 19, 5, 3), "Call Centre", "skowalski", "KBA",
         [(16, "PASSWORD_RESET"), (31, "ADDRESS_CHANGE"), (35, "DEVICE_ORDER")]),
        ("CUST-100296", datetime(2026, 11, 14, 10, 12, 47), "Store", "nfraser", "ID_CHECK",
         [(78, "PASSWORD_RESET"), (81, "EMAIL_CHANGE")]),
    ]
    for cust, ts, channel, agent, verif, follow in plan:
        events.append(cust_ev(ts, cust, "SIM_SWAP", channel, agent, verif))
        for minutes, et in follow:
            events.append(cust_ev(ts + timedelta(minutes=minutes, seconds=rng.randint(0, 50)), cust, et,
                                  "Online", "", "SMS_OTP" if et == "PASSWORD_RESET" else "PASSWORD"))
    events.sort(key=lambda e: (e["timestamp"], e["customer_id"]))
    for i, e in enumerate(events, 1):
        e["event_id"] = f"EV{i:06d}"
    return events


def cust_ev(ts, cust, et, channel, agent, verif):
    return {"timestamp": fmt_ts(ts), "customer_id": cust, "event_type": et, "channel": channel,
            "agent": agent, "verification": verif}


def agent_signins(rng, people, auth, cust):
    """Every agent action in the CRM needs a same-day sign-in before it."""
    office = {p["username"]: p["office"] for p in people}
    signed = {}
    for e in auth:
        if e["result"] == "SUCCESS":
            signed.setdefault((e["username"], e["timestamp"][:10]), []).append(e["timestamp"])
    added = []
    for e in sorted(cust, key=lambda x: x["timestamp"]):
        agent, day = e["agent"], e["timestamp"][:10]
        if not agent or any(t <= e["timestamp"] for t in signed.get((agent, day), [])):
            continue
        ts = datetime.fromisoformat(e["timestamp"]) - timedelta(minutes=rng.randint(10, 90))
        ev = auth_event(ts, agent, office_ip(rng, office[agent]), office[agent], "SUCCESS", "CRM", "Y")
        added.append(ev)
        signed.setdefault((agent, day), []).append(ev["timestamp"])
    auth += added
    auth.sort(key=lambda e: (e["timestamp"], e["username"]))
    return len(added)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="data", help="Output folder (default: data)")
    args = parser.parse_args(argv)
    out = Path(args.out)
    # One seeded stream per section, so changing one section doesn't reshuffle the others.
    rng = {name: random.Random(f"{SEED}-{name}") for name in
           ("people", "auth", "firewall", "voice", "customer", "agents", "directory")}
    pools = IpPool(random.Random(f"{SEED}-ips"))
    people = build_people(rng["people"])
    auth = build_auth(rng["auth"], people, pools)
    firewall = build_firewall(rng["firewall"], people, pools)
    exts, calls = build_voice(rng["voice"])
    cust = build_customer_events(rng["customer"], people)
    agent_signins(rng["agents"], people, auth, cust)
    users, hr, ents = build_directory(rng["directory"], people, auth)

    write_csv(out / "users.csv", users, ["username", "display_name", "employee_id", "department", "account_type",
                                         "account_status", "mfa_enrolled", "created_date", "last_logon"])
    write_csv(out / "hr_roster.csv", hr, ["employee_id", "full_name", "department", "status", "termination_date"])
    write_csv(out / "entitlements.csv", ents, ["username", "system", "permission"])
    write_csv(out / "auth_log.csv", auth, ["timestamp", "username", "src_ip", "city", "country", "lat", "lon",
                                           "result", "app", "mfa"])
    write_csv(out / "firewall_log.csv", firewall, ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
                                                   "protocol", "action", "rule_name", "bytes"])
    write_csv(out / "extensions.csv", exts, ["extension", "label", "department"])
    write_csv(out / "voip_cdr.csv", calls, ["call_id", "start_time", "extension", "dialled_number",
                                            "duration_sec", "disposition", "trunk"])
    write_csv(out / "customer_events.csv", cust, ["event_id", "timestamp", "customer_id", "event_type",
                                                  "channel", "agent", "verification"])
    print(f"Wrote {len(users)} accounts, {len(auth)} sign-ins, {len(firewall)} firewall events, "
          f"{len(calls)} calls and {len(cust)} customer account events to {out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
