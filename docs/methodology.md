# Methodology

How the lab turns raw logs into alerts, incidents, findings and compliance results, and what each number in the reports means.

## Data

`generate_data.py` writes one week of synthetic data (Monday 2026-11-09 to Sunday 2026-11-15) for a fictional Saskatchewan telecom with 135 accounts. The seed is fixed, so the files are identical every time.

| File | Rows | What it is |
|---|---|---|
| users.csv | 135 | Directory export: account type, status, MFA, last sign-in |
| hr_roster.csv | 130 | HR records, including leavers and termination dates |
| entitlements.csv | 283 | Who holds which permission in which system |
| sod_rules.csv | 4 | Separation-of-duties pairs |
| auth_log.csv | 958 | Sign-ins to SSO, VPN, CRM and billing, with geolocation |
| firewall_log.csv | 5,752 | Edge and internal firewall events |
| voip_cdr.csv | 1,429 | Call detail records from the PBX |
| extensions.csv | 121 | Phone extensions and where they are |
| customer_events.csv | 1,640 | Customer account changes: SIM swaps, resets, port-outs |
| incident_updates.csv | 26 | Analyst actions on each incident (the ticket history) |

Planted in the data: a password spray, a brute-force takeover of a privileged account, an impossible-travel sign-in, a leaver's account signing in, an external and an internal port scan, toll fraud on a boardroom phone, three SIM swap takeovers, and a 4-hour firewall log outage. Also planted, to prove the rules stay quiet: a real business trip to Toronto, a legitimate weekend call to the UK, and a SIM swap followed by a password reset three days later.

## Pipeline

1. **Data checks** (`secops/checks.py`): required columns, valid timestamps, IPs, ports and codes, entitlements for real users, a directory export that isn't older than the sign-in log, and analyst updates that point at real incidents and move forward in time. `--strict` makes any problem fail the run.
2. **Detections** (`secops/detections.py`): seven rules, described in `detection-catalogue.md`.
3. **Incidents** (`secops/incidents.py`): alerts about the same user, IP, extension or customer within 24 hours become one incident. Severity is the worst of its alerts.
4. **Response tracking**: each incident's status and times come from `incident_updates.csv`. Closing an incident also counts as containing it.
5. **Access review** (`secops/access_review.py`): directory vs HR vs entitlements, against `access-management-standard.md`.
6. **Compliance** (`secops/compliance.py`): 12 checks with a measured value, target and evidence, mapped to NIST CSF 2.0.
7. **Metrics** (`secops/metrics.py`, `sql/`): results are loaded into an in-memory SQLite database; the named queries in `sql/metrics.sql` produce every table in the reports.

## Severity and response targets

| Severity | Acknowledge within | Contain within |
|---|---|---|
| Critical | 15 minutes | 4 hours |
| High | 1 hour | 24 hours |
| Medium | 4 hours | 72 hours |
| Low | 24 hours | 7 days |

Severity starts from the rule and is raised for privileged accounts, internal scanning sources, confirmed money movement (port-out or device order) and estimated toll fraud losses of $1,000 or more.

## Measures

| Measure | Definition |
|---|---|
| Time to detect | From the first malicious event to the incident opening (the rule run that raised the first alert). For impossible travel the malicious event is the second sign-in. |
| Time to acknowledge | From the incident opening to the first analyst update. |
| Time to contain | From the incident opening to the first Contained or Closed update. |
| Ack target met / SLA met | Yes or No when done; Overdue when not done and past due at the report date; Pending when not yet due. |
| Medians | Middle value across incidents; incidents with no time yet are left out. |

## Limits

- The data is synthetic and small. Thresholds that work here would need tuning on real volumes.
- Geolocation is taken as given in the log; real geo-IP data is noisier.
- The analyst actions in `incident_updates.csv` are written to illustrate the process, including deliberate misses.
- No real systems, people or customers are involved, and nothing was scanned or attacked.
