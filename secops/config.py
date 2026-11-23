"""Thresholds, severities, SLAs and rule metadata used across the lab.

Every number here is a lab setting, chosen to be easy to explain in a review.
Change them in one place and the detections, reports and tests follow.
"""
from __future__ import annotations

# --- Detection run ---------------------------------------------------------
# Rules are assumed to run every 5 minutes, so an alert is raised at the next
# 5-minute run after the event that crossed the threshold.
RUN_INTERVAL_MINUTES = 5

# Business hours used by the toll fraud rule (local time, Monday to Friday).
BUSINESS_START_HOUR = 7
BUSINESS_END_HOUR = 19

# --- Rule thresholds -------------------------------------------------------
SPRAY_MIN_ACCOUNTS = 10          # distinct accounts failed from one source IP
SPRAY_WINDOW_MIN = 30

BRUTE_MIN_FAILURES = 8           # failures against one account
BRUTE_WINDOW_MIN = 15
BRUTE_SUCCESS_WITHIN_MIN = 30    # success after the burst that turns it into an alert

TRAVEL_MAX_KMH = 900             # faster than a commercial flight
TRAVEL_MIN_KM = 500              # ignore short hops (VPN egress, nearby cities)

SCAN_MIN_PORTS = 25              # distinct destination ports, one source to one host
SCAN_WINDOW_MIN = 5

TOLL_WINDOW_MIN = 60
TOLL_MIN_CALLS = 8               # international calls in the window, after hours
TOLL_MIN_HIGH_RISK_MINUTES = 30  # or minutes to high-risk destinations in the window
TOLL_CRITICAL_COST = 1000.00     # estimated cost (CAD) that makes it Critical

SIM_TAKEOVER_WINDOW_HOURS = 24
SIM_RISKY_EVENTS = ("PASSWORD_RESET", "EMAIL_CHANGE", "ADDRESS_CHANGE", "PORT_OUT_REQUEST", "DEVICE_ORDER")
SIM_CRITICAL_EVENTS = ("PORT_OUT_REQUEST", "DEVICE_ORDER")

# --- Access management (see docs/access-management-standard.md) -----------
DORMANT_DAYS = 90
TERMINATION_GRACE_DAYS = 1
MFA_COVERAGE_TARGET = 95.0       # percent of enabled human accounts
PRIVILEGED_PERMISSIONS = {"user_admin", "audit_log_admin", "firewall_change", "pbx_admin"}

# --- Severity and response targets ----------------------------------------
SEVERITIES = ("Low", "Medium", "High", "Critical")
# Hours to acknowledge and to contain, measured from when the incident opened.
ACK_TARGET_HOURS = {"Critical": 0.25, "High": 1, "Medium": 4, "Low": 24}
CONTAIN_SLA_HOURS = {"Critical": 4, "High": 24, "Medium": 72, "Low": 168}
INCIDENT_MERGE_HOURS = 24
INCIDENT_STATUSES = ("Open", "Acknowledged", "Contained", "Closed")

# Countries treated as high-risk for international revenue share fraud in this
# lab, with illustrative per-minute rates (CAD). Not a real tariff.
HIGH_RISK_COUNTRIES = {
    "+53": ("Cuba", 1.20),
    "+371": ("Latvia (premium range)", 1.85),
    "+232": ("Sierra Leone", 2.10),
    "+252": ("Somalia", 2.40),
    "+224": ("Guinea", 1.95),
}
STANDARD_RATES = {
    "+1": ("Canada/US", 0.00),
    "+44": ("United Kingdom", 0.03),
    "+91": ("India", 0.05),
    "+86": ("China", 0.04),
    "+63": ("Philippines", 0.09),
}

RULES = {
    "DET-01": {
        "name": "Password spraying",
        "technique": "T1110.003 Brute Force: Password Spraying",
        "category": "Account compromise attempt",
        "entity_type": "source_ip",
        "playbook": "Block the source IP at the VPN and edge firewall; check for any success from it; "
                    "force a password reset for any account that signed in from it.",
    },
    "DET-02": {
        "name": "Brute force followed by a successful sign-in",
        "technique": "T1110.001 Brute Force: Password Guessing",
        "category": "Account compromise",
        "entity_type": "user",
        "playbook": "Disable the account and end its sessions; reset the password and enrol MFA; "
                    "review what the account did after the sign-in.",
    },
    "DET-03": {
        "name": "Impossible travel",
        "technique": "T1078 Valid Accounts",
        "category": "Account compromise",
        "entity_type": "user",
        "playbook": "Call the user on a known number to confirm; if not them, revoke sessions, "
                    "reset the password and review activity from the second location.",
    },
    "DET-04": {
        "name": "Sign-in by a terminated employee's account",
        "technique": "T1078 Valid Accounts",
        "category": "Access misuse",
        "entity_type": "user",
        "playbook": "Disable the account now; tell HR and the former manager; review what was "
                    "accessed; check why the leaver process did not disable it.",
    },
    "DET-05": {
        "name": "Port scan",
        "technique": "T1046 Network Service Discovery",
        "category": "Reconnaissance",
        "entity_type": "source_ip",
        "playbook": "External: confirm everything was denied and block the IP. Internal: isolate the "
                    "host, identify its owner and check it for malware.",
    },
    "DET-06": {
        "name": "Toll fraud: after-hours international calling",
        "technique": "T1496 Resource Hijacking",
        "category": "Fraud (voice)",
        "entity_type": "extension",
        "playbook": "Block international dialling on the extension; reset its SIP credentials; "
                    "ask the carrier to stop the calls; estimate the loss for Finance.",
    },
    "DET-07": {
        "name": "SIM swap followed by account takeover",
        "technique": "T1451 SIM Card Swap (ATT&CK for Mobile)",
        "category": "Fraud (customer account)",
        "entity_type": "customer",
        "playbook": "Lock the customer account; cancel any port-out or device order; restore the "
                    "SIM with ID verification; contact the customer; review the agent's verification.",
    },
}
