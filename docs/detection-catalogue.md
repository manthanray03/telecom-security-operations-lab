# Detection catalogue

Seven rules, each mapped to MITRE ATT&CK, with its logic, threshold, severity, known false positives and the response playbook the analyst follows. Thresholds live in `secops/config.py`; the code is in `secops/detections.py`; each rule has unit tests in `tests/test_detections.py`, including the benign cases that must stay quiet.

Rules are assumed to run every 5 minutes, so an alert is raised at the first run after the event that crossed the threshold.

| Rule | Name | Log source | MITRE ATT&CK | Base severity |
|---|---|---|---|---|
| DET-01 | Password spraying | Sign-ins | T1110.003 Brute Force: Password Spraying | Medium (High if any success) |
| DET-02 | Brute force followed by a successful sign-in | Sign-ins | T1110.001 Brute Force: Password Guessing | High (Critical if privileged) |
| DET-03 | Impossible travel | Sign-ins | T1078 Valid Accounts | High (Critical if privileged) |
| DET-04 | Sign-in by a terminated employee's account | Sign-ins + HR roster | T1078 Valid Accounts | High |
| DET-05 | Port scan | Firewall | T1046 Network Service Discovery | Medium external, High internal |
| DET-06 | Toll fraud: after-hours international calling | VoIP call detail records | T1496 Resource Hijacking | High (Critical at $1,000+) |
| DET-07 | SIM swap followed by account takeover | Customer account events | T1451 SIM Card Swap (ATT&CK for Mobile) | High (Critical with port-out or device order) |

## DET-01 Password spraying

**Logic.** One source IP fails to sign in to 10 or more different accounts within 30 minutes.
**Why it matters.** Spraying tries one common password across many accounts to stay under lockout limits.
**False positives.** A misconfigured shared device or proxy retrying stale credentials. Check whether the usernames are real and whether the IP belongs to us.
**Playbook.** Block the IP at the VPN gateway and edge firewall. Search for any successful sign-in from it in the next 24 hours; reset any account that signed in. Tell targeted users to report unexpected MFA prompts.

## DET-02 Brute force followed by a successful sign-in

**Logic.** 8 or more failures against one account within 15 minutes, then a success within 30 minutes. Failures alone don't alert; the success is what matters.
**Severity.** Raised to Critical when the account holds a privileged permission (`user_admin`, `audit_log_admin`, `firewall_change`, `pbx_admin`).
**False positives.** A user who forgot a changed password and finally got it right. Their location and device usually match their history.
**Playbook.** Disable the account and end its sessions. Verify the user by phone on a known number, reset the password and enrol MFA. Review what the session did (for a network admin: the change log).

## DET-03 Impossible travel

**Logic.** Two successful sign-ins by the same user more than 500 km apart at an implied speed above 900 km/h, where the second location has not been seen for that user before.
**Why the "new location" condition.** When the real user signs back in from home after an attacker used the account abroad, that return trip is also "impossible". It isn't suspicious, so it is not alerted.
**False positives.** VPN or cloud proxy exits in another city. The 500 km floor ignores short hops between Saskatchewan offices.
**Playbook.** Call the user on a known number. If it wasn't them, revoke sessions, reset the password and check for mailbox rules, downloads and MFA changes made from the second location.

## DET-04 Sign-in by a terminated employee's account

**Logic.** A successful sign-in by an account whose HR record says Terminated, on a day after the termination date.
**False positives.** HR data entered with the wrong date. Confirm with HR before contacting anyone.
**Playbook.** Disable the account now. Tell HR and the former manager. Pull the application's audit log for what was viewed or changed. Find out why the leaver process missed it (see access review check AM-02).

## DET-05 Port scan

**Logic.** One source touches 25 or more distinct ports on one destination within 5 minutes.
**Severity.** Medium from outside (common internet noise, usually all denied). High from inside, because an internal host scanning servers may be infected or misused.
**False positives.** Authorized vulnerability scanners. Keep their IPs on an allow list.
**Playbook.** External: confirm every attempt was denied and block the IP. Internal: isolate the host, identify its owner from DHCP and asset records, and scan it for malware.

## DET-06 Toll fraud: after-hours international calling

**Logic.** For one extension, outside business hours (07:00 to 19:00, Monday to Friday), 8 or more international calls within 60 minutes, or 30 or more minutes to high-risk destinations in that window.
**Cost.** The alert estimates the loss from illustrative per-minute rates in `secops/config.py` (not a real tariff).
**False positives.** Staff who travel or work with overseas partners after hours. A single long call to a standard destination stays below both thresholds.
**Playbook.** Block international dialling on the extension and reset its SIP credentials. Ask the carrier to stop calls in progress. Estimate the loss for Finance and file a credit request.

## DET-07 SIM swap followed by account takeover

**Logic.** A SIM swap on a customer account, then a password reset within 24 hours. Other risky changes in the same window (email, address, port-out, device order) are listed in the evidence.
**Why it works.** After a swap the attacker receives the customer's one-time codes, so an SMS-based password reset is the usual next step.
**Severity.** Critical when a port-out request or device order follows, because money or the number itself is about to leave.
**False positives.** A customer who gets a new phone and resets their password the same day. The investigation checks the verification method and whether the customer confirms.
**Playbook.** Lock the account. Cancel any port-out or device order. Restore the SIM only after photo ID verification. Contact the customer on an alternate number. Review the verification the agent performed.
